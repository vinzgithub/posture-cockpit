# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Authorized, paginated domain metadata. No score averaging or storage writes."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ..core.scoring import FULL_COVERAGE
from .database import Database, Row

OVERDUE_GRACE = timedelta(hours=2)
MANUAL_OLD = timedelta(days=30)
EVALUATIONS = ("all", "complete", "partial", "undetermined", "not_evaluated")
SEVERITIES = ("all", "critical", "warning", "info")
FRESHNESS = ("all", "scheduled", "overdue", "failed", "running", "manual", "manual_old", "suspended", "unknown")
SORTS = {
    "attention": "has_critical DESC, fail_count DESC, (freshness='overdue') DESC, (freshness='failed') DESC, "
                 "coverage IS NOT NULL, coverage, measured_at IS NOT NULL, "
                 "measured_at, name, id",
    "name": "name, id",
    "recent": "measured_at IS NULL, measured_at DESC, name, id",
}


@dataclass(frozen=True)
class DomainFilter:
    name: str = ""
    evaluation: str = "all"
    severity: str = "all"
    freshness: str = "all"
    sort: str = "attention"
    page: int = 1
    size: int = 50

    def __post_init__(self) -> None:
        if (len(self.name) > 253 or self.evaluation not in EVALUATIONS or self.severity not in SEVERITIES
                or self.freshness not in FRESHNESS or self.sort not in SORTS
                or not 1 <= self.page <= 1_000_000 or not 1 <= self.size <= 100):
            raise ValueError("invalid domain pagination or filter")


@dataclass(frozen=True)
class DomainPage:
    rows: list[Row]
    total: int
    facts: dict[str, int]


BASE = """
WITH visible AS (
    SELECT d.*, p.name AS perimeter_name FROM domains d
    LEFT JOIN perimeters p ON p.id=d.perimeter_id
    WHERE (:internal OR d.perimeter_id IS NULL)
), current AS (
    SELECT d.*, s.id AS scan_id, s.score, s.grade, s.coverage, s.diagnostic_coverage,
           s.grade_withheld_reason, s.started_at, s.via, st.id AS state_id,
           st.at AS measured_at, st.origin AS measurement_origin,
           CASE WHEN s.score IS NULL THEN 'not_evaluated'
                WHEN s.grade_withheld_reason IS NOT NULL THEN 'undetermined'
                WHEN s.coverage<:full_coverage THEN 'partial' ELSE 'complete' END AS evaluation,
           sc.domain_id AS schedule_id, sc.enabled AS schedule_enabled,
           CASE
             WHEN sc.domain_id IS NULL OR sc.enabled=0 THEN
               CASE WHEN julianday(s.started_at)<julianday(:old_cutoff) THEN 'manual_old' ELSE 'manual' END
             WHEN :scheduler='off' THEN 'suspended'
             WHEN r.state='running' AND julianday(r.lease_until)>julianday(:now)
                  AND :scheduler IN ('here','elsewhere') THEN 'running'
             WHEN sc.failures>0 THEN 'failed'
             WHEN :scheduler NOT IN ('here','elsewhere') THEN 'unknown'
             WHEN r.state='running' OR julianday(sc.next_run_at) IS NULL THEN 'unknown'
             WHEN julianday(sc.next_run_at)<julianday(:late_cutoff) THEN 'overdue'
             ELSE 'scheduled'
           END AS freshness
    FROM visible d
    LEFT JOIN scans s ON s.id=(SELECT id FROM scans WHERE domain_id=d.id
                              ORDER BY started_at DESC,id DESC LIMIT 1)
    LEFT JOIN scan_states st ON st.id=(SELECT id FROM scan_states WHERE scan_id=s.id
                                      ORDER BY at DESC,id DESC LIMIT 1)
    LEFT JOIN schedules sc ON sc.domain_id=d.id
    LEFT JOIN schedule_runs r ON r.id=(SELECT id FROM schedule_runs WHERE domain_id=d.id
                                      ORDER BY claimed_at DESC,id DESC LIMIT 1)
), facts AS (
    SELECT current.*,
       (SELECT COUNT(*) FROM findings f LEFT JOIN rechecks rc
          ON rc.scan_id=f.scan_id AND rc.check_id=f.check_id
        WHERE f.scan_id=current.scan_id AND COALESCE(rc.status,f.status)='fail') AS fail_count,
       EXISTS(SELECT 1 FROM events e WHERE e.domain_id=current.id AND e.state='open') AS has_open,
       EXISTS(SELECT 1 FROM events e WHERE e.domain_id=current.id AND e.state='open'
               AND e.severity='critical') AS has_critical
    FROM current
)
"""


def statements(filters: DomainFilter, *, internal: bool, scheduler: str, now: datetime
               ) -> tuple[dict[str, str], dict[str, object]]:
    """SQL and bound values, exposed for tests and EXPLAIN profiling of the actual queries."""
    if scheduler not in ("here", "elsewhere", "off", "stalled"):
        raise ValueError("unknown scheduler state")
    now = now.astimezone(UTC)
    literal = filters.name.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    params: dict[str, object] = {
        "internal": int(internal), "scheduler": scheduler, "now": now.isoformat(),
        "old_cutoff": (now - MANUAL_OLD).isoformat(), "late_cutoff": (now - OVERDUE_GRACE).isoformat(),
        "full_coverage": FULL_COVERAGE, "name": f"%{literal}%", "evaluation": filters.evaluation,
        "severity": filters.severity, "freshness": filters.freshness, "size": filters.size,
        "offset": (filters.page - 1) * filters.size,
    }
    where = (" WHERE name LIKE :name ESCAPE '\\' "
             "AND (:evaluation='all' OR evaluation=:evaluation) "
             "AND (:freshness='all' OR freshness=:freshness) "
             "AND (:severity='all' OR EXISTS(SELECT 1 FROM events e WHERE e.domain_id=facts.id "
             "AND e.state='open' AND e.severity=:severity)) ")
    return {
        "page": BASE + "SELECT * FROM facts" + where + "ORDER BY " + SORTS[filters.sort]  # noqa: S608
                + " LIMIT :size OFFSET :offset",
        "count": BASE + "SELECT COUNT(*) FROM facts" + where,  # noqa: S608
        "facts": BASE + "SELECT COUNT(*) AS domains, "  # noqa: S608
                 "COALESCE(SUM(fail_count>0 OR has_open OR evaluation!='complete' "
                 "OR freshness IN ('overdue','failed')),0) AS attention, "
                 "COALESCE(SUM(score IS NULL),0) AS no_conclusive FROM facts",
        # The event policy is the existing one: global events visible to administrators only.
        "open_events": "SELECT COUNT(*) FROM events e LEFT JOIN domains d ON d.id=e.domain_id "
                       "WHERE e.state='open' AND (e.domain_id IS NULL OR d.id IS NOT NULL) "
                       "AND (:internal OR (e.domain_id IS NOT NULL AND d.perimeter_id IS NULL))",
    }, params


def domain_page(db: Database, filters: DomainFilter, *, internal: bool, scheduler: str,
                now: datetime) -> DomainPage:
    queries, params = statements(filters, internal=internal, scheduler=scheduler, now=now)
    # Bind centrally rather than interpolating any filter into a statement.
    def read(query: str) -> list[Row]:
        return db.all(query, params)

    rows = read(queries["page"])
    total = int(read(queries["count"])[0][0])
    facts = {key: int(value) for key, value in dict(read(queries["facts"])[0]).items()}
    facts["open_events"] = int(read(queries["open_events"])[0][0])
    return DomainPage(rows, total, facts)
