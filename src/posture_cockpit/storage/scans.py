# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Domains and their scans.

A scan is saved with all its findings and never changes afterwards. When the
user clicks "Vérifier" on the plan, that one check runs again and its result
is saved as a *recheck* of the scan: the current state of the domain is the
scan's findings with their latest rechecks applied (:meth:`Scan.current`),
while the plan keeps the order computed from the original findings.

A new full scan creates a new row, so the history of scores stays available.

The score, grade and coverage stored with a scan are those of
:func:`~posture_cockpit.core.scoring.assess` on its current findings, written
at each save and recheck; :meth:`Scan.assessment` computes the same from the
findings, so every page, the API and the PDF show the same result.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from ..core import scoring
from ..core.engine import ScanResult
from ..core.model import HTTPS_ROOT_CHECK, Finding
from .database import Database, Row, utcnow


class CorruptScan(Exception):
    """An existing scan cannot be decoded. Never expose its stored payload to a client."""

    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        super().__init__("scan_unreadable")


@dataclass(frozen=True)
class Recheck:
    finding: Finding
    checked_at: str


@dataclass(frozen=True)
class Scan:
    id: int
    domain_id: int
    domain: str
    started_at: str
    duration_ms: int
    score: int | None  # current score, rechecks included; None: not evaluated
    grade: str | None
    coverage: float
    version: str
    perimeter: str                                # internal perimeter of the scan, "" for the Internet
    findings: list[Finding]                       # as found by the scan
    rechecks: dict[str, Recheck] = field(default_factory=dict)  # by check id

    def current(self) -> list[Finding]:
        """The findings with the latest recheck of each one applied."""
        return [self.rechecks[f.check_id].finding if f.check_id in self.rechecks else f for f in self.findings]

    def addresses(self) -> dict:
        root = next((f for f in self.current() if f.check_id == HTTPS_ROOT_CHECK), None)
        return dict(root.outcome.evidence.get("addresses", {})) if root else {}

    def nonconclusive(self) -> int:
        """Attempted (host, address) pairs without a conclusive answer; unattempted pairs are excluded."""
        addresses = self.addresses()
        return addresses.get("attempted", 0) - addresses.get("conclusive", 0)

    def assessment(self) -> scoring.Assessment:
        """Score, grade and coverage of the current findings."""
        return scoring.assess(self.current())


def _stored_finding(check_id: str, category: str, weight: int, status: str, payload: str) -> Finding:
    data = json.loads(payload)
    if not isinstance(data, dict) or not isinstance(data.get("summary"), str):
        raise ValueError("invalid outcome")
    for name in ("params", "evidence"):
        if not isinstance(data.get(name, {}), dict):
            raise ValueError("invalid outcome mapping")
    family = data.get("family") or {}
    if not isinstance(family, dict):
        raise ValueError("invalid family")
    if family.get("floor") is not None and not math.isfinite(float(family["floor"])):
        raise ValueError("non-finite floor")
    if family.get("name") == "https" and family.get("role") == "root" and check_id != HTTPS_ROOT_CHECK:
        raise ValueError("false HTTPS root")
    return Finding.from_stored(check_id, category, weight, status, data)


def _finding(row: Row) -> Finding:
    return _stored_finding(row["check_id"], row["category"], row["weight"], row["status"], row["outcome"])


class Scans:
    def __init__(self, db: Database):
        self.db = db

    # ---------------------------------------------------------------- domains
    def add_domain(self, name: str, user_id: int | None, perimeter_id: int | None = None) -> int:
        """Id of the domain, created if needed (in ``perimeter_id``, or on the Internet).

        A domain keeps the perimeter it was created in: callers check it first."""
        row = self.db.one("SELECT id FROM domains WHERE name = ?", (name,))
        if row:
            return int(row["id"])
        cur = self.db.execute("INSERT INTO domains(name, created_at, created_by, perimeter_id) VALUES(?, ?, ?, ?)",
                              (name, utcnow(), user_id, perimeter_id))
        return int(cur.lastrowid or 0)

    def domain(self, name: str) -> Row | None:
        """The domain, with the name of its perimeter (``perimeter``, None on the Internet)."""
        return self.db.one("SELECT d.*, p.name AS perimeter FROM domains d "
                           "LEFT JOIN perimeters p ON p.id = d.perimeter_id WHERE d.name = ?", (name,))

    def domains(self, *, internal: bool) -> list[Row]:
        """Every domain with its latest scan (id, score, grade, date), most recently scanned first.

        ``internal``: include the domains of internal perimeters (for administrators only)."""
        return self.db.all(
            "SELECT d.*, p.name AS perimeter, s.id AS scan_id, s.score, s.grade, s.coverage, s.started_at "
            "FROM domains d "
            "LEFT JOIN perimeters p ON p.id = d.perimeter_id "
            "LEFT JOIN scans s ON s.id = (SELECT id FROM scans WHERE domain_id = d.id"
            " ORDER BY started_at DESC, id DESC LIMIT 1) "
            "WHERE ? OR d.perimeter_id IS NULL "
            "ORDER BY s.started_at IS NULL, s.started_at DESC, d.name", (int(internal),))

    def set_dns_host(self, domain_id: int, host_id: str) -> None:
        self.db.execute("UPDATE domains SET dns_host = ? WHERE id = ?", (host_id, domain_id))

    def delete_domain(self, domain_id: int) -> None:
        """The domain and all its scans."""
        self.db.execute("DELETE FROM domains WHERE id = ?", (domain_id,))

    # ------------------------------------------------------------------ scans
    def save(self, domain_id: int, result: ScanResult, version: str, user_id: int | None,
             perimeter: str = "") -> int:
        assessment = scoring.assess(result.findings)
        with self.db.transaction():
            cur = self.db.execute(
                "INSERT INTO scans(domain_id, started_at, duration_ms, score, grade, coverage, version, started_by,"
                " perimeter) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (domain_id, result.started_at.replace(microsecond=0).isoformat(), result.duration_ms,
                 assessment.score, assessment.grade, assessment.coverage, version, user_id, perimeter))
            scan_id = int(cur.lastrowid or 0)
            self.db.executemany(
                "INSERT INTO findings(scan_id, check_id, category, weight, status, outcome) VALUES(?, ?, ?, ?, ?, ?)",
                [(scan_id, f.check_id, f.category, f.weight, f.status.value, json.dumps(f.outcome_json()))
                 for f in result.findings])
            self._update_metrics(scan_id, assessment, result.findings)
        return scan_id

    def latest(self, domain_id: int) -> Scan | None:
        scan_id = self.latest_id(domain_id)
        return self.get(scan_id) if scan_id else None

    def latest_id(self, domain_id: int) -> int | None:
        """The number of the latest scan of a domain: the one the plan of fixes shows."""
        scan_id = self.db.value("SELECT id FROM scans WHERE domain_id = ? ORDER BY started_at DESC, id DESC LIMIT 1",
                                (domain_id,))
        return int(scan_id) if scan_id else None

    def get(self, scan_id: int) -> Scan | None:
        row = self.db.one("SELECT s.*, d.name AS domain FROM scans s JOIN domains d ON d.id = s.domain_id "
                          "WHERE s.id = ?", (scan_id,))
        if row is None:
            return None
        try:
            return self._read_scan(scan_id, row)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError) as error:
            raise CorruptScan(scan_id) from error

    def _read_scan(self, scan_id: int, row: Row) -> Scan:
        findings = [_finding(r) for r in self.db.all("SELECT * FROM findings WHERE scan_id = ? ORDER BY rowid",
                                                     (scan_id,))]
        originals = {f.check_id: f for f in findings}
        rechecks = {}
        for r in self.db.all("SELECT * FROM rechecks WHERE scan_id = ?", (scan_id,)):
            original = originals.get(r["check_id"])
            if original is not None:
                rechecked = _stored_finding(r["check_id"], original.category, original.weight, r["status"],
                                            r["outcome"])
                rechecks[r["check_id"]] = Recheck(rechecked, r["checked_at"])
        return Scan(row["id"], row["domain_id"], row["domain"], row["started_at"], row["duration_ms"], row["score"],
                    row["grade"], row["coverage"], row["version"], row["perimeter"], findings, rechecks)

    def history(self, domain_id: int, limit: int = 24) -> list[Row]:
        """The last scans of a domain (date, score, grade, coverage, perimeter), newest first."""
        return self.db.all("SELECT * FROM scans "
                           "WHERE domain_id = ? ORDER BY started_at DESC, id DESC LIMIT ?", (domain_id, limit))

    def history_page(self, domain_id: int, *, page: int = 1, page_size: int = 20) -> tuple[list[Row], int]:
        """Page of stored scans and total count; no changes to historic records."""
        if page < 1 or not 1 <= page_size <= 100:
            raise ValueError("Invalid history pagination")
        total = int(self.db.value("SELECT COUNT(*) FROM scans WHERE domain_id = ?", (domain_id,)) or 0)
        rows = self.db.all(
            "SELECT * FROM scans "
            "WHERE domain_id = ? ORDER BY started_at DESC, id DESC LIMIT ? OFFSET ?",
            (domain_id, page_size, (page - 1) * page_size),
        )
        return rows, total

    def https_history(self, domain: str, now: datetime | None = None) -> dict:
        """Read observations only, including the latest rechecks; never contact the network."""
        from ..core.https_history import summarize

        events: list[tuple[str, dict]] = []
        rows = self.db.all(
            "SELECT s.started_at AS at, f.outcome FROM findings f JOIN scans s ON s.id=f.scan_id "
            "JOIN domains d ON d.id=s.domain_id WHERE d.name=? AND f.check_id=? "
            "UNION ALL SELECT r.checked_at AS at, r.outcome FROM rechecks r JOIN scans s ON s.id=r.scan_id "
            "JOIN domains d ON d.id=s.domain_id WHERE d.name=? AND r.check_id=? ORDER BY at",
            (domain, HTTPS_ROOT_CHECK, domain, HTTPS_ROOT_CHECK))
        for row in rows:
            try:
                evidence = json.loads(row["outcome"]).get("evidence", {})
                observed = [(e["at"], e["observation"]) for e in evidence.get("https_history_previous", [])]
                observed.append((row["at"], evidence.get("https_history", {})))
                # Validate this scan's observations in isolation before accepting any of them.
                summarize(observed, now or datetime.now(UTC))
                events.extend(observed)
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
                continue
        return summarize(events, now or datetime.now(UTC))

    def _update_metrics(self, scan_id: int, a: scoring.Assessment, findings: list[Finding]) -> None:
        root = next((f for f in findings if f.check_id == HTTPS_ROOT_CHECK), None)
        addresses = root.outcome.evidence.get("addresses", {}) if root else {}
        self.db.execute(
            "UPDATE scans SET score_raw=?, score_cap=?, score_final=?, diagnostic_coverage=?, checks_blocked=?, "
            "addresses_discovered=?, addresses_attempted=?, addresses_conclusive=?, grade_withheld_reason=?, "
            "cap_reasons=? WHERE id=?",
            (a.score_raw, a.score_cap, a.score_final, a.diagnostic_coverage, a.blocked,
             addresses.get("discovered"), addresses.get("attempted"), addresses.get("conclusive"),
             a.grade_withheld_reason, json.dumps(a.cap_reasons), scan_id))

    def save_recheck(self, scan_id: int, finding: Finding) -> scoring.Assessment:
        return self.save_rechecks(scan_id, [finding])

    def save_rechecks(self, scan_id: int, findings: list[Finding]) -> scoring.Assessment:
        """Store a whole recheck group and its metrics in one transaction."""
        with self.db.transaction():
            stamp = utcnow()
            for finding in findings:
                if finding.check_id == HTTPS_ROOT_CHECK:
                    previous = self.db.one("SELECT outcome, checked_at FROM rechecks WHERE scan_id=? AND check_id=?",
                                           (scan_id, HTTPS_ROOT_CHECK))
                    if previous:
                        old = json.loads(previous["outcome"]).get("evidence", {})
                        from ..core.https_history import compact

                        events = [(e["at"], e["observation"]) for e in old.get("https_history_previous", [])]
                        events.append((previous["checked_at"], old.get("https_history", {})))
                        trail = compact(events)
                        finding = replace(finding, outcome=replace(
                            finding.outcome, evidence={**finding.outcome.evidence, "https_history_previous": trail}))
                self.db.execute(
                    "INSERT INTO rechecks(scan_id, check_id, status, outcome, checked_at) VALUES(?, ?, ?, ?, ?) "
                    "ON CONFLICT(scan_id, check_id) DO UPDATE SET status = excluded.status, "
                    "outcome = excluded.outcome, "
                    "checked_at = excluded.checked_at",
                    (scan_id, finding.check_id, finding.status.value, json.dumps(finding.outcome_json()), stamp))
            scan = self.get(scan_id)
            assert scan is not None
            assessment = scan.assessment()
            self.db.execute("UPDATE scans SET score = ?, grade = ?, coverage = ? WHERE id = ?",
                            (assessment.score, assessment.grade, assessment.coverage, scan_id))
            self._update_metrics(scan_id, assessment, scan.current())
        return assessment
