# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Bounded portfolio enrichment and factual scheduler state; no risk score."""
from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import datetime

from ..core import scoring
from ..core.compare import CheckChange, Snapshot, check_changes, compare_check, last_conclusive
from ..storage import Row
from ..storage.portfolio import DomainFilter, DomainPage
from ..storage.schedules import Schedule
from .scheduler import STALE, Scheduler, status
from .services import Services


@dataclass(frozen=True)
class Transition:
    change: CheckChange
    at: str
    previous_at: str
    missed: int = 0


@dataclass
class DomainView:
    row: Row
    schedule: Schedule | None = None
    last_run: Row | None = None
    events: dict[str, int] | None = None
    transition: Transition | None = None
    first_id: str | None = None
    first_title: str | None = None
    unreadable: bool = False
    scan_age_days: int | None = None


def scheduler_state(s: Services, scheduler: Scheduler | None, now: datetime) -> str:
    """A recent, non-future heartbeat is required before asserting operational lateness."""
    try:
        observed = status(s, scheduler, now)
        if observed["state"] == "off":
            return "off"
        at = observed["heartbeat_at"]
        if (at is not None and at.tzinfo is not None
                and 0 <= (now - at).total_seconds() <= STALE.total_seconds()):
            return str(observed["state"])
    except (ValueError, TypeError, OverflowError):
        pass
    return "off" if not s.config.scheduler else "stalled"


def latest_transition(states: list[Snapshot]) -> Transition | None:
    """Last proven transition within 30 states, without crossing a rules/inventory boundary."""
    for index in range(min(len(states) - 1, 29)):
        current, previous = states[index], states[index + 1]
        changes = check_changes(previous, current)
        if not changes.available:
            return None
        candidates = []
        for change in changes.changes:
            before_at, missed = previous.at, 0
            if change.kind == "unmeasured":
                # A later conclusive status may be compared with a known earlier one;
                # explicitly preserve the intervening missed measurements.
                if change.current not in ("ok", "warn", "fail"):
                    continue
                last = last_conclusive(states[index:], change.check_id)
                if last.state is None:
                    continue
                change = compare_check(change.check_id, last.state.checks[change.check_id], change.current)
                before_at, missed = last.state.at, len(last.missed)
            if change.kind in ("improved", "regressed", "new_issue", "not_applicable"):
                candidates.append(Transition(change, current.at, before_at, missed))
        if candidates:
            priority = {"regressed": 0, "new_issue": 1, "improved": 2, "not_applicable": 3}
            return min(candidates, key=lambda c: (priority[c.change.kind], c.change.check_id))
    return None


def load(s: Services, filters: DomainFilter, *, internal: bool, scheduler: str, now: datetime,
         lang: str) -> tuple[DomainPage, list[DomainView]]:
    """One authorized page; never fetch scans, histories or plans of off-page domains."""
    page = s.scans.domains_page(filters, internal=internal, scheduler=scheduler, now=now)
    if not page.rows:
        return page, []
    ids = [int(row["id"]) for row in page.rows]
    scan_ids = [int(row["scan_id"]) for row in page.rows if row["scan_id"] is not None]
    state_ids = [int(row["state_id"]) for row in page.rows if row["state_id"] is not None]
    scans, unreadable = s.scans.get_many(scan_ids)
    histories = s.scans.page_states(state_ids)
    schedules = s.schedules.for_domains(ids)
    marks = ",".join("?" * len(ids))
    events: dict[int, dict[str, int]] = {}
    for event in s.db.all("SELECT domain_id,severity,COUNT(*) AS n FROM events WHERE state='open' "  # noqa: S608
                          f"AND domain_id IN ({marks}) GROUP BY domain_id,severity", ids):
        events.setdefault(event["domain_id"], {})[event["severity"]] = event["n"]
    runs = {row["domain_id"]: row for row in s.db.all(
        "SELECT r.* FROM schedule_runs r "  # noqa: S608
        f"WHERE r.domain_id IN ({marks}) AND r.id=(SELECT id FROM schedule_runs "
        "WHERE domain_id=r.domain_id ORDER BY claimed_at DESC,id DESC LIMIT 1)", ids)}
    views = []
    for row in page.rows:
        did = row["id"]
        schedule = schedules.get(did)
        if schedule is not None and scheduler not in ("here", "elsewhere"):
            schedule = replace(schedule, next_run_at=None)
        view = DomainView(row, schedule, runs.get(did), events.get(did, {}), unreadable=row["scan_id"] in unreadable)
        try:
            snapshots = [Snapshot.from_row(dict(state)) for state in histories.get(did, [])]
            view.transition = latest_transition(snapshots)
        except (ValueError, TypeError, KeyError):
            view.transition = None
        scan = scans.get(row["scan_id"])
        if scan is not None:
            try:
                items = scoring.plan(scan.current(), s.registry).items
                if items:
                    finding = items[0].finding
                    view.first_id = finding.check_id
                    view.first_title = s.catalog.first(
                        lang, [f"{finding.outcome.summary}.action", f"{finding.check_id}.action"],
                        {"domain": scan.domain, **finding.outcome.params})
            except (ValueError, TypeError, KeyError, ArithmeticError):
                view.unreadable = True
        if row["started_at"]:
            with suppress(ValueError, TypeError, OverflowError):
                view.scan_age_days = max(0, (now - datetime.fromisoformat(row["started_at"])).days)
        views.append(view)
    return page, views
