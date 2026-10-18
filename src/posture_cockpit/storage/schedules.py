# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Scheduled scans and their runs (0.5.0): ``schedules`` and ``schedule_runs`` of schema 5.

One schedule per domain. When it is due is computed from its definition and the runs recorded
(core/schedule_time.py), never by adding a period to the last time: ``next_run_at`` is only the
time the scheduler looks at, written again at every change.

A run is one row per domain and slot (``UNIQUE(domain_id, slot)``). Its transitions, each in
one ``BEGIN IMMEDIATE`` transaction, so that two processes writing the same file run one after
the other (Révision 1, point 1):

- T1 claim: no row for the slot; insert ``running`` with a new random token (``claim``), its
  owner, ``attempts = 1`` and a lease of :data:`LEASE`; ``next_run_at`` moves on.
- T2 retry: the row is ``interrupted`` with ``attempts = 1`` and the slot is late by less than
  half a period; ``running`` again, ``attempts = 2``, a new token, a new lease.
- T3 finish: only while the row is ``running`` with *this* token: the scan, its state and the
  row ``done`` with ``scan_id`` are written in the same transaction. Otherwise nothing at all is
  written: a process that lost its claim never records a result.
- T4 fail, T5 interrupt: the same condition on the token.
- T6 reconcile: a ``running`` row whose lease has expired becomes ``interrupted``. The lease is
  longer than the time allowed to a scan, so a live attempt is never reconciled.
- T7 miss, skip: no row for the slot; insert ``missed`` or ``skipped`` with the reason.

No ``await`` happens inside any of them (storage/database.py).
"""

from __future__ import annotations

import os
import secrets
import socket
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any

from ..core import schedule_time
from ..core.schedule_time import Definition, Occurrence
from .database import Database, Row

LEASE = timedelta(minutes=15)       # longer than the 10 minutes allowed to a scheduled scan
RETENTION = timedelta(days=400)     # finished runs are deleted after this; never running or interrupted ones
ATTEMPTED = ("running", "done", "failed", "interrupted")  # runs that reached the network


def iso(moment: datetime) -> str:
    """A time as stored: ISO 8601, UTC, to the second."""
    return moment.astimezone(UTC).replace(microsecond=0).isoformat()


def owner() -> str:
    """Who claims: host and process, for the administration page and the logs."""
    return f"{socket.gethostname()}:{os.getpid()}"


@dataclass(frozen=True)
class Schedule:
    domain_id: int
    domain: str
    perimeter_id: int | None
    definition: Definition
    enabled: bool
    next_run_at: str | None
    failures: int
    updated_at: str
    updated_by: int | None

    def describe(self) -> dict[str, Any]:
        """What the audit log keeps of it."""
        d = self.definition
        return {"frequency": d.frequency, "time": schedule_time.format_time(d.at_minute), "weekday": d.weekday,
                "monthday": d.monthday, "enabled": self.enabled}


@dataclass(frozen=True)
class Decision:
    """What the slot due now needs: ``run`` (T1), ``retry`` (T2, ``run_id``) or ``missed`` (T7)."""
    action: str
    occurrence: Occurrence
    run_id: int | None = None


@dataclass(frozen=True)
class Claim:
    run_id: int
    domain_id: int
    slot: str
    token: str
    attempts: int


def _definition(row: Row) -> Definition:
    return Definition(row["frequency"], int(row["at_minute"]), row["weekday"], row["monthday"])


class Schedules:
    def __init__(self, db: Database, tz: tzinfo):
        self.db = db
        self.tz = tz

    # ----------------------------------------------------------- definitions
    def get(self, domain_id: int) -> Schedule | None:
        row = self.db.one("SELECT sc.*, d.name AS domain, d.perimeter_id FROM schedules sc "
                          "JOIN domains d ON d.id = sc.domain_id WHERE sc.domain_id = ?", (domain_id,))
        return self._schedule(row) if row else None

    def _schedule(self, row: Row) -> Schedule:
        return Schedule(row["domain_id"], row["domain"], row["perimeter_id"], _definition(row), bool(row["enabled"]),
                        row["next_run_at"], row["failures"], row["updated_at"], row["updated_by"])

    def set(self, domain_id: int, definition: Definition, *, enabled: bool, user_id: int | None,
            now: datetime) -> tuple[Schedule | None, Schedule]:
        """Creates or changes the schedule of a domain; returns it before and after."""
        with self.db.transaction(immediate=True):
            before = self.get(domain_id)
            self.db.execute(
                "INSERT INTO schedules(domain_id, frequency, weekday, monthday, at_minute, enabled, updated_at,"
                " updated_by) VALUES(?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(domain_id) DO UPDATE SET"
                " frequency = excluded.frequency, weekday = excluded.weekday, monthday = excluded.monthday,"
                " at_minute = excluded.at_minute, enabled = excluded.enabled, updated_at = excluded.updated_at,"
                " updated_by = excluded.updated_by",
                (domain_id, definition.frequency, definition.weekday, definition.monthday, definition.at_minute,
                 int(enabled), iso(now), user_id))
            self._refresh(domain_id, now)
            after = self.get(domain_id)
        assert after is not None
        return before, after

    def remove(self, domain_id: int) -> Schedule | None:
        """Deletes the schedule of a domain, not its runs (they stay with the domain); returns it."""
        with self.db.transaction(immediate=True):
            before = self.get(domain_id)
            self.db.execute("DELETE FROM schedules WHERE domain_id = ?", (domain_id,))
        return before

    # ------------------------------------------------------------ due times
    def _runs_by_slot(self, domain_id: int) -> dict[str, Row]:
        return {r["slot"]: r for r in self.db.all("SELECT * FROM schedule_runs WHERE domain_id = ?", (domain_id,))}

    def decide(self, schedule: Schedule, now: datetime) -> Decision | None:
        """What the latest occurrence at or before ``now`` needs, if anything (see the module)."""
        definition = schedule.definition
        candidate = schedule_time.latest(definition, self.tz, schedule.domain, now)
        if candidate is None:
            return None
        runs = self._runs_by_slot(schedule.domain_id)
        # Not an occurrence from before the schedule was set (created, changed, resumed: no catching
        # up on a time that did not apply yet), nor one less than half a period after an attempt
        # (a changed time never runs a domain twice in a period).
        not_after = [datetime.fromisoformat(schedule.updated_at)]
        not_after += [datetime.fromisoformat(r["claimed_at"]) + definition.half_period for slot, r in runs.items()
                      if r["state"] in ATTEMPTED and slot != candidate.slot]
        if candidate.at <= max(not_after):
            return None
        late = schedule_time.too_late(candidate, definition, now)
        row = runs.get(candidate.slot)
        if row is None:
            return Decision("missed" if late else "run", candidate)
        if row["state"] == "interrupted" and row["attempts"] < 2 and not late:
            return Decision("retry", candidate, row["id"])
        return None

    def _next_run_at(self, schedule: Schedule, now: datetime) -> str:
        decision = self.decide(schedule, now)
        if decision is not None:
            return iso(decision.occurrence.at)  # due now (a missed slot too: it is noted at once)
        attempted = [datetime.fromisoformat(r["claimed_at"]) for r in self._runs_by_slot(schedule.domain_id).values()
                     if r["state"] in ATTEMPTED]
        threshold = max([now, datetime.fromisoformat(schedule.updated_at),
                         *(a + schedule.definition.half_period for a in attempted)])
        return iso(schedule_time.following(schedule.definition, self.tz, schedule.domain, threshold).at)

    def _refresh(self, domain_id: int, now: datetime) -> None:
        schedule = self.get(domain_id)
        if schedule is not None:
            self.db.execute("UPDATE schedules SET next_run_at = ? WHERE domain_id = ?",
                            (self._next_run_at(schedule, now), domain_id))

    def refresh(self, domain_id: int, now: datetime) -> None:
        with self.db.transaction(immediate=True):
            self._refresh(domain_id, now)

    def refresh_all(self, now: datetime) -> None:
        """Every due time computed again from its definition (at start, after a change of zone)."""
        with self.db.transaction(immediate=True):
            for (domain_id,) in self.db.all("SELECT domain_id FROM schedules"):
                self._refresh(domain_id, now)

    def due(self, now: datetime) -> list[Schedule]:
        """Enabled schedules whose time has come, the oldest first."""
        rows = self.db.all("SELECT sc.*, d.name AS domain, d.perimeter_id FROM schedules sc "
                           "JOIN domains d ON d.id = sc.domain_id "
                           "WHERE sc.enabled = 1 AND sc.next_run_at IS NOT NULL AND sc.next_run_at <= ? "
                           "ORDER BY sc.next_run_at, sc.domain_id", (iso(now),))
        return [self._schedule(r) for r in rows]

    # ---------------------------------------------------------- transitions
    def claim(self, schedule: Schedule, decision: Decision, who: str, now: datetime) -> Claim | None:
        """T1 or T2. None when the slot was taken meanwhile (another process, a change)."""
        token = secrets.token_hex(16)
        try:
            with self.db.transaction(immediate=True):
                current = self.get(schedule.domain_id)
                again = self.decide(current, now) if current is not None and current.enabled else None
                if again is None or again.action != decision.action or again.occurrence != decision.occurrence:
                    return None
                if decision.action == "run":
                    cur = self.db.execute(
                        "INSERT INTO schedule_runs(domain_id, slot, state, claim, owner, attempts, claimed_at,"
                        " lease_until) VALUES(?, ?, 'running', ?, ?, 1, ?, ?)",
                        (schedule.domain_id, decision.occurrence.slot, token, who, iso(now), iso(now + LEASE)))
                    run_id, attempts = int(cur.lastrowid or 0), 1
                elif decision.action == "retry":
                    cur = self.db.execute(
                        "UPDATE schedule_runs SET state = 'running', attempts = 2, claim = ?, owner = ?,"
                        " claimed_at = ?, lease_until = ?, reason = '', finished_at = NULL"
                        " WHERE id = ? AND state = 'interrupted' AND attempts = 1",
                        (token, who, iso(now), iso(now + LEASE), decision.run_id))
                    if cur.rowcount != 1:
                        return None
                    assert decision.run_id is not None
                    run_id, attempts = decision.run_id, 2
                else:
                    raise ValueError(f"not a claim: {decision.action}")
                self._refresh(schedule.domain_id, now)
        except sqlite3.IntegrityError:  # UNIQUE(domain_id, slot): another process inserted it first
            return None
        return Claim(run_id, schedule.domain_id, decision.occurrence.slot, token, attempts)

    def note(self, schedule: Schedule, occurrence: Occurrence, state: str, reason: str, who: str,
             now: datetime) -> bool:
        """T7: a slot noted ``missed`` or ``skipped`` (with its reason) instead of run."""
        if state not in ("missed", "skipped"):
            raise ValueError(state)
        try:
            with self.db.transaction(immediate=True):
                self.db.execute(
                    "INSERT INTO schedule_runs(domain_id, slot, state, reason, claim, owner, attempts, claimed_at,"
                    " finished_at) VALUES(?, ?, ?, ?, ?, ?, 1, ?, ?)",
                    (schedule.domain_id, occurrence.slot, state, reason, secrets.token_hex(16), who, iso(now),
                     iso(now)))
                self._refresh(schedule.domain_id, now)
        except sqlite3.IntegrityError:
            return False
        return True

    def finish(self, claim: Claim, save: Callable[[], int], now: datetime) -> int | None:
        """T3: ``save()`` records the scan (inside this transaction) only while the claim holds;
        returns the scan id, or None when the claim was lost or the domain deleted: then nothing
        at all is written."""
        with self.db.transaction(immediate=True):
            if not self._holds(claim):
                return None
            scan_id = save()
            self.db.execute("UPDATE schedule_runs SET state = 'done', scan_id = ?, finished_at = ?, lease_until = NULL,"
                            " reason = '' WHERE id = ? AND state = 'running' AND claim = ?",
                            (scan_id, iso(now), claim.run_id, claim.token))
            self.db.execute("UPDATE schedules SET failures = 0 WHERE domain_id = ?", (claim.domain_id,))
            # A successful scheduled scan conclusively resolves a consecutive-failure incident.
            self.db.execute(
                "UPDATE events SET state='resolved', severity='info', resolved_at=?, updated_at=?, "
                "resolved_scan_id=?, resolution='scheduled_scan_succeeded' "
                "WHERE domain_id=? AND kind='schedule_failures' AND subject='' AND state='open'",
                (iso(now), iso(now), scan_id, claim.domain_id))
        return scan_id

    def _holds(self, claim: Claim) -> bool:
        return self.db.one("SELECT 1 FROM schedule_runs r JOIN domains d ON d.id = r.domain_id "
                           "WHERE r.id = ? AND r.state = 'running' AND r.claim = ?",
                           (claim.run_id, claim.token)) is not None

    def fail(self, claim: Claim, reason: str, now: datetime) -> bool:
        """T4: the attempt failed (timeout, error, database); one more consecutive failure."""
        with self.db.transaction(immediate=True):
            cur = self.db.execute(
                "UPDATE schedule_runs SET state = 'failed', reason = ?, finished_at = ?, lease_until = NULL"
                " WHERE id = ? AND state = 'running' AND claim = ?",
                (reason[:200], iso(now), claim.run_id, claim.token))
            if cur.rowcount != 1:
                return False
            self.db.execute("UPDATE schedules SET failures = failures + 1 WHERE domain_id = ?", (claim.domain_id,))
            failures = int(self.db.value("SELECT failures FROM schedules WHERE domain_id=?", (claim.domain_id,)) or 0)
            if failures >= 3:
                # One live incident per domain; update rather than flood the event center.
                existing = self.db.one(
                    "SELECT id FROM events WHERE domain_id=? AND kind='schedule_failures' "
                    "AND subject='' AND state='open'", (claim.domain_id,))
                if existing:
                    self.db.execute("UPDATE events SET updated_at=? WHERE id=?", (iso(now), existing["id"]))
                else:
                    self.db.execute(
                        "INSERT INTO events(domain_id,category,kind,subject,state,severity,opened_at,updated_at) "
                        "VALUES(?,'technical','schedule_failures','','open','warning',?,?)",
                        (claim.domain_id, iso(now), iso(now)))
            self._refresh(claim.domain_id, now)
        return True

    def interrupt(self, claim: Claim, reason: str, now: datetime) -> bool:
        """T5: the server stops during the scan; the slot may be retried once (T2)."""
        with self.db.transaction(immediate=True):
            cur = self.db.execute(
                "UPDATE schedule_runs SET state = 'interrupted', reason = ?, finished_at = ?, lease_until = NULL"
                " WHERE id = ? AND state = 'running' AND claim = ?", (reason, iso(now), claim.run_id, claim.token))
            if cur.rowcount == 1:
                self._refresh(claim.domain_id, now)
            return cur.rowcount == 1

    def reconcile(self, now: datetime) -> int:
        """T6: running rows whose lease expired (a process killed, a machine stopped) become
        interrupted, and may be retried once. Returns how many."""
        with self.db.transaction(immediate=True):
            rows = self.db.all("SELECT id, domain_id FROM schedule_runs WHERE state = 'running' AND lease_until < ?",
                               (iso(now),))
            for row in rows:
                self.db.execute("UPDATE schedule_runs SET state = 'interrupted', reason = 'lease_expired',"
                                " finished_at = ?, lease_until = NULL WHERE id = ? AND state = 'running'",
                                (iso(now), row["id"]))
            for domain_id in {row["domain_id"] for row in rows}:
                self._refresh(domain_id, now)
        return len(rows)

    def purge(self, now: datetime) -> int:
        """Finished runs older than :data:`RETENTION`; never a running or interrupted one."""
        cur = self.db.execute("DELETE FROM schedule_runs WHERE state IN ('done', 'failed', 'skipped', 'missed')"
                              " AND finished_at < ?", (iso(now - RETENTION),))
        return cur.rowcount

    # ------------------------------------------------------------- listings
    def upcoming(self, limit: int = 10, *, internal: bool = True) -> list[Schedule]:
        rows = self.db.all("SELECT sc.*, d.name AS domain, d.perimeter_id FROM schedules sc "
                           "JOIN domains d ON d.id = sc.domain_id"
                           " WHERE sc.enabled = 1 AND (? OR d.perimeter_id IS NULL)"
                           " ORDER BY sc.next_run_at, d.name LIMIT ?", (int(internal), limit))
        return [self._schedule(r) for r in rows]

    def runs(self, domain_id: int | None = None, *, limit: int = 20, not_done: bool = False) -> list[Row]:
        """Runs, the latest claimed first: of one domain, or of all, the problems only if asked."""
        where, params = ["1"], []
        if domain_id is not None:
            where.append("r.domain_id = ?")
            params.append(domain_id)
        if not_done:
            where.append("r.state != 'done'")
        return self.db.all(f"SELECT r.*, d.name AS domain FROM schedule_runs r JOIN domains d ON d.id = r.domain_id "  # noqa: S608
                           f"WHERE {' AND '.join(where)} ORDER BY r.claimed_at DESC, r.id DESC LIMIT ?",
                           (*params, limit))
