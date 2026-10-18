# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The scheduler of scheduled scans (0.5.0): one asyncio task in the web process.

- **Role.** With ``POSTURE_COCKPIT_SCHEDULER=off`` nothing starts. Otherwise the process tries
  the exclusive lock ``.posture-cockpit-scheduler.lock`` (storage/instance_lock.py) without
  waiting, and again every minute while another process has it. On taking the role it computes
  every due time again from its definition (a change of zone, a stopped instance) and waits
  :data:`START_DELAY` before the first scan.
- **Tick**, every minute or as soon as a schedule changes: a heartbeat in ``meta``; expired
  leases reconciled; the daily maintenance (purge of old runs); then the due schedules, the
  oldest first, one at a time.
- **One due schedule**, synchronously up to the claim (no other task can step in): the decision
  (storage/schedules.py); missed, skipped (a scan of the domain already running here, internal
  scans turned off) or deferred in memory, without writing (no slot left for the scheduler, which
  always leaves one to the people, or its hourly share used); else the claim. Then the scan,
  exactly as a manual one but with the perimeter read again, within :data:`SCAN_TIMEOUT`; the
  result is recorded only while the claim holds (``finish``), with ``via = 'schedule'``.
- **Failures.** A timeout, an exception or a database error makes the run ``failed`` and counts
  one more consecutive failure; a stop of the server during the scan makes it ``interrupted``
  (written in ``finally``), retried once at the next start if still in time. An unexpected error
  of the loop is logged and the loop starts again a minute later; the heartbeat shows it.

It never calls ``scan_and_save``, which would create a deleted domain again and write an audit
entry per scan: Internet scans are traced in ``schedule_runs``, internal ones in the audit log
too, one by one.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import socket
import sqlite3
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from .. import __version__
from ..scanner import InternalScansDisabled
from ..storage import instance_lock
from ..storage.schedules import Claim, Schedule, Schedules, owner
from .limits import TooManyScans
from .scanning import scanning
from .services import Services

log = logging.getLogger("uvicorn.error")

START_DELAY = timedelta(seconds=120)    # nothing runs while the instance starts
TICK = timedelta(seconds=60)
SCAN_TIMEOUT = timedelta(seconds=600)   # shorter than the lease of a claim (15 minutes)
LOCK_RETRY = timedelta(seconds=60)
PRINCIPAL = "system:scheduler"
HEARTBEAT_KEY = "scheduler_heartbeat"
MAINTENANCE_KEY = "scheduler_maintenance"
STALE = timedelta(minutes=3)            # a heartbeat older than this: the scheduler is not running


class Scheduler:
    def __init__(self, services: Services, schedules: Schedules, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC),
                 sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
                 take_lock: Callable[[], instance_lock.Held] | None = None):
        self.s = services
        self.schedules = schedules
        self.clock = clock
        self.sleep = sleep
        self._take_lock = take_lock or (lambda: instance_lock.scheduler(services.config.data_dir))
        self._lock: instance_lock.Held | None = None
        self._deferred: dict[int, datetime] = {}   # domain id -> not before (in memory only)
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.leader = False
        self.who = owner()

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        """Called at the start of the application (inside its event loop)."""
        self._wake = asyncio.Event()
        self._task = asyncio.create_task(self.run(), name="posture-cockpit-scheduler")

    async def stop(self) -> None:
        """Called when the application stops: the running scan, if any, is interrupted."""
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(self._task, 5)
            self._task = None
        self._release()

    def wake(self) -> None:
        """A schedule changed: look at the due times now rather than at the next tick."""
        self._wake.set()

    def _release(self) -> None:
        if self._lock is not None:
            self._lock.release()
            self._lock = None
        self.leader = False

    async def run(self) -> None:
        try:
            await self._become_leader()
            await self.sleep(START_DELAY.total_seconds())
            while True:
                try:
                    await self.run_once()
                except asyncio.CancelledError:
                    raise
                except Exception:  # supervision: logged, the loop starts again after a tick
                    log.exception("The scheduler failed; it starts again in a minute.")
                    await self.sleep(TICK.total_seconds())
                    continue
                await self._pause()
        finally:
            self._release()

    async def _become_leader(self) -> None:
        while True:
            try:
                self._lock = self._take_lock()
                break
            except instance_lock.Busy:
                await self.sleep(LOCK_RETRY.total_seconds())
        self.leader = True
        now = self.clock()
        self.schedules.refresh_all(now)
        self._heartbeat(now)
        log.info("Scheduled scans: this process schedules them (%s).", self.who)

    async def _pause(self) -> None:
        self._wake.clear()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._wake.wait(), TICK.total_seconds())

    # ------------------------------------------------------------------ tick
    def _heartbeat(self, now: datetime) -> None:
        self.s.db.set_meta(HEARTBEAT_KEY, json.dumps(
            {"pid": os.getpid(), "host": socket.gethostname(), "version": __version__,
             "at": now.astimezone(UTC).replace(microsecond=0).isoformat()}))

    def _maintenance(self, now: datetime) -> None:
        today = now.astimezone(UTC).date().isoformat()
        if self.s.db.get_meta(MAINTENANCE_KEY) == today:
            return
        purged = self.schedules.purge(now)
        self.s.db.set_meta(MAINTENANCE_KEY, today)
        if purged:
            log.info("Scheduled scans: %d finished runs older than 400 days deleted.", purged)

    async def run_once(self) -> None:
        """One tick: heartbeat, reconciliation, maintenance, then every due schedule in turn."""
        now = self.clock()
        self._heartbeat(now)
        self.schedules.reconcile(now)
        self._maintenance(now)
        handled: set[int] = set()
        while True:
            now = self.clock()
            schedule = next((x for x in self.schedules.due(now)
                             if x.domain_id not in handled and self._deferred.get(x.domain_id, now) <= now), None)
            if schedule is None:
                return
            handled.add(schedule.domain_id)
            self._deferred.pop(schedule.domain_id, None)
            await self._handle(schedule, now)

    def _defer(self, schedule: Schedule, now: datetime, seconds: float) -> None:
        self._deferred[schedule.domain_id] = now + timedelta(seconds=seconds)

    async def _handle(self, schedule: Schedule, now: datetime) -> None:
        # Synchronous up to the claim: nothing else can run in this process meanwhile.
        decision = self.schedules.decide(schedule, now)
        if decision is None:
            self.schedules.refresh(schedule.domain_id, now)
            return
        if decision.action == "missed":
            self.schedules.note(schedule, decision.occurrence, "missed", "", self.who, now)
            return
        internal = schedule.perimeter_id is not None
        reason = ("scan_in_progress" if schedule.domain in self.s.in_progress
                  else "internal_disabled" if internal and not self.s.config.internal_scans else "")
        if reason:
            if decision.action == "run":
                self.schedules.note(schedule, decision.occurrence, "skipped", reason, self.who, now)
            else:  # a retry keeps its row; it is looked at again later, while still in time
                self._defer(schedule, now, TICK.total_seconds())
            return
        keep_free = 1 if self.s.scan_limiter.concurrent >= 2 else 0
        try:
            release = self.s.scan_limiter.take(PRINCIPAL, keep_free=keep_free)
        except TooManyScans as e:  # nothing written: the slot stays due
            self._defer(schedule, now, TICK.total_seconds() if e.reason == "busy" else e.retry_after)
            return
        try:
            claim = self.schedules.claim(schedule, decision, self.who, now)
            if claim is None:
                return
            with scanning(self.s, schedule.domain):
                await self._scan(schedule, claim)
        finally:
            release()

    async def _scan(self, schedule: Schedule, claim: Claim) -> None:
        s = self.s
        try:
            perimeter = s.perimeters.get(schedule.perimeter_id) if schedule.perimeter_id is not None else None
            result = await asyncio.wait_for(
                s.scanner.scan(schedule.domain, perimeter, history=s.scans.https_history(schedule.domain)),
                SCAN_TIMEOUT.total_seconds())
        except asyncio.CancelledError:
            self.schedules.interrupt(claim, "shutdown", self.clock())
            raise
        except TimeoutError:
            self.schedules.fail(claim, "timeout", self.clock())
            log.warning("Scheduled scan of %s: no result after %d s.", schedule.domain, SCAN_TIMEOUT.total_seconds())
            return
        except InternalScansDisabled:
            self.schedules.fail(claim, "internal_disabled", self.clock())
            return
        except Exception:
            self.schedules.fail(claim, "error", self.clock())
            log.exception("Scheduled scan of %s failed.", schedule.domain)
            return

        def save() -> int:
            name = perimeter.name if perimeter else ""
            scan_id = s.scans.save(schedule.domain_id, result, __version__, None, name, via="schedule")
            if perimeter is not None:  # internal scans are audited one by one, as manual ones
                s.audit.record("scan.internal", target=schedule.domain, via="schedule", perimeter=name)
            return scan_id

        try:
            scan_id = self.schedules.finish(claim, save, self.clock())
        except sqlite3.Error:
            log.exception("Scheduled scan of %s: the result could not be recorded.", schedule.domain)
            with contextlib.suppress(sqlite3.Error):  # else the lease expires and the run is reconciled
                self.schedules.fail(claim, "database", self.clock())
            return
        if scan_id is None:
            log.info("Scheduled scan of %s: not recorded (claim lost or domain deleted).", schedule.domain)


def status(services: Services, scheduler: Scheduler | None, now: datetime) -> dict[str, Any]:
    """The state of scheduled scans for the administration page: ``off`` (turned off here),
    ``here`` (this process schedules), ``elsewhere`` (another process, its heartbeat recent) or
    ``stalled`` (no recent heartbeat), with the heartbeat seen."""
    raw = services.db.get_meta(HEARTBEAT_KEY)
    try:
        beat = json.loads(raw) if raw else None
        at = datetime.fromisoformat(beat["at"]) if beat else None
    except (ValueError, KeyError, TypeError):
        beat, at = None, None
    if scheduler is not None and scheduler.leader:
        state = "here"
    elif at is not None and now - at <= STALE:
        state = "elsewhere"
    elif not services.config.scheduler:
        state = "off"
    else:
        state = "stalled"
    return {"state": state, "heartbeat": beat, "heartbeat_at": at}
