# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: the scheduler between real processes (Révision 1, point 1; condition 1 of the validation).

Processes started with multiprocessing share one data folder: two schedulers with the lock, two
without it, a process killed (os._exit) before its claim, during its scan, inside the transaction
that records the result and after it, and a process that loses its claim to another one and
finishes late. After each, every scan made by the scheduler is referenced by exactly one run
``done``, and the other way round."""

import asyncio
import multiprocessing
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from posture_cockpit.config import Config
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.schedule_time import Definition
from posture_cockpit.scanner import DEMO_DOMAIN, demo_data
from posture_cockpit.storage import instance_lock
from posture_cockpit.storage.schedules import LEASE
from posture_cockpit.web.app import create_app
from posture_cockpit.web.scheduler import Scheduler

PARIS = ZoneInfo("Europe/Paris")
CONTEXT = multiprocessing.get_context("spawn")


def network(domain):
    return FixtureNetwork(demo_data(DEMO_DOMAIN))


def open_instance(folder: Path):
    app = create_app(Config(data_dir=folder, timezone=PARIS), network_factory=network)
    return app, app.state.services


def child(folder: str, now: str, mode: str, barrier, results, release=None) -> None:
    """One process: a scheduler at the time ``now``, in a given ``mode`` (see the tests)."""
    try:
        _app, s = open_instance(Path(folder))
        moment = datetime.fromisoformat(now)
        scheduler = Scheduler(s, s.schedules, clock=lambda: moment)
        if mode == "exit_before_claim":
            s.schedules.claim = lambda *args: os._exit(0)
        elif mode == "exit_during_scan":
            async def killed(domain, perimeter=None, history=None):
                os._exit(0)
            s.scanner.scan = killed
        elif mode == "exit_in_finish":
            save = s.scans.save

            def save_then_die(*args, **kwargs):
                save(*args, **kwargs)
                os._exit(0)  # inside the transaction of T3, before it commits
            s.scans.save = save_then_die
        elif mode == "exit_after_finish":
            finish = s.schedules.finish
            s.schedules.finish = lambda *args: (finish(*args), os._exit(0))
        elif mode == "hold":
            scan = s.scanner.scan

            async def held(domain, perimeter=None, history=None):
                await asyncio.get_running_loop().run_in_executor(None, release.wait, 60)
                return await scan(domain, perimeter, history=history)
            s.scanner.scan = held

        async def main() -> str:
            if mode == "lock":
                try:
                    lock = instance_lock.scheduler(Path(folder))
                except instance_lock.Busy:
                    lock = None
                barrier.wait(timeout=30)  # both have tried: the lock is still held by the winner
                if lock is None:
                    barrier.wait(timeout=60)  # until the winner has run its tick
                    return "standby"
                scheduler.leader = True
                await scheduler.run_once()
                barrier.wait(timeout=60)
                lock.release()
                return "leader"
            if barrier is not None:
                barrier.wait(timeout=30)
            await scheduler.run_once()
            return "ran"

        results.put((mode, asyncio.run(main())))
        s.db.close()
    except BaseException as error:  # reported to the test
        results.put((mode, repr(error)))


class Folder:
    def __init__(self, path: Path):
        self.path = path
        app, s = open_instance(path)
        self.domain_id = s.scans.add_domain(DEMO_DOMAIN, None)
        set_at = datetime(2026, 10, 20, 1, 0, tzinfo=PARIS).astimezone(UTC)
        s.schedules.set(self.domain_id, Definition("daily", 300), enabled=True, user_id=None, now=set_at)
        self.due = datetime.fromisoformat(s.schedules.get(self.domain_id).next_run_at)
        s.db.close()
        app.state.folder_lock.release()

    def start(self, mode: str, now: datetime, barrier=None, release=None):
        results = CONTEXT.Queue()
        process = CONTEXT.Process(target=child, args=(str(self.path), now.isoformat(), mode, barrier, results, release))
        process.start()
        return process, results

    def query(self, sql: str):
        app, s = open_instance(self.path)
        try:
            return [dict(r) for r in s.db.all(sql)]
        finally:
            s.db.close()
            app.state.folder_lock.release()

    def recover(self, now: datetime) -> None:
        """Another process, later, takes the role (as at the start of a server) and ticks once."""
        app, s = open_instance(self.path)
        try:
            scheduler = Scheduler(s, s.schedules, clock=lambda: now, take_lock=lambda: instance_lock.Held(None))
            asyncio.run(scheduler._become_leader())
            asyncio.run(scheduler.run_once())
        finally:
            s.db.close()
            app.state.folder_lock.release()

    def check_invariant(self) -> tuple[list[dict], list[dict]]:
        runs = self.query("SELECT * FROM schedule_runs ORDER BY id")
        scans = self.query("SELECT id FROM scans WHERE via = 'schedule'")
        assert sorted(r["scan_id"] for r in runs if r["state"] == "done") == sorted(s["id"] for s in scans)
        return runs, scans


@pytest.fixture
def folder(tmp_path):
    return Folder(tmp_path)


def wait(processes) -> None:
    for process in processes:
        process.join(timeout=60)
        assert not process.is_alive()


def test_two_schedulers_with_the_lock_one_claims_the_other_never_does(folder):
    barrier = CONTEXT.Barrier(2)
    started = [folder.start("lock", folder.due, barrier) for _ in range(2)]
    outcomes = sorted(results.get(timeout=60)[1] for _, results in started)
    wait([p for p, _ in started])
    assert outcomes == ["leader", "standby"]
    runs, scans = folder.check_invariant()
    assert len(runs) == 1 and len(scans) == 1


def test_two_schedulers_without_any_lock_record_one_scan(folder):
    barrier = CONTEXT.Barrier(2)
    started = [folder.start("nolock", folder.due, barrier) for _ in range(2)]
    outcomes = [results.get(timeout=60)[1] for _, results in started]
    wait([p for p, _ in started])
    assert outcomes == ["ran", "ran"]
    runs, scans = folder.check_invariant()
    assert len(runs) == 1 and len(scans) == 1 and runs[0]["attempts"] == 1


@pytest.mark.parametrize(("mode", "attempts", "states"), [
    ("exit_before_claim", 1, ["done"]),    # nothing written: the next process claims it
    ("exit_during_scan", 2, ["done"]),     # running, lease expired, reconciled, retried
    ("exit_in_finish", 2, ["done"]),       # the transaction of T3 never committed
    ("exit_after_finish", 1, ["done"]),    # done: nothing to do again
])
def test_a_process_killed_at_any_moment_leaves_exactly_one_scan(folder, mode, attempts, states):
    process, _ = folder.start(mode, folder.due)
    wait([process])
    folder.recover(folder.due + LEASE + timedelta(minutes=1))
    runs, scans = folder.check_invariant()
    assert [r["state"] for r in runs] == states and runs[0]["attempts"] == attempts and len(scans) == 1


def test_a_process_killed_during_its_scan_is_not_retried_too_late(folder):
    process, _ = folder.start("exit_during_scan", folder.due)
    wait([process])
    folder.recover(folder.due + timedelta(hours=12, minutes=1))  # half a period later
    runs, scans = folder.check_invariant()
    assert [(r["state"], r["reason"]) for r in runs] == [("interrupted", "lease_expired")] and scans == []


def test_a_process_that_lost_its_claim_records_nothing(folder):
    """A scans; its lease expires; B reconciles, retries and records; A finishes late: nothing."""
    release = CONTEXT.Event()
    process, results = folder.start("hold", folder.due, release=release)
    for _ in range(300):
        running = folder.query("SELECT * FROM schedule_runs WHERE state = 'running'")
        if running:
            break
        time.sleep(0.1)
    assert running and running[0]["attempts"] == 1
    folder.recover(folder.due + LEASE + timedelta(minutes=1))  # B
    release.set()
    assert results.get(timeout=60) == ("hold", "ran")
    wait([process])
    runs, scans = folder.check_invariant()
    assert len(scans) == 1 and [(r["state"], r["attempts"]) for r in runs] == [("done", 2)]
    assert runs[0]["owner"] != running[0]["owner"] or runs[0]["claim"] != running[0]["claim"]
