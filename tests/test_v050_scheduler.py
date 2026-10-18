# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: the scheduler, situation by situation (specification, section 5).

An explicit clock and the recorded answers of the demonstration domain: no real waiting, no
network. The races between processes are in test_v050_scheduler_concurrency.py."""

import asyncio
import contextlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from posture_cockpit.config import Config
from posture_cockpit.core import schedule_time
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.schedule_time import Definition
from posture_cockpit.scanner import DEMO_DOMAIN, demo_data
from posture_cockpit.storage import instance_lock
from posture_cockpit.storage.perimeters import parse_form
from posture_cockpit.storage.schedules import LEASE, RETENTION, iso
from posture_cockpit.web import scheduler as scheduler_module
from posture_cockpit.web.app import create_app
from posture_cockpit.web.scheduler import Scheduler, status

PARIS = ZoneInfo("Europe/Paris")
DAILY_5 = Definition("daily", 300)


def local(*args) -> datetime:
    return datetime(*args, tzinfo=PARIS).astimezone(UTC)


class Clock:
    def __init__(self, now: datetime):
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def network(domain):
    return FixtureNetwork(demo_data(DEMO_DOMAIN) if domain.endswith(".example") else {"dns": {f"{domain} SOA": None}})


class Instance:
    def __init__(self, folder, **settings):
        settings.setdefault("timezone", PARIS)
        self.app = create_app(Config(data_dir=folder, **settings), network_factory=network)
        self.s = self.app.state.services
        self.clock = Clock(local(2026, 10, 20, 1, 0))
        self.scheduler = Scheduler(self.s, self.s.schedules, clock=self.clock)

    def domain(self, name=DEMO_DOMAIN, perimeter_id=None) -> int:
        return self.s.scans.add_domain(name, None, perimeter_id)

    def schedule(self, domain_id, definition=DAILY_5, at=None):
        return self.s.schedules.set(domain_id, definition, enabled=True, user_id=None, now=at or self.clock())[1]

    def at_next(self, domain_id):
        self.clock.now = datetime.fromisoformat(self.s.schedules.get(domain_id).next_run_at)

    def tick(self):
        asyncio.run(self.scheduler.run_once())

    def runs(self):
        return [dict(r) for r in self.s.db.all("SELECT * FROM schedule_runs ORDER BY id")]

    def scheduled_scans(self):
        return [dict(r) for r in self.s.db.all("SELECT * FROM scans WHERE via = 'schedule' ORDER BY id")]

    def close(self):
        self.s.db.close()
        self.app.state.folder_lock.release()


@pytest.fixture
def pc(tmp_path):
    instance = Instance(tmp_path)
    yield instance
    instance.close()


def blocking(started: asyncio.Event | None = None, release: asyncio.Event | None = None):
    async def scan(domain, perimeter=None, history=None):
        if started:
            started.set()
        await (release.wait() if release else asyncio.sleep(3600))
    return scan


def test_a_due_scan_runs_once_is_recorded_as_scheduled_and_the_next_one_follows(pc):
    domain_id = pc.domain()
    pc.schedule(domain_id)
    pc.at_next(domain_id)
    pc.tick()
    [run] = pc.runs()
    [scan] = pc.scheduled_scans()
    assert (run["state"], run["scan_id"], run["slot"]) == ("done", scan["id"], "2026-10-20T05:00")
    assert scan["started_by"] is None and scan["engine"] == 4
    assert pc.s.db.value("SELECT origin FROM scan_states WHERE scan_id = ?", (scan["id"],)) == "scan"
    pc.tick()  # nothing more the same day
    assert len(pc.runs()) == 1
    tomorrow = local(2026, 10, 21, 5, 0) + schedule_time.spread(DEMO_DOMAIN)
    assert pc.s.schedules.get(domain_id).next_run_at == iso(tomorrow)
    assert pc.s.audit.latest(action_prefix="scan") == []  # Internet scans: traced in the runs only


def test_ten_domains_due_together_run_one_after_the_other_oldest_first(pc):
    ids = [pc.domain(f"d{n}.example") for n in range(10)]
    for domain_id in ids:
        pc.schedule(domain_id)
    pc.clock.now = local(2026, 10, 20, 5, 11)
    running = []
    scan = pc.s.scanner.scan

    async def watching(domain, perimeter=None, history=None):
        running.append(pc.s.scan_limiter.running)
        return await scan(domain, perimeter, history=history)

    pc.s.scanner.scan = watching
    pc.tick()
    runs = pc.runs()
    assert len(runs) == 10 and {r["state"] for r in runs} == {"done"} and running == [1] * 10
    order = [r["domain_id"] for r in runs]
    spreads = [schedule_time.spread(f"d{ids.index(i)}.example") for i in order]
    assert spreads == sorted(spreads)  # the oldest due time first


def test_a_clean_stop_during_the_scan_interrupts_it_and_the_next_start_retries_once(pc, tmp_path):
    domain_id = pc.domain()
    pc.schedule(domain_id)
    pc.at_next(domain_id)
    started = asyncio.Event()
    pc.s.scanner.scan = blocking(started)

    async def stopped_during_the_scan():
        task = asyncio.create_task(pc.scheduler.run_once())
        await started.wait()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(stopped_during_the_scan())
    [run] = pc.runs()
    assert (run["state"], run["reason"], run["attempts"]) == ("interrupted", "shutdown", 1)
    assert pc.scheduled_scans() == [] and pc.s.in_progress == set() and pc.s.scan_limiter.running == 0
    pc.close()
    again = Instance(tmp_path)  # started again, two minutes later
    try:
        again.clock.now = datetime.fromisoformat(run["claimed_at"]) + timedelta(minutes=2)
        asyncio.run(again.scheduler._become_leader())
        again.tick()
        [run] = again.runs()
        assert (run["state"], run["attempts"]) == ("done", 2) and len(again.scheduled_scans()) == 1
    finally:
        again.close()
        pc.app.state.folder_lock = instance_lock.Held(None)


def test_a_run_left_running_by_a_killed_process_is_reconciled_then_retried(pc):
    domain_id = pc.domain()
    schedule = pc.schedule(domain_id)
    pc.at_next(domain_id)
    claimed_at = pc.clock()
    decision = pc.s.schedules.decide(schedule, claimed_at)
    assert pc.s.schedules.claim(schedule, decision, "killed:1", claimed_at) is not None  # then kill -9
    pc.clock.now = claimed_at + timedelta(minutes=5)
    pc.tick()
    assert pc.runs()[0]["state"] == "running" and pc.scheduled_scans() == []  # its lease still holds
    pc.clock.now = claimed_at + LEASE + timedelta(minutes=1)
    pc.tick()
    [run] = pc.runs()
    assert (run["state"], run["attempts"], run["owner"]) == ("done", 2, pc.scheduler.who)
    assert len(pc.scheduled_scans()) == 1


def test_a_manual_scan_of_the_domain_running_skips_the_scheduled_one(pc):
    domain_id = pc.domain()
    pc.schedule(domain_id)
    pc.at_next(domain_id)
    pc.s.in_progress.add(DEMO_DOMAIN)
    pc.tick()
    assert [(r["state"], r["reason"]) for r in pc.runs()] == [("skipped", "scan_in_progress")]
    pc.s.in_progress.clear()
    pc.tick()
    assert len(pc.runs()) == 1 and pc.scheduled_scans() == []  # the manual result is enough


def test_the_people_keep_a_slot_and_a_busy_limiter_writes_nothing(tmp_path):
    pc = Instance(tmp_path, max_concurrent_scans=2)
    try:
        domain_id = pc.domain()
        pc.schedule(domain_id)
        pc.at_next(domain_id)
        release = pc.s.scan_limiter.take("user:1")  # a person scans: one slot left, kept for people
        pc.tick()
        assert pc.runs() == []
        release()
        pc.tick()  # deferred for a minute: not yet
        assert pc.runs() == []
        pc.clock.now += timedelta(minutes=1)
        pc.tick()
        assert [r["state"] for r in pc.runs()] == ["done"]
    finally:
        pc.close()


def test_the_hourly_share_of_the_scheduler_defers_until_it_frees(tmp_path):
    pc = Instance(tmp_path, scans_per_hour=1)
    try:
        ids = [pc.domain(f"d{n}.example") for n in range(2)]
        for domain_id in ids:
            pc.schedule(domain_id)
        pc.clock.now = local(2026, 10, 20, 5, 11)
        pc.tick()
        assert [r["state"] for r in pc.runs()] == ["done"]  # one per hour: the other one waits
        pc.s.scan_limiter._clock = lambda: 10_000.0  # an hour later for the limiter
        pc.clock.now += timedelta(hours=1, minutes=1)
        pc.tick()
        assert [r["state"] for r in pc.runs()] == ["done", "done"]
    finally:
        pc.close()


def test_a_scan_too_long_fails_with_a_timeout(pc, monkeypatch):
    monkeypatch.setattr(scheduler_module, "SCAN_TIMEOUT", timedelta(seconds=0.05))
    domain_id = pc.domain()
    pc.schedule(domain_id)
    pc.at_next(domain_id)
    pc.s.scanner.scan = blocking()
    pc.tick()
    [run] = pc.runs()
    assert (run["state"], run["reason"]) == ("failed", "timeout")
    assert pc.s.schedules.get(domain_id).failures == 1 and pc.s.in_progress == set()


def test_an_error_of_the_scan_fails_the_run_and_the_loop_goes_on(pc):
    first, second = pc.domain("a.example"), pc.domain("b.example")
    pc.schedule(first)
    pc.schedule(second)
    pc.clock.now = local(2026, 10, 20, 5, 11)
    scan = pc.s.scanner.scan

    async def failing_once(domain, perimeter=None, history=None):
        if domain == "a.example":
            raise RuntimeError("a bug in a check")
        return await scan(domain, perimeter, history=history)

    pc.s.scanner.scan = failing_once
    pc.tick()
    states = {r["domain_id"]: (r["state"], r["reason"]) for r in pc.runs()}
    assert states == {first: ("failed", "error"), second: ("done", "")}


def test_three_failures_in_a_row_are_counted_and_a_success_resets_them(pc):
    domain_id = pc.domain()
    pc.schedule(domain_id)
    scan = pc.s.scanner.scan

    async def broken(domain, perimeter=None, history=None):
        raise OSError("network down")

    for day in (20, 21, 22):
        pc.s.scanner.scan = broken
        pc.clock.now = local(2026, 10, day, 5, 11)
        pc.tick()
    assert pc.s.schedules.get(domain_id).failures == 3
    pc.s.scanner.scan = scan
    pc.clock.now = local(2026, 10, 23, 5, 11)
    pc.tick()
    assert pc.s.schedules.get(domain_id).failures == 0


def test_a_database_error_when_recording_fails_the_run(pc, monkeypatch):
    domain_id = pc.domain()
    pc.schedule(domain_id)
    pc.at_next(domain_id)

    def full(*args, **kwargs):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(pc.s.scans, "save", full)
    pc.tick()
    [run] = pc.runs()
    assert (run["state"], run["reason"]) == ("failed", "database") and pc.scheduled_scans() == []


def test_a_domain_deleted_during_its_scan_is_not_recorded_nor_recreated(pc):
    domain_id = pc.domain()
    pc.schedule(domain_id)
    pc.at_next(domain_id)
    scan = pc.s.scanner.scan

    async def deleted_meanwhile(domain, perimeter=None, history=None):
        result = await scan(domain, perimeter, history=history)
        pc.s.scans.delete_domain(domain_id)
        return result

    pc.s.scanner.scan = deleted_meanwhile
    pc.tick()
    assert pc.s.db.value("SELECT COUNT(*) FROM domains") == 0 and pc.s.db.value("SELECT COUNT(*) FROM scans") == 0


def internal_domain(pc) -> int:
    perimeter_id = pc.s.perimeters.create(parse_form("siege", "10.20.0.0/16", "10.20.0.53", "443", ""), None)
    return pc.domain("intranet.siege.example", perimeter_id)


def test_an_internal_domain_is_skipped_while_internal_scans_are_off(pc):
    domain_id = internal_domain(pc)
    pc.schedule(domain_id)
    pc.at_next(domain_id)
    pc.tick()
    assert [(r["state"], r["reason"]) for r in pc.runs()] == [("skipped", "internal_disabled")]
    assert pc.s.schedules.get(domain_id).failures == 0  # not a failure


def test_an_internal_domain_is_scanned_in_its_perimeter_and_audited(tmp_path):
    pc = Instance(tmp_path, internal_scans=True)
    try:
        domain_id = internal_domain(pc)
        pc.schedule(domain_id)
        pc.at_next(domain_id)
        seen = []
        scan = pc.s.scanner.scan

        async def watching(domain, perimeter=None, history=None):
            seen.append(perimeter.name if perimeter else None)
            return await scan(domain, perimeter, history=history)

        pc.s.scanner.scan = watching
        pc.tick()
        [scheduled] = pc.scheduled_scans()
        assert seen == ["siege"] and scheduled["perimeter"] == "siege"
        [entry] = pc.s.audit.latest(action_prefix="scan.internal")
        assert entry["target"] == "intranet.siege.example" and entry["detail"] == {"via": "schedule",
                                                                                   "perimeter": "siege"}
    finally:
        pc.close()


def test_the_perimeter_is_read_again_when_the_scan_runs(tmp_path):
    pc = Instance(tmp_path, internal_scans=True)
    try:
        domain_id = internal_domain(pc)
        pc.schedule(domain_id)
        pc.at_next(domain_id)
        perimeter_id = pc.s.db.value("SELECT perimeter_id FROM domains WHERE id = ?", (domain_id,))
        pc.s.perimeters.update(perimeter_id, parse_form("siege-2", "10.30.0.0/16", "", "443", ""))
        pc.tick()
        assert pc.scheduled_scans()[0]["perimeter"] == "siege-2"
    finally:
        pc.close()


def test_a_paused_or_removed_schedule_runs_nothing(pc):
    domain_id = pc.domain()
    pc.schedule(domain_id)
    pc.s.schedules.set(domain_id, DAILY_5, enabled=False, user_id=None, now=pc.clock())
    pc.clock.now = local(2026, 10, 20, 5, 11)
    pc.tick()
    assert pc.runs() == []
    pc.s.schedules.set(domain_id, DAILY_5, enabled=True, user_id=None, now=pc.clock())
    pc.s.schedules.remove(domain_id)
    pc.clock.now = local(2026, 10, 21, 5, 11)
    pc.tick()
    assert pc.runs() == []


def test_a_clock_going_back_runs_no_slot_twice(pc):
    domain_id = pc.domain()
    pc.schedule(domain_id)
    pc.at_next(domain_id)
    pc.tick()
    for back in (timedelta(minutes=1), timedelta(hours=1), timedelta(hours=6)):
        pc.clock.now -= back
        pc.tick()
    pc.clock.now = local(2026, 10, 20, 5, 30)
    pc.tick()
    assert len(pc.runs()) == 1


def test_a_suspended_machine_catches_up_once(pc):
    domain_id = pc.domain()
    pc.schedule(domain_id, Definition("weekly", 300, weekday=1), at=local(2026, 10, 12, 1, 0))
    pc.clock.now = local(2026, 10, 19, 5, 11)
    pc.tick()
    pc.clock.now = local(2026, 10, 27, 9, 0)  # the machine slept from Sunday to Tuesday
    pc.tick()
    pc.tick()
    assert [r["slot"] for r in pc.runs()] == ["2026-10-19T05:00", "2026-10-26T05:00"]


def test_heartbeat_and_status(pc):
    assert status(pc.s, pc.scheduler, pc.clock())["state"] == "off"  # this instance: scheduler off
    pc.tick()
    beat = json.loads(pc.s.db.get_meta("scheduler_heartbeat"))
    assert beat["at"] == iso(pc.clock()) and beat["version"] == "0.5.0"
    assert status(pc.s, None, pc.clock() + timedelta(minutes=2))["state"] == "elsewhere"
    assert status(pc.s, None, pc.clock() + timedelta(minutes=4))["state"] == "off"
    pc.scheduler.leader = True
    assert status(pc.s, pc.scheduler, pc.clock())["state"] == "here"


def test_status_of_an_instance_whose_scheduler_stopped_beating(tmp_path):
    pc = Instance(tmp_path, scheduler=True)
    try:
        pc.tick()
        assert status(pc.s, None, pc.clock() + timedelta(minutes=4))["state"] == "stalled"
    finally:
        pc.close()


def test_old_runs_are_purged_once_a_day(pc):
    domain_id = pc.domain()
    pc.schedule(domain_id, at=local(2024, 1, 1, 1, 0))
    pc.clock.now = local(2024, 1, 1, 5, 11)
    pc.tick()
    pc.clock.now = local(2024, 1, 1, 5, 11) + RETENTION + timedelta(days=1)
    purge = pc.s.schedules.purge
    calls = []
    pc.s.schedules.purge = lambda now: calls.append(now) or purge(now)
    pc.tick()
    pc.tick()
    assert len(calls) == 1
    [run] = pc.runs()  # the run of 2024 is gone; the one of the day stays
    assert run["slot"] != "2024-01-01T05:00" and run["state"] == "done"


def test_the_loop_survives_an_unexpected_error_and_says_so(pc, caplog):
    sleeps = []

    async def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) > 3:
            raise asyncio.CancelledError

    async def broken():
        raise RuntimeError("bug")

    pc.scheduler = Scheduler(pc.s, pc.s.schedules, clock=pc.clock, sleep=sleep,
                             take_lock=lambda: instance_lock.Held(None))
    pc.scheduler.run_once = broken

    async def main():
        with contextlib.suppress(asyncio.CancelledError):
            await pc.scheduler.run()

    asyncio.run(main())
    assert sleeps[0] == 120 and sleeps[1:] == [60, 60, 60]
    assert "The scheduler failed" in caplog.text and not pc.scheduler.leader


def test_a_second_process_waits_for_the_lock_and_takes_the_role_when_it_is_free(tmp_path, pc):
    held = instance_lock.scheduler(tmp_path)
    sleeps = []

    async def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            held.release()  # the first process stops

    second = Scheduler(pc.s, pc.s.schedules, clock=pc.clock, sleep=sleep)

    async def main():
        await second._become_leader()

    asyncio.run(main())
    assert sleeps == [60, 60] and second.leader
    second._release()
    assert not second.leader


def test_the_setting_of_the_scheduler(monkeypatch, tmp_path):
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(tmp_path))
    for value, expected in ((None, True), ("", True), ("on", True), ("off", False), ("false", False)):
        if value is None:
            monkeypatch.delenv("POSTURE_COCKPIT_SCHEDULER", raising=False)
        else:
            monkeypatch.setenv("POSTURE_COCKPIT_SCHEDULER", value)
        assert Config.from_env().scheduler is expected
    assert Config(data_dir=tmp_path).scheduler is False  # built directly (the tests): off
    app = create_app(Config(data_dir=tmp_path / "off"))
    assert app.state.scheduler is None
    app.state.services.db.close()
    app.state.folder_lock.release()


def test_the_application_starts_its_scheduler_and_stops_it(tmp_path):
    import time

    from fastapi.testclient import TestClient

    app = create_app(Config(data_dir=tmp_path, scheduler=True))
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        scheduler = app.state.scheduler
        for _ in range(100):
            if scheduler.leader:
                break
            time.sleep(0.02)
        assert scheduler.leader
        with pytest.raises(instance_lock.Busy):  # the role is taken
            instance_lock.scheduler(tmp_path)
        assert json.loads(app.state.services.db.get_meta("scheduler_heartbeat"))["pid"] > 0
    assert not scheduler.leader and scheduler._task is None
    instance_lock.scheduler(tmp_path).release()  # given back when the application stopped
