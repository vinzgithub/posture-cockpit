# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: schedules and their runs in the database (storage/schedules.py).

The transitions T1 to T7 of Révision 1, point 1, with an explicit clock: claim, retry, finish
only with the token, fail, interrupt, reconcile an expired lease, miss and skip; and the rules of
due times: no catching up on a time set later, the latest missed occurrence only, half a period
after an attempt."""

import asyncio
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

import worlds
from posture_cockpit.core import engine, schedule_time
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.registry import Registry
from posture_cockpit.core.schedule_time import Definition
from posture_cockpit.storage import Database, Scans
from posture_cockpit.storage.schedules import LEASE, RETENTION, Schedules, iso

PARIS = ZoneInfo("Europe/Paris")
DOMAIN = "example.org"
SPREAD = schedule_time.spread(DOMAIN)
DAILY_5 = Definition("daily", 300)


def local(*args) -> datetime:
    return datetime(*args, tzinfo=PARIS).astimezone(UTC)


@pytest.fixture(scope="module")
def result():
    return asyncio.run(engine.scan(DOMAIN, Registry.discover().checks(), FixtureNetwork(worlds.healthy(), worlds.NOW),
                                   timeout=5, now=worlds.NOW))


class Instance:
    def __init__(self, path, result):
        self.db = Database(path)
        self.scans = Scans(self.db)
        self.schedules = Schedules(self.db, PARIS)
        self.result = result
        self.domain_id = self.scans.add_domain(DOMAIN, None)

    def save(self) -> int:
        return self.scans.save(self.domain_id, self.result, "0.5.0", None, "", via="schedule")

    def schedule(self):
        return self.schedules.get(self.domain_id)

    def runs(self):
        return [dict(r) for r in self.db.all("SELECT * FROM schedule_runs ORDER BY id")]

    def scheduled_scans(self) -> int:
        return self.db.value("SELECT COUNT(*) FROM scans WHERE via = 'schedule'")

    def claim_due(self, now, who="a:1"):
        schedule = self.schedule()
        decision = self.schedules.decide(schedule, now)
        assert decision is not None and decision.action in ("run", "retry"), decision
        return self.schedules.claim(schedule, decision, who, now)


@pytest.fixture
def pc(tmp_path, result):
    instance = Instance(tmp_path / "posture_cockpit.db", result)
    yield instance
    instance.db.close()


def every_scheduled_scan_is_one_done_run(pc):
    """The invariant of Révision 1: each scan via schedule is referenced by exactly one done run,
    and each done run by its scan."""
    done = pc.db.all("SELECT scan_id FROM schedule_runs WHERE state = 'done'")
    scans = pc.db.all("SELECT id FROM scans WHERE via = 'schedule'")
    assert sorted(r[0] for r in done) == sorted(r[0] for r in scans)


def test_a_new_schedule_starts_with_the_next_occurrence_never_an_earlier_one(pc):
    _, after = pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 10, 0))
    assert after.next_run_at == iso(local(2026, 10, 21, 5, 0) + SPREAD)  # not 05:00 today: set at 10:00
    assert pc.schedules.decide(after, local(2026, 10, 20, 10, 1)) is None
    _, early = pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 21, 4, 0))
    assert early.next_run_at == iso(local(2026, 10, 21, 5, 0) + SPREAD)


def test_claim_run_finish(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 10, 0))
    at = local(2026, 10, 21, 5, 0) + SPREAD
    assert pc.schedules.due(at - timedelta(seconds=1)) == []
    [due] = pc.schedules.due(at)
    claim = pc.claim_due(at)
    assert claim is not None and (claim.slot, claim.attempts) == ("2026-10-21T05:00", 1)
    [run] = pc.runs()
    assert run["state"] == "running" and run["claim"] == claim.token and run["lease_until"] == iso(at + LEASE)
    assert pc.schedules.claim(due, pc.schedules.decide(due, at) or _run(due, at), "b:2", at) is None  # taken
    assert pc.schedule().next_run_at == iso(local(2026, 10, 22, 5, 0) + SPREAD)
    scan_id = pc.schedules.finish(claim, pc.save, at + timedelta(minutes=1))
    [run] = pc.runs()
    assert scan_id and (run["state"], run["scan_id"], run["lease_until"]) == ("done", scan_id, None)
    assert pc.db.value("SELECT via FROM scans WHERE id = ?", (scan_id,)) == "schedule"
    assert pc.db.value("SELECT COUNT(*) FROM scan_states WHERE scan_id = ?", (scan_id,)) == 1
    every_scheduled_scan_is_one_done_run(pc)


def _run(schedule, at):
    from posture_cockpit.storage.schedules import Decision
    return Decision("run", schedule_time.latest(schedule.definition, PARIS, DOMAIN, at))


def test_a_failure_counts_and_the_next_occurrence_follows(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 10, 0))
    at = local(2026, 10, 21, 5, 0) + SPREAD
    claim = pc.claim_due(at)
    assert pc.schedules.fail(claim, "timeout", at + timedelta(minutes=10))
    assert pc.schedule().failures == 1 and pc.runs()[0]["state"] == "failed"
    assert pc.schedule().next_run_at == iso(local(2026, 10, 22, 5, 0) + SPREAD)
    assert pc.schedules.decide(pc.schedule(), at + timedelta(hours=1)) is None  # a failed slot is not retried
    claim = pc.claim_due(local(2026, 10, 22, 5, 0) + SPREAD)
    pc.schedules.finish(claim, pc.save, local(2026, 10, 22, 5, 5))
    assert pc.schedule().failures == 0


def test_an_interrupted_run_is_retried_once(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 10, 0))
    at = local(2026, 10, 21, 5, 0) + SPREAD
    first = pc.claim_due(at)
    assert pc.schedules.interrupt(first, "shutdown", at + timedelta(minutes=2))
    assert pc.schedule().next_run_at == iso(at)  # its time again, for one retry
    later = at + timedelta(minutes=5)
    decision = pc.schedules.decide(pc.schedule(), later)
    assert decision is not None and decision.action == "retry"
    second = pc.schedules.claim(pc.schedule(), decision, "b:2", later)
    assert second is not None and second.attempts == 2 and second.run_id == first.run_id
    assert second.token != first.token
    assert pc.schedules.interrupt(second, "shutdown", later + timedelta(minutes=1))
    assert pc.schedules.decide(pc.schedule(), later + timedelta(minutes=2)) is None  # two attempts at most
    assert pc.schedule().next_run_at == iso(local(2026, 10, 22, 5, 0) + SPREAD)
    assert pc.runs()[0]["attempts"] == 2


def test_an_interrupted_run_too_late_is_not_retried(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 10, 0))
    at = local(2026, 10, 21, 5, 0) + SPREAD
    pc.schedules.interrupt(pc.claim_due(at), "shutdown", at + timedelta(minutes=1))
    assert pc.schedules.decide(pc.schedule(), at + timedelta(hours=12)) is None  # half a period


def test_an_expired_lease_is_reconciled_and_a_live_one_is_not(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 10, 0))
    at = local(2026, 10, 21, 5, 0) + SPREAD
    pc.claim_due(at)
    assert pc.schedules.reconcile(at + LEASE - timedelta(seconds=1)) == 0
    assert pc.schedules.reconcile(at + LEASE + timedelta(seconds=1)) == 1
    [run] = pc.runs()
    assert (run["state"], run["reason"], run["lease_until"]) == ("interrupted", "lease_expired", None)
    assert pc.schedules.decide(pc.schedule(), at + LEASE + timedelta(seconds=2)).action == "retry"


def test_a_process_that_lost_its_claim_never_records_a_result(pc):
    """A scans; its lease expires, the row is reconciled and retried by B; A finishing late
    changes nothing; only B's scan is recorded."""
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 10, 0))
    at = local(2026, 10, 21, 5, 0) + SPREAD
    a = pc.claim_due(at, "a:1")
    later = at + LEASE + timedelta(seconds=5)
    pc.schedules.reconcile(later)
    b = pc.claim_due(later, "b:2")
    assert b.attempts == 2
    assert pc.schedules.finish(a, pc.save, later + timedelta(seconds=1)) is None
    assert not pc.schedules.fail(a, "error", later) and not pc.schedules.interrupt(a, "shutdown", later)
    assert pc.scheduled_scans() == 0 and pc.runs()[0]["state"] == "running"
    scan_id = pc.schedules.finish(b, pc.save, later + timedelta(minutes=1))
    assert scan_id and pc.scheduled_scans() == 1
    [run] = pc.runs()
    assert (run["state"], run["scan_id"], run["owner"]) == ("done", scan_id, "b:2")
    every_scheduled_scan_is_one_done_run(pc)


def test_a_domain_deleted_during_the_scan_is_neither_recorded_nor_recreated(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 10, 0))
    at = local(2026, 10, 21, 5, 0) + SPREAD
    claim = pc.claim_due(at)
    pc.scans.delete_domain(pc.domain_id)
    assert pc.schedules.finish(claim, pc.save, at + timedelta(minutes=1)) is None
    assert pc.db.value("SELECT COUNT(*) FROM domains") == 0 and pc.db.value("SELECT COUNT(*) FROM scans") == 0
    assert pc.runs() == []


def test_the_save_failing_writes_nothing(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 10, 0))
    at = local(2026, 10, 21, 5, 0) + SPREAD
    claim = pc.claim_due(at)

    def broken():
        pc.save()
        raise OSError("disk full")

    with pytest.raises(OSError):
        pc.schedules.finish(claim, broken, at + timedelta(minutes=1))
    assert pc.db.value("SELECT COUNT(*) FROM scans") == 0 and pc.runs()[0]["state"] == "running"
    assert pc.schedules.fail(claim, "database", at + timedelta(minutes=1))


def test_stopped_two_weeks_the_slot_of_the_day_is_noted_missed(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 1, 10, 0))
    pc.schedules.finish(pc.claim_due(local(2026, 10, 2, 5, 0) + SPREAD), pc.save, local(2026, 10, 2, 5, 5))
    now = local(2026, 10, 16, 20, 0)  # back after two weeks, at 20:00
    pc.schedules.refresh_all(now)
    [due] = pc.schedules.due(now)
    decision = pc.schedules.decide(due, now)
    assert (decision.action, decision.occurrence.slot) == ("missed", "2026-10-16T05:00")
    assert pc.schedules.note(due, decision.occurrence, "missed", "", "a:1", now)
    assert [r["state"] for r in pc.runs()] == ["done", "missed"]  # only the latest missed occurrence
    assert pc.schedule().next_run_at == iso(local(2026, 10, 17, 5, 0) + SPREAD)
    assert pc.schedules.due(now) == []


def test_stopped_from_sunday_to_tuesday_the_monday_scan_runs_once(pc):
    monday = Definition("weekly", 300, weekday=1)
    pc.schedules.set(pc.domain_id, monday, enabled=True, user_id=None, now=local(2026, 10, 1, 10, 0))
    pc.schedules.finish(pc.claim_due(local(2026, 10, 12, 5, 0) + SPREAD), pc.save, local(2026, 10, 12, 5, 5))
    now = local(2026, 10, 20, 10, 2)
    pc.schedules.refresh_all(now)
    claim = pc.claim_due(now)
    assert claim.slot == "2026-10-19T05:00"
    pc.schedules.finish(claim, pc.save, now + timedelta(minutes=1))
    assert pc.schedules.decide(pc.schedule(), now + timedelta(hours=2)) is None
    assert pc.schedule().next_run_at == iso(local(2026, 10, 26, 5, 0) + SPREAD)


def test_a_time_changed_after_the_run_of_the_day_waits_for_the_next_day(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 1, 0))
    pc.schedules.finish(pc.claim_due(local(2026, 10, 20, 5, 0) + SPREAD), pc.save, local(2026, 10, 20, 5, 5))
    _, changed = pc.schedules.set(pc.domain_id, Definition("daily", 360), enabled=True, user_id=None,
                                  now=local(2026, 10, 20, 5, 20))
    assert changed.next_run_at == iso(local(2026, 10, 21, 6, 0) + SPREAD)
    assert pc.schedules.decide(changed, local(2026, 10, 20, 6, 30)) is None


def test_a_paused_schedule_is_not_due_and_does_not_catch_up_when_resumed(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 1, 0))
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=False, user_id=None, now=local(2026, 10, 20, 2, 0))
    assert pc.schedules.due(local(2026, 10, 20, 6, 0)) == []
    _, resumed = pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 7, 0))
    assert pc.schedules.decide(resumed, local(2026, 10, 20, 7, 1)) is None
    assert resumed.next_run_at == iso(local(2026, 10, 21, 5, 0) + SPREAD)


def test_a_clock_going_back_never_runs_a_slot_again(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 1, 0))
    at = local(2026, 10, 20, 5, 0) + SPREAD
    pc.schedules.finish(pc.claim_due(at), pc.save, at + timedelta(minutes=2))
    for now in (at - timedelta(hours=1), at, at + timedelta(minutes=30)):  # NTP moved the clock back
        pc.schedules.refresh_all(now)
        assert pc.schedules.decide(pc.schedule(), now) is None
    assert len(pc.runs()) == 1


def test_skipped_and_missed_slots_are_noted_once(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 1, 0))
    at = local(2026, 10, 20, 5, 0) + SPREAD
    decision = pc.schedules.decide(pc.schedule(), at)
    assert pc.schedules.note(pc.schedule(), decision.occurrence, "skipped", "scan_in_progress", "a:1", at)
    assert not pc.schedules.note(pc.schedule(), decision.occurrence, "skipped", "scan_in_progress", "a:1", at)
    assert pc.schedules.decide(pc.schedule(), at) is None
    with pytest.raises(ValueError):
        pc.schedules.note(pc.schedule(), decision.occurrence, "done", "", "a:1", at)
    assert [(r["state"], r["reason"]) for r in pc.runs()] == [("skipped", "scan_in_progress")]


def test_two_connections_without_any_lock_claim_a_slot_once(pc, tmp_path, result):
    """Even if the lock of the scheduler failed (a file system without locks), the slot is claimed
    once: the second claim finds it taken."""
    other = Instance(tmp_path / "posture_cockpit.db", result)
    try:
        pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 1, 0))
        at = local(2026, 10, 20, 5, 0) + SPREAD
        first, second = pc.schedule(), other.schedule()
        decisions = pc.schedules.decide(first, at), other.schedules.decide(second, at)
        claims = [pc.schedules.claim(first, decisions[0], "a:1", at),
                  other.schedules.claim(second, decisions[1], "b:2", at)]
        assert sum(c is not None for c in claims) == 1
        assert len(pc.runs()) == 1
    finally:
        other.db.close()


def test_finished_runs_are_purged_after_400_days_and_nothing_else(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2024, 1, 1, 1, 0))
    old = local(2024, 1, 1, 5, 0) + SPREAD
    pc.schedules.finish(pc.claim_due(old), pc.save, old + timedelta(minutes=1))
    pc.schedules.interrupt(pc.claim_due(local(2024, 1, 2, 5, 0) + SPREAD), "shutdown", local(2024, 1, 2, 5, 2))
    now = local(2024, 1, 2, 5, 0) + RETENTION + timedelta(days=1)
    assert pc.schedules.purge(now) == 1
    assert [r["state"] for r in pc.runs()] == ["interrupted"]
    assert pc.db.value("SELECT COUNT(*) FROM scans") == 1 and pc.db.value("SELECT COUNT(*) FROM scan_states") == 1


def test_removing_a_schedule_keeps_its_runs(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 1, 0))
    at = local(2026, 10, 20, 5, 0) + SPREAD
    pc.schedules.finish(pc.claim_due(at), pc.save, at)
    before = pc.schedules.remove(pc.domain_id)
    assert before.describe() == {"frequency": "daily", "time": "05:00", "weekday": None, "monthday": None,
                                 "enabled": True}
    assert pc.schedule() is None and len(pc.runs()) == 1
    assert pc.schedules.due(at + timedelta(days=2)) == []


def test_listings_for_the_administration(pc):
    pc.schedules.set(pc.domain_id, DAILY_5, enabled=True, user_id=None, now=local(2026, 10, 20, 1, 0))
    at = local(2026, 10, 20, 5, 0) + SPREAD
    pc.schedules.fail(pc.claim_due(at), "timeout", at + timedelta(minutes=10))
    assert [s.domain for s in pc.schedules.upcoming()] == [DOMAIN]
    assert [r["state"] for r in pc.schedules.runs(not_done=True)] == ["failed"]
    assert [r["domain"] for r in pc.schedules.runs(pc.domain_id)] == [DOMAIN]
