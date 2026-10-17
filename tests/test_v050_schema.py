# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: the constraints of schema 5, and what goes with a deleted domain.

The schedules, their runs and the events are filled in later steps; the database already
refuses what they must never hold."""

import sqlite3

import pytest

from helpers import DEMO, post, setup_account
from posture_cockpit.storage import Database

NOW = "2026-10-17T12:00:00+00:00"


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "posture_cockpit.db")
    d.execute("INSERT INTO users(id, username, pw_hash, created_at) VALUES(1, 'a', 'x', ?)", (NOW,))
    d.execute("INSERT INTO domains(id, name, created_at) VALUES(1, 'example.org', ?)", (NOW,))
    d.execute("INSERT INTO domains(id, name, created_at) VALUES(2, 'example.net', ?)", (NOW,))
    d.execute("INSERT INTO scans(id, domain_id, started_at, duration_ms, score, grade, version) "
              "VALUES(1, 1, ?, 1, 90, 'A', '0.5.0')", (NOW,))
    d.execute("INSERT INTO scans(id, domain_id, started_at, duration_ms, score, grade, version) "
              "VALUES(2, 1, ?, 1, 90, 'A', '0.5.0')", (NOW,))
    yield d
    d.close()


def schedule(db, **values):
    row = {"domain_id": 1, "frequency": "daily", "weekday": None, "monthday": None, "at_minute": 120,
           "updated_at": NOW, **values}
    db.execute(f"INSERT INTO schedules({', '.join(row)}) VALUES({', '.join('?' * len(row))})",
               tuple(row.values()))


def run(db, **values):
    row = {"domain_id": 1, "slot": "2026-10-17T02:00", "state": "running", "claim": "c1", "owner": "p1",
           "claimed_at": NOW, "lease_until": NOW, **values}
    db.execute(f"INSERT INTO schedule_runs({', '.join(row)}) VALUES({', '.join('?' * len(row))})",
               tuple(row.values()))


def event(db, **values):
    row = {"domain_id": 1, "category": "security", "kind": "grade.dropped", "subject": "", "state": "open",
           "severity": "warning", "opened_at": NOW, "updated_at": NOW, **values}
    db.execute(f"INSERT INTO events({', '.join(row)}) VALUES({', '.join('?' * len(row))})",
               tuple(row.values()))


@pytest.mark.parametrize("values", [
    {"at_minute": -1}, {"at_minute": 1440}, {"frequency": "hourly"},
    {"frequency": "weekly"}, {"frequency": "daily", "weekday": 3}, {"frequency": "weekly", "weekday": 0},
    {"frequency": "weekly", "weekday": 8}, {"frequency": "monthly"}, {"frequency": "monthly", "monthday": 32},
    {"frequency": "daily", "monthday": 1}, {"enabled": 2}, {"domain_id": 99},
])
def test_a_schedule_must_be_well_formed(db, values):
    with pytest.raises(sqlite3.IntegrityError):
        schedule(db, **values)


def test_one_schedule_per_domain(db):
    schedule(db, at_minute=0)
    schedule(db, domain_id=2, frequency="weekly", weekday=7, at_minute=1439)
    with pytest.raises(sqlite3.IntegrityError):
        schedule(db, frequency="monthly", monthday=31)


@pytest.mark.parametrize("values", [
    {"state": "running", "lease_until": None},     # a running claim always has a lease
    {"state": "done", "lease_until": NOW},          # a finished one never keeps it
    {"state": "queued"}, {"attempts": 0}, {"attempts": 3}, {"domain_id": 99}, {"scan_id": 99},
])
def test_a_run_must_be_well_formed(db, values):
    with pytest.raises(sqlite3.IntegrityError):
        run(db, **values)


def test_one_run_per_domain_and_slot_and_one_run_per_scan(db):
    run(db, state="done", lease_until=None, scan_id=1)
    with pytest.raises(sqlite3.IntegrityError):
        run(db, claim="c2")                                     # the same slot again
    run(db, domain_id=2, claim="c3")                            # another domain, same slot
    run(db, slot="2026-10-18T02:00", state="failed", lease_until=None, scan_id=None)
    with pytest.raises(sqlite3.IntegrityError):
        run(db, slot="2026-10-19T02:00", state="done", lease_until=None, scan_id=1)  # a scan for two runs
    run(db, slot="2026-10-19T02:00", state="done", lease_until=None, scan_id=2, attempts=2)


@pytest.mark.parametrize("values", [
    {"category": "other"}, {"state": "closed"}, {"severity": "high"}, {"domain_id": 99}, {"opened_scan_id": 99},
])
def test_an_event_must_be_well_formed(db, values):
    with pytest.raises(sqlite3.IntegrityError):
        event(db, **values)


def test_one_open_event_per_subject_for_a_domain_and_for_the_instance(db):
    event(db)
    with pytest.raises(sqlite3.IntegrityError):
        event(db)                                               # the same, still open
    event(db, subject="mail.dmarc")                             # another subject
    event(db, domain_id=2)                                      # another domain
    event(db, state="resolved", resolved_at=NOW)                # closed ones accumulate
    event(db, state="resolved", resolved_at=NOW)
    event(db, state="notice")
    event(db, domain_id=None, category="technical", kind="scheduler.stalled")
    with pytest.raises(sqlite3.IntegrityError):
        event(db, domain_id=None, category="technical", kind="scheduler.stalled")
    for category in ("security", "measurement", "technical"):
        event(db, category=category, kind=f"k.{category}", state="notice")


def test_a_deleted_scan_keeps_its_runs_and_events_without_it(db):
    run(db, state="done", lease_until=None, scan_id=2)
    event(db, opened_scan_id=2, resolved_scan_id=2, state="resolved", resolved_at=NOW)
    db.execute("DELETE FROM scans WHERE id = 2")
    assert db.value("SELECT scan_id FROM schedule_runs") is None
    assert tuple(db.one("SELECT opened_scan_id, resolved_scan_id FROM events")) == (None, None)


def test_deleting_a_domain_takes_everything_it_holds_and_the_audit_counts_it(client, world):
    setup_account(client)
    for _ in range(2):
        post(client, "/domains", "/domains", domain=DEMO)
    post(client, f"/domains/{DEMO}/verify/mail.dmarc", f"/domains/{DEMO}")
    s = client.app.state.services
    domain_id = s.scans.domain(DEMO)["id"]
    scan_id = s.scans.latest_id(domain_id)
    schedule(s.db, domain_id=domain_id)
    run(s.db, domain_id=domain_id, state="done", lease_until=None, scan_id=scan_id)
    event(s.db, domain_id=domain_id, opened_scan_id=scan_id)
    event(s.db, domain_id=domain_id, kind="other", state="resolved", resolved_at=NOW)
    tables = ("scans", "findings", "rechecks", "scan_states", "schedules", "schedule_runs", "events")
    assert all(s.db.value(f"SELECT COUNT(*) FROM {t}") for t in tables)  # noqa: S608
    post(client, f"/domains/{DEMO}/delete", f"/domains/{DEMO}/details")
    assert {t: s.db.value(f"SELECT COUNT(*) FROM {t}") for t in tables} == dict.fromkeys(tables, 0)  # noqa: S608
    [entry] = s.audit.latest(action_prefix="domain.deleted")
    assert entry["target"] == DEMO
    assert entry["detail"] == {"perimeter": "", "scans": 2, "states": 3, "runs": 1, "events": 2}
