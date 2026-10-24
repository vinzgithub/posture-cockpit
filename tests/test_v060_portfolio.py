# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MC05: permissions before counts, deterministic pagination, actual bulk loads."""
import json
from datetime import timedelta
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from helpers import PASSWORD, log_in, post, setup_account
from portfolio_fixtures import populate
from posture_cockpit.core import engine
from posture_cockpit.core.compare import Snapshot
from posture_cockpit.core.model import Finding, Outcome, Status
from posture_cockpit.core.schedule_time import Definition
from posture_cockpit.security import hash_password
from posture_cockpit.storage.portfolio import DomainFilter
from posture_cockpit.web import portfolio
from worlds import DOMAIN, NOW, healthy, run


def meta(s, **kw):
    return s.scans.domains_page(DomainFilter(**kw), internal=True, scheduler="elsewhere", now=NOW)


def test_empty_portfolio_and_access_control(client):
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    setup_account(client)
    page = client.get("/dashboard")
    assert page.status_code == 200 and "Aucun domaine ne correspond" in page.text
    assert 'href="/dashboard" aria-current="page"' in page.text
    assert "no-store" in page.headers["cache-control"]


@pytest.mark.parametrize("count", [1, 100, 1000])
def test_paginated_scans_only_and_constant_query_count(client, count, monkeypatch):
    setup_account(client)
    s = client.app.state.services
    populate(s, count, NOW)
    forbidden = Mock(side_effect=AssertionError("per-domain fetch forbidden"))
    monkeypatch.setattr(s.scans, "get", forbidden)
    monkeypatch.setattr(s.scans, "latest_states", forbidden)
    before = list(s.db._conn.iterdump())
    statements = []
    s.db._conn.set_trace_callback(statements.append)
    page, views = portfolio.load(s, DomainFilter(size=50, sort="name"), internal=False,
                                 scheduler="off", now=NOW, lang="fr")
    s.db._conn.set_trace_callback(None)
    assert len(statements) == 11
    assert page.total == count - count // 10
    assert len(views) == min(page.total, 50)
    assert page.facts["open_events"] == 3 * page.total
    assert all(not v.row["name"].startswith("secret") for v in views)
    assert all(v.first_id == "mail.dmarc" for v in views)
    assert all(v.transition is not None for v in views)
    assert not forbidden.called
    assert list(s.db._conn.iterdump()) == before


def test_t16_private_and_global_events_never_leak_through_counts_or_filters(client):
    setup_account(client)
    s = client.app.state.services
    populate(s, 10, NOW)
    s.accounts.create("reader", hash_password(PASSWORD))
    s.db.execute("INSERT INTO events(category,kind,state,severity,opened_at,updated_at) "
                 "VALUES('technical','fixture-global','open','critical',?,?)", (NOW.isoformat(), NOW.isoformat()))
    admin = meta(s)
    assert admin.facts["domains"] == 10 and admin.facts["open_events"] == 31
    with TestClient(client.app) as reader:
        log_in(reader, "reader", PASSWORD)
        before = list(s.db._conn.iterdump())
        response = reader.get("/dashboard")
        assert response.status_code == 200
        assert "secret-0010.example" not in response.text and "SECRET_PERIMETER" not in response.text
        assert "fixture-global" not in response.text
        visible = s.scans.domains_page(DomainFilter(), internal=False, scheduler="off", now=NOW)
        assert visible.facts == {"domains": 9, "attention": 9, "no_conclusive": 0, "open_events": 27}
        assert 'data-domain="secret' not in reader.get("/dashboard?q=secret&severity=critical").text
        assert "0 domaine(s) correspondant(s)" in reader.get("/dashboard?q=secret").text
        assert list(s.db._conn.iterdump()) == before


@pytest.mark.parametrize("sort", ["attention", "name", "recent"])
def test_stable_order_nulls_and_no_missing_or_duplicate_domains(client, sort):
    setup_account(client)
    s = client.app.state.services
    populate(s, 101, NOW, internal_every=0)
    s.scans.add_domain("unmeasured.example", None)
    seen = []
    for page_number in range(1, 4):
        page = meta(s, page=page_number, size=50, sort=sort)
        seen.extend(row["id"] for row in page.rows)
        assert [r["id"] for r in page.rows] == [r["id"] for r in meta(s, page=page_number, size=50, sort=sort).rows]
    assert len(seen) == len(set(seen)) == 102


def test_combined_filters_and_literal_search_characters(client):
    setup_account(client)
    s = client.app.state.services
    populate(s, 100, NOW)
    page = meta(s, name="domain-00", evaluation="complete", severity="critical", freshness="overdue", sort="name")
    assert page.rows and all(row["freshness"] == "overdue" for row in page.rows)
    assert all(row["evaluation"] == "complete" and row["has_critical"] for row in page.rows)
    for name in ("%", "_", "' OR 1=1 --"):
        assert meta(s, name=name).total == 0
    s.scans.add_domain("literal%.example", None)
    assert meta(s, name="%").total == 1


@pytest.mark.parametrize("params", [
    {"page": "0"}, {"page": "²"}, {"page": "-1"}, {"page": "9999999999999"},
    {"size": "101"}, {"size": "0"}, {"sort": "score;DROP TABLE domains"},
    {"evaluation": "unknown"}, {"severity": "secret"}, {"freshness": "stale;"}, {"q": "x" * 254},
])
def test_bad_dashboard_parameters_are_rejected(client, params):
    setup_account(client)
    assert client.get("/dashboard", params=params).status_code == 400


def test_pagination_keeps_filters_and_limits_page_size(client):
    setup_account(client)
    s = client.app.state.services
    populate(s, 101, NOW, internal_every=0)
    page = client.get("/dashboard?q=domain&severity=critical&size=50&sort=name")
    assert page.status_code == 200 and "page=2" in page.text
    assert "severity=critical" in page.text and "size=50" in page.text
    assert page.text.count('data-domain="') == 50
    assert client.get("/dashboard?page=4&size=50").status_code == 404
    assert client.get("/dashboard?page=1&page=2").status_code == 400


def seed_schedule(client, *, enabled=True):
    setup_account(client)
    s = client.app.state.services
    fs = list(run(healthy()).values())
    did = s.scans.add_domain(DOMAIN, None)
    sid = s.scans.save(did, engine.ScanResult(DOMAIN, NOW - timedelta(days=31), 1, fs), "0.5.0", None, via="web")
    s.schedules.set(did, Definition("daily", 300), enabled=enabled, user_id=None, now=NOW - timedelta(days=3))
    s.db.execute("UPDATE schedules SET next_run_at=? WHERE domain_id=?", ((NOW - timedelta(hours=3)).isoformat(),did))
    return s, did, sid


def test_t27_instance_off_never_asserts_overdue_and_is_read_only(client):
    s, _, _ = seed_schedule(client)
    before = list(s.db._conn.iterdump())
    _, rows = portfolio.load(s, DomainFilter(), internal=True, scheduler="off", now=NOW, lang="fr")
    assert rows[0].row["freshness"] == "suspended"
    assert rows[0].schedule.next_run_at is None
    assert s.scans.domains_page(DomainFilter(freshness="overdue"), internal=True, scheduler="off", now=NOW).total == 0
    response = client.get("/dashboard")
    assert response.status_code == 200 and "Analyses programmées suspendues" in response.text
    assert list(s.db._conn.iterdump()) == before


def test_t30_paused_or_missing_schedule_has_only_an_informational_old_scan_marker(client):
    s, did, _ = seed_schedule(client, enabled=False)
    assert meta(s).rows[0]["freshness"] == "manual_old"
    s.schedules.remove(did)
    assert meta(s).rows[0]["freshness"] == "manual_old"
    assert meta(s).facts["attention"] == 0
    response = client.get("/dashboard")
    assert "cette ancienneté ne crée aucun événement" in response.text
    assert s.db.value("SELECT COUNT(*) FROM events") == 0


def test_operational_grace_failures_and_running_lease_are_distinct(client):
    s, did, _ = seed_schedule(client)
    assert meta(s).rows[0]["freshness"] == "overdue"
    s.db.execute("UPDATE schedules SET next_run_at=? WHERE domain_id=?", ((NOW-timedelta(hours=2)).isoformat(),did))
    assert meta(s).rows[0]["freshness"] == "scheduled"
    s.db.execute("UPDATE schedules SET next_run_at=? WHERE domain_id=?", ((NOW-timedelta(hours=1)).isoformat(),did))
    assert meta(s).rows[0]["freshness"] == "scheduled"
    s.db.execute("UPDATE schedules SET failures=1 WHERE domain_id=?", (did,))
    assert meta(s).rows[0]["freshness"] == "failed"
    s.db.execute("INSERT INTO schedule_runs(domain_id,slot,state,claim,owner,claimed_at,lease_until) "
                 "VALUES(?,'fixture','running','claim','fixture',?,?)", (did,NOW.isoformat(),
                                                                         (NOW+timedelta(minutes=10)).isoformat()))
    assert meta(s).rows[0]["freshness"] == "running"


def test_stalled_future_or_bad_heartbeat_cannot_prove_lateness(client):
    s, _, _ = seed_schedule(client)
    s.config.scheduler = True
    for value in (None, "broken", json.dumps({"at": NOW.replace(tzinfo=None).isoformat()}),
                  json.dumps({"at": (NOW-timedelta(minutes=4)).isoformat()}),
                  json.dumps({"at": (NOW+timedelta(minutes=4)).isoformat()})):
        if value is not None:
            s.db.set_meta("scheduler_heartbeat", value)
        assert portfolio.scheduler_state(s, None, NOW) == "stalled"
    s.db.set_meta("scheduler_heartbeat", json.dumps({"at": NOW.isoformat()}))
    assert portfolio.scheduler_state(s, None, NOW) == "elsewhere"
    s.config.scheduler = False  # another process with a fresh heartbeat may still schedule this instance
    assert portfolio.scheduler_state(s, None, NOW) == "elsewhere"
    page = s.scans.domains_page(DomainFilter(freshness="overdue"), internal=True, scheduler="stalled", now=NOW)
    assert page.total == 0


def test_batch_loader_matches_individual_scan_and_handles_corruption(client):
    setup_account(client)
    s = client.app.state.services
    populate(s, 2, NOW, internal_every=0)
    single = s.scans.get(3)
    loaded, unreadable = s.scans.get_many([3,6])
    assert not unreadable and loaded[3] == single
    s.db.execute("UPDATE findings SET outcome='not-json' WHERE scan_id=3")
    loaded, unreadable = s.scans.get_many([3,6])
    assert set(loaded) == {6} and unreadable == {3}
    assert client.get("/dashboard").status_code == 200
    with pytest.raises(ValueError):
        s.scans.get_many([3]*101)


def test_bilingual_dashboard_and_shared_public_domains(client):
    setup_account(client)
    s = client.app.state.services
    s.scans.add_domain("another-owner.example", None)
    post(client, "/lang", "/dashboard", lang="en", back="/dashboard")
    page = client.get("/dashboard")
    assert page.status_code == 200 and "Accessible domains" in page.text
    assert "another-owner.example" in page.text
    assert "No measurement recorded" in page.text


@pytest.mark.parametrize(("before", "after", "kind"), [("ok", "fail", "regressed"), ("fail", "ok", "improved")])
def test_last_proven_transition_preserves_measurement_gap(before, after, kind):
    def state(status, n):
        return Snapshot((NOW+timedelta(seconds=n)).isoformat(), "recheck", 4, 80, 1.0, "complete",
                        {"mail.dmarc": status}, 1, "", n)
    result = portfolio.latest_transition([state(after,3), state("error",2), state(before,1)])
    assert result.change.kind == kind and result.missed == 1
    assert result.at == state(after,3).at and result.previous_at == state(before,1).at


def test_coverage_rounding_matches_the_assessment_not_binary_float_floor(client):
    setup_account(client)
    s = client.app.state.services
    did = s.scans.add_domain(DOMAIN, None)
    findings = [Finding("fixture.good", "dns", 29, Outcome(Status.OK, "fixture")),
                Finding("fixture.gap", "dns", 21, Outcome(Status.ERROR, "fixture"))]
    s.scans.save(did, engine.ScanResult(DOMAIN, NOW, 1, findings), "0.5.0", None)
    page = client.get("/dashboard")
    assert page.status_code == 200 and "Couverture : 58 %" in page.text
    assert "Couverture diagnostique : 58 %" in page.text
