# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Scheduled-scan configuration: authorization, CSRF, persistence and UI."""

from helpers import DEMO, PASSWORD, post, setup_account


def _ready(client):
    setup_account(client, demo=True)
    response = post(client, "/admin/confirm", "/admin/confirm", password=PASSWORD)
    assert response.status_code == 303
    return client.app.state.services


def test_schedule_can_be_saved_paused_and_removed(client):
    services = _ready(client)
    detail = f"/domains/{DEMO}/details"
    schedule_url = f"/domains/{DEMO}/schedule"
    assert "Analyse programmée" in client.get(detail).text
    response = post(client, schedule_url, detail, frequency="weekly", time="04:35",
                    weekday="3", monthday="1", enabled="on")
    assert response.status_code == 303
    domain = services.scans.domain(DEMO)
    saved = services.schedules.get(domain["id"])
    assert saved is not None and saved.enabled
    assert saved.definition.frequency == "weekly"
    assert saved.definition.weekday == 3 and saved.definition.at_minute == 275
    assert "Chaque Mercredi" in client.get(detail).text
    response = post(client, schedule_url, detail, frequency="weekly", time="04:35",
                    weekday="3", monthday="1")
    assert response.status_code == 303
    assert not services.schedules.get(domain["id"]).enabled
    response = post(client, schedule_url, detail, frequency="off", time="05:00")
    assert response.status_code == 303
    assert services.schedules.get(domain["id"]) is None
    assert services.db.value("SELECT COUNT(*) FROM schedules") == 0


def test_invalid_schedule_does_not_change_existing_definition(client):
    services = _ready(client)
    domain = services.scans.domain(DEMO)
    target = f"/domains/{DEMO}/schedule"
    detail = f"/domains/{DEMO}/details"
    post(client, target, detail, frequency="daily", time="05:00", enabled="on")
    response = post(client, target, detail, frequency="monthly", time="25:00", monthday="40",
                    weekday="1", enabled="on")
    assert response.status_code == 400
    assert "Paramètres de programmation invalides" in response.text
    assert services.schedules.get(domain["id"]).definition.frequency == "daily"


def test_configure_schedule_requires_recent_admin_confirmation_and_csrf(client):
    setup_account(client, demo=True)
    url = f"/domains/{DEMO}/schedule"
    response = client.post(url, data={"frequency": "daily", "time": "05:00", "enabled": "on"},
                           follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/admin/confirm"
    response = post(client, url, f"/domains/{DEMO}/details",
                    frequency="daily", time="05:00", enabled="on")
    assert response.status_code == 303 and response.headers["location"] == "/admin/confirm"


def test_scheduler_status_is_shown_in_administration(client):
    _ready(client)
    page = client.get("/admin")
    assert page.status_code == 200
    assert "Analyses programmées" in page.text
    assert "Prochaines analyses" in page.text


def test_admin_confirmation_returns_to_schedule_without_replaying_post(client):
    setup_account(client, demo=True)
    detail = f"/domains/{DEMO}/details"
    schedule_url = f"/domains/{DEMO}/schedule"
    response = post(client, schedule_url, detail, frequency="daily", time="05:00", enabled="on")
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/confirm"
    response = post(client, "/admin/confirm", "/admin/confirm", password=PASSWORD)
    assert response.status_code == 303
    assert response.headers["location"] == detail + "#schedule"
    assert client.app.state.services.db.value("SELECT COUNT(*) FROM schedules") == 0
    response = post(client, schedule_url, detail, frequency="daily", time="05:00", enabled="on")
    assert response.status_code == 303
    assert client.app.state.services.db.value("SELECT COUNT(*) FROM schedules") == 1


def test_schedule_form_has_frequency_sensitive_fields(client):
    _ready(client)
    page = client.get(f"/domains/{DEMO}/details")
    assert page.status_code == 200
    assert "data-schedule-form" in page.text
    for kind in ("time", "weekday", "monthday"):
        assert f'data-schedule-field="{kind}"' in page.text



def test_schedule_run_slot_is_rendered_as_nominal_local_time(client):
    """The slot is a local wall time: do not convert it from UTC or expose ISO syntax."""
    services = _ready(client)
    domain = services.scans.domain(DEMO)
    post(client, f"/domains/{DEMO}/schedule", f"/domains/{DEMO}/details",
         frequency="daily", time="18:18", enabled="on")
    services.db.execute(
        "INSERT INTO schedule_runs(domain_id, slot, state, reason, claim, owner, attempts, claimed_at,"
        " finished_at) VALUES(?, ?, 'done', '', ?, 'test:1', 1, ?, ?)",
        (domain["id"], "2026-10-18T18:18", "test-claim", "2026-10-18T16:23:56+00:00",
         "2026-10-18T16:23:56+00:00"),
    )
    page = client.get(f"/domains/{DEMO}/details")
    assert page.status_code == 200
    assert "18 octobre 2026 18:18" in page.text
    assert "2026-10-18T18:18" not in page.text
