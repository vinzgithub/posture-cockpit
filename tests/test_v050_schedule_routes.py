# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Scheduled-scan configuration: authorization, CSRF, persistence and UI."""

from helpers import DEMO, PASSWORD, page_csrf, post, setup_account


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
    _ready(client)
    url = f"/domains/{DEMO}/schedule"
    response = client.post(url, data={"frequency": "daily", "time": "05:00", "enabled": "on"},
                           follow_redirects=False)
    assert response.status_code == 403
    with client.session_transaction() as session:
        session["admin_until"] = 0
    response = post(client, url, f"/domains/{DEMO}/details",
                    frequency="daily", time="05:00", enabled="on")
    assert response.status_code == 303 and response.headers["location"] == "/admin/confirm"


def test_scheduler_status_is_shown_in_administration(client):
    _ready(client)
    page = client.get("/admin")
    assert page.status_code == 200
    assert "Analyses programmées" in page.text
    assert "Prochaines analyses" in page.text
