# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Event ledger and web access: visibility, seen marker, and idempotency."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from helpers import post, setup_account
from posture_cockpit.storage.events import record_state


def test_event_lifecycle_and_idempotency(client):
    setup_account(client, demo=True)
    s = client.app.state.services
    domain = s.scans.domain("menuiserie-dupont.example")
    assert domain is not None
    scan_id = s.scans.latest_id(domain["id"])
    assert scan_id is not None
    previous = s.db.one("SELECT * FROM scan_states WHERE scan_id=? ORDER BY id DESC LIMIT 1", (scan_id,))
    assert previous is not None
    checks = json.loads(previous["checks"])
    healthy = next((k for k, v in checks.items() if v == "ok"), None)
    assert healthy is not None
    checks[healthy] = "fail"
    at = (datetime.fromisoformat(previous["at"]) + timedelta(minutes=2)).isoformat()

    with s.db.transaction():
        s.db.execute(
            "INSERT INTO scan_states(scan_id, at, origin, engine, score, grade, coverage, evaluation,"
            " metrics, checks) VALUES (?, ?, 'recheck', ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, at, previous["engine"], previous["score"], previous["grade"],
             previous["coverage"], previous["evaluation"], previous["metrics"], json.dumps(checks)),
        )
        record_state(s.db, domain["id"], scan_id)
        record_state(s.db, domain["id"], scan_id)

    rows = s.db.all("SELECT * FROM events WHERE domain_id=? AND kind='check' AND subject=?",
                    (domain["id"], healthy))
    assert len(rows) == 1 and rows[0]["state"] == "open"
    assert rows[0]["severity"] == "critical"

    page = client.get("/events")
    assert page.status_code == 200 and healthy in page.text
    assert "Événements" in page.text

    # Deliberate resolution with a conclusive observation, same scoring generation.
    checks[healthy] = "ok"
    at2 = (datetime.fromisoformat(at) + timedelta(minutes=1)).isoformat()
    with s.db.transaction():
        s.db.execute(
            "INSERT INTO scan_states(scan_id, at, origin, engine, score, grade, coverage, evaluation,"
            " metrics, checks) VALUES (?, ?, 'recheck', ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, at2, previous["engine"], previous["score"], previous["grade"],
             previous["coverage"], previous["evaluation"], previous["metrics"], json.dumps(checks)),
        )
        record_state(s.db, domain["id"], scan_id)

    row = s.db.one("SELECT state,resolved_at FROM events WHERE domain_id=? AND kind='check'",
                   (domain["id"],))
    assert row["state"] == "resolved" and row["resolved_at"] == at2


def test_event_seen_requires_csrf_and_does_not_resolve(client):
    setup_account(client, demo=True)
    s = client.app.state.services
    domain = s.scans.domain("menuiserie-dupont.example")
    stamp = datetime.now(UTC).isoformat()
    s.db.execute(
        "INSERT INTO events(domain_id,category,kind,subject,state,severity,opened_at,updated_at) "
        "VALUES(?,'security','check','tls.cert','open','critical',?,?)",
        (domain["id"], stamp, stamp))
    assert client.get("/events").status_code == 200
    rejected = client.post("/events/seen", data={}, follow_redirects=False)
    assert rejected.status_code == 403
    response = post(client, "/events/seen", "/events")
    assert response.status_code == 303
    assert s.db.value("SELECT state FROM events WHERE subject='tls.cert'") == "open"
    assert s.db.value("SELECT events_seen_at FROM users LIMIT 1") is not None


def test_score_drop_remains_open_until_original_baseline_is_recovered(client):
    setup_account(client, demo=True)
    s = client.app.state.services
    domain = s.scans.domain("menuiserie-dupont.example")
    scan_id = s.scans.latest_id(domain["id"])
    before = s.db.one("SELECT * FROM scan_states WHERE scan_id=? ORDER BY id DESC LIMIT 1",
                      (scan_id,))
    baseline = int(before["score"])
    start = datetime.fromisoformat(before["at"])
    for minutes, score in ((2, baseline - 12), (3, baseline - 11), (4, baseline)):
        with s.db.transaction():
            s.db.execute(
                "INSERT INTO scan_states(scan_id,at,origin,engine,score,grade,coverage,evaluation,"
                " metrics,checks) VALUES(?,?,'recheck',?,?,?,?,?,?,?)",
                (scan_id, (start + timedelta(minutes=minutes)).isoformat(),
                 before["engine"], score, before["grade"], before["coverage"],
                 before["evaluation"], before["metrics"], before["checks"]),
            )
            record_state(s.db, domain["id"], scan_id)
        state = s.db.value("SELECT state FROM events WHERE domain_id=? AND kind='score_drop'",
                           (domain["id"],))
        assert state == ("resolved" if score == baseline else "open")
