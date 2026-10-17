# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: how each scan was started (scans.via), in the history and in the API.

The API only adds two keys, via and engine (test_v050_contract.py keeps the others as 0.4.1
gave them)."""

import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from helpers import DEMO, log_in, post, setup_account
from posture_cockpit.config import Config
from posture_cockpit.core import generation
from posture_cockpit.security import new_token, token_hash
from posture_cockpit.web.app import create_app

DATA = Path(__file__).parent / "data"
TOKEN = "legacy-api-token-for-tests-0123456789"


@pytest.fixture
def signed_in(client):
    setup_account(client)
    return client


def api_key(client) -> dict:
    token = new_token()
    client.app.state.services.accounts.add_token(1, "test", token_hash(token))
    return {"Authorization": f"Bearer {token}"}


def test_a_scan_from_the_pages_and_one_from_the_api_say_so(signed_in):
    key = api_key(signed_in)
    post(signed_in, "/domains", "/domains", domain=DEMO)
    post(signed_in, f"/domains/{DEMO}/scan", f"/domains/{DEMO}")
    answer = signed_in.post(f"/api/v1/domains/{DEMO}/scan", headers=key)
    assert answer.status_code == 200
    assert (answer.json()["via"], answer.json()["engine"]) == ("api", generation.GENERATION)
    db = signed_in.app.state.services.db
    assert [r[0] for r in db.all("SELECT via FROM scans ORDER BY id")] == ["web", "web", "api"]
    assert {r[0] for r in db.all("SELECT engine FROM scans")} == {generation.GENERATION}
    listed = {d["domain"]: d for d in signed_in.get("/api/v1/domains", headers=key).json()["domains"]}
    assert (listed[DEMO]["via"], listed[DEMO]["engine"]) == ("api", generation.GENERATION)  # the latest


def test_the_database_refuses_an_unknown_origin(signed_in):
    post(signed_in, "/domains", "/domains", domain=DEMO)
    with pytest.raises(sqlite3.IntegrityError):
        signed_in.app.state.services.db.execute("UPDATE scans SET via = 'cron'")


@pytest.mark.parametrize(("lang", "header", "web", "api", "unknown"), [
    ("fr", "Origine", "Manuelle", "API", "Non enregistrée : analyse faite avant la version 0.5.0"),
    ("en", "Started", "Manually", "API", "Not recorded: scan made before version 0.5.0"),
])
def test_the_history_shows_the_origin_in_both_languages(signed_in, lang, header, web, api, unknown):
    key = api_key(signed_in)
    post(signed_in, "/domains", "/domains", domain=DEMO)
    signed_in.post(f"/api/v1/domains/{DEMO}/scan", headers=key)
    db = signed_in.app.state.services.db
    db.execute("INSERT INTO scans(domain_id, started_at, duration_ms, score, grade, version) "
               "SELECT domain_id, '2026-01-01T00:00:00+00:00', 1, 50, 'C', '0.4.1' FROM scans LIMIT 1")
    post(signed_in, "/lang", "/domains", lang=lang, back="/domains")
    page = signed_in.get(f"/domains/{DEMO}/history").text
    cells = [cell.strip() for cell in re.findall(r'<td class="history-via"[^>]*>(.*?)</td>', page)]
    assert len(cells) == 3
    assert cells[0] == api and cells[1] == web  # newest first
    assert f'title="{unknown}"' in cells[2] and ">—<" in cells[2]
    assert f"<th>{header}</th>" in page and "history.via" not in page


def test_scans_made_before_0_5_0_have_no_origin_and_their_generation_if_known(tmp_path):
    for version, engine in (("v0.3.0", None), ("v0.4.1", 4)):
        folder = tmp_path / version
        folder.mkdir()
        with sqlite3.connect(folder / "posture_cockpit.db") as conn:
            conn.executescript((DATA / f"database-{version}.sql").read_text())
        app = create_app(Config(data_dir=folder))
        try:
            with TestClient(app) as client:
                domains = client.get("/api/v1/domains", headers={"Authorization": f"Bearer {TOKEN}"}).json()["domains"]
                assert {(d["via"], d["engine"]) for d in domains} == {(None, engine)}
                if version == "v0.3.0":
                    assert log_in(client).status_code == 303
                    page = client.get(f"/domains/{DEMO}/history").text
                    assert 'class="history-via" data-label="Origine"><span title="Non enregistrée' in page
        finally:
            app.state.services.db.close()
