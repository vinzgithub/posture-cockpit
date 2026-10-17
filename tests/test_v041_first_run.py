# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.4.1: the first account needs the one-time setup code written to the server log."""

import logging
import sqlite3
import threading

import pytest
from fastapi.testclient import TestClient

from helpers import PASSWORD, log_in, page_csrf, setup_account, setup_code
from posture_cockpit.config import Config
from posture_cockpit.storage import Accounts, Database
from posture_cockpit.web import first_run
from posture_cockpit.web.app import create_app


def form(client, code, **extra):
    return {"csrf": page_csrf(client, "/setup"), "setup_code": code, "username": "vincent",
            "password": PASSWORD, "password2": PASSWORD, "lang": "fr", **extra}


def accounts(client):
    return client.app.state.services.accounts


def test_the_setup_page_asks_for_the_code_and_says_where_it_is(client):
    page = client.get("/setup").text
    assert 'name="setup_code"' in page and "docker compose logs posture-cockpit" in page


@pytest.mark.parametrize("code", ["", "AAAA-BBBB-CCCC", "x" * 64])
def test_no_account_without_the_right_code(client, code):
    r = client.post("/setup", data=form(client, code), follow_redirects=False)
    assert r.status_code == 403 and accounts(client).count() == 0
    assert "initialisation incorrect" in r.text
    entries = client.app.state.services.db.all("SELECT action FROM audit_log")
    assert [e["action"] for e in entries] == ["setup.code_refused"]


def test_the_code_survives_a_mistake_in_the_form_and_is_used_once(client):
    code = setup_code(client.app)
    r = client.post("/setup", data=form(client, code, password2="something else"), follow_redirects=False)
    assert r.status_code == 400 and accounts(client).count() == 0
    assert code in r.text  # kept in the form, as the username is
    r = client.post("/setup", data=form(client, code.lower().replace("-", " ")), follow_redirects=False)
    assert r.status_code == 303 and accounts(client).count() == 1
    assert accounts(client).by_name("vincent")["is_admin"]
    db = client.app.state.services.db
    assert db.get_meta(first_run.META_KEY) is None
    assert not first_run.consume(db, code)


def test_a_restart_draws_a_new_code_until_an_account_exists(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="uvicorn.error"):
        first = create_app(Config(data_dir=tmp_path))
        second = create_app(Config(data_dir=tmp_path))
    assert first.state.setup_code != second.state.setup_code
    assert first.state.setup_code in caplog.text and second.state.setup_code in caplog.text
    db = second.state.services.db
    assert not first_run.matches(db, first.state.setup_code) and first_run.matches(db, second.state.setup_code)
    with TestClient(second) as client:
        assert setup_account(client).status_code == 303
    third = create_app(Config(data_dir=tmp_path))
    assert third.state.setup_code is None and third.state.services.db.get_meta(first_run.META_KEY) is None


def test_existing_accounts_never_see_a_code(tmp_path, caplog):
    app = create_app(Config(data_dir=tmp_path))
    with TestClient(app) as client:
        setup_account(client)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="uvicorn.error"):
        again = create_app(Config(data_dir=tmp_path))
    assert again.state.setup_code is None and "setup code" not in caplog.text.lower()
    with TestClient(again) as client:
        assert client.get("/setup", follow_redirects=False).headers["location"] == "/login"
        assert log_in(client).status_code == 303


def test_a_code_set_by_the_operator_is_accepted_and_never_logged(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="uvicorn.error"):
        app = create_app(Config(data_dir=tmp_path, setup_code="Mon code secret 2026"))
    assert "Mon code secret" not in caplog.text and "POSTURE_COCKPIT_SETUP_CODE" in caplog.text
    with TestClient(app) as client:
        assert client.post("/setup", data=form(client, "MONCODESECRET2026"), follow_redirects=False).status_code == 303


def test_a_short_operator_code_stops_the_start(tmp_path):
    with pytest.raises(ValueError, match="POSTURE_COCKPIT_SETUP_CODE"):
        Config(data_dir=tmp_path, setup_code="court")


def test_guessing_is_throttled(client):
    for _ in range(5):
        client.post("/setup", data=form(client, "WRONG-CODE-0000"))
    r = client.post("/setup", data=form(client, setup_code(client.app)), follow_redirects=False)
    assert r.status_code == 429 and accounts(client).count() == 0


def test_generated_codes():
    codes = {first_run.new_code() for _ in range(200)}
    assert len(codes) == 200
    for code in codes:
        assert len(code) == 14 and code.count("-") == 2
        assert not set(code.replace("-", "")) - set(first_run.ALPHABET)


# ------------------------------------------------- one transaction (counter-review P1)
def test_a_failure_while_creating_the_account_keeps_the_code_valid(client, monkeypatch):
    code = setup_code(client.app)
    db = client.app.state.services.db
    accounts_class = type(accounts(client))
    real_create = accounts_class.create

    def failing_create(self, *args, **kwargs):
        real_create(self, *args, **kwargs)  # the row is written, then the failure comes
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(accounts_class, "create", failing_create)
    with TestClient(client.app, raise_server_exceptions=False) as other:
        r = other.post("/setup", data=form(other, code), follow_redirects=False)
    assert r.status_code == 500
    assert accounts(client).count() == 0 and first_run.matches(db, code)  # both rolled back
    monkeypatch.setattr(accounts_class, "create", real_create)
    assert client.post("/setup", data=form(client, code), follow_redirects=False).status_code == 303
    assert accounts(client).count() == 1 and db.get_meta(first_run.META_KEY) is None


def test_a_failure_after_consuming_the_code_rolls_it_back(tmp_path, monkeypatch):
    app = create_app(Config(data_dir=tmp_path))
    services = app.state.services
    code = app.state.setup_code
    real_consume = first_run.consume

    def consumed_then_fails(db, given):
        assert real_consume(db, given)  # the code is deleted...
        raise RuntimeError("power cut between the two writes")  # ...and the account never comes

    monkeypatch.setattr(first_run, "consume", consumed_then_fails)
    with pytest.raises(RuntimeError):
        first_run.create_administrator(services.db, services.accounts, code, "vincent", "hash", "fr")
    assert first_run.matches(services.db, code) and services.accounts.count() == 0


@pytest.mark.parametrize("connections", ["shared", "separate"])
def test_simultaneous_requests_create_one_administrator(tmp_path, connections):
    app = create_app(Config(data_dir=tmp_path))
    code = app.state.setup_code
    databases = ([app.state.services.db] * 8 if connections == "shared"
                 else [Database(tmp_path / "posture_cockpit.db") for _ in range(8)])  # like separate processes
    start = threading.Barrier(len(databases))
    results = []

    def attempt(n, db):
        start.wait()
        results.append(first_run.create_administrator(db, Accounts(db), code, f"admin{n}", "hash", "fr"))

    threads = [threading.Thread(target=attempt, args=(n, db)) for n, db in enumerate(databases)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert len(results) == 8 and len([r for r in results if r is not None]) == 1
    rows = app.state.services.db.all("SELECT username, is_admin FROM users")
    assert len(rows) == 1 and rows[0]["is_admin"] == 1
    assert app.state.services.db.get_meta(first_run.META_KEY) is None
