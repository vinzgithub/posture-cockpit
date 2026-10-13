# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The name of the session cookie: stable by default, configurable for two instances on one address."""

import pytest
from fastapi.testclient import TestClient

from helpers import setup_account
from posture_cockpit.config import DEFAULT_SESSION_COOKIE, Config
from posture_cockpit.web.app import create_app


def _cookie_names(response) -> list[str]:
    return [h.split("=", 1)[0] for h in response.headers.get_list("set-cookie")]


def test_the_default_name_is_unchanged(client):
    # Existing installations keep their sessions after the update.
    assert DEFAULT_SESSION_COOKIE == "posture_cockpit"
    assert _cookie_names(setup_account(client)) == ["posture_cockpit"]


def test_two_instances_on_one_address_keep_separate_sessions(tmp_path):
    """Browsers send the cookies of 192.168.2.15 to every port: with two names, signing in
    to one instance no longer signs the user out of the other."""
    production = create_app(Config(data_dir=tmp_path / "prod"))
    validation = create_app(Config(data_dir=tmp_path / "test", session_cookie="posture_cockpit_validation"))
    with TestClient(production) as prod, TestClient(validation) as test:
        setup_account(prod)
        r = setup_account(test)
        assert _cookie_names(r) == ["posture_cockpit_validation"]
        # The browser would now hold both cookies: each instance reads only its own.
        test.cookies.set("posture_cockpit", prod.cookies.get("posture_cockpit"))
        prod.cookies.set("posture_cockpit_validation", test.cookies.get("posture_cockpit_validation"))
        assert prod.get("/domains", follow_redirects=False).status_code == 200
        assert test.get("/domains", follow_redirects=False).status_code == 200
        # What happened on 13 October with one name for both: the other instance's cookie
        # replaced this one, its signature did not match, and the user was signed out.
        prod.cookies.set("posture_cockpit", test.cookies.get("posture_cockpit_validation"))
        r = prod.get("/domains", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"


@pytest.mark.parametrize("name", ["", "a b", "posture;cockpit", "pc=1", "é", "x" * 65])
def test_names_browsers_would_mangle_are_refused(tmp_path, name):
    with pytest.raises(ValueError, match="POSTURE_COCKPIT_SESSION_COOKIE"):
        Config(data_dir=tmp_path, session_cookie=name)


def test_secure_prefixes_need_https(tmp_path):
    with pytest.raises(ValueError, match="COOKIE_SECURE"):
        Config(data_dir=tmp_path, session_cookie="__Host-posture")
    config = Config(data_dir=tmp_path, session_cookie="__Host-posture", cookie_secure=True)
    assert config.session_cookie == "__Host-posture"


def test_the_name_comes_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("POSTURE_COCKPIT_SESSION_COOKIE", " posture_cockpit_validation ")
    assert Config.from_env().session_cookie == "posture_cockpit_validation"
    monkeypatch.setenv("POSTURE_COCKPIT_SESSION_COOKIE", "bad name")
    with pytest.raises(ValueError):
        Config.from_env()
