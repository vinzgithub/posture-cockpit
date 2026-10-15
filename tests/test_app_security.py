# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Security of the web application itself: redirects, sign-in, scan limits, headers, files."""

import pytest
from fastapi.testclient import TestClient

from helpers import DEMO, PASSWORD, log_in, page_csrf, post, setup_account
from posture_cockpit import security
from posture_cockpit.config import Config, secret_key
from posture_cockpit.security import LoginThrottle, new_token, token_hash
from posture_cockpit.web.app import create_app
from posture_cockpit.web.deps import local_path
from posture_cockpit.web.limits import ScanLimiter, TooManyScans


# ----------------------------------------------------------------- redirects
@pytest.mark.parametrize(("target", "expected"), [
    ("/domains/example.org?task=mail.dmarc#task", "/domains/example.org?task=mail.dmarc#task"),
    ("/settings", "/settings"),
    ("//evil.example/", "/domains"),
    ("/\\evil.example/", "/domains"),       # 0.1.0 let this through: browsers read it as //evil.example
    ("\\\\evil.example", "/domains"),
    ("https://evil.example/", "/domains"),
    ("javascript:alert(1)", "/domains"),
    ("/\t/evil.example", "/domains"),       # browsers drop tabs and line breaks from addresses
    ("/\n/evil.example", "/domains"),
    ("", "/domains"),
])
def test_only_local_paths_are_followed(target, expected):
    assert local_path(target) == expected


def test_language_switch_cannot_send_elsewhere(client):
    setup_account(client)
    r = client.post("/lang", data={"csrf": page_csrf(client, "/domains"), "lang": "en", "back": "/\\evil.example"},
                    follow_redirects=False)
    assert r.headers["location"] == "/domains"


# ------------------------------------------------------------------- sign-in
def test_an_unknown_name_costs_a_password_check_too(client, monkeypatch):
    """0.1.0 answered faster for unknown names, which told which accounts exist."""
    setup_account(client)
    checked = []
    real = security.verify_password

    def spy(password, stored):
        checked.append(stored)
        return real(password, stored)

    monkeypatch.setattr("posture_cockpit.web.routes.auth.verify_password", spy)
    assert log_in(client, "nobody", "whatever password").status_code == 401
    assert checked == [security.dummy_password_hash()]


def test_guesses_from_many_addresses_still_lock_the_account(app, client):
    """0.1.0 only counted failures by address."""
    setup_account(client)
    services = app.state.services
    services.throttle = LoginThrottle(max_failures=1000)  # as if every guess came from a new address
    with TestClient(app) as attacker:
        for _ in range(10):
            assert log_in(attacker, "vincent", "not the password").status_code == 401
        assert log_in(attacker, "vincent", PASSWORD).status_code == 429  # even the right password waits
        assert log_in(attacker, "Vincent", PASSWORD).status_code == 429  # whatever the case
    assert [e["action"] for e in services.audit.latest(2)] == ["login.locked", "login.locked"]


def test_the_throttle_does_not_grow_without_end():
    throttle = LoginThrottle(max_failures=5, lock_seconds=0)
    for i in range(LoginThrottle.MAX_KEYS + 50):
        throttle.failure(f"name-{i}")
    assert len(throttle._state) <= LoginThrottle.MAX_KEYS


# --------------------------------------------------------------- scan limits
class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_scan_limiter_quota_and_concurrency():
    clock = Clock()
    limiter = ScanLimiter(concurrent=1, per_hour=2, clock=clock)
    with limiter.slot("a"):
        with pytest.raises(TooManyScans) as busy, limiter.slot("b"):
            pass
        assert busy.value.reason == "busy"
    with limiter.slot("a"):
        pass
    with pytest.raises(TooManyScans) as quota, limiter.slot("a"):
        pass
    assert quota.value.reason == "quota" and 3500 < quota.value.retry_after <= 3601
    with limiter.slot("a", counts=False):  # a recheck does not use the hourly share
        pass
    with limiter.slot("b"):  # another account has its own share
        pass
    clock.now += 3600
    with limiter.slot("a"):
        pass


def test_scans_over_the_quota_are_refused_on_the_page_and_the_api(tmp_path, world):
    app = create_app(Config(data_dir=tmp_path, scans_per_hour=1))
    with TestClient(app) as client:
        setup_account(client)
        assert post(client, "/domains", domain=DEMO).status_code == 303
        r = post(client, "/domains", domain=DEMO)
        assert r.status_code == 429 and "nombre d&#39;analyses autorisées par heure" in r.text
        token = new_token()
        app.state.services.accounts.add_token(1, "cron", token_hash(token))
        r = client.post(f"/api/v1/domains/{DEMO}/scan", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
        # Checking one fix again is still possible: it does not use the hourly share.
        r = post(client, f"/domains/{DEMO}/verify/mail.dmarc", f"/domains/{DEMO}")
        page = client.get(r.headers["location"]).text
        assert "autorisées par heure" not in page and "Pas encore visible" in page


# ------------------------------------------------------------------- headers
def test_response_headers(tmp_path):
    with TestClient(create_app(Config(data_dir=tmp_path))) as client:
        headers = client.get("/setup").headers
        assert headers["cross-origin-opener-policy"] == "same-origin"
        assert headers["cross-origin-resource-policy"] == "same-origin"
        assert "strict-transport-security" not in headers  # plain HTTP: HSTS would be ignored
    with TestClient(create_app(Config(data_dir=tmp_path / "s", cookie_secure=True))) as client:
        assert client.get("/healthz").headers["strict-transport-security"] == "max-age=31536000"


# --------------------------------------------------------------------- files
def test_the_data_folder_and_its_secrets_are_private(tmp_path):
    folder = tmp_path / "data"
    secret_key(folder)
    assert folder.stat().st_mode & 0o777 == 0o700
    assert (folder / ".secret_key").stat().st_mode & 0o777 == 0o600


def test_package_version_matches_project_metadata_and_healthz(client):
    import tomllib
    from pathlib import Path

    from posture_cockpit import __version__

    project = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    assert __version__ == project["project"]["version"] == "0.3.2"
    assert client.get("/healthz").json()["version"] == __version__
