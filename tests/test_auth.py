# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Accounts: first run, sign-in with two-factor authentication, administration, rescue tools."""

import base64
import re

import pytest
from fastapi.testclient import TestClient

from helpers import PASSWORD, csrf_of, log_in, log_out, page_csrf, post, setup_account, setup_code
from posture_cockpit import cli
from posture_cockpit.security import totp_at, totp_match, totp_step, totp_uri

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()
RFC_VECTORS = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
               (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]
CODE_RE = re.compile(r"<code>([a-z2-9]{5}-[a-z2-9]{5})</code>")
TEMP = "temporary pass 1"
OWN = "steph own password"


def accounts(client):
    return client.app.state.services.accounts


def code_now(secret, clock, offset=0):
    return totp_at(secret, totp_step(clock.now) + offset)


def enable_mfa(client, clock):
    """Turns two-factor authentication on; returns the secret and the recovery codes."""
    r = post(client, "/settings/totp/setup", "/settings")
    assert r.headers["location"] == "/settings/totp"
    page = client.get("/settings/totp")
    assert "data:image/svg+xml" in page.text
    secret = accounts(client).totp(1)["secret"]
    r = client.post("/settings/totp/enable", data={"csrf": csrf_of(page.text), "code": code_now(secret, clock),
                                                   "password": PASSWORD})
    codes = CODE_RE.findall(r.text)
    assert r.status_code == 200 and len(set(codes)) == 10
    return secret, codes


def send_code(client, code):
    return client.post("/login/code", data={"csrf": page_csrf(client, "/login/code"), "code": code},
                       follow_redirects=False)


# ------------------------------------------------------------------- TOTP
@pytest.mark.parametrize(("at", "expected"), RFC_VECTORS)
def test_totp_matches_rfc_6238(at, expected):
    assert totp_at(RFC_SECRET, at // 30, digits=8) == expected


def test_totp_accepts_neighbour_steps_once():
    now = 1_800_000_000
    step = totp_step(now)
    assert totp_match(RFC_SECRET, totp_at(RFC_SECRET, step), step - 1, now) == step
    assert totp_match(RFC_SECRET, totp_at(RFC_SECRET, step + 1), 0, now) == step + 1
    assert totp_match(RFC_SECRET, totp_at(RFC_SECRET, step + 2), 0, now) is None
    assert totp_match(RFC_SECRET, totp_at(RFC_SECRET, step), step, now) is None  # replay


def test_totp_uri_names_the_application():
    assert totp_uri("JBSWY3DPEHPK3PXP", "vincent").startswith("otpauth://totp/Posture%20Cockpit%3Avincent?")


# -------------------------------------------------------------- first run
def test_first_run(client):
    assert client.get("/domains", follow_redirects=False).headers["location"] == "/setup"
    r = setup_account(client)
    assert r.headers["location"] == "/domains"
    assert client.get("/setup", follow_redirects=False).headers["location"] == "/login"
    assert accounts(client).get(1)["is_admin"] == 1


def test_first_run_with_the_demo_domain(client):
    r = setup_account(client, demo=True)
    assert r.headers["location"] == "/domains/menuiserie-dupont.example"
    assert "Publier une politique DMARC" in client.get(r.headers["location"]).text


def test_setup_refuses_short_passwords(client):
    r = client.post("/setup", data={"csrf": page_csrf(client, "/setup"), "setup_code": setup_code(client.app),
                                    "username": "vincent", "password": "short", "password2": "short"})
    assert r.status_code == 400 and accounts(client).count() == 0


def test_forms_need_the_csrf_token(client):
    setup_account(client)
    r = client.post("/domains", data={"domain": "example.org"})
    assert r.status_code == 403


# ------------------------------------------------------- two-factor sign-in
def test_sign_in_asks_for_a_code_once_enabled(client, clock):
    setup_account(client)
    secret, _ = enable_mfa(client, clock)
    log_out(client)
    assert log_in(client).headers["location"] == "/login/code"
    assert client.get("/domains", follow_redirects=False).headers["location"] == "/login"  # password alone: nothing
    assert send_code(client, code_now(secret, clock)).status_code == 401  # the code used to enable cannot be replayed
    clock.advance(30)
    assert send_code(client, code_now(secret, clock)).headers["location"] == "/domains"
    assert client.get("/domains").status_code == 200


def test_recovery_code_works_once(client, clock):
    setup_account(client)
    _, codes = enable_mfa(client, clock)
    log_out(client)
    log_in(client)
    assert send_code(client, codes[0].upper().replace("-", " ")).headers["location"] == "/domains"
    assert "Il vous en reste 9" in client.get("/domains").text
    log_out(client)
    log_in(client)
    assert send_code(client, codes[0]).status_code == 401


def test_code_page_expires(client, clock):
    setup_account(client)
    secret, _ = enable_mfa(client, clock)
    log_out(client)
    log_in(client)
    clock.advance(301)
    r = client.post("/login/code", data={"csrf": page_csrf(client, "/login"), "code": code_now(secret, clock)},
                    follow_redirects=False)
    assert r.headers["location"] == "/login"


def test_wrong_codes_and_passwords_share_the_throttle(client, clock):
    setup_account(client)
    secret, _ = enable_mfa(client, clock)
    log_out(client)
    log_in(client)
    for _ in range(4):
        assert send_code(client, "000000").status_code == 401
    assert log_in(client).headers["location"] == "/login/code"  # retyping the password gives no extra tries
    assert send_code(client, "000000").status_code == 401
    clock.advance(30)
    assert send_code(client, code_now(secret, clock)).status_code == 429
    assert log_in(client).status_code == 429


def test_other_browsers_are_signed_out_when_2fa_is_turned_on(app, client, clock):
    setup_account(client)
    with TestClient(app) as other:
        log_in(other)
        assert other.get("/domains").status_code == 200
        enable_mfa(client, clock)
        assert client.get("/domains").status_code == 200
        assert other.get("/domains", follow_redirects=False).headers["location"] == "/login"


def test_turning_2fa_off_needs_password_and_code(client, clock):
    setup_account(client)
    _, codes = enable_mfa(client, clock)
    clock.advance(30)
    r = post(client, "/settings/totp/disable", "/settings", password=PASSWORD, code="000000")
    assert r.status_code == 400 and accounts(client).totp_enabled(1)
    r = post(client, "/settings/totp/disable", "/settings", password=PASSWORD, code=codes[3])
    assert r.status_code == 303 and not accounts(client).totp_enabled(1)


def test_new_recovery_codes_replace_the_old_ones(client, clock):
    setup_account(client)
    secret, old = enable_mfa(client, clock)
    clock.advance(30)
    r = post(client, "/settings/totp/codes", "/settings", password=PASSWORD, code=code_now(secret, clock))
    new = CODE_RE.findall(r.text)
    assert len(new) == 10 and not set(new) & set(old)


# ------------------------------------------------------------ administration
def confirm_admin(client, password=PASSWORD):
    return post(client, "/admin/confirm", "/admin/confirm", password=password)


def test_admin_pages_ask_for_the_password_again(client, clock):
    setup_account(client)
    assert client.get("/admin", follow_redirects=False).headers["location"] == "/admin/confirm"
    assert confirm_admin(client, "wrong password").status_code == 400
    assert confirm_admin(client).headers["location"] == "/admin"
    assert client.get("/admin").status_code == 200
    clock.advance(601)
    assert client.get("/admin", follow_redirects=False).headers["location"] == "/admin/confirm"


def test_new_account_chooses_its_password_and_cannot_administer(app, client):
    setup_account(client)
    confirm_admin(client)
    r = post(client, "/admin/users", "/admin", username="steph", password=TEMP, password2=TEMP, lang="en")
    assert r.headers["location"] == "/admin"
    with TestClient(app) as steph:
        log_in(steph, "steph", TEMP)
        assert steph.get("/domains", follow_redirects=False).headers["location"] == "/account/password"
        r = post(steph, "/account/password", "/account/password", new=TEMP, new2=TEMP)
        assert r.status_code == 400  # must differ from the temporary one
        r = post(steph, "/account/password", "/account/password", new=OWN, new2=OWN)
        assert r.headers["location"] == "/domains"
        assert "Domains" in steph.get("/domains").text  # in English, as chosen by the admin
        assert steph.get("/admin").status_code == 403


def test_admin_deletes_an_account_after_typing_its_name(client):
    setup_account(client)
    confirm_admin(client)
    post(client, "/admin/users", "/admin", username="steph", password=TEMP, password2=TEMP)
    uid = accounts(client).by_name("steph")["id"]
    assert post(client, f"/admin/users/{uid}/delete", f"/admin/users/{uid}", confirm="nope").status_code == 400
    assert post(client, f"/admin/users/{uid}/delete", f"/admin/users/{uid}", confirm="steph").status_code == 303
    assert accounts(client).by_name("steph") is None
    assert post(client, "/admin/users/1/delete", "/admin", confirm="vincent").status_code == 400  # not yourself


def test_a_new_account_never_opens_with_the_cookie_of_a_deleted_one(app, client):
    """0.1.0 to 0.3.1: SQLite gave the id of the deleted account to the next one, which started
    with the default session epoch. A browser of the deleted account, signed in with its temporary
    password, was then taken for the new account and could choose its password, then administer."""
    setup_account(client)
    confirm_admin(client)
    post(client, "/admin/users", "/admin", username="steph", password=TEMP, password2=TEMP)
    steph_id = accounts(client).by_name("steph")["id"]
    with TestClient(app) as old_browser, TestClient(app) as eve_browser:
        log_in(old_browser, "steph", TEMP)  # and never chooses a password
        assert old_browser.get("/domains", follow_redirects=False).headers["location"] == "/account/password"
        post(client, f"/admin/users/{steph_id}/delete", f"/admin/users/{steph_id}", confirm="steph")
        assert old_browser.get("/domains", follow_redirects=False).headers["location"] == "/login"

        post(client, "/admin/users", "/admin", username="eve", password=TEMP, password2=TEMP, is_admin="on")
        eve = accounts(client).by_name("eve")
        assert eve["id"] == steph_id and eve["is_admin"]  # the case that was open: same id, an administrator

        assert old_browser.get("/domains", follow_redirects=False).headers["location"] == "/login"
        assert old_browser.get("/account/password", follow_redirects=False).headers["location"] == "/login"
        r = post(old_browser, "/account/password", "/login", new=OWN, new2=OWN)  # its own CSRF token
        assert r.headers["location"] == "/login"
        assert old_browser.get("/admin", follow_redirects=False).headers["location"] == "/login"
        assert accounts(client).by_name("eve")["must_change_password"]  # nothing was changed for eve

        # eve signs in normally with the password the administrator gave her
        assert log_in(eve_browser, "eve", TEMP).headers["location"] == "/domains"
        assert eve_browser.get("/domains", follow_redirects=False).headers["location"] == "/account/password"
        r = post(eve_browser, "/account/password", "/account/password", new=OWN, new2=OWN)
        assert r.headers["location"] == "/domains"
        assert eve_browser.get("/domains").status_code == 200


def test_an_account_and_its_session_epoch_are_created_together(client, monkeypatch):
    setup_account(client)
    store = accounts(client)

    def failing(user_id):
        raise RuntimeError("disk full")

    monkeypatch.setattr(store, "new_session_epoch", failing)
    with pytest.raises(RuntimeError):
        store.create("steph", "hash")
    assert store.by_name("steph") is None and store.count() == 1  # no account without its epoch


def test_admin_turns_an_extension_off(client):
    setup_account(client)
    confirm_admin(client)
    post(client, "/admin/extensions/mail", "/admin", enabled="0")
    assert client.app.state.services.settings.disabled_extensions() == {"mail"}
    post(client, "/domains", "/domains", domain="menuiserie-dupont.example")
    page = client.get("/domains/menuiserie-dupont.example").text
    assert "DMARC" not in page
    post(client, "/admin/extensions/mail", "/admin", enabled="1")
    assert client.app.state.services.settings.disabled_extensions() == set()


# ----------------------------------------------------------------- rescue
def test_cli_disables_2fa_and_signs_everyone_out(client, clock, tmp_path, monkeypatch, capsys):
    setup_account(client)
    enable_mfa(client, clock)
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(tmp_path))
    assert cli.main(["disable-totp", "vincent"]) == 0
    assert "disabled" in capsys.readouterr().out
    assert client.get("/domains", follow_redirects=False).headers["location"] == "/login"
    assert log_in(client).headers["location"] == "/domains"
    assert cli.main(["make-admin", "nobody"]) == 1
