# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The user's own settings: password, two-factor authentication, API keys.

Turning two-factor authentication on takes three steps:
1. ``POST /settings/totp/setup`` stores a new secret, not yet active;
2. ``GET /settings/totp`` shows its QR code;
3. ``POST /settings/totp/enable`` checks a first code and the password, turns it
   on and shows the recovery codes, once (only their hashes are kept).
"""

from __future__ import annotations

import segno
from fastapi import APIRouter, Depends, Request
from starlette.datastructures import FormData

from ...security import (
    MIN_PASSWORD_LENGTH,
    hash_password,
    new_recovery_codes,
    new_token,
    new_totp_secret,
    recovery_code_hash,
    token_hash,
    totp_match,
    totp_uri,
)
from ...storage import Row
from ..credentials import check_password_again, check_password_and_code, failed, password_problem, succeeded
from ..deps import (
    audit,
    checked_form,
    field,
    flash,
    redirect,
    render,
    require_user,
    sign_out_other_browsers,
    t,
)
from ..services import services

router = APIRouter()


def settings_page(request: Request, user: Row, status: int = 200, **context):
    s = services(request)
    return render(request, "settings.html", status=status, min_length=MIN_PASSWORD_LENGTH,
                  totp_on=s.accounts.totp_enabled(user["id"]), codes_left=s.accounts.recovery_codes_left(user["id"]),
                  tokens=s.accounts.tokens(user["id"]), **context)


@router.get("/settings")
async def settings(request: Request, user: Row = Depends(require_user)):
    return settings_page(request, user)


@router.post("/settings/password")
async def change_password(request: Request, user: Row = Depends(require_user),
                          form: FormData = Depends(checked_form)):
    new = str(form.get("new", ""))
    problem = (check_password_again(request, user, str(form.get("current", "")))
               or password_problem(new, str(form.get("new2", ""))))
    if problem:
        return settings_page(request, user, status=400, error=t(request, problem, n=MIN_PASSWORD_LENGTH))
    services(request).accounts.set_password(user["id"], hash_password(new))
    sign_out_other_browsers(request, user["id"])
    succeeded(request)
    audit(request, "password.changed", user=user)
    flash(request, "ok", "flash.password_changed")
    return redirect("/settings")


# ------------------------------------------------ two-factor authentication
def totp_setup_page(request: Request, user: Row, status: int = 200, **context):
    row = services(request).accounts.totp(user["id"])
    assert row is not None  # the callers check that a setup is in progress
    secret = row["secret"]
    qr = segno.make(totp_uri(secret, user["username"]), error="m")
    return render(request, "totp_setup.html", status=status,
                  qr=qr.svg_data_uri(scale=5, border=3, dark="#101828", light="#ffffff"),
                  secret_groups=[secret[i:i + 4] for i in range(0, len(secret), 4)], **context)


@router.post("/settings/totp/setup")
async def totp_setup(request: Request, user: Row = Depends(require_user), form: FormData = Depends(checked_form)):
    accounts = services(request).accounts
    if not accounts.totp_enabled(user["id"]):
        accounts.start_totp_setup(user["id"], new_totp_secret())
    return redirect("/settings/totp")


@router.get("/settings/totp")
async def totp_setup_get(request: Request, user: Row = Depends(require_user)):
    row = services(request).accounts.totp(user["id"])
    if row is None or row["enabled_at"]:
        return redirect("/settings#mfa")
    return totp_setup_page(request, user)


@router.post("/settings/totp/enable")
async def totp_enable(request: Request, user: Row = Depends(require_user), form: FormData = Depends(checked_form)):
    s = services(request)
    row = s.accounts.totp(user["id"])
    if row is None or row["enabled_at"]:
        return redirect("/settings#mfa")
    problem = check_password_again(request, user, str(form.get("password", "")))
    step = None if problem else totp_match(row["secret"], field(form, "code", 20), 0)
    if problem or step is None:
        if not problem:
            failed(request, user["username"])
        return totp_setup_page(request, user, status=400, error=t(request, problem or "error.code_setup"))
    codes = new_recovery_codes()
    s.accounts.enable_totp(user["id"], step, [recovery_code_hash(c) for c in codes])
    sign_out_other_browsers(request, user["id"])
    succeeded(request)
    audit(request, "totp.enabled", user=user)
    return render(request, "totp_codes.html", codes=codes, just_enabled=True)


@router.post("/settings/totp/codes")
async def totp_new_codes(request: Request, user: Row = Depends(require_user), form: FormData = Depends(checked_form)):
    s = services(request)
    if not s.accounts.totp_enabled(user["id"]):
        return redirect("/settings#mfa")
    problem = check_password_and_code(request, user, str(form.get("password", "")), field(form, "code", 40))
    if problem:
        return settings_page(request, user, status=400, error=t(request, problem))
    codes = new_recovery_codes()
    s.accounts.replace_recovery_codes(user["id"], [recovery_code_hash(c) for c in codes])
    succeeded(request)
    audit(request, "totp.codes_renewed", user=user)
    return render(request, "totp_codes.html", codes=codes, just_enabled=False)


@router.post("/settings/totp/disable")
async def totp_disable(request: Request, user: Row = Depends(require_user), form: FormData = Depends(checked_form)):
    s = services(request)
    if s.accounts.totp(user["id"]) is None:
        return redirect("/settings#mfa")
    if not s.accounts.totp_enabled(user["id"]):  # setup abandoned before the first code
        s.accounts.disable_totp(user["id"])
        return redirect("/settings#mfa")
    problem = check_password_and_code(request, user, str(form.get("password", "")), field(form, "code", 40))
    if problem:
        return settings_page(request, user, status=400, error=t(request, problem))
    s.accounts.disable_totp(user["id"])
    sign_out_other_browsers(request, user["id"])
    succeeded(request)
    audit(request, "totp.disabled", user=user)
    flash(request, "ok", "flash.totp_disabled")
    return redirect("/settings#mfa")


# ----------------------------------------------------------------- API keys
@router.post("/settings/token")
async def add_token(request: Request, user: Row = Depends(require_user), form: FormData = Depends(checked_form)):
    name = field(form, "name", 60) or "Home Assistant"
    token = new_token()
    services(request).accounts.add_token(user["id"], name, token_hash(token))
    audit(request, "token.created", user=user, target=name)
    # Shown once, in this response only: never stored in clear, never put in the cookie.
    return settings_page(request, user, new_token=token, new_token_name=name)


@router.post("/settings/token/{token_id}/revoke")
async def revoke_token(request: Request, token_id: int, user: Row = Depends(require_user),
                       form: FormData = Depends(checked_form)):
    services(request).accounts.revoke_token(user["id"], token_id)
    audit(request, "token.revoked", user=user, token_id=token_id)
    flash(request, "ok", "flash.token_revoked")
    return redirect("/settings#api")
