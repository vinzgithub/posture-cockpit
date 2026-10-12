# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""First run, sign-in (password, then authenticator code), sign-out, language.

Sign-in with two-factor authentication happens in two steps. After the right
password the session only holds ``mfa_uid`` (nothing is open yet); the user
is signed in once the code is checked, within MFA_PENDING_SECONDS.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Request
from starlette.datastructures import FormData

from ...i18n import LOCALES
from ...scanner import DEMO_DOMAIN
from ...security import MIN_PASSWORD_LENGTH, hash_password, verify_password
from ...storage import Row
from ..credentials import check_second_factor, password_problem
from ..deps import (
    checked_form,
    client_key,
    field,
    flash,
    lang_of,
    pending_login,
    redirect,
    render,
    require_user,
    require_user_any_password,
    sign_in,
    sign_out_other_browsers,
    t,
)
from ..scanning import scan_and_save
from ..services import services

router = APIRouter()


# ----------------------------------------------------------------- first run
@router.get("/")
async def index(request: Request, user: Row = Depends(require_user)):
    return redirect("/domains")


@router.get("/setup")
async def setup_page(request: Request):
    if services(request).accounts.count() > 0:
        return redirect("/login")
    return render(request, "setup.html", min_length=MIN_PASSWORD_LENGTH)


@router.post("/setup")
async def setup(request: Request, form: FormData = Depends(checked_form)):
    s = services(request)
    if s.accounts.count() > 0:
        return redirect("/login")
    username, password = field(form, "username", 41), str(form.get("password", ""))
    lang = field(form, "lang")
    request.session["lang"] = lang if lang in LOCALES else "fr"
    problem = ("error.username" if not 1 <= len(username) <= 40
               else password_problem(password, str(form.get("password2", ""))))
    if problem:
        return render(request, "setup.html", status=400, min_length=MIN_PASSWORD_LENGTH, username=username,
                      error=t(request, problem, n=MIN_PASSWORD_LENGTH))
    # The first account administers the others.
    uid = s.accounts.create(username, hash_password(password), is_admin=True, lang=lang_of(request))
    user = s.accounts.get(uid)
    assert user is not None
    sign_in(request, user)
    if form.get("demo"):
        await scan_and_save(s, DEMO_DOMAIN, uid)
        return redirect(f"/domains/{DEMO_DOMAIN}")
    flash(request, "info", "flash.welcome")
    return redirect("/domains")


# -------------------------------------------------------------------- sign-in
@router.get("/login")
async def login_page(request: Request):
    if services(request).accounts.count() == 0:
        return redirect("/setup")
    return render(request, "login.html")


@router.post("/login")
async def login(request: Request, form: FormData = Depends(checked_form)):
    s = services(request)
    key = client_key(request)
    if s.throttle.locked(key):
        return render(request, "login.html", status=429, error=t(request, "error.locked"))
    user = s.accounts.by_name(field(form, "username", 41))
    if user is None or not verify_password(str(form.get("password", "")), user["pw_hash"]):
        s.throttle.failure(key)
        return render(request, "login.html", status=401, error=t(request, "error.login"))
    if s.accounts.totp_enabled(user["id"]):
        # The code comes next. The throttle is not reset here: wrong codes and wrong
        # passwords add up, so typing the password again gives no extra tries.
        lang = lang_of(request)
        request.session.clear()
        request.session.update({"mfa_uid": user["id"], "mfa_at": int(time.time()), "lang": lang})
        return redirect("/login/code")
    s.throttle.success(key)
    sign_in(request, user)
    return redirect("/domains")


@router.get("/login/code")
async def login_code_page(request: Request):
    if pending_login(request) is None:
        return redirect("/login")
    return render(request, "login_code.html")


@router.post("/login/code")
async def login_code(request: Request, form: FormData = Depends(checked_form)):
    s = services(request)
    key = client_key(request)
    user = pending_login(request)
    if user is None:
        request.session.pop("mfa_uid", None)
        flash(request, "error", "error.code_expired")
        return redirect("/login")
    if s.throttle.locked(key):
        return render(request, "login_code.html", status=429, error=t(request, "error.locked"))
    used = check_second_factor(s, user["id"], field(form, "code", 40))
    if used is None:
        s.throttle.failure(key)
        return render(request, "login_code.html", status=401, error=t(request, "error.code"))
    s.throttle.success(key)
    sign_in(request, user)
    if used == "recovery":
        flash(request, "warn", "flash.recovery_used", n=s.accounts.recovery_codes_left(user["id"]))
    return redirect("/domains")


@router.post("/logout")
async def logout(request: Request, form: FormData = Depends(checked_form)):
    lang = lang_of(request)
    request.session.clear()
    request.session["lang"] = lang
    return redirect("/login")


@router.post("/lang")
async def set_lang(request: Request, form: FormData = Depends(checked_form)):
    lang = field(form, "lang")
    if lang in LOCALES:
        request.session["lang"] = lang
        uid = request.session.get("uid")
        if uid:
            services(request).accounts.set_lang(uid, lang)
    back = field(form, "back", 300)
    return redirect(back if back.startswith("/") and not back.startswith("//") else "/domains")


# ------------------------------------------------- password chosen by an admin
@router.get("/account/password")
async def must_change_page(request: Request, user: Row = Depends(require_user_any_password)):
    if not user["must_change_password"]:
        return redirect("/domains")
    return render(request, "account_password.html", min_length=MIN_PASSWORD_LENGTH)


@router.post("/account/password")
async def must_change(request: Request, user: Row = Depends(require_user_any_password),
                      form: FormData = Depends(checked_form)):
    if not user["must_change_password"]:
        return redirect("/domains")
    new = str(form.get("new", ""))
    problem = password_problem(new, str(form.get("new2", "")))
    if problem is None and verify_password(new, user["pw_hash"]):
        problem = "error.password_same"
    if problem:
        return render(request, "account_password.html", status=400, min_length=MIN_PASSWORD_LENGTH,
                      error=t(request, problem, n=MIN_PASSWORD_LENGTH))
    services(request).accounts.set_password(user["id"], hash_password(new), must_change=False)
    sign_out_other_browsers(request, user["id"])
    flash(request, "ok", "flash.password_set")
    return redirect("/domains")
