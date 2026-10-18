# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Administration: accounts, extensions, report signature, audit log.

The pages ask for the administrator's password again every ten minutes
(``/admin/confirm``), so a browser left open is not enough to create an account
or turn off two-factor authentication for someone. Every change made here is
written to the audit log. Internal perimeters have their own module
(perimeters.py) and a section of the main page.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from starlette.datastructures import FormData
from starlette.exceptions import HTTPException

from ...i18n import LOCALES
from ...security import MIN_PASSWORD_LENGTH, hash_password
from ...storage import Row
from ..credentials import check_password_again, password_problem, succeeded
from ..deps import (
    ADMIN_CONFIRM_SECONDS,
    audit,
    checked_form,
    field,
    flash,
    lang_of,
    redirect,
    render,
    require_admin,
    require_admin_unconfirmed,
    t,
)
from ..scheduler import status as scheduler_status
from ..services import services

router = APIRouter(prefix="/admin")


@router.get("/confirm")
async def confirm_page(request: Request, user: Row = Depends(require_admin_unconfirmed)):
    return render(request, "admin_confirm.html")


@router.post("/confirm")
async def confirm(request: Request, user: Row = Depends(require_admin_unconfirmed),
                  form: FormData = Depends(checked_form)):
    problem = check_password_again(request, user, str(form.get("password", "")))
    if problem:
        audit(request, "confirm.failed", user=user)
        return render(request, "admin_confirm.html", status=400, error=t(request, problem))
    succeeded(request)
    request.session["admin_until"] = int(time.time()) + ADMIN_CONFIRM_SECONDS
    return redirect("/admin")


def admin_page(request: Request, me: Row, status: int = 200, **context):
    s = services(request)
    disabled = s.settings.disabled_extensions()
    lang = lang_of(request)

    def label(extension, part: str, default: str) -> str:
        # An extension may translate its name and description; otherwise its own wording is shown.
        key = f"{extension.id}.extension.{part}"
        return s.catalog.text(lang, key) if s.catalog.has(lang, key) else default

    extensions = [{"ext": e, "enabled": e.id not in disabled, "name": label(e, "name", e.name),
                   "description": label(e, "description", e.description)} for e in s.registry.extensions]
    return render(request, "admin.html", status=status, me=me, users=s.accounts.all(), extensions=extensions,
                  load_errors=s.registry.errors, report_author=s.settings.report_author(),
                  min_length=MIN_PASSWORD_LENGTH, perimeters=s.perimeters.all(),
                  internal_enabled=s.config.internal_scans, audit_entries=s.audit.latest(8),
                  scheduler=scheduler_status(s, getattr(request.app.state, 'scheduler', None), datetime.now(UTC)),
                  upcoming=s.schedules.upcoming(10), run_problems=s.schedules.runs(limit=10, not_done=True), **context)


@router.get("")
async def admin_home(request: Request, me: Row = Depends(require_admin)):
    return admin_page(request, me)


# ------------------------------------------------------------------ accounts
@router.post("/users")
async def create_user(request: Request, me: Row = Depends(require_admin), form: FormData = Depends(checked_form)):
    s = services(request)
    username, password = field(form, "username", 41), str(form.get("password", ""))
    lang = field(form, "lang") if field(form, "lang") in LOCALES else lang_of(request)
    problem: str | None
    if not 1 <= len(username) <= 40:
        problem = "error.username"
    elif s.accounts.name_taken(username):
        problem = "error.username_taken"
    else:
        problem = password_problem(password, str(form.get("password2", "")))
    if problem:
        return admin_page(request, me, status=400, error=t(request, problem, n=MIN_PASSWORD_LENGTH),
                          draft={"username": username, "lang": lang, "is_admin": bool(form.get("is_admin"))})
    # The new user chooses their own password at first sign-in.
    s.accounts.create(username, hash_password(password), is_admin=bool(form.get("is_admin")),
                      must_change_password=True, lang=lang)
    audit(request, "user.created", user=me, target=username, admin=bool(form.get("is_admin")))
    flash(request, "ok", "flash.user_created", name=username)
    return redirect("/admin")


def target_user(request: Request, me: Row, user_id: int, allow_self: bool = False) -> Row:
    target = services(request).accounts.get(user_id)
    if target is None:
        raise HTTPException(404)
    if target["id"] == me["id"] and not allow_self:
        raise HTTPException(400)  # use the settings page for your own account
    return target


def user_page(request: Request, me: Row, target: Row, status: int = 200, **context):
    return render(request, "admin_user.html", status=status, me=me, target=target,
                  totp_on=services(request).accounts.totp_enabled(target["id"]), min_length=MIN_PASSWORD_LENGTH,
                  **context)


@router.get("/users/{user_id}")
async def user_detail(request: Request, user_id: int, me: Row = Depends(require_admin)):
    return user_page(request, me, target_user(request, me, user_id, allow_self=True))


@router.post("/users/{user_id}/password")
async def reset_password(request: Request, user_id: int, me: Row = Depends(require_admin),
                         form: FormData = Depends(checked_form)):
    s = services(request)
    target = target_user(request, me, user_id)
    password = str(form.get("password", ""))
    problem = password_problem(password, str(form.get("password2", "")))
    if problem:
        return user_page(request, me, target, status=400, error=t(request, problem, n=MIN_PASSWORD_LENGTH))
    s.accounts.set_password(user_id, hash_password(password), must_change=True)
    s.accounts.new_session_epoch(user_id)
    audit(request, "user.password_reset", user=me, target=target["username"])
    flash(request, "ok", "flash.user_password_reset", name=target["username"])
    return redirect(f"/admin/users/{user_id}")


@router.post("/users/{user_id}/totp-off")
async def totp_off(request: Request, user_id: int, me: Row = Depends(require_admin),
                   form: FormData = Depends(checked_form)):
    s = services(request)
    target = target_user(request, me, user_id)
    s.accounts.disable_totp(user_id)
    s.accounts.new_session_epoch(user_id)
    audit(request, "user.totp_off", user=me, target=target["username"])
    flash(request, "ok", "flash.user_totp_off", name=target["username"])
    return redirect(f"/admin/users/{user_id}")


@router.post("/users/{user_id}/role")
async def toggle_admin(request: Request, user_id: int, me: Row = Depends(require_admin),
                       form: FormData = Depends(checked_form)):
    target = target_user(request, me, user_id)
    services(request).accounts.set_admin(user_id, not target["is_admin"])
    audit(request, "user.role", user=me, target=target["username"], admin=not target["is_admin"])
    flash(request, "ok", "flash.user_admin_off" if target["is_admin"] else "flash.user_admin_on",
          name=target["username"])
    return redirect(f"/admin/users/{user_id}")


@router.post("/users/{user_id}/delete")
async def delete_user(request: Request, user_id: int, me: Row = Depends(require_admin),
                      form: FormData = Depends(checked_form)):
    target = target_user(request, me, user_id)
    if field(form, "confirm", 41) != target["username"]:
        return user_page(request, me, target, status=400, error=t(request, "error.confirm_username"))
    services(request).accounts.delete(user_id)
    audit(request, "user.deleted", user=me, target=target["username"])
    flash(request, "ok", "flash.user_deleted", name=target["username"])
    return redirect("/admin")


# ---------------------------------------------------------------- extensions
@router.post("/extensions/{extension_id}")
async def toggle_extension(request: Request, extension_id: str, me: Row = Depends(require_admin),
                           form: FormData = Depends(checked_form)):
    s = services(request)
    if extension_id not in {e.id for e in s.registry.extensions}:
        raise HTTPException(404)
    enable = form.get("enabled") == "1"
    s.settings.set_extension_enabled(extension_id, enable)
    audit(request, "extension.enabled" if enable else "extension.disabled", user=me, target=extension_id)
    flash(request, "ok", "flash.extension_on" if enable else "flash.extension_off", name=extension_id)
    return redirect("/admin#extensions")


# -------------------------------------------------------------------- report
@router.post("/report")
async def report_author(request: Request, me: Row = Depends(require_admin), form: FormData = Depends(checked_form)):
    services(request).settings.set_report_author(field(form, "author", 80))
    audit(request, "report.author", user=me)
    flash(request, "ok", "flash.saved")
    return redirect("/admin#report")


# ----------------------------------------------------------------- audit log
@router.get("/audit")
async def audit_log(request: Request, me: Row = Depends(require_admin), action: str = ""):
    """The latest entries of the audit log, optionally those whose action starts with ``action``."""
    entries = services(request).audit.latest(500, action_prefix=action[:40])
    return render(request, "admin_audit.html", entries=entries, action=action[:40])
