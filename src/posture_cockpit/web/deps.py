# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""What routes have in common: who is signed in, CSRF-checked forms, page rendering.

Access rules are FastAPI dependencies that raise an exception when they are
not met; :mod:`.app` turns each exception into the right redirect::

    @router.get("/settings")
    async def settings_page(request: Request, user: Row = Depends(require_user)): ...

    @router.post("/settings/password")
    async def change_password(request: Request, user: Row = Depends(require_user),
                              form: FormData = Depends(checked_form)): ...
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.datastructures import FormData
from starlette.exceptions import HTTPException

from .. import __version__
from ..i18n import LOCALES, fmt_date, pick_locale
from ..security import csrf_token, csrf_valid
from ..storage import Row
from .services import services

# Time allowed between the right password and the authenticator code.
MFA_PENDING_SECONDS = 300
# After an administrator types the password again, the admin pages stay open this long.
ADMIN_CONFIRM_SECONDS = 600


class NeedSetup(Exception):
    """No account exists yet: go to the first-run page."""


class NeedLogin(Exception):
    """Nobody is signed in."""


class NeedPasswordChange(Exception):
    """An administrator set this user's password: they must choose their own first."""


class NeedAdminConfirm(Exception):
    """Admin pages need the password again every ADMIN_CONFIRM_SECONDS."""


class CsrfError(Exception):
    """The form did not carry this session's CSRF token."""


# ----------------------------------------------------------------- the user
def current_user(request: Request) -> Row | None:
    """The signed-in user, or None. A stale session epoch (password or 2FA changed
    from another browser) counts as signed out."""
    uid = request.session.get("uid")
    if not uid:
        return None
    accounts = services(request).accounts
    if request.session.get("epoch", "0") != accounts.session_epoch(uid):
        return None
    return accounts.get(uid)


def sign_in(request: Request, user: Row) -> None:
    request.session.clear()  # a new session id-wise: nothing from before the login survives
    request.session["uid"] = user["id"]
    request.session["epoch"] = services(request).accounts.session_epoch(user["id"])
    request.session["lang"] = user["lang"]


def sign_out_other_browsers(request: Request, user_id: int) -> None:
    request.session["epoch"] = services(request).accounts.new_session_epoch(user_id)


def pending_login(request: Request) -> Row | None:
    """The user who typed the right password and still has to give a code."""
    uid = request.session.get("mfa_uid")
    started = request.session.get("mfa_at", 0)
    if not uid or not 0 <= time.time() - started <= MFA_PENDING_SECONDS:
        return None
    return services(request).accounts.get(uid)


def client_key(request: Request) -> str:
    """What the login throttle counts failures by: the client's address."""
    return request.client.host if request.client else "unknown"


def require_user(request: Request) -> Row:
    if services(request).accounts.count() == 0:
        raise NeedSetup()
    user = current_user(request)
    if user is None:
        raise NeedLogin()
    if user["must_change_password"]:
        raise NeedPasswordChange()
    return user


def require_user_any_password(request: Request) -> Row:
    """Like require_user, but also for users who must still choose their password."""
    if services(request).accounts.count() == 0:
        raise NeedSetup()
    user = current_user(request)
    if user is None:
        raise NeedLogin()
    return user


def require_admin_unconfirmed(request: Request) -> Row:
    user = require_user(request)
    if not user["is_admin"]:
        raise HTTPException(403)
    return user


def require_admin(request: Request) -> Row:
    user = require_admin_unconfirmed(request)
    if request.session.get("admin_until", 0) < time.time():
        raise NeedAdminConfirm()
    return user


def visible_domain(request: Request, name: str, user: Row) -> Row:
    """The domain ``name`` if ``user`` may see it, otherwise a 404.

    The domains of internal perimeters are for administrators only: for anyone
    else they do not exist (the same answer as for an unknown name)."""
    row = services(request).scans.domain(name)
    if row is None or (row["perimeter_id"] is not None and not user["is_admin"]):
        raise HTTPException(404)
    return row


# --------------------------------------------------------------------- audit
def audit(request: Request, action: str, /, *, user: Row | None = None, target: str = "", **detail: Any) -> None:
    """Writes an entry in the audit log, with the address of the client. Never pass a secret."""
    services(request).audit.record(action, user=user, target=target, client=client_key(request), **detail)


# -------------------------------------------------------------------- forms
async def checked_form(request: Request) -> FormData:
    """The submitted form, once its CSRF token is checked (the X-CSRF-Token header also works)."""
    form = await request.form()
    provided = request.headers.get("x-csrf-token") or form.get("csrf")
    if not csrf_valid(request.session, provided if isinstance(provided, str) else None):
        raise CsrfError()
    return form


def field(form: FormData, name: str, max_length: int = 200) -> str:
    value = form.get(name, "")
    return value.strip()[:max_length] if isinstance(value, str) else ""


# ----------------------------------------------------------------- language
def lang_of(request: Request) -> str:
    lang = request.session.get("lang")
    if lang in LOCALES:
        return lang
    return pick_locale(request.headers.get("accept-language"), services(request).config.default_locale)


def t(request: Request, key: str, /, **params: Any) -> str:
    return services(request).catalog.text(lang_of(request), key, params)


# ---------------------------------------------------------------- rendering
def flash(request: Request, level: str, key: str, **params: Any) -> None:
    """A message shown once on the next page. ``level``: ok, info, warn or error."""
    request.session.setdefault("flash", []).append([level, key, {k: str(v) for k, v in params.items()}])


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def render(request: Request, template: str, status: int = 200, **context: Any) -> HTMLResponse:
    s = services(request)
    lang = lang_of(request)
    catalog = s.catalog

    def text(key: str, /, **params: Any) -> str:
        return catalog.text(lang, key, params)

    base = {
        "lang": lang,
        "user": current_user(request),
        "version": __version__,
        "csrf": csrf_token(request.session),
        "flashes": request.session.pop("flash", []),
        "t": text,
        "date": lambda value: fmt_date(str(value)[:10], lang) if value else "",
        "path": request.url.path,
    }
    return s.templates.TemplateResponse(request, template, {**base, **context}, status_code=status)
