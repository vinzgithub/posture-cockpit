# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Checks on passwords and codes, shared by the sign-in, settings and admin pages.

Every failed check counts in the login throttles (by client address and by
account name), so the settings pages cannot be used to guess a password or a
code either.
"""

from __future__ import annotations

from fastapi import Request

from ..security import MIN_PASSWORD_LENGTH, LoginThrottle, is_totp_code, recovery_code_hash, totp_match, verify_password
from ..storage import Row
from .deps import client_key
from .services import Services, services


def password_problem(password: str, again: str) -> str | None:
    """Translation key of what is wrong with a new password, or None."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return "error.password_short"
    if password != again:
        return "error.password_mismatch"
    return None


def check_second_factor(s: Services, user_id: int, code: str) -> str | None:
    """``"totp"`` or ``"recovery"`` when ``code`` is valid (it is then used up), else None."""
    row = s.accounts.totp(user_id)
    if row is None or not row["enabled_at"]:
        return None
    if is_totp_code(code):
        step = totp_match(row["secret"], code, row["last_step"])
        if step is None:
            return None
        s.accounts.set_totp_last_step(user_id, step)
        return "totp"
    if code.strip() and s.accounts.use_recovery_code(user_id, recovery_code_hash(code)):
        return "recovery"
    return None


def _counters(request: Request, username: str) -> list[tuple[LoginThrottle, str]]:
    s = services(request)
    counters = [(s.throttle, client_key(request))]
    if username:
        counters.append((s.account_throttle, username.strip().lower()[:41]))
    return counters


def throttled(request: Request, username: str = "") -> bool:
    """Whether attempts are refused for now, from this address or for this account."""
    return any(throttle.locked(key) for throttle, key in _counters(request, username))


def failed(request: Request, username: str = "") -> None:
    """A wrong password or code: it counts for the address and for the account."""
    for throttle, key in _counters(request, username):
        throttle.failure(key)


def check_password_again(request: Request, user: Row, password: str) -> str | None:
    """For sensitive changes: the current password, typed again. Translation key of the error, or None."""
    if throttled(request, user["username"]):
        return "error.locked"
    if not verify_password(password, user["pw_hash"]):
        failed(request, user["username"])
        return "error.password_current"
    return None


def check_password_and_code(request: Request, user: Row, password: str, code: str) -> str | None:
    """Both the password and a code (authenticator or recovery), to change two-factor settings."""
    problem = check_password_again(request, user, password)
    if problem:
        return problem
    if check_second_factor(services(request), user["id"], code) is None:
        failed(request, user["username"])
        return "error.code"
    return None


def succeeded(request: Request, username: str = "") -> None:
    """A sensitive action went through: forget the failures of this address (and of this account)."""
    for throttle, key in _counters(request, username):
        throttle.success(key)
