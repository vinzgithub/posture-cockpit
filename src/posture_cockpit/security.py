# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Security primitives of the web interface, using the standard library only.

- passwords: scrypt hashes;
- two-factor authentication: TOTP codes (RFC 6238) and single-use recovery codes;
- API keys: random tokens stored as SHA-256 hashes;
- CSRF tokens kept in the signed session cookie;
- a login throttle shared by wrong passwords and wrong codes, counted by
  client address and by account name.

Nothing here knows about the database or the web framework, so each piece can be
tested on its own (see tests/test_security.py).
"""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import re
import secrets
import struct
import time
from threading import Lock
from urllib.parse import quote, urlencode

MIN_PASSWORD_LENGTH = 10
_SCRYPT = {"n": 2**14, "r": 8, "p": 1}

# TOTP parameters supported by every authenticator app.
TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1  # also accept the previous and the next code (phone clock drift)
TOTP_ISSUER = "Posture Cockpit"

RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o or 1/l/i, which are easily confused


# ---------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    """Salted scrypt hash, stored as ``scrypt$n$r$p$salt$digest``."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${salt.hex()}${digest.hex()}"


@functools.cache
def dummy_password_hash() -> str:
    """A hash no password matches, for unknown account names: checking it takes as long as a real
    check, so the response time does not tell which accounts exist."""
    return hash_password(secrets.token_urlsafe(32))


def verify_password(password: str, stored: str) -> bool:
    """True when ``password`` matches a hash made by :func:`hash_password`."""
    try:
        algo, n, r, p, salt_hex, digest_hex = stored.split("$")
        if algo != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), dklen=32,
                                n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


# ----------------------------------------------------------------- API keys
def new_token() -> str:
    """A new API key, shown once to the user and then only kept as a hash."""
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --------------------------------------------------------------------- TOTP
def new_totp_secret() -> str:
    """160 random bits in base32 without padding, the form authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _b32decode(secret: str) -> bytes:
    s = secret.upper().replace(" ", "")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def totp_at(secret: str, step: int, digits: int = TOTP_DIGITS, digest: str = "sha1") -> str:
    """The code of one time step: an RFC 4226 HOTP code with the step as counter (RFC 6238)."""
    mac = hmac.new(_b32decode(secret), struct.pack(">Q", step), digest).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def totp_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // TOTP_PERIOD)


def is_totp_code(code: str) -> bool:
    return bool(re.fullmatch(rf"\d{{{TOTP_DIGITS}}}", re.sub(r"\s", "", code or "")))


def totp_match(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """The time step ``code`` belongs to, or None.

    Steps at or before ``last_step`` are refused: once a code has been used,
    neither it nor an older one works again (no replay)."""
    if not is_totp_code(code):
        return None
    code = re.sub(r"\s", "", code)
    current = totp_step(now)
    found = None
    for step in range(current - TOTP_WINDOW, current + TOTP_WINDOW + 1):
        if hmac.compare_digest(totp_at(secret, step), code) and step > last_step:
            found = step
    return found


def totp_uri(secret: str, account: str) -> str:
    """The otpauth:// link encoded in the QR code shown during setup."""
    label = quote(f"{TOTP_ISSUER}:{account}", safe="")
    query = urlencode({"secret": secret, "issuer": TOTP_ISSUER, "algorithm": "SHA1",
                       "digits": TOTP_DIGITS, "period": TOTP_PERIOD}, quote_via=quote)
    return f"otpauth://totp/{label}?{query}"


def new_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Single-use codes like ``k7m2q-x9fhr`` (about 50 bits each)."""
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def recovery_code_hash(code: str) -> str:
    """Hash of a recovery code; case, spaces and dashes do not matter."""
    normalized = re.sub(r"[^a-z0-9]", "", (code or "").lower())
    return hashlib.sha256(normalized.encode()).hexdigest()


# --------------------------------------------------------------------- CSRF
def csrf_token(session: dict) -> str:
    """The CSRF token of this session, created on first use."""
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


def csrf_valid(session: dict, provided: str | None) -> bool:
    expected = session.get("csrf")
    return bool(expected and provided and hmac.compare_digest(expected, provided))


# ----------------------------------------------------------------- throttle
class LoginThrottle:
    """After ``max_failures`` failures for one key, refuse attempts for ``lock_seconds``.

    The web interface keeps two: one by client address, one by account name
    (so that guesses spread over many addresses still stop). Kept in memory: a
    restart clears it. Wrong passwords and wrong codes share the same
    counters, so typing the right password again gives no extra tries."""

    MAX_KEYS = 10_000  # beyond, expired entries are dropped (names typed at random must not fill memory)

    def __init__(self, max_failures: int = 5, lock_seconds: int = 300):
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self._state: dict[str, tuple[int, float]] = {}
        self._lock = Lock()

    def locked(self, key: str) -> bool:
        with self._lock:
            failures, until = self._state.get(key, (0, 0.0))
            return failures >= self.max_failures and time.monotonic() < until

    def failure(self, key: str) -> None:
        with self._lock:
            failures, until = self._state.get(key, (0, 0.0))
            if failures >= self.max_failures and time.monotonic() >= until:
                failures = 0  # the previous lock has expired: start counting again
            failures += 1
            self._state[key] = (failures, time.monotonic() + self.lock_seconds)
            if len(self._state) > self.MAX_KEYS:
                now = time.monotonic()
                self._state = {k: v for k, v in self._state.items() if v[1] > now}

    def success(self, key: str) -> None:
        with self._lock:
            self._state.pop(key, None)
