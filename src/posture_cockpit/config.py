# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Runtime configuration, read from ``POSTURE_COCKPIT_*`` environment variables."""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass, field
from datetime import tzinfo
from pathlib import Path

from .timezones import UTC, instance_zone

ENV_PREFIX = "POSTURE_COCKPIT_"
DEFAULT_SESSION_COOKIE = "posture_cockpit"
_COOKIE_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
# A setup code chosen by the operator (POSTURE_COCKPIT_SETUP_CODE) has at least this many letters or digits.
MIN_SETUP_CODE = 12


class StartupError(RuntimeError):
    """A problem the operator has to fix before the instance can start. The message says how."""


def _env(name: str, default: str) -> str:
    return os.environ.get(ENV_PREFIX + name, default)


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(ENV_PREFIX + name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    """Settings of one running instance. Tests build it directly."""

    data_dir: Path
    cookie_secure: bool = False
    frame_ancestors: str = "'self'"
    default_locale: str = "fr"
    session_max_age: int = 7 * 24 * 3600
    # Seconds allowed to each check before it is reported as "could not be checked".
    check_timeout: float = 15.0
    # DNS resolvers to query (IP addresses). Empty: those of the system.
    nameservers: list[str] = field(default_factory=list)
    # Internal perimeters (scans of private networks). Off unless the operator turns them on.
    internal_scans: bool = False
    # Scans running at the same time on the instance, and scans per account and per hour.
    max_concurrent_scans: int = 4
    scans_per_hour: int = 30
    # Time zone of pages and reports. Stored times and the API stay in UTC (see timezones.py).
    timezone: tzinfo = UTC
    # Name of the session cookie. Browsers share cookies between the ports of one address:
    # two instances reached at the same address need two names (see docs/user/INSTALLATION.md).
    session_cookie: str = DEFAULT_SESSION_COOKIE
    # One-time code that protects the creation of the first account. Empty: a new random code at
    # each start while no account exists, written to the server log (see web/first_run.py).
    setup_code: str = ""

    def __post_init__(self) -> None:
        check_cookie_name(self.session_cookie, secure=self.cookie_secure)
        if self.setup_code and len(normalize_setup_code(self.setup_code)) < MIN_SETUP_CODE:
            raise ValueError(f"POSTURE_COCKPIT_SETUP_CODE: at least {MIN_SETUP_CODE} letters or digits")

    @property
    def db_path(self) -> Path:
        """One SQLite file holds the accounts and the scan results."""
        return self.data_dir / "posture_cockpit.db"

    @classmethod
    def from_env(cls) -> Config:
        nameservers = [s.strip() for s in _env("NAMESERVERS", "").split(",") if s.strip()]
        config = cls(
            data_dir=Path(_env("DATA_DIR", "./data")),
            cookie_secure=_env_bool("COOKIE_SECURE", False),
            frame_ancestors=_env("FRAME_ANCESTORS", "'self'"),
            default_locale=_env("DEFAULT_LOCALE", "fr"),
            session_max_age=int(_env("SESSION_MAX_AGE", str(7 * 24 * 3600))),
            check_timeout=float(_env("CHECK_TIMEOUT", "15")),
            nameservers=nameservers,
            internal_scans=_env_bool("INTERNAL_SCANS", False),
            max_concurrent_scans=max(1, int(_env("MAX_CONCURRENT_SCANS", "4"))),
            scans_per_hour=max(1, int(_env("SCANS_PER_HOUR", "30"))),
            timezone=instance_zone(os.environ.get(ENV_PREFIX + "TIMEZONE"), os.environ.get("TZ")),
            session_cookie=_env("SESSION_COOKIE", DEFAULT_SESSION_COOKIE).strip(),
            setup_code=_env("SETUP_CODE", "").strip(),
        )
        check_dkim_selectors(_env("DKIM_SELECTORS", ""))
        return config


def check_cookie_name(name: str, *, secure: bool) -> None:
    """Raises ValueError for a cookie name browsers would refuse or mangle.

    Letters, digits, ``_`` and ``-`` only. The ``__Host-`` and ``__Secure-`` prefixes
    make browsers drop the cookie unless it is sent over HTTPS only, so they need
    ``POSTURE_COCKPIT_COOKIE_SECURE=true``."""
    if not _COOKIE_NAME.fullmatch(name):
        raise ValueError(f"POSTURE_COCKPIT_SESSION_COOKIE: {name!r} is not a valid cookie name "
                         "(letters, digits, _ and -, at most 64)")
    if name.lower().startswith(("__host-", "__secure-")) and not secure:
        raise ValueError(f"POSTURE_COCKPIT_SESSION_COOKIE: {name!r} needs POSTURE_COCKPIT_COOKIE_SECURE=true")


def check_dkim_selectors(value: str) -> None:
    """A wrong POSTURE_COCKPIT_DKIM_SELECTORS stops the start, with its reason, rather than
    making the DKIM check fail on every scan (0.3.1). The DKIM check reads the variable itself."""
    from .checks.mail import dkim_selectors  # here: the checks are not needed to read the configuration

    try:
        dkim_selectors(value)
    except ValueError as e:
        raise ValueError(f"POSTURE_COCKPIT_DKIM_SELECTORS: {e}") from None


def normalize_setup_code(code: str) -> str:
    """The letters and digits of a setup code, in capitals: spaces and dashes do not count."""
    return "".join(c for c in code.upper() if c.isalnum())


# Below this length a stored session key is damaged (the key written on first start has 64 characters).
MIN_SECRET_KEY = 32


def prepare_data_dir(data_dir: Path) -> None:
    """Creates the data folder if needed and checks that this account can write in it.

    Raises StartupError with what to do: the usual cause is a folder of the host mounted on
    /data in Docker, which belongs to root while the application runs as uid 10001."""
    try:
        data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)  # an existing folder keeps its rights
        if not data_dir.is_dir():
            raise StartupError(f"The data folder {data_dir} is not a folder.")
        probe = data_dir / f".write-test-{os.getpid()}"
        os.close(os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        probe.unlink()
    except OSError as error:
        raise StartupError(_unwritable(data_dir, error)) from None


def _unwritable(data_dir: Path, error: OSError) -> str:
    account = f"uid {os.getuid()}, gid {os.getgid()}" if hasattr(os, "getuid") else "the current account"
    owner = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else "<account>"
    return (f"The data folder {data_dir} cannot be written by Posture Cockpit ({account}): "
            f"{error.strerror or error}. With Docker, keep the named volume of compose.yaml; a folder of "
            f"the host mounted on /data must belong to that account (chown -R {owner} <folder>). "
            "See docs/user/INSTALLATION.md.")


def secret_key(data_dir: Path) -> str:
    """Key that signs the session cookie, created on first start and kept in the data folder.

    An existing key readable by other accounts is restricted to its owner. An empty or
    truncated key stops the start instead of signing sessions with a weak key."""
    prepare_data_dir(data_dir)
    path = data_dir / ".secret_key"
    try:
        if path.exists():
            key = path.read_text().strip()
            if len(key) < MIN_SECRET_KEY:
                raise StartupError(f"The session key {path} is empty or damaged. Restore it from a backup, "
                                   "or delete it to create a new one (every browser is then signed out).")
            if path.stat().st_mode & 0o077:
                os.chmod(path, 0o600)
            return key
        key = secrets.token_urlsafe(48)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
        return key
    except OSError as error:
        raise StartupError(f"The session key {path} cannot be read or created: {error.strerror or error}. "
                           "It must belong to the account that runs Posture Cockpit.") from None
