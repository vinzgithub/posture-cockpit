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

    def __post_init__(self) -> None:
        check_cookie_name(self.session_cookie, secure=self.cookie_secure)

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


def secret_key(data_dir: Path) -> str:
    """Key that signs the session cookie, created on first start and kept in the data folder."""
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)  # an existing folder keeps its rights
    path = data_dir / ".secret_key"
    if path.exists():
        return path.read_text().strip()
    key = secrets.token_urlsafe(48)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    return key
