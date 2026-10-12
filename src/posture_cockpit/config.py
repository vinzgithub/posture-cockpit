# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Runtime configuration, read from ``POSTURE_COCKPIT_*`` environment variables."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

ENV_PREFIX = "POSTURE_COCKPIT_"


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

    @property
    def db_path(self) -> Path:
        """One SQLite file holds the accounts and the scan results."""
        return self.data_dir / "posture_cockpit.db"

    @classmethod
    def from_env(cls) -> Config:
        nameservers = [s.strip() for s in _env("NAMESERVERS", "").split(",") if s.strip()]
        return cls(
            data_dir=Path(_env("DATA_DIR", "./data")),
            cookie_secure=_env_bool("COOKIE_SECURE", False),
            frame_ancestors=_env("FRAME_ANCESTORS", "'self'"),
            default_locale=_env("DEFAULT_LOCALE", "fr"),
            session_max_age=int(_env("SESSION_MAX_AGE", str(7 * 24 * 3600))),
            check_timeout=float(_env("CHECK_TIMEOUT", "15")),
            nameservers=nameservers,
        )


def secret_key(data_dir: Path) -> str:
    """Key that signs the session cookie, created on first start and kept in the data folder."""
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / ".secret_key"
    if path.exists():
        return path.read_text().strip()
    key = secrets.token_urlsafe(48)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    return key
