# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The SQLite database: one connection, transactions, and schema migrations.

The repositories (:class:`~.accounts.Accounts`, :class:`~.scans.Scans`) hold the
queries; this class only owns the connection. SQLite runs in WAL mode so pages
can read while a scan is being saved.

Migrations: :data:`~.schema.MIGRATIONS` is a list of SQL scripts. The database
remembers how many it has applied (``meta.schema_version``) and applies the
next ones at start-up, each in its own transaction. To change the schema,
*append* a script; never edit one that has been released.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any

from .schema import MIGRATIONS

Row = sqlite3.Row


def utcnow() -> str:
    """Current time as stored in the database: ISO 8601, UTC, to the second."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class Database:
    def __init__(self, path: Path, migrations: Sequence[str] = MIGRATIONS):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self._migrate(migrations)

    def close(self) -> None:
        self._conn.close()

    # ---------------------------------------------------------------- queries
    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def executemany(self, sql: str, rows: Sequence[Sequence[Any]]) -> None:
        with self._lock:
            self._conn.executemany(sql, rows)

    def all(self, sql: str, params: Sequence[Any] = ()) -> list[Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: Sequence[Any] = ()) -> Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def value(self, sql: str, params: Sequence[Any] = ()) -> Any:
        row = self.one(sql, params)
        return row[0] if row else None

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Everything inside happens, or nothing does."""
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                yield
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    # ------------------------------------------------------------------- meta
    def get_meta(self, key: str) -> str | None:
        return self.value("SELECT value FROM meta WHERE key = ?", (key,))

    def set_meta(self, key: str, value: str) -> None:
        self.execute("INSERT INTO meta(key, value) VALUES(?, ?) "
                     "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    def delete_meta(self, key: str) -> None:
        self.execute("DELETE FROM meta WHERE key = ?", (key,))

    # ------------------------------------------------------------- migrations
    @property
    def schema_version(self) -> int:
        return int(self.get_meta("schema_version") or 0)

    def _migrate(self, migrations: Sequence[str]) -> None:
        for version in range(self.schema_version + 1, len(migrations) + 1):
            script = migrations[version - 1]
            with self._lock:
                try:
                    # executescript() runs several statements; BEGIN/COMMIT make them one transaction.
                    self._conn.executescript(
                        f"BEGIN;\n{script.strip().rstrip(';')};\n"
                        f"INSERT INTO meta(key, value) VALUES('schema_version', '{version}') "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value;\nCOMMIT;")
                except sqlite3.Error:
                    if self._conn.in_transaction:
                        self._conn.execute("ROLLBACK")
                    raise
