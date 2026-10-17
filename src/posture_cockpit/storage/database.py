# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The SQLite database: one connection, transactions, and schema migrations.

The repositories (:class:`~.accounts.Accounts`, :class:`~.scans.Scans`) hold the
queries; this class only owns the connection. SQLite runs in WAL mode so pages
can read while a scan is being saved.

Migrations: :data:`~.schema.MIGRATIONS` is a list of SQL scripts, or Python
functions for changes SQL alone cannot make (recomputing values). The database
remembers how many it has applied (``meta.schema_version``) and applies the
next ones at start-up, each in its own transaction. To change the schema,
*append* a migration; never edit one that has been released.

Before migrating a database that already holds data, a copy of it is written
to ``backups/`` next to it. While migrating, foreign keys are switched off (the
procedure SQLite documents for rebuilding a table: otherwise dropping the old
table would delete the rows that refer to it) and checked again before each
commit. The database file is readable by its owner only.

A database whose schema is newer than the migrations this version knows (written by a
later release) is refused at start-up and left untouched: running on it could damage it.

One owner per transaction (0.5.0). The connection is shared by the whole process, and its lock
lets the thread that holds it in again: every asyncio task runs on that same thread. A task that
waited (``await``) inside a transaction would let another task's statements join it, and roll back
with it, without either of them knowing. So a transaction remembers the thread and the task that
opened it, and any use of the connection by another one while it is open raises
:class:`TransactionOwnerError` instead. Another *thread* simply waits for the lock, as before.
The rule it enforces: no ``await`` inside ``with db.transaction():`` (tests/test_v050_contract.py
checks the code for it).
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any

from ..config import StartupError
from .schema import MIGRATIONS, Migration

Row = sqlite3.Row


class UnsupportedSchema(StartupError):
    """The database was written by a version of Posture Cockpit this one does not know."""

    def __init__(self, path: Path, found: int, known: int):
        self.found, self.known = found, known
        super().__init__(
            f"The database {path} uses schema {found}; this version of Posture Cockpit handles schema {known} "
            "at most. It was written by a newer version: run that version again, or restore the backup "
            "made before the update (see docs/user/INSTALLATION.md, Rollback). Nothing was changed.")


class TransactionOwnerError(RuntimeError):
    """The connection was used by another task or thread while a transaction was open."""


def _current_owner() -> tuple[int, asyncio.Task[Any] | None]:
    """The thread, and the asyncio task when there is one, that uses the connection now."""
    try:
        task = asyncio.current_task()
    except RuntimeError:  # no event loop in this thread
        task = None
    return threading.get_ident(), task


def utcnow() -> str:
    """Current time as stored in the database: ISO 8601, UTC, to the second."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class Database:
    def __init__(self, path: Path, migrations: Sequence[Migration] = MIGRATIONS):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = RLock()
        self._depth = 0  # transactions in progress on this connection (see transaction())
        self._owner: tuple[int, asyncio.Task[Any] | None] | None = None  # who opened the transaction
        _private_file(path)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA busy_timeout = 5000")
            self._conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            self._migrate(migrations)
        except sqlite3.DatabaseError as error:
            self._conn.close()
            raise StartupError(f"The database {path} cannot be opened ({error}). Restore a backup "
                               "(see docs/user/INSTALLATION.md).") from None
        except BaseException:
            self._conn.close()
            raise

    def close(self) -> None:
        self._conn.close()

    # ---------------------------------------------------------------- queries
    def _check_owner(self) -> None:
        """Called with the lock held: refuses a use of the connection by anyone but the owner of
        the open transaction (see the module documentation)."""
        if self._depth and self._owner != _current_owner():
            raise TransactionOwnerError(
                "The database was used by another task while a transaction was open. A transaction "
                "must end before its task waits (no await inside 'with db.transaction():').")

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            self._check_owner()
            return self._conn.execute(sql, params)

    def executemany(self, sql: str, rows: Sequence[Sequence[Any]]) -> None:
        with self._lock:
            self._check_owner()
            self._conn.executemany(sql, rows)

    def all(self, sql: str, params: Sequence[Any] = ()) -> list[Row]:
        with self._lock:
            self._check_owner()
            return self._conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: Sequence[Any] = ()) -> Row | None:
        with self._lock:
            self._check_owner()
            return self._conn.execute(sql, params).fetchone()

    def value(self, sql: str, params: Sequence[Any] = ()) -> Any:
        row = self.one(sql, params)
        return row[0] if row else None

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[None]:
        """Everything inside happens, or nothing does.

        A transaction inside another one joins it (0.4.1): an inner failure undoes the whole outer
        transaction. ``immediate`` takes the write lock at once, so that two processes checking
        then writing the same rows run one after the other instead of failing. Only the thread and
        task that opened it may use the connection until it ends (0.5.0, see the module documentation)."""
        with self._lock:
            if self._depth:
                self._check_owner()
                self._depth += 1
                try:
                    yield
                finally:
                    self._depth -= 1
                return
            self._conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            self._depth, self._owner = 1, _current_owner()
            try:
                yield
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            finally:
                self._depth, self._owner = 0, None
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
        value = str(self.get_meta("schema_version") or "0")
        if not value.isascii() or not value.isdigit():
            raise StartupError(f"The database {self.path} has an unreadable schema version ({value!r}). "
                               "Restore a backup (see docs/user/INSTALLATION.md).")
        return int(value)

    def _migrate(self, migrations: Sequence[Migration]) -> None:
        if self.schema_version > len(migrations):
            raise UnsupportedSchema(self.path, self.schema_version, len(migrations))
        first = self.schema_version + 1
        if first > len(migrations):
            return
        if first > 1:
            self.backup(f"schema{first - 1}")
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = OFF")  # has no effect inside a transaction
            try:
                for version in range(first, len(migrations) + 1):
                    self._apply(version, migrations[version - 1])
            finally:
                self._conn.execute("PRAGMA foreign_keys = ON")

    def _apply(self, version: int, migration: Migration) -> None:
        self._conn.execute("BEGIN")
        try:
            if callable(migration):
                migration(self._conn)
            else:
                for statement in _statements(migration):
                    self._conn.execute(statement)
            broken = self._conn.execute("PRAGMA foreign_key_check").fetchall()
            if broken:
                raise sqlite3.IntegrityError(f"migration {version} leaves broken references: {broken[:3]}")
            self._conn.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                               "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (str(version),))
            self._conn.execute("COMMIT")
        except BaseException:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise

    def backup(self, label: str) -> Path:
        """Copies the database to ``backups/<name>-<label>-<time>.db`` next to it and returns the path."""
        with self._lock:
            self._check_owner()  # before writing anything
        folder = self.path.parent / "backups"
        folder.mkdir(exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        target = folder / f"{self.path.stem}-{label}-{stamp}.db"
        _private_file(target)
        copy = sqlite3.connect(str(target))
        try:
            with self._lock:
                self._check_owner()
                self._conn.backup(copy)
        finally:
            copy.close()
        return target


def _private_file(path: Path) -> None:
    """Creates ``path`` readable by its owner only, or restricts it if it exists.

    SQLite gives its journal files the permissions of the database file."""
    if path.exists():
        os.chmod(path, 0o600)
    else:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))


def _statements(script: str) -> Iterator[str]:
    """The statements of an SQL script, one at a time (executescript() would commit on its own).

    A semicolon inside a string or a comment does not end a statement: SQLite's
    own parser (complete_statement) decides. The last statement may omit its semicolon."""
    pieces = script.split(";")
    buffer = ""
    for index, piece in enumerate(pieces):
        last = index == len(pieces) - 1
        buffer += piece if last else piece + ";"
        if last or sqlite3.complete_statement(buffer):
            if any(line.strip() and not line.strip().startswith("--") for line in buffer.splitlines()):
                yield buffer
            buffer = ""
