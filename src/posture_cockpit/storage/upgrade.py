# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Opening the database for the server and the commands, with a verified backup before any
migration (0.5.0).

Once migrated, a database is refused by the versions that came before (database.py,
UnsupportedSchema): going back means restoring a backup made before. So, before migrating a
database that holds data, :func:`open_database` writes a complete backup archive (backup.py:
database and session key) to ``backups/posture-cockpit-before-schema<N>-<time>.tar.gz``, where N
is the schema it is about to reach, and checks it:

- enough free space first: twice the size of the database (the archive, and the raw copy that
  database.py still makes before migrating);
- the archive read back completely (backup.check: names, sizes, hashes, SQLite integrity);
- its schema, its accounts, domains and scans equal to those of the database;
- its session key equal to the one of the data folder, when the folder has one.

If any of these fails, nothing is migrated: the start (or the command) stops with a message
saying what to do, the database is left as it was, byte for byte, and an archive that failed
its verification is deleted rather than left beside the good ones. The archive is then recorded
in ``meta.upgrade_backup`` and shown by ``posture-cockpit info``.

A new instance (no database yet, or an empty one) and a database already up to date get no
archive: there is nothing to go back to. Two processes starting together on the same data folder
may both write an archive; only one of them migrates (database.py re-reads the schema version
inside each migration's transaction).
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from collections.abc import Callable, Sequence
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..config import Config, StartupError
from . import backup
from .database import Database, UnsupportedSchema
from .schema import MIGRATIONS, Migration

META_KEY = "upgrade_backup"
SPACE_FACTOR = 2


def free_space(folder: Path) -> int:
    return shutil.disk_usage(folder).free


def _megabytes(size: int) -> str:
    return f"{size / 1024**2:.1f} MB"


def space_needed(db_path: Path) -> int:
    """Bytes of free space a backup before migrating needs (the database and its journal, twice)."""
    size = sum(p.stat().st_size for p in (db_path, db_path.with_name(db_path.name + "-wal")) if p.exists())
    return SPACE_FACTOR * size


def read_meta(db_path: Path, key: str) -> str | None:
    """A value of ``meta``, read without migrating, locking or writing anything (for ``info``)."""
    if not db_path.is_file():
        return None
    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone() is None:
            return None
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return None if row is None else str(row[0])


def last_upgrade_backup(db_path: Path) -> dict[str, Any] | None:
    """The record of the archive written before the last migration, if any."""
    value = read_meta(db_path, META_KEY)
    if value is None:
        return None
    try:
        record = json.loads(value)
    except ValueError:
        return None
    return record if isinstance(record, dict) else None


def open_database(config: Config, migrations: Sequence[Migration] | None = None,
                  say: Callable[[str], None] | None = None) -> Database:
    """The database of ``config``, migrated if needed after a verified backup (see the module).

    ``migrations`` replaces the list of the application (the tests use it); ``say`` receives a
    line about the archive written, for the log of the server or the output of a command."""
    migrations = MIGRATIONS if migrations is None else migrations
    db_path, target = config.db_path, len(migrations)
    record = None
    found = _schema_or_none(db_path)
    if found is not None and found > target:
        # Refused before SQLite opens it for writing: not even its journal mode changes.
        raise UnsupportedSchema(db_path, found, target)
    if found is not None and 0 < found < target:
        record = _backup_before(config.data_dir, db_path, found, target)
    db = Database(db_path, migrations)
    if record is not None:
        try:
            db.set_meta(META_KEY, json.dumps(record, sort_keys=True))
        except BaseException:
            db.close()
            raise
        if say:
            say(f"Before updating the database from schema {found} to {target}, a verified backup was "
                f"written to {record['path']} (restore it to go back, see docs/user/INSTALLATION.md).")
    return db


def _schema_or_none(db_path: Path) -> int | None:
    """The schema of an existing database; None when there is none, or when it cannot be read
    (Database then refuses it with its own message, before anything is written)."""
    if not db_path.is_file() or db_path.stat().st_size == 0:
        return None
    try:
        return backup.schema_of(db_path)
    except (sqlite3.DatabaseError, backup.BackupError):
        return None


def _refuse(reason: str) -> StartupError:
    return StartupError(f"{reason} The database was not updated and is unchanged; this version did not start. "
                        "See docs/user/INSTALLATION.md, Update.")


def _backup_before(data_dir: Path, db_path: Path, found: int, target: int) -> dict[str, Any] | None:
    """Writes and verifies the archive made before migrating from ``found`` to ``target``. None
    when another process migrated the database meanwhile (it wrote its own archive first)."""
    needed, free = space_needed(db_path), free_space(data_dir)
    if free < needed:
        raise _refuse(f"Not enough free space in {data_dir} to back up the database before updating it "
                      f"({_megabytes(free)} free, {_megabytes(needed)} needed). Free some space, for example "
                      "old backups in backups/, then start again.")
    expected = backup.counts(db_path)
    key = data_dir / backup.KEY_NAME
    key_hash = backup._sha256(key) if key.is_file() else None
    folder = data_dir / "backups"
    folder.mkdir(exist_ok=True)
    try:
        for _attempt in range(100):
            name = backup._free(folder, f"posture-cockpit-before-schema{target}", ".tar.gz")
            try:
                path = backup.create_file(data_dir, name)[0]
                break
            except backup.BackupError:
                if not name.exists():
                    raise
                # another process starting at the same time took this name in the same second
        else:  # pragma: no cover - a hundred processes in the same second
            raise backup.BackupError("no free name in backups/")
    except (backup.BackupError, OSError, sqlite3.DatabaseError) as error:
        raise _refuse(f"The backup before the update could not be written ({error}).") from None
    try:
        with path.open("rb") as archive:
            manifest = backup.check(archive, data_dir)
        problems = []
        if manifest["schema"] != found:
            problems.append(f"schema {manifest['schema']} instead of {found}")
        if manifest["counts"] != expected:
            problems.append(f"content {manifest['counts']} instead of {expected}")
        files = manifest["files"]
        if key_hash is not None and files.get(backup.KEY_NAME, {}).get("sha256") != key_hash:
            problems.append("session key missing or different")
        if problems and backup.schema_of(db_path) >= target:
            path.unlink()  # another process started at the same time and migrated it after its own backup
            return None
        if problems:
            raise backup.BackupError("it does not match the database: " + ", ".join(problems))
    except (backup.BackupError, OSError, KeyError, TypeError) as error:
        path.unlink(missing_ok=True)
        raise _refuse(f"The backup written before the update failed its verification ({error}); it was "
                      "deleted.") from None
    return {"path": str(path.relative_to(data_dir)), "sha256": backup._sha256(path),
            "from_schema": found, "to_schema": target, "counts": expected,
            "session_key": key_hash is not None,
            "created_at": datetime.now(UTC).replace(microsecond=0).isoformat()}
