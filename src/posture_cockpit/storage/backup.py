# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Backups of an instance, and their restoration (0.4.1).

A backup is a ``.tar.gz`` holding three files:

- ``manifest.json``: format, version of the application, schema, date, SHA-256 of the files;
- ``posture_cockpit.db``: a consistent copy made with SQLite's online backup API. It reads
  through the write-ahead log (WAL), so it can be made while the server runs, and it is
  written as a single file (no ``-wal`` beside it);
- ``.secret_key``: the key that signs the sessions (absent if the instance never started).

Restoring checks the whole archive before touching anything (names, sizes, hashes,
integrity, schema), refuses while a server still uses the database, keeps a copy of the
current data in ``backups/``, then puts the files in place. A backup of an older schema is
migrated at the next start, like any older database. Nothing here contacts the network.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from .. import __version__
from ..config import MIN_SECRET_KEY, prepare_data_dir
from .schema import MIGRATIONS

FORMAT = 1
DB_NAME = "posture_cockpit.db"
KEY_NAME = ".secret_key"
MANIFEST_NAME = "manifest.json"
# Largest file accepted in an archive: a database of several years stays far below.
LIMITS = {MANIFEST_NAME: 64 * 1024, DB_NAME: 8 * 1024**3, KEY_NAME: 4096}
_CHUNK = 1024 * 1024


class BackupError(Exception):
    """A backup that cannot be made or restored. The message says why, and what to do."""


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _private(path: Path) -> None:
    os.chmod(path, 0o600)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def schema_of(db_path: Path) -> int:
    """Schema version of a database, read without migrating it (0: a database without meta)."""
    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone() is None:
            return 0
        row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    value = str(row[0]) if row else "0"
    if not value.isascii() or not value.isdigit():
        raise BackupError(f"{db_path}: unreadable schema version {value!r}")
    return int(value)


def counts(db_path: Path) -> dict[str, int]:
    """Accounts, domains and scans of a database (the tables of every schema since 0.1)."""
    result = {}
    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
        for table in ("users", "domains", "scans"):
            exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            result[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] if exists else 0  # noqa: S608
    return result


def in_use(db_path: Path) -> bool:
    """Whether another connection (a running server) has the database open.

    Every open SQLite connection keeps a lock that forbids an exclusive one; the locks hold
    between containers that share the volume, since they share the host's kernel."""
    if not db_path.exists():
        return False
    conn = sqlite3.connect(str(db_path), timeout=0, isolation_level=None)
    try:
        conn.execute("PRAGMA locking_mode = EXCLUSIVE")
        conn.execute("BEGIN EXCLUSIVE")
        conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
        conn.execute("ROLLBACK")
        return False
    except sqlite3.OperationalError:
        return True
    except sqlite3.DatabaseError:  # not a database at all: no server can be using it
        return False
    finally:
        conn.close()


def _snapshot(db_path: Path, target: Path) -> None:
    """A consistent single-file copy of a database, WAL included, checked by SQLite."""
    with closing(sqlite3.connect(str(db_path), timeout=30)) as source, closing(sqlite3.connect(str(target))) as copy:
        source.backup(copy)
        copy.execute("PRAGMA journal_mode = DELETE")  # the copy carries everything in one file
        problem = copy.execute("PRAGMA integrity_check").fetchone()[0]
    _private(target)
    if problem != "ok":
        raise BackupError(f"The database {db_path} is damaged ({problem}): no backup was written.")


@contextmanager
def _workdir(data_dir: Path) -> Iterator[Path]:
    """A private temporary folder in the data folder: on the volume, not in a small /tmp."""
    folder = Path(tempfile.mkdtemp(prefix=".backup-", dir=data_dir))
    try:
        yield folder
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def default_path(data_dir: Path) -> Path:
    return data_dir / "backups" / f"posture-cockpit-{_stamp()}.tar.gz"


def create(data_dir: Path, out: IO[bytes]) -> dict[str, Any]:
    """Writes a backup of the instance whose data is in ``data_dir`` to ``out``; returns the manifest."""
    db_path = data_dir / DB_NAME
    if not db_path.is_file():
        raise BackupError(f"There is no database in {data_dir}: nothing to back up.")
    with _workdir(data_dir) as work:
        copy = work / DB_NAME
        _snapshot(db_path, copy)
        files = {DB_NAME: copy}
        key = data_dir / KEY_NAME
        if key.is_file():
            shutil.copyfile(key, work / KEY_NAME)
            _private(work / KEY_NAME)
            files[KEY_NAME] = work / KEY_NAME
        manifest = {"format": FORMAT, "application": "posture-cockpit", "version": __version__,
                    "schema": schema_of(copy), "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
                    "counts": counts(copy),
                    "files": {name: {"sha256": _sha256(path), "size": path.stat().st_size}
                              for name, path in files.items()}}
        body = json.dumps(manifest, indent=2).encode()
        with tarfile.open(fileobj=out, mode="w|gz") as tar:
            _add(tar, MANIFEST_NAME, io.BytesIO(body), len(body))
            for name, path in files.items():
                with path.open("rb") as f:
                    _add(tar, name, f, path.stat().st_size)
    return manifest


def _add(tar: tarfile.TarFile, name: str, data: IO[bytes], size: int) -> None:
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = size, 0o600, int(time.time())
    tar.addfile(info, data)


def create_file(data_dir: Path, target: Path | None = None) -> tuple[Path, dict[str, Any]]:
    """A backup written to a file (by default in ``backups/``), readable by its owner only."""
    target = target or default_path(data_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            manifest = create(data_dir, out)
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target, manifest


def _read(source: IO[bytes], into: Path) -> dict[str, Any]:
    """Unpacks a backup into ``into`` after checking every member; returns its manifest."""
    found: dict[str, Path] = {}
    try:
        with tarfile.open(fileobj=source, mode="r|gz") as tar:
            for member in tar:
                if member.name not in LIMITS or member.name in found or not member.isfile():
                    raise BackupError(f"Not a Posture Cockpit backup: unexpected entry {member.name!r}.")
                if member.size > LIMITS[member.name]:
                    raise BackupError(f"Not a Posture Cockpit backup: {member.name} is too large.")
                data = tar.extractfile(member)
                assert data is not None
                path = into / member.name
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as f:
                    shutil.copyfileobj(data, f, _CHUNK)
                found[member.name] = path
    except (tarfile.TarError, EOFError, OSError) as error:
        raise BackupError(f"The archive cannot be read ({error}).") from None
    if MANIFEST_NAME not in found or DB_NAME not in found:
        raise BackupError("Not a Posture Cockpit backup: manifest.json or the database is missing.")
    try:
        manifest = json.loads(found[MANIFEST_NAME].read_text())
        if manifest.get("format") != FORMAT or manifest.get("application") != "posture-cockpit":
            raise BackupError("Not a Posture Cockpit backup, or a format this version does not know.")
        listed = manifest["files"]
        if set(listed) != set(found) - {MANIFEST_NAME}:
            raise BackupError("The archive does not hold the files its manifest lists.")
        for name, expected in listed.items():
            if _sha256(found[name]) != expected["sha256"]:
                raise BackupError(f"{name} does not match its manifest: the archive is damaged.")
    except (ValueError, KeyError, TypeError, AttributeError):
        raise BackupError("The manifest of the archive is unreadable.") from None
    db = found[DB_NAME]
    try:
        with closing(sqlite3.connect(f"file:{db}?mode=ro", uri=True)) as conn:
            problem = conn.execute("PRAGMA integrity_check").fetchone()[0]
    except sqlite3.DatabaseError as error:
        raise BackupError(f"The database of the archive cannot be opened ({error}).") from None
    if problem != "ok":
        raise BackupError(f"The database of the archive is damaged ({problem}).")
    schema = schema_of(db)
    if schema > len(MIGRATIONS):
        raise BackupError(f"The backup uses schema {schema}; this version handles schema {len(MIGRATIONS)} at most. "
                          "Restore it with the version that made it.")
    if KEY_NAME in found and len(found[KEY_NAME].read_text().strip()) < MIN_SECRET_KEY:
        raise BackupError("The session key of the archive is empty or damaged.")
    return manifest


def check(source: IO[bytes], data_dir: Path) -> dict[str, Any]:
    """Checks an archive completely without restoring it."""
    prepare_data_dir(data_dir)
    with _workdir(data_dir) as work:
        return _read(source, work)


def restore(data_dir: Path, source: IO[bytes], *, replace: bool = False) -> dict[str, Any]:
    """Restores a backup into ``data_dir``. Returns the manifest, plus where the former data went."""
    prepare_data_dir(data_dir)
    db_path, key_path = data_dir / DB_NAME, data_dir / KEY_NAME
    if in_use(db_path):
        raise BackupError("The database is in use: stop Posture Cockpit first (docker compose stop).")
    exists = db_path.exists() and db_path.stat().st_size > 0
    if exists and not replace:
        raise BackupError(f"{data_dir} already holds an instance. Add --replace to replace it "
                          "(a copy of the current data is kept in backups/).")
    with _workdir(data_dir) as work:
        manifest = _read(source, work)
        kept: list[str] = []
        if exists:
            saved = data_dir / "backups"
            saved.mkdir(exist_ok=True)
            stamp = _stamp()
            before = saved / f"posture_cockpit-before-restore-{stamp}.db"
            try:
                _snapshot(db_path, before)
            except (sqlite3.DatabaseError, BackupError):  # a damaged database is kept as it is
                before.unlink(missing_ok=True)
                for suffix in ("", "-wal"):
                    if Path(f"{db_path}{suffix}").exists():
                        shutil.copyfile(f"{db_path}{suffix}", f"{before}{suffix}")
                        _private(Path(f"{before}{suffix}"))
            kept.append(str(before))
            if key_path.is_file():
                shutil.copyfile(key_path, saved / f"secret_key-before-restore-{stamp}")
                _private(saved / f"secret_key-before-restore-{stamp}")
                kept.append(str(saved / f"secret_key-before-restore-{stamp}"))
        # A journal left beside the former database would be replayed onto the restored one.
        for suffix in ("-wal", "-shm", "-journal"):
            Path(f"{db_path}{suffix}").unlink(missing_ok=True)
        os.replace(work / DB_NAME, db_path)
        _private(db_path)
        if (work / KEY_NAME).is_file():
            os.replace(work / KEY_NAME, key_path)
            _private(key_path)
    return {**manifest, "kept": kept}
