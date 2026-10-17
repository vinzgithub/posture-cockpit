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
integrity, schema), holds the exclusive lock of the data folder from start to end
(instance_lock.py), saves the current data as a backup in ``backups/``, then swaps the files,
all of them or none. A backup of an older schema is
migrated at the next start, like any older database. Nothing here contacts the network.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
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
from . import instance_lock
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


def _free(folder: Path, stem: str, suffix: str = "") -> Path:
    """``folder/stem-<time><suffix>``, with -2, -3... when two are made in the same second."""
    base = f"{stem}-{_stamp()}"
    path, n = folder / f"{base}{suffix}", 1
    while path.exists():
        n += 1
        path = folder / f"{base}-{n}{suffix}"
    return path


def default_path(data_dir: Path) -> Path:
    return _free(data_dir / "backups", "posture-cockpit", ".tar.gz")


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
    """A backup written to a file (by default a new one in ``backups/``), readable by its owner only.

    An existing file is never overwritten: a given target is refused, a default name moves on."""
    (target.parent if target else data_dir / "backups").mkdir(parents=True, exist_ok=True)
    for _ in range(100):
        path = target or default_path(data_dir)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            if target:
                raise BackupError(f"{target} already exists: choose another file.") from None
    else:  # pragma: no cover - a hundred backups in the same second
        raise BackupError("No free name for the backup in backups/.")
    try:
        with os.fdopen(fd, "wb") as out:
            manifest = create(data_dir, out)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path, manifest


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
    """Restores a backup into ``data_dir``: all of it, or nothing.

    The exclusive lock of the data folder (instance_lock.py) is held from the first check to the
    last file: no server starts and no command opens the database in between. The archive is
    checked completely before anything changes. The former data is first saved as a backup
    archive in ``backups/`` (or, when it is too damaged to be read, copied as it is). The files
    are then swapped by renames on the same file system; if one of them fails, the former files
    are put back and the error says so.

    The session key: the one of the archive when it holds one. When it holds none (an instance
    that never started), an existing instance being replaced gets a new key, never its former
    one: the sessions of the former accounts must not open the restored accounts that have the
    same numbers. A new instance gets its key at its first start.

    Returns the manifest, plus ``kept`` (where the former data went) and ``new_key``."""
    prepare_data_dir(data_dir)
    db_path = data_dir / DB_NAME
    try:
        with instance_lock.exclusive(data_dir):
            # Servers of 0.4.0 and earlier do not take the lock: an open SQLite connection betrays them.
            if in_use(db_path):
                raise BackupError("The database is in use: stop Posture Cockpit first (docker compose stop).")
            exists = db_path.exists() and db_path.stat().st_size > 0
            if exists and not replace:
                raise BackupError(f"{data_dir} already holds an instance. Add --replace to replace it "
                                  "(a backup of the current data is kept in backups/).")
            with _workdir(data_dir) as work:
                try:
                    manifest = _read(source, work)
                    kept = [str(_keep_former(data_dir))] if exists else []
                except OSError as error:  # a full disk, a folder that cannot be written...
                    raise BackupError(f"The restoration could not be prepared ({error}); "
                                      "nothing was changed.") from None
                new_key = _swap(data_dir, work, replacing=exists)
    except instance_lock.Busy:
        raise BackupError("Posture Cockpit, a command or another restoration uses this data folder: "
                          "stop Posture Cockpit first (docker compose stop).") from None
    return {**manifest, "kept": kept, "new_key": new_key}


_FORMER_FILES = (DB_NAME, f"{DB_NAME}-wal", f"{DB_NAME}-shm", f"{DB_NAME}-journal", KEY_NAME)


def _keep_former(data_dir: Path) -> Path:
    """The former data saved before it is replaced: a backup archive, restorable like any other,
    or a plain copy of its files when the database is too damaged to be read."""
    (data_dir / "backups").mkdir(exist_ok=True)
    try:
        return create_file(data_dir, _free(data_dir / "backups", "posture-cockpit-before-restore", ".tar.gz"))[0]
    except (BackupError, sqlite3.DatabaseError):
        folder = _free(data_dir / "backups", "before-restore")
        folder.mkdir(mode=0o700)
        for name in _FORMER_FILES:
            if (data_dir / name).is_file():
                shutil.copyfile(data_dir / name, folder / name)
                _private(folder / name)
        return folder


def _swap(data_dir: Path, work: Path, *, replacing: bool) -> bool:
    """Puts the restored files in place; on any failure, puts the former ones back. True when
    a new session key was made (see restore)."""
    aside = Path(tempfile.mkdtemp(prefix=".restore-former-", dir=data_dir))
    moved: list[tuple[Path, Path]] = []
    placed: list[Path] = []
    new_key = False
    try:
        # The former journals go too: a -wal left beside the restored database would be replayed onto it.
        for name in _FORMER_FILES:
            if (data_dir / name).exists():
                os.replace(data_dir / name, aside / name)
                moved.append((data_dir / name, aside / name))
        os.replace(work / DB_NAME, data_dir / DB_NAME)
        placed.append(data_dir / DB_NAME)
        _private(data_dir / DB_NAME)
        if (work / KEY_NAME).is_file():
            os.replace(work / KEY_NAME, data_dir / KEY_NAME)
            placed.append(data_dir / KEY_NAME)
            _private(data_dir / KEY_NAME)
        elif replacing:
            fd = os.open(data_dir / KEY_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            placed.append(data_dir / KEY_NAME)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_urlsafe(48))
            new_key = True
        _sync(data_dir)
    except BaseException as error:
        problems = []
        for path in placed:
            try:
                path.unlink(missing_ok=True)
            except OSError as e:  # pragma: no cover - reported below
                problems.append(f"{path}: {e}")
        for original, kept in reversed(moved):
            try:
                os.replace(kept, original)
            except OSError as e:
                problems.append(f"{original}: {e}")
        if problems:  # the former files stay where they are, and the message says where
            raise BackupError(f"The restoration failed ({error}) and the former files could not all be put "
                              f"back ({'; '.join(problems)}): they are in {aside}.") from error
        shutil.rmtree(aside, ignore_errors=True)
        if isinstance(error, BackupError):
            raise
        raise BackupError(f"The restoration failed ({error}); the former data is back, unchanged.") from error
    shutil.rmtree(aside, ignore_errors=True)
    return new_key


def _sync(folder: Path) -> None:
    """Writes the renames of ``folder`` to disk (where the system allows it)."""
    try:
        fd = os.open(folder, os.O_RDONLY)
    except OSError:  # pragma: no cover - Windows
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - some file systems refuse it on a folder
        pass
    finally:
        os.close(fd)
