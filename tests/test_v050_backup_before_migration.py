# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: a verified backup archive before any migration (storage/upgrade.py).

Most tests replace the migration to schema 5 by a dummy one (the four migrations of 0.4.1, then
the dummy), on the database made by the code of v0.4.1 (schema 4): they check the backup, not
the migration (test_v050_migration.py). The path of the server and of the account commands is
checked with the real migrations, on the database of v0.3.0."""

import hashlib
import json
import multiprocessing
import sqlite3
import stat
import time
from pathlib import Path

import pytest

from posture_cockpit import cli
from posture_cockpit.config import Config, StartupError
from posture_cockpit.storage import backup, open_database, upgrade
from posture_cockpit.storage.database import Database
from posture_cockpit.storage.schema import MIGRATIONS
from posture_cockpit.web.app import create_app

DATA = Path(__file__).parent / "data"
DUMMY = [*MIGRATIONS[:4], "CREATE TABLE v050_dummy(x INTEGER)"]
KEY = "k" * 64
CONTENT = {"users": 2, "domains": 5, "scans": 5}


def legacy(folder: Path, version: str = "v0.4.1", *, key: bool = True) -> Path:
    folder.mkdir(parents=True)
    with sqlite3.connect(folder / "posture_cockpit.db") as conn:
        conn.executescript((DATA / f"database-{version}.sql").read_text())
    if key:
        (folder / ".secret_key").write_text(KEY)
        (folder / ".secret_key").chmod(0o600)
    return folder


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rows(path: Path) -> dict[str, list[tuple]]:
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {t: conn.execute(f"SELECT * FROM {t} ORDER BY rowid").fetchall() for t in tables}  # noqa: S608


def archives(folder: Path, target: int = 5) -> list[Path]:
    return sorted((folder / "backups").glob(f"posture-cockpit-before-schema{target}-*.tar.gz"))


def test_an_archive_is_written_verified_and_recorded_before_migrating(tmp_path):
    folder = legacy(tmp_path / "a")
    lines = []
    db = open_database(Config(data_dir=folder), DUMMY, say=lines.append)
    try:
        assert db.schema_version == 5
        record = json.loads(db.get_meta("upgrade_backup"))
    finally:
        db.close()
    [archive] = archives(folder)
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    with archive.open("rb") as f:
        manifest = backup.check(f, folder)
    assert manifest["schema"] == 4 and manifest["counts"] == CONTENT
    assert manifest["files"][".secret_key"]["sha256"] == hashlib.sha256(KEY.encode()).hexdigest()
    assert record["path"] == str(archive.relative_to(folder)) and record["sha256"] == digest(archive)
    assert (record["from_schema"], record["to_schema"], record["counts"]) == (4, 5, CONTENT)
    assert record["session_key"] is True
    assert lines and str(archive.relative_to(folder)) in lines[0] and "schema 4 to 5" in lines[0]


def test_the_archive_restores_elsewhere_the_database_and_the_key_as_they_were(tmp_path):
    folder = legacy(tmp_path / "a")
    before = rows(folder / "posture_cockpit.db")
    open_database(Config(data_dir=folder), DUMMY).close()
    [archive] = archives(folder)
    with archive.open("rb") as f:
        backup.restore(tmp_path / "elsewhere", f)
    restored = tmp_path / "elsewhere" / "posture_cockpit.db"
    assert backup.schema_of(restored) == 4
    assert rows(restored) == before  # every table, every row
    assert (tmp_path / "elsewhere" / ".secret_key").read_text() == KEY


def test_info_announces_the_archive_then_shows_it(tmp_path, monkeypatch, capsys):
    folder = legacy(tmp_path / "a")
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(folder))
    monkeypatch.setattr(cli, "MIGRATIONS", DUMMY)
    assert cli.main(["info"]) == 0
    out = capsys.readouterr().out
    assert "schema 4 (migrated at the next start)" in out
    assert "Before migrating, the next start writes a verified backup" in out and "MB free now" in out
    assert "Backup before the last update" not in out
    open_database(Config(data_dir=folder), DUMMY).close()
    assert cli.main(["info"]) == 0
    out = capsys.readouterr().out
    [archive] = archives(folder)
    assert f"Backup before the last update: {archive.relative_to(folder)} (schema 4 to 5" in out
    assert "verified)" in out and "Before migrating" not in out
    archive.unlink()
    assert cli.main(["info"]) == 0
    assert "NO LONGER in the backups folder" in capsys.readouterr().out


def corrupt(path: Path) -> None:
    data = bytearray(path.read_bytes())
    middle = len(data) // 2
    data[middle:middle + 64] = bytes(64)
    path.write_bytes(bytes(data))


def failing(monkeypatch, case):
    """Makes one step of the backup before the migration go wrong."""
    if case == "not enough space":
        monkeypatch.setattr(upgrade, "free_space", lambda folder: 4096)
        return "Not enough free space"
    if case == "archive damaged on disk":
        written = backup.create_file

        def create_then_damage(data_dir, target=None):
            path, manifest = written(data_dir, target)
            corrupt(path)
            return path, manifest
        monkeypatch.setattr(backup, "create_file", create_then_damage)
        return "failed its verification"
    if case == "archive cannot be written":
        def full_disk(data_dir, target=None):
            raise OSError(28, "No space left on device")
        monkeypatch.setattr(backup, "create_file", full_disk)
        return "could not be written"
    read = backup.check

    def check_then_differ(source, data_dir):
        manifest = read(source, data_dir)
        if case == "other content":
            manifest["counts"] = {**manifest["counts"], "scans": manifest["counts"]["scans"] - 1}
        elif case == "other schema":
            manifest["schema"] = 3
        elif case == "other session key":
            manifest["files"][".secret_key"]["sha256"] = "0" * 64
        return manifest
    monkeypatch.setattr(backup, "check", check_then_differ)
    return "does not match the database"


CASES = ["not enough space", "archive damaged on disk", "archive cannot be written",
         "other content", "other schema", "other session key"]


@pytest.mark.parametrize("case", CASES)
def test_any_failure_of_the_backup_stops_before_the_migration_and_changes_nothing(tmp_path, monkeypatch, case):
    folder = legacy(tmp_path / "a")
    db_path = folder / "posture_cockpit.db"
    before = digest(db_path)
    message = failing(monkeypatch, case)
    with pytest.raises(StartupError, match=message) as refused:
        open_database(Config(data_dir=folder), DUMMY)
    assert "The database was not updated and is unchanged" in str(refused.value)
    assert digest(db_path) == before and backup.schema_of(db_path) == 4
    assert not (folder / "posture_cockpit.db-wal").exists() or (folder / "posture_cockpit.db-wal").stat().st_size == 0
    left = list((folder / "backups").iterdir()) if (folder / "backups").exists() else []
    assert left == []  # no archive that failed its verification, no copy: nothing was migrated
    assert upgrade.read_meta(db_path, "upgrade_backup") is None
    monkeypatch.undo()  # once the cause is gone, the next start backs up and migrates
    open_database(Config(data_dir=folder), DUMMY).close()
    assert backup.schema_of(db_path) == 5 and len(archives(folder)) == 1


def test_no_archive_for_a_new_instance_nor_for_a_database_already_up_to_date(tmp_path):
    new = tmp_path / "new"
    open_database(Config(data_dir=new), DUMMY).close()
    open_database(Config(data_dir=new), DUMMY).close()
    assert backup.schema_of(new / "posture_cockpit.db") == 5 and not (new / "backups").exists()
    current = legacy(tmp_path / "current")
    open_database(Config(data_dir=current), DUMMY).close()
    [first] = archives(current)
    open_database(Config(data_dir=current), DUMMY).close()  # up to date: nothing to do
    assert archives(current) == [first] and len(list((current / "backups").glob("*.db"))) == 1


def test_a_database_written_by_a_newer_version_is_refused_without_any_archive(tmp_path):
    folder = legacy(tmp_path / "a")
    db_path = folder / "posture_cockpit.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE meta SET value = '9' WHERE key = 'schema_version'")
    before = digest(db_path)
    with pytest.raises(StartupError, match="uses schema 9"):
        open_database(Config(data_dir=folder), DUMMY)
    assert digest(db_path) == before and not (folder / "backups").exists()


def test_the_server_backs_up_before_migrating_with_the_real_migrations(tmp_path):
    folder = legacy(tmp_path / "a", "v0.3.0")
    app = create_app(Config(data_dir=folder))
    try:
        assert app.state.services.db.schema_version == len(MIGRATIONS)
        record = json.loads(app.state.services.db.get_meta("upgrade_backup"))
    finally:
        app.state.services.db.close()
        app.state.folder_lock.release()
    [archive] = archives(folder, len(MIGRATIONS))
    with archive.open("rb") as f:
        manifest = backup.check(f, folder)
    assert manifest["schema"] == 3 and manifest["counts"] == {"users": 2, "domains": 2, "scans": 2}
    assert record["from_schema"] == 3 and record["path"] == str(archive.relative_to(folder))


def test_an_account_command_takes_the_same_path(tmp_path, monkeypatch, capsys):
    folder = legacy(tmp_path / "a", "v0.3.0")
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(folder))
    assert cli.main(["make-admin", "lecteur"]) == 0
    [archive] = archives(folder, len(MIGRATIONS))
    assert str(archive.relative_to(folder)) in capsys.readouterr().err
    assert backup.schema_of(folder / "posture_cockpit.db") == len(MIGRATIONS)


def test_an_account_command_refuses_when_the_backup_fails(tmp_path, monkeypatch, capsys):
    folder = legacy(tmp_path / "a", "v0.3.0")
    before = digest(folder / "posture_cockpit.db")
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(folder))
    monkeypatch.setattr(upgrade, "free_space", lambda folder: 0)
    assert cli.main(["make-admin", "lecteur"]) == 2
    assert "Not enough free space" in capsys.readouterr().err
    assert digest(folder / "posture_cockpit.db") == before


def slow_migration(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS applied(at REAL)")
    conn.execute("INSERT INTO applied VALUES(?)", (time.time(),))
    time.sleep(0.5)  # long enough for the other process to be waiting for the write lock


def start_instance(folder: str, barrier, results) -> None:
    """One process starting on the data folder (run by multiprocessing)."""
    try:
        barrier.wait(timeout=30)
        db = open_database(Config(data_dir=Path(folder)), [*MIGRATIONS[:4], slow_migration])
        results.put(("started", db.schema_version))
        db.close()
    except BaseException as error:  # reported by the test
        results.put(("failed", repr(error)))


def test_two_processes_migrating_together_apply_each_migration_once(tmp_path):
    folder = legacy(tmp_path / "a")
    Database(folder / "posture_cockpit.db", MIGRATIONS[:4]).close()  # in WAL mode, as an instance always is
    context = multiprocessing.get_context("spawn")
    barrier, results = context.Barrier(2), context.Queue()
    processes = [context.Process(target=start_instance, args=(str(folder), barrier, results)) for _ in range(2)]
    for process in processes:
        process.start()
    outcomes = [results.get(timeout=60) for _ in processes]
    for process in processes:
        process.join(timeout=30)
    assert outcomes == [("started", 5), ("started", 5)]
    with sqlite3.connect(folder / "posture_cockpit.db") as conn:
        assert conn.execute("SELECT COUNT(*) FROM applied").fetchone()[0] == 1  # applied once, not twice
    found = archives(folder)
    assert 1 <= len(found) <= 2  # each process may have backed up before the other migrated
    for archive in found:
        with archive.open("rb") as f:
            assert backup.check(f, folder)["schema"] == 4
