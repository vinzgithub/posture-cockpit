# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: scripts/data-fingerprint.py, the fingerprint of the data used by the update and rollback
recette: stable, changed by the least change, never showing a value nor the session key, read
only, on schema 4 and 5."""

import json
import sqlite3
import stat
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

from posture_cockpit.config import Config
from posture_cockpit.storage import Database, backup, open_database
from posture_cockpit.storage.schema import MIGRATIONS

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "data-fingerprint.py"
DATA = Path(__file__).parent / "data"
KEY = "session-key-for-the-fingerprint-tests-0123456789"


def run(*args, check=True) -> subprocess.CompletedProcess:
    result = subprocess.run(  # noqa: S603 - this interpreter, the script of the repository
        [sys.executable, "-I", str(SCRIPT), *map(str, args)], capture_output=True, text=True,
        timeout=120, check=False)
    if check:
        assert result.returncode == 0, result.stderr
    return result


@pytest.fixture
def instance(tmp_path) -> Path:
    folder = tmp_path / "instance"
    folder.mkdir()
    with sqlite3.connect(folder / "posture_cockpit.db") as conn:
        conn.executescript((DATA / "database-v0.4.1.sql").read_text())
    (folder / ".secret_key").write_text(KEY)
    return folder


@pytest.fixture
def salt(tmp_path) -> Path:
    return tmp_path / "salt"


def fingerprint(path, salt) -> dict:
    return json.loads(run("--salt-file", salt, path).stdout)


def save(tmp_path, name, data) -> Path:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(data))
    return path


def test_the_fingerprint_is_stable_and_creates_a_private_salt(instance, salt):
    first = fingerprint(instance, salt)
    assert stat.S_IMODE(salt.stat().st_mode) == 0o600 and len(salt.read_bytes()) == 32
    assert fingerprint(instance, salt) == first
    assert first["schema"] == 4 and first["integrity"] == "ok" and first["broken_references"] == 0
    assert first["counts"] == {"users": 2, "administrators": 1, "two_factor": 1, "recovery_codes_unused": 8,
                               "api_keys": 1, "perimeters": 1, "domains": 5, "scans": 5, "findings": 100,
                               "rechecks": 1, "audit_log": 4}


@pytest.mark.parametrize(("change", "table", "report"), [
    ("UPDATE users SET pw_hash = pw_hash || 'x' WHERE id = 2", "users", {"changed_rows": {"[2]": ["pw_hash"]}}),
    ("UPDATE users SET is_admin = 1 WHERE id = 2", "users", {"changed_rows": {"[2]": ["is_admin"]}}),
    ("DELETE FROM api_tokens", "api_tokens", {"removed_rows": ["[1]"]}),
    ("UPDATE meta SET value = value || '1' WHERE key = 'session_epoch:1'", "meta",
     {"changed_rows": {'["session_epoch:1"]': ["value"]}}),
    ("UPDATE findings SET status = 'ok' WHERE rowid = 7", "findings", {"changed_columns": ["status"]}),
])
def test_the_least_change_is_seen_and_located(instance, salt, tmp_path, change, table, report):
    before = save(tmp_path, "before", fingerprint(instance, salt))
    with sqlite3.connect(instance / "posture_cockpit.db") as conn:
        conn.execute(change)
    after = save(tmp_path, "after", fingerprint(instance, salt))
    result = run("compare", before, after, "--json", check=False)
    assert result.returncode == 1
    found = json.loads(result.stdout)
    assert not found["identical"] and not found["kept"]
    assert {k: v for k, v in found["tables"][table].items() if k != "rows"} == report
    assert set(found["tables"]) == {table}  # nothing else reported
    assert run("compare", before, after, "--except", table).returncode == 0


def test_an_addition_keeps_the_first(instance, salt, tmp_path):
    before = save(tmp_path, "before", fingerprint(instance, salt))
    with sqlite3.connect(instance / "posture_cockpit.db") as conn:
        conn.execute("INSERT INTO api_tokens(user_id, name, token_hash, created_at) VALUES(1, 'n', 'h', 'd')")
    result = run("compare", before, save(tmp_path, "after", fingerprint(instance, salt)))
    assert "api_tokens: rows 1 -> 2; added rows 1: [2]" in result.stdout
    assert "everything of the first kept: yes" in result.stdout


def test_no_value_of_the_database_and_never_the_key_appear(instance, salt):
    output = run("--salt-file", salt, instance).stdout
    assert KEY not in output
    with sqlite3.connect(instance / "posture_cockpit.db") as conn:
        values = set()
        for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
            keys = {r[1] for r in conn.execute(f"PRAGMA table_info({table})") if r[5]}
            columns = [r[1] for r in conn.execute(f"PRAGMA table_info({table})") if r[1] not in keys]
            for row in conn.execute(f"SELECT {', '.join(columns)} FROM {table}"):  # noqa: S608
                values |= {v for v in row if isinstance(v, str) and len(v) >= 4}
    assert {"vincent", "lecteur", "menuiserie-dupont.example", "10.20.0.0/16"} <= values
    assert [v for v in values if json.dumps(v) in output] == []  # as a string of the JSON


def test_it_works_on_schema_5_and_tells_what_the_migration_added(instance, salt, tmp_path):
    before = save(tmp_path, "e0", fingerprint(instance, salt))
    open_database(Config(data_dir=instance)).close()
    migrated = fingerprint(instance, salt)
    assert migrated["schema"] == 5 and migrated["counts"]["scan_states"] == 5
    result = run("compare", before, save(tmp_path, "e1", migrated), "--except", "meta.value")
    assert "added tables: events, scan_states, schedule_runs, schedules" in result.stdout
    assert "scans: rows 5 -> 5; added columns: engine, via" in result.stdout
    assert "everything of the first kept: yes" in result.stdout
    assert run("compare", before, tmp_path / "e1.json", check=False).returncode == 1  # schema_version changed


def test_the_archive_before_the_migration_is_the_data_before_it(instance, salt, tmp_path):
    before = fingerprint(instance, salt)
    open_database(Config(data_dir=instance)).close()
    [archive] = (instance / "backups").glob("posture-cockpit-before-schema5-*.tar.gz")
    assert fingerprint(archive, salt) == {**before, "session_key_mode": fingerprint(archive, salt)["session_key_mode"]}
    assert fingerprint(archive, salt)["fingerprint"] == before["fingerprint"]


def test_it_reads_without_changing_a_byte_or_a_file(instance, salt):
    Database(instance / "posture_cockpit.db", MIGRATIONS[:4]).close()  # in WAL mode, stopped cleanly
    listing = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in instance.iterdir()}
    run("--salt-file", salt, instance)
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in instance.iterdir()} == listing


def test_a_running_instance_is_refused(instance, salt):
    db = Database(instance / "posture_cockpit.db")
    try:
        db.execute("INSERT INTO meta(key, value) VALUES('running', '1')")  # kept in the write-ahead log
        assert (instance / "posture_cockpit.db-wal").stat().st_size > 0
        result = run("--salt-file", salt, instance, check=False)
        assert result.returncode == 2 and "Stop it (docker compose stop)" in result.stderr
    finally:
        db.close()


def test_fingerprints_of_two_salts_are_not_compared(instance, tmp_path):
    first = save(tmp_path, "a", fingerprint(instance, tmp_path / "salt-a"))
    second = save(tmp_path, "b", fingerprint(instance, tmp_path / "salt-b"))
    assert json.loads(first.read_text())["fingerprint"] != json.loads(second.read_text())["fingerprint"]
    result = run("compare", first, second, check=False)
    assert result.returncode == 2 and "same salt" in result.stderr


def test_a_restored_copy_is_identical_and_a_lost_activity_is_listed(instance, salt, tmp_path):
    """The rollback in small: the data before an update, then activity, then the restoration of the
    archive made before: the losses are exactly that activity."""
    e0 = save(tmp_path, "e0", fingerprint(instance, salt))
    open_database(Config(data_dir=instance)).close()
    [archive] = (instance / "backups").glob("posture-cockpit-before-schema5-*.tar.gz")
    with closing(sqlite3.connect(instance / "posture_cockpit.db")) as conn, conn:  # closed: the log is emptied
        conn.execute("UPDATE users SET pw_hash = 'changed' WHERE id = 1")
        conn.execute("DELETE FROM api_tokens")
    e3 = save(tmp_path, "e3", fingerprint(instance, salt))
    with archive.open("rb") as f:
        backup.restore(tmp_path / "restored", f)
    e2 = save(tmp_path, "e2", fingerprint(tmp_path / "restored", salt))
    assert "identical: yes" in run("compare", e0, e2).stdout
    losses = json.loads(run("compare", e3, e2, "--json", check=False).stdout)
    assert losses["tables"]["users"]["changed_rows"] == {"[1]": ["pw_hash"]}
    assert losses["tables"]["api_tokens"]["added_rows"] == ["[1]"]  # the revoked key is back
    assert set(losses["tables"]["scans"]["removed_columns"]) == {"via", "engine"}
    assert "scan_states" in losses["tables"] and losses["tables"]["scan_states"] == {"removed": True}
