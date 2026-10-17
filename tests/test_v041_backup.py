# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.4.1: consistent backups (WAL included) and checked restorations."""

import gzip
import io
import json
import sqlite3
import stat
import tarfile

import pytest
from fastapi.testclient import TestClient

from helpers import DEMO, log_in, setup_account
from posture_cockpit import cli
from posture_cockpit.config import Config
from posture_cockpit.storage import Database, backup
from posture_cockpit.web.app import create_app


def instance(tmp_path, world_network, demo=True):
    """An instance with an account and the demo scan; its server connection stays open."""
    app = create_app(Config(data_dir=tmp_path), network_factory=world_network)
    with TestClient(app) as client:
        assert setup_account(client, demo=demo).status_code == 303
    return app


@pytest.fixture
def network(world):
    from posture_cockpit.core.fixture import FixtureNetwork

    return lambda domain: FixtureNetwork(world.get(domain, {"dns": {f"{domain} SOA": None}}))


def archive(app_dir):
    out = io.BytesIO()
    manifest = backup.create(app_dir, out)
    out.seek(0)
    return out, manifest


def test_a_backup_made_while_the_server_runs_holds_what_the_wal_holds(tmp_path, network):
    app = instance(tmp_path / "a", network)
    wal = tmp_path / "a" / "posture_cockpit.db-wal"
    assert wal.exists() and wal.stat().st_size > 0  # recent writes still in the journal
    out, manifest = archive(tmp_path / "a")
    assert manifest["schema"] == 4 and manifest["counts"] == {"users": 1, "domains": 1, "scans": 1}
    with tarfile.open(fileobj=out, mode="r:gz") as tar:
        assert tar.getnames() == ["manifest.json", "posture_cockpit.db", ".secret_key"]
        assert all(m.mode == 0o600 for m in tar.getmembers())
    app.state.services.db.close()


def test_restore_into_a_new_instance_keeps_accounts_scans_and_sessions(tmp_path, network):
    app = instance(tmp_path / "a", network)
    with TestClient(app) as client:
        log_in(client)
        cookie = client.cookies.get("posture_cockpit")
    out, _ = archive(tmp_path / "a")
    result = backup.restore(tmp_path / "b", out)
    assert result["kept"] == []
    for name in ("posture_cockpit.db", ".secret_key"):
        assert stat.S_IMODE((tmp_path / "b" / name).stat().st_mode) == 0o600
    assert (tmp_path / "b" / ".secret_key").read_text() == (tmp_path / "a" / ".secret_key").read_text()
    restored = create_app(Config(data_dir=tmp_path / "b"), network_factory=network)
    assert restored.state.setup_code is None
    with TestClient(restored) as client:
        client.cookies.set("posture_cockpit", cookie)  # the same key: the session is still valid
        assert client.get("/domains", follow_redirects=False).status_code == 200
        assert DEMO in client.get(f"/domains/{DEMO}").text
    app.state.services.db.close()


def test_restore_refuses_while_the_server_uses_the_database(tmp_path, network):
    app = instance(tmp_path / "a", network)
    out, _ = archive(tmp_path / "a")
    with pytest.raises(backup.BackupError, match="stop Posture Cockpit first"):
        backup.restore(tmp_path / "a", out, replace=True)
    app.state.services.db.close()


def test_replacing_an_instance_keeps_a_copy_of_its_data(tmp_path, network):
    source = instance(tmp_path / "a", network)
    out, _ = archive(tmp_path / "a")
    source.state.services.db.close()
    other = instance(tmp_path / "b", network, demo=False)
    other.state.services.db.close()
    with pytest.raises(backup.BackupError, match="--replace"):
        backup.restore(tmp_path / "b", out)
    out.seek(0)
    (tmp_path / "b" / "posture_cockpit.db-wal").write_bytes(b"stale journal")
    result = backup.restore(tmp_path / "b", out, replace=True)
    assert not (tmp_path / "b" / "posture_cockpit.db-wal").exists()
    assert len(result["kept"]) == 1 and result["kept"][0].endswith(".tar.gz")  # a restorable backup
    with open(result["kept"][0], "rb") as former:
        assert backup.check(former, tmp_path / "scratch")["counts"]["scans"] == 0
    assert backup.counts(tmp_path / "b" / "posture_cockpit.db")["scans"] == 1


def tamper(out, name, change):
    members = {}
    with tarfile.open(fileobj=out, mode="r:gz") as tar:
        for m in tar.getmembers():
            members[m.name] = tar.extractfile(m).read()
    members = change(members)
    new = io.BytesIO()
    with tarfile.open(fileobj=new, mode="w:gz") as tar:
        for member, data in members.items():
            info = tarfile.TarInfo(member)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    new.seek(0)
    return new


@pytest.mark.parametrize(("change", "message"), [
    (lambda m: {**m, "../evil": b"x"}, "unexpected entry"),
    (lambda m: {k: v for k, v in m.items() if k != "posture_cockpit.db"}, "missing"),
    (lambda m: {**m, "posture_cockpit.db": m["posture_cockpit.db"][:-10] + b"0123456789"}, "does not match"),
    (lambda m: {**m, "manifest.json": json.dumps({**json.loads(m["manifest.json"]), "format": 9}).encode()},
     "format"),
])
def test_a_damaged_or_foreign_archive_is_refused_before_anything_changes(tmp_path, network, change, message):
    app = instance(tmp_path / "a", network)
    out, _ = archive(tmp_path / "a")
    app.state.services.db.close()
    with pytest.raises(backup.BackupError, match=message):
        backup.restore(tmp_path / "b", tamper(out, "", change))
    assert not (tmp_path / "b" / "posture_cockpit.db").exists()
    with pytest.raises(backup.BackupError):
        backup.restore(tmp_path / "c", io.BytesIO(gzip.compress(b"not a tar file")))


def test_a_backup_of_a_newer_schema_is_refused(tmp_path, network):
    app = instance(tmp_path / "a", network)
    app.state.services.db.execute("UPDATE meta SET value = '9' WHERE key = 'schema_version'")
    out, _ = archive(tmp_path / "a")
    with pytest.raises(backup.BackupError, match="schema 9"):
        backup.restore(tmp_path / "b", out)
    app.state.services.db.close()


def test_an_older_backup_is_migrated_at_the_next_start(tmp_path):
    Database(tmp_path / "old" / "posture_cockpit.db", migrations=[]).close()  # nothing but meta: schema 0
    db = Database(tmp_path / "v3" / "posture_cockpit.db")
    db.execute("UPDATE meta SET value = '3' WHERE key = 'schema_version'")
    db.close()
    out, manifest = archive(tmp_path / "v3")
    assert manifest["schema"] == 3 and ".secret_key" not in manifest["files"]
    backup.restore(tmp_path / "new", out)
    assert backup.schema_of(tmp_path / "new" / "posture_cockpit.db") == 3


def test_the_command_line(tmp_path, network, monkeypatch, capsys):
    app = instance(tmp_path / "a", network)
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(tmp_path / "a"))
    assert cli.main(["backup"]) == 0
    written = sorted((tmp_path / "a" / "backups").glob("posture-cockpit-*.tar.gz"))
    assert len(written) == 1 and stat.S_IMODE(written[0].stat().st_mode) == 0o600
    assert "1 account(s), 1 domain(s), 1 scan(s), session key included" in capsys.readouterr().err
    assert cli.main(["check-backup", str(written[0])]) == 0
    assert "Backup complete and readable" in capsys.readouterr().out
    assert cli.main(["info"]) == 0
    assert "schema 4 (up to date), 1 account(s)" in capsys.readouterr().out
    assert cli.main(["restore", str(written[0]), "--replace"]) == 2  # the server still has it open
    assert "stop Posture Cockpit first" in capsys.readouterr().err
    app.state.services.db.close()
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(tmp_path / "b"))
    assert cli.main(["restore", str(written[0])]) == 0
    assert "Backup restored" in capsys.readouterr().out
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(tmp_path / "c"))
    assert cli.main(["backup"]) == 2
    assert "nothing to back up" in capsys.readouterr().err


def test_a_damaged_database_is_not_backed_up(tmp_path):
    db = Database(tmp_path / "posture_cockpit.db")
    db.close()
    data = bytearray((tmp_path / "posture_cockpit.db").read_bytes())
    data[100:4000] = b"\x00" * 3900
    (tmp_path / "posture_cockpit.db").write_bytes(bytes(data))
    with pytest.raises((backup.BackupError, sqlite3.DatabaseError)):
        backup.create(tmp_path, io.BytesIO())
