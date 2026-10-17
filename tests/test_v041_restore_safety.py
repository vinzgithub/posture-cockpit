# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.4.1, counter-review: a restoration has the data folder to itself from start to end, and
restores everything or nothing, the session key included."""

import errno
import io
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from helpers import log_in, setup_account
from posture_cockpit import cli
from posture_cockpit.config import Config, StartupError
from posture_cockpit.storage import Database, backup, instance_lock
from posture_cockpit.web.app import create_app

SRC = Path(__file__).parent.parent / "src"


def started(folder, demo=False):
    """An instance with its first account; the application stays open, as a running server."""
    app = create_app(Config(data_dir=folder))
    client = TestClient(app)
    assert setup_account(client, demo=demo).status_code == 303
    return app


def stop(app):
    app.state.folder_lock.release()
    app.state.services.db.close()


def archive(folder, *, without_key=False):
    out = io.BytesIO()
    backup.create(folder, out)
    out.seek(0)
    if not without_key:
        return out
    import tarfile

    new = io.BytesIO()
    with tarfile.open(fileobj=out, mode="r:gz") as src, tarfile.open(fileobj=new, mode="w:gz") as dst:
        members = {m.name: (m, src.extractfile(m).read()) for m in src.getmembers()}
        import json

        manifest = json.loads(members["manifest.json"][1])
        del manifest["files"][".secret_key"]
        for name, (member, data) in members.items():
            if name == ".secret_key":
                continue
            data = json.dumps(manifest).encode() if name == "manifest.json" else data
            member.size = len(data)
            dst.addfile(member, io.BytesIO(data))
    new.seek(0)
    return new


def snapshot(folder):
    return {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file() and p.name != instance_lock.LOCK_NAME}


# ------------------------------------------------------------------ exclusivity
def test_a_running_server_keeps_any_restoration_out(tmp_path):
    source = started(tmp_path / "a")
    out = archive(tmp_path / "a")
    server = started(tmp_path / "b")
    server.state.services.db.close()  # only the lock of the folder is left: it is enough
    with pytest.raises(backup.BackupError, match="stop Posture Cockpit first"):
        backup.restore(tmp_path / "b", out, replace=True)
    stop(source)


def test_a_server_of_0_4_0_without_the_lock_is_detected_by_its_connection(tmp_path):
    source = started(tmp_path / "a")
    out = archive(tmp_path / "a")
    stop(source)
    old_server = started(tmp_path / "b")
    old_server.state.folder_lock.release()  # 0.4.0 takes no lock, but keeps its SQLite connection
    with pytest.raises(backup.BackupError, match="The database is in use"):
        backup.restore(tmp_path / "b", out, replace=True)
    old_server.state.services.db.close()


def test_no_server_starts_and_no_command_runs_during_a_restoration(tmp_path, monkeypatch):
    stop(started(tmp_path))
    with instance_lock.exclusive(tmp_path):
        with pytest.raises(StartupError, match="A restoration is in progress"):
            create_app(Config(data_dir=tmp_path))
        monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(tmp_path))
        assert cli.main(["backup"]) == 2
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "a new long password")
        assert cli.main(["reset-password", "vincent"]) == 2
    app = create_app(Config(data_dir=tmp_path))  # free again afterwards
    stop(app)


def test_the_lock_is_held_until_the_last_file_is_in_place(tmp_path, monkeypatch):
    source = started(tmp_path / "a")
    out = archive(tmp_path / "a")
    stop(source)
    stop(started(tmp_path / "b"))
    seen = []
    real_replace = os.replace

    def watching_replace(src, dst):
        try:
            instance_lock.shared(tmp_path / "b").release()
            seen.append("free")
        except instance_lock.Busy:
            seen.append("held")
        return real_replace(src, dst)

    monkeypatch.setattr(backup.os, "replace", watching_replace)
    backup.restore(tmp_path / "b", out, replace=True)
    assert seen and set(seen) == {"held"}


class SlowArchive(io.BytesIO):
    """An archive that waits before giving its first bytes, to keep a restoration going."""

    def __init__(self, data, gate):
        super().__init__(data)
        self.gate, self.started = gate, threading.Event()

    def read(self, *args):
        self.started.set()
        assert self.gate.wait(10)
        return super().read(*args)


def test_two_restorations_never_run_together(tmp_path):
    source = started(tmp_path / "a")
    data = archive(tmp_path / "a").getvalue()
    stop(source)
    gate = threading.Event()
    slow = SlowArchive(data, gate)
    outcome = {}
    first = threading.Thread(target=lambda: outcome.setdefault("first", backup.restore(tmp_path / "b", slow)))
    first.start()
    assert slow.started.wait(10)
    with pytest.raises(backup.BackupError, match="another restoration"):
        backup.restore(tmp_path / "b", io.BytesIO(data))
    with pytest.raises(StartupError, match="A restoration is in progress"):
        create_app(Config(data_dir=tmp_path / "b"))
    gate.set()
    first.join(10)
    assert outcome["first"]["counts"]["users"] == 1


def test_another_process_holding_the_folder_keeps_the_restoration_out(tmp_path):
    source = started(tmp_path / "a")
    out = archive(tmp_path / "a")
    stop(source)
    (tmp_path / "b").mkdir()
    holder = subprocess.Popen(  # noqa: S603 - this interpreter, a fixed script
        [sys.executable, "-c", "import sys, time; from pathlib import Path; "
         "from posture_cockpit.storage import instance_lock; "
         "held = instance_lock.shared(Path(sys.argv[1])); print('ready', flush=True); time.sleep(30)",
         str(tmp_path / "b")], stdout=subprocess.PIPE, text=True, env={**os.environ, "PYTHONPATH": str(SRC)})
    try:
        assert holder.stdout.readline().strip() == "ready"
        with pytest.raises(backup.BackupError, match="stop Posture Cockpit first"):
            backup.restore(tmp_path / "b", out)
    finally:
        holder.kill()
        holder.wait()
    out.seek(0)
    assert backup.restore(tmp_path / "b", out)["counts"]["users"] == 1


# ------------------------------------------------------------- all or nothing
def former_instance(tmp_path):
    source = started(tmp_path / "a", demo=True)
    out = archive(tmp_path / "a")
    stop(source)
    target = started(tmp_path / "b")
    target.state.services.db.execute("CREATE TABLE marker(x)")  # left in the WAL of the former database
    stop(target)
    return out, snapshot(tmp_path / "b")


@pytest.mark.parametrize("failing", ["posture_cockpit.db", ".secret_key"])
def test_a_failed_swap_puts_the_former_files_back_unchanged(tmp_path, monkeypatch, failing):
    out, before = former_instance(tmp_path)
    real_replace = os.replace

    def failing_replace(src, dst):
        if Path(dst).name == failing and ".backup-" in str(src):  # a restored file being put in place
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_replace(src, dst)

    monkeypatch.setattr(backup.os, "replace", failing_replace)
    with pytest.raises(backup.BackupError, match="the former data is back, unchanged"):
        backup.restore(tmp_path / "b", out, replace=True)
    after = snapshot(tmp_path / "b")
    assert after == before  # database, its journal and the key, byte for byte
    assert not [p for p in (tmp_path / "b").iterdir() if p.name.startswith((".backup-", ".restore-former-"))]
    db = Database(tmp_path / "b" / "posture_cockpit.db")
    assert db.value("SELECT COUNT(*) FROM sqlite_master WHERE name = 'marker'") == 1
    db.close()


def test_a_full_disk_while_saving_the_former_data_changes_nothing(tmp_path, monkeypatch):
    out, before = former_instance(tmp_path)

    def full(*args, **kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(backup, "create_file", full)
    with pytest.raises(backup.BackupError, match="nothing was changed"):
        backup.restore(tmp_path / "b", out, replace=True)
    assert snapshot(tmp_path / "b") == before


def test_a_full_disk_while_unpacking_changes_nothing(tmp_path, monkeypatch):
    out, before = former_instance(tmp_path)

    def full(*args, **kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(backup.shutil, "copyfileobj", full)
    with pytest.raises(backup.BackupError):
        backup.restore(tmp_path / "b", out, replace=True)
    assert snapshot(tmp_path / "b") == before
    assert not [p for p in (tmp_path / "b").iterdir() if p.name.startswith(".backup-")]


def test_the_former_data_can_be_restored_back(tmp_path):
    out, _ = former_instance(tmp_path)
    key = (tmp_path / "b" / ".secret_key").read_text()
    kept = backup.restore(tmp_path / "b", out, replace=True)["kept"][0]
    assert backup.counts(tmp_path / "b" / "posture_cockpit.db")["scans"] == 1
    with open(kept, "rb") as former:
        backup.restore(tmp_path / "b", former, replace=True)
    assert backup.counts(tmp_path / "b" / "posture_cockpit.db") == {"users": 1, "domains": 0, "scans": 0}
    assert (tmp_path / "b" / ".secret_key").read_text() == key


def test_a_damaged_former_database_is_kept_as_it_is(tmp_path):
    out, _ = former_instance(tmp_path)
    (tmp_path / "b" / "posture_cockpit.db").write_bytes(b"\0" * 8192)
    (tmp_path / "b" / "posture_cockpit.db-wal").unlink(missing_ok=True)
    kept = Path(backup.restore(tmp_path / "b", out, replace=True)["kept"][0])
    assert kept.is_dir() and (kept / "posture_cockpit.db").read_bytes() == b"\0" * 8192
    assert backup.counts(tmp_path / "b" / "posture_cockpit.db")["users"] == 1


# ------------------------------------------------------------ the session key
def test_a_backup_without_key_never_keeps_the_key_of_the_replaced_instance(tmp_path, capsys, monkeypatch):
    source = started(tmp_path / "a")
    out = archive(tmp_path / "a", without_key=True)
    stop(source)
    target = started(tmp_path / "b")
    with TestClient(target) as client:
        log_in(client)
        cookie = client.cookies.get("posture_cockpit")
    old_key = (tmp_path / "b" / ".secret_key").read_text()
    stop(target)
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(tmp_path / "b"))
    archive_file = tmp_path / "no-key.tar.gz"
    archive_file.write_bytes(out.getvalue())
    assert cli.main(["restore", str(archive_file), "--replace"]) == 0
    assert "a new one was made, every browser signs in again" in capsys.readouterr().out
    new_key = (tmp_path / "b" / ".secret_key").read_text()
    assert new_key != old_key and len(new_key) >= 32
    restored = create_app(Config(data_dir=tmp_path / "b"))
    with TestClient(restored) as client:
        client.cookies.set("posture_cockpit", cookie)  # a session of the replaced instance
        assert client.get("/domains", follow_redirects=False).headers["location"] == "/login"
    stop(restored)


def test_a_backup_without_key_into_a_new_folder_lets_the_first_start_make_it(tmp_path):
    source = started(tmp_path / "a")
    out = archive(tmp_path / "a", without_key=True)
    stop(source)
    result = backup.restore(tmp_path / "new", out)
    assert result["new_key"] is False and not (tmp_path / "new" / ".secret_key").exists()
    app = create_app(Config(data_dir=tmp_path / "new"))
    assert (tmp_path / "new" / ".secret_key").exists() and app.state.setup_code is None
    stop(app)
