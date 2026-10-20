# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.4.1: what stops the start, with a message that says what to do."""

import logging
import os
import sqlite3
import stat

import pytest

from posture_cockpit.config import Config, StartupError, prepare_data_dir, secret_key
from posture_cockpit.storage import Database, UnsupportedSchema
from posture_cockpit.storage.schema import MIGRATIONS
from posture_cockpit.web.app import create_app


def test_schema_5_is_the_schema_of_0_5_0():
    # 0.4.1 added no migration; 0.5.0 adds the fifth: the images 0.4.x refuse a database once it is
    # migrated, going back to them means restoring the backup made before (docs/user/INSTALLATION.md).
    assert len(MIGRATIONS) == 5


def new_db(tmp_path):
    db = Database(tmp_path / "posture_cockpit.db")
    db.close()
    return tmp_path / "posture_cockpit.db"


@pytest.mark.parametrize("found", [6, 99])
def test_a_newer_schema_is_refused_and_left_untouched(tmp_path, found):
    path = new_db(tmp_path)
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", (str(found),))
    before = path.read_bytes()
    with pytest.raises(UnsupportedSchema, match=f"schema {found}; this version of Posture Cockpit handles schema 5"):
        Database(path)
    assert path.read_bytes() == before and not (tmp_path / "backups").exists()


def test_an_unreadable_schema_version_is_refused(tmp_path):
    path = new_db(tmp_path)
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE meta SET value = 'quatre' WHERE key = 'schema_version'")
    with pytest.raises(StartupError, match="unreadable schema version"):
        Database(path)


def test_a_file_that_is_not_a_database_is_refused(tmp_path):
    (tmp_path / "posture_cockpit.db").write_bytes(b"not a database" * 100)
    with pytest.raises(StartupError, match="cannot be opened"):
        Database(tmp_path / "posture_cockpit.db")


def test_the_application_logs_why_it_cannot_start(tmp_path, caplog):
    path = new_db(tmp_path)
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE meta SET value = '7' WHERE key = 'schema_version'")
    with caplog.at_level(logging.ERROR, logger="uvicorn.error"), pytest.raises(UnsupportedSchema):
        create_app(Config(data_dir=tmp_path))
    assert "Posture Cockpit cannot start" in caplog.text and "schema 7" in caplog.text


def test_a_data_path_that_is_a_file_is_refused(tmp_path):
    (tmp_path / "data").write_text("")
    with pytest.raises(StartupError, match=r"not a folder|cannot be written"):
        prepare_data_dir(tmp_path / "data")


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root writes everywhere")
def test_an_unwritable_data_folder_says_how_to_fix_it(tmp_path):
    folder = tmp_path / "data"
    folder.mkdir()
    folder.chmod(0o500)
    try:
        with pytest.raises(StartupError, match=r"chown -R \d+:\d+ <folder>"):
            prepare_data_dir(folder)
    finally:
        folder.chmod(0o700)


def test_the_session_key_is_kept_and_restricted_to_its_owner(tmp_path):
    key = secret_key(tmp_path)
    path = tmp_path / ".secret_key"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and len(key) >= 32
    path.chmod(0o644)
    assert secret_key(tmp_path) == key and stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("content", ["", "   \n", "short"])
def test_an_empty_or_truncated_session_key_stops_the_start(tmp_path, content):
    (tmp_path / ".secret_key").write_text(content)
    with pytest.raises(StartupError, match="empty or damaged"):
        secret_key(tmp_path)
