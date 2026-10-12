# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Database migrations and rechecks; the copyright notice in every source file."""

import asyncio
import sqlite3
from pathlib import Path

import pytest

from posture_cockpit.core import engine
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.registry import Registry
from posture_cockpit.storage import Database, Scans
from worlds import DOMAIN, NOW, changed, healthy

ROOT = Path(__file__).resolve().parents[1]
NOTICE = "Copyright © 2026 Vincent Fournet"
SPDX = "SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0"


def test_migrations_run_once_and_in_order(tmp_path):
    path = tmp_path / "db.sqlite"
    db = Database(path, ["CREATE TABLE a (x)", "CREATE TABLE b (y)"])
    assert db.schema_version == 2
    db.close()
    db = Database(path, ["CREATE TABLE a (x)", "CREATE TABLE b (y)", "ALTER TABLE a ADD COLUMN z"])
    assert db.schema_version == 3
    assert [r["name"] for r in db.all("PRAGMA table_info(a)")] == ["x", "z"]


def test_a_failed_migration_changes_nothing(tmp_path):
    db = Database(tmp_path / "db.sqlite", ["CREATE TABLE a (x)"])
    with pytest.raises(sqlite3.OperationalError):
        db._migrate(["CREATE TABLE a (x)", "CREATE TABLE c (x); THIS IS NOT SQL"])
    assert db.schema_version == 1
    assert db.one("SELECT name FROM sqlite_master WHERE name = 'c'") is None


def test_rechecks_update_the_score_but_keep_the_scan(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    scans = Scans(db)
    registry = Registry.discover()
    broken = changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": None})
    result = asyncio.run(engine.scan(DOMAIN, registry.checks(), FixtureNetwork(broken, NOW), now=NOW))
    scan_id = scans.save(scans.add_domain(DOMAIN, None), result, "test", None)
    before = scans.get(scan_id)
    assert before.score < 100
    fixed = asyncio.run(engine.scan(DOMAIN, [registry.get("mail.dmarc")], FixtureNetwork(healthy(), NOW), now=NOW))
    assert scans.save_recheck(scan_id, fixed.findings[0]) == 100
    after = scans.get(scan_id)
    assert after.score == 100 and after.grade == "A"
    assert next(f for f in after.findings if f.check_id == "mail.dmarc").status.value == "fail"  # original kept
    assert next(f for f in after.current() if f.check_id == "mail.dmarc").status.value == "ok"


def source_files():
    for name in ("Dockerfile", "compose.yaml"):
        if (ROOT / name).exists():
            yield ROOT / name
    for folder in ("src/posture_cockpit", "tests", "examples", ".github"):
        for path in (ROOT / folder).rglob("*"):
            if path.suffix in {".py", ".js", ".css", ".html", ".yml", ".yaml"} and "__pycache__" not in path.parts:
                yield path


def test_every_source_file_has_the_notice():
    missing = [str(p.relative_to(ROOT)) for p in source_files()
               if NOTICE not in (text := p.read_text(encoding="utf-8")) or SPDX not in text]
    assert missing == []


def test_the_notice_shows_in_the_footer(client):
    page = client.get("/setup").text
    assert "© 2026 Vincent Fournet" in page
    assert "Copyright" not in page  # template comments are never sent
