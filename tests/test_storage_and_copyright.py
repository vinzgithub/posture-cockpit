# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Database migrations and rechecks; the copyright notice in every source file."""

import asyncio
import sqlite3
from pathlib import Path

import pytest

from posture_cockpit.core import engine, scoring
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.registry import Registry
from posture_cockpit.storage import Database, Scans
from posture_cockpit.storage.schema import MIGRATIONS
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


def test_migrations_may_be_python_and_keep_semicolons_in_strings(tmp_path):
    def fill(conn):
        conn.execute("INSERT INTO a(x) VALUES ('from python')")

    db = Database(tmp_path / "db.sqlite", ["CREATE TABLE a (x); INSERT INTO a VALUES ('one; two') -- a; comment", fill])
    assert [r["x"] for r in db.all("SELECT x FROM a ORDER BY rowid")] == ["one; two", "from python"]


def test_a_migration_that_breaks_references_is_rolled_back(tmp_path):
    db = Database(tmp_path / "db.sqlite", [
        "CREATE TABLE parent (id INTEGER PRIMARY KEY); "
        "CREATE TABLE child (parent_id INTEGER NOT NULL REFERENCES parent(id) ON DELETE CASCADE); "
        "INSERT INTO parent VALUES (1); INSERT INTO child VALUES (1)"])
    # Foreign keys are off during migrations (to rebuild tables), so this delete would orphan the child row.
    with pytest.raises(sqlite3.IntegrityError, match="broken references"):
        db._migrate([*["-- 1"], "DELETE FROM parent"])
    assert db.schema_version == 1 and db.value("SELECT COUNT(*) FROM parent") == 1
    assert db.value("PRAGMA foreign_keys") == 1  # switched on again


def test_upgrade_from_0_1_0_keeps_the_data_and_a_backup(tmp_path):
    path = tmp_path / "posture_cockpit.db"
    old = Database(path, MIGRATIONS[:1])
    old.execute("INSERT INTO users(username, pw_hash, created_at, is_admin) VALUES('vincent', 'x', '2026-01-01', 1)")
    old.execute("INSERT INTO domains(name, created_at) VALUES('example.org', '2026-01-01')")
    finding = "INSERT INTO findings VALUES(?, ?, ?, ?, ?, '{\"summary\": \"x\"}')"
    # Scan 1: an ordinary scan, scored 75/B by 0.1.0.
    old.execute("INSERT INTO scans(domain_id, started_at, duration_ms, score, grade, version) "
                "VALUES(1, '2026-01-02T10:00:00+00:00', 900, 75, 'B', '0.1.0')")
    old.execute(finding, (1, "mail.dmarc", "mail", 10, "warn"))
    old.execute(finding, (1, "tls.certificate", "tls", 10, "ok"))
    # Scan 2: almost nothing could be checked, and 0.1.0 said 100/A.
    old.execute("INSERT INTO scans(domain_id, started_at, duration_ms, score, grade, version) "
                "VALUES(1, '2026-01-03T10:00:00+00:00', 900, 100, 'A', '0.1.0')")
    old.execute(finding, (2, "tls.certificate", "tls", 10, "error"))
    old.execute(finding, (2, "web.hsts", "web", 6, "error"))
    old.execute(finding, (2, "dns.caa", "dns", 2, "ok"))
    old.execute("INSERT INTO rechecks VALUES(1, 'mail.dmarc', 'warn', '{\"summary\": \"y\"}', '2026-01-03')")
    old.close()

    db = Database(path)
    assert db.schema_version == len(MIGRATIONS)
    assert db.value("SELECT username FROM users") == "vincent"
    assert dict(db.one("SELECT name, perimeter_id FROM domains")) == {"name": "example.org", "perimeter_id": None}
    assert db.value("SELECT COUNT(*) FROM findings") == 5 and db.value("SELECT COUNT(*) FROM rechecks") == 1
    rows = [dict(r) for r in db.all("SELECT id, score, grade, coverage, perimeter FROM scans ORDER BY id")]
    assert rows[0] == {"id": 1, "score": 75, "grade": "B", "coverage": 1.0, "perimeter": ""}  # unchanged
    assert rows[1]["score"] is None and rows[1]["grade"] is None                              # not evaluated
    assert rows[1]["coverage"] == pytest.approx(2 / 18)
    assert Scans(db).get(1).assessment().score == 75

    backups = list((tmp_path / "backups").glob("posture_cockpit-schema1-*.db"))
    assert len(backups) == 1
    copy = sqlite3.connect(backups[0])
    assert copy.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone() == ("1",)
    assert copy.execute("SELECT score, grade FROM scans WHERE id = 2").fetchone() == (100, "A")  # as it was
    copy.close()
    for file in (path, backups[0]):
        assert file.stat().st_mode & 0o777 == 0o600, file


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
    assert scans.save_recheck(scan_id, fixed.findings[0]).score == 100
    after = scans.get(scan_id)
    assert after.score == 100 and after.grade == "A" and after.coverage == 1.0
    assert after.assessment() == scoring.assess(after.current())  # what is stored is what is computed
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
