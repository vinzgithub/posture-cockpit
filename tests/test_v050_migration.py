# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: migration 5 on the databases made by the real code of v0.3.0, v0.4.0 and v0.4.1.

Additive only: every table and column that existed keeps every row and value; scans get their
origin (unknown: NULL) and the generation of their rules (exact versions only); each scan gets
one state made of its stored values, never recalculated."""

import json
import multiprocessing
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from helpers import DEMO, log_in, page_csrf
from posture_cockpit.config import Config
from posture_cockpit.core import generation, scoring
from posture_cockpit.security import totp_at, totp_step
from posture_cockpit.storage import backup, open_database, schema
from posture_cockpit.storage.database import Database
from posture_cockpit.storage.schema import MIGRATIONS
from posture_cockpit.web.app import create_app
from worlds import DOMAIN

DATA = Path(__file__).parent / "data"
TOKEN = "legacy-api-token-for-tests-0123456789"
TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"  # of the administrator, database of v0.4.1
VERSIONS = {"v0.3.0": 3, "v0.4.0": 4, "v0.4.1": 4}
NEW_TABLES = {"schedules", "schedule_runs", "scan_states", "events"}


def legacy(folder: Path, version: str) -> Path:
    folder.mkdir(parents=True)
    with sqlite3.connect(folder / "posture_cockpit.db") as conn:
        conn.executescript((DATA / f"database-{version}.sql").read_text())
    return folder / "posture_cockpit.db"


def content(path: Path) -> dict[str, list[dict]]:
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {t: [dict(r) for r in conn.execute(f"SELECT * FROM {t} ORDER BY rowid")]  # noqa: S608
                for t in tables}


def no_scoring(monkeypatch):
    """Makes any call to the code of the scoring fail."""
    def refused(*args, **kwargs):
        raise AssertionError("the migration called the code of the scoring")
    for name in ("assess", "_assess", "plan", "counts", "grade"):
        monkeypatch.setattr(scoring, name, refused)


@pytest.mark.parametrize("version", VERSIONS)
def test_every_existing_row_and_value_is_kept_and_nothing_is_recalculated(tmp_path, monkeypatch, version):
    path = legacy(tmp_path / version, version)
    assert backup.schema_of(path) == VERSIONS[version]
    before = content(path)
    with monkeypatch.context() as patched:
        no_scoring(patched)
        db = Database(path)
        try:
            assert db.schema_version == 5 and db.all("PRAGMA foreign_key_check") == []
            assert db.value("PRAGMA integrity_check") == "ok"
        finally:
            db.close()
    after = content(path)
    assert set(after) - set(before) == NEW_TABLES
    for table, rows in before.items():
        if table == "meta":
            assert {r["key"]: r["value"] for r in after["meta"]} == {
                **{r["key"]: r["value"] for r in rows}, "schema_version": "5"}
            continue
        assert len(after[table]) == len(rows), table
        for old, new in zip(rows, after[table], strict=True):
            assert {k: new[k] for k in old} == old, table  # every existing column, every value
    for scan in after["scans"]:
        assert scan["via"] is None
        assert scan["engine"] == {"0.4.0": 4, "0.4.1": 4}.get(scan["version"])
    assert all(user["events_seen_at"] is None for user in after["users"])
    assert after["schedules"] == after["schedule_runs"] == after["events"] == []


@pytest.mark.parametrize("version", VERSIONS)
def test_each_scan_gets_one_state_made_of_its_stored_values(tmp_path, version):
    path = legacy(tmp_path / version, version)
    Database(path).close()
    data = content(path)
    states = {s["scan_id"]: s for s in data["scan_states"]}
    assert len(data["scan_states"]) == len(data["scans"]) == len(states)  # one, and only one, per scan
    rechecked = {r["scan_id"] for r in data["rechecks"]}
    assert rechecked  # every legacy database holds a rechecked scan
    for scan in data["scans"]:
        state = states[scan["id"]]
        if scan["id"] in rechecked:
            # No state for the moment of the scan: its values were overwritten by the recheck.
            assert state["origin"] == "legacy"
            assert state["at"] == max(r["checked_at"] for r in data["rechecks"] if r["scan_id"] == scan["id"])
        else:
            assert (state["origin"], state["at"]) == ("scan", scan["started_at"])
        assert (state["score"], state["grade"], state["coverage"], state["engine"]) == (
            scan["score"], scan["grade"], scan["coverage"], scan["engine"])
        assert json.loads(state["metrics"]) == {
            **{name: scan[name] for name in schema.METRICS},
            "cap_reasons": json.loads(scan["cap_reasons"]) if scan["cap_reasons"] is not None else None}
        checks = {f["check_id"]: f["status"] for f in data["findings"] if f["scan_id"] == scan["id"]}
        checks.update({r["check_id"]: r["status"] for r in data["rechecks"]
                       if r["scan_id"] == scan["id"] and r["check_id"] in checks})
        assert json.loads(state["checks"]) == checks
    assert not any(s["origin"] == "scan" for s in data["scan_states"] if s["scan_id"] in rechecked)


def test_the_stored_evaluation_is_the_one_the_application_gives(tmp_path):
    """The evaluation of each state, deduced from the stored columns, equals the evaluation the
    API computes from the findings for the same scan (database of v0.4.1: every case)."""
    path = legacy(tmp_path / "v0.4.1", "v0.4.1")
    app = create_app(Config(data_dir=tmp_path / "v0.4.1"))
    try:
        with TestClient(app) as client:
            given = {d["domain"]: d["evaluation"] for d in client.get(
                "/api/v1/domains", headers={"Authorization": f"Bearer {TOKEN}"}).json()["domains"]}
    finally:
        app.state.services.db.close()
    with sqlite3.connect(path) as conn:
        stored = dict(conn.execute("SELECT d.name, st.evaluation FROM scan_states st JOIN scans s ON s.id = st.scan_id "
                                   "JOIN domains d ON d.id = s.domain_id").fetchall())
    assert stored == given
    assert set(stored.values()) == {"complete", "undetermined", "not_evaluated"}


@pytest.mark.parametrize("version", VERSIONS)
def test_pages_pdf_and_api_work_on_a_migrated_database(tmp_path, version):
    legacy(tmp_path / version, version)
    app = create_app(Config(data_dir=tmp_path / version))
    try:
        with TestClient(app) as client:
            signed_in = log_in(client)
            if signed_in.headers["location"] == "/login/code":  # two-factor authentication (v0.4.1)
                signed_in = client.post("/login/code", data={"csrf": page_csrf(client, "/login/code"),
                                                             "code": totp_at(TOTP_SECRET, totp_step())},
                                        follow_redirects=False)
            assert signed_in.status_code == 303 and signed_in.headers["location"] == "/domains"
            assert DEMO in client.get("/domains").text
            for page in ("/domains", f"/domains/{DEMO}", f"/domains/{DEMO}/history", f"/domains/{DOMAIN}",
                         f"/domains/{DEMO}/details", f"/domains/{DEMO}/history/1"):
                assert client.get(page).status_code == 200, page
            pdf = client.get(f"/domains/{DEMO}/report.pdf")
            assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-")
            assert client.get("/api/v1/domains", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200
    finally:
        app.state.services.db.close()


def test_a_migration_that_fails_leaves_schema_4_intact(tmp_path):
    path = legacy(tmp_path / "v0.4.1", "v0.4.1")
    Database(path, MIGRATIONS[:4]).close()
    before = content(path)

    def fails_at_the_end(conn):
        schema._schema_5(conn)
        raise sqlite3.OperationalError("disk I/O error (injected)")

    with pytest.raises(Exception, match="injected"):
        Database(path, [*MIGRATIONS[:4], fails_at_the_end])
    assert backup.schema_of(path) == 4
    assert content(path) == before  # no new table, no new column, no state


def test_the_generations_frozen_in_the_migration_are_those_of_core_generation():
    assert {v: g for v, g in generation.RELEASED.items() if v < "0.5"} == schema.GENERATIONS_OF_SCHEMA_4
    assert schema.FULL_COVERAGE_OF_SCHEMA_4 == scoring.FULL_COVERAGE


def start_instance(folder: str, barrier, results) -> None:
    """One process starting on the data folder with the real migrations (run by multiprocessing)."""
    try:
        barrier.wait(timeout=30)
        db = open_database(Config(data_dir=Path(folder)))
        results.put(("started", db.schema_version))
        db.close()
    except BaseException as error:  # reported by the test
        results.put(("failed", repr(error)))


def test_two_processes_starting_together_migrate_once(tmp_path):
    path = legacy(tmp_path / "a", "v0.4.1")
    Database(path, MIGRATIONS[:4]).close()  # in WAL mode, as an instance always is
    context = multiprocessing.get_context("spawn")
    barrier, results = context.Barrier(2), context.Queue()
    processes = [context.Process(target=start_instance, args=(str(tmp_path / "a"), barrier, results))
                 for _ in range(2)]
    for process in processes:
        process.start()
    outcomes = [results.get(timeout=60) for _ in processes]
    for process in processes:
        process.join(timeout=30)
    assert outcomes == [("started", 5), ("started", 5)]
    data = content(path)
    assert len(data["scan_states"]) == len(data["scans"]) == 5  # the states were not added twice
