# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.4.1 on databases made by the real code of v0.3.0 (schema 3) and v0.4.0 (schema 4).

The dumps come from tests/data/make_legacy_databases.py, run with the code of each release."""

import io
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from helpers import DEMO, log_in
from posture_cockpit.config import Config
from posture_cockpit.storage import backup
from posture_cockpit.web.app import create_app
from worlds import DOMAIN

DATA = Path(__file__).parent / "data"
TOKEN = "legacy-api-token-for-tests-0123456789"


def legacy(tmp_path, version):
    folder = tmp_path / version
    folder.mkdir()
    with sqlite3.connect(folder / "posture_cockpit.db") as conn:
        conn.executescript((DATA / f"database-{version}.sql").read_text())
    return folder


def rows(path):
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {t: [dict(r) for r in conn.execute(f"SELECT * FROM {t} ORDER BY rowid")]  # noqa: S608
                for t in tables}


@pytest.mark.parametrize(("version", "schema"), [("v0.3.0", 3), ("v0.4.0", 4)])
def test_existing_databases_open_unchanged_and_work(tmp_path, version, schema):
    folder = legacy(tmp_path, version)
    assert backup.schema_of(folder / "posture_cockpit.db") == schema
    before = rows(folder / "posture_cockpit.db")
    app = create_app(Config(data_dir=folder))
    assert app.state.setup_code is None  # accounts exist: no setup code, no change of behaviour
    after = rows(folder / "posture_cockpit.db")
    for table, old_rows in before.items():
        if table == "meta":
            continue
        assert len(after[table]) == len(old_rows), table
        for old, new in zip(old_rows, after[table], strict=True):
            assert {k: new[k] for k in old} == old, table  # existing columns untouched
    assert backup.schema_of(folder / "posture_cockpit.db") == 5
    copies = list((folder / "backups").glob("*.db")) if (folder / "backups").exists() else []
    assert len(copies) == (1 if schema < 5 else 0)  # a copy is made before migrating, only then

    with TestClient(app) as client:
        assert log_in(client).status_code == 303
        for path in ("/domains", f"/domains/{DEMO}", f"/domains/{DEMO}/history", f"/domains/{DOMAIN}",
                     f"/domains/{DEMO}/details", f"/domains/{DEMO}/history/1"):
            assert client.get(path).status_code == 200, path
        pdf = client.get(f"/domains/{DEMO}/report.pdf")
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-")
        api = client.get("/api/v1/domains", headers={"Authorization": f"Bearer {TOKEN}"})
        assert api.status_code == 200
        summaries = {d["domain"]: d for d in api.json()["domains"]}
        stored = {r["id"]: r for r in after["scans"]}
        for d in summaries.values():
            assert {"score", "grade", "coverage", "evaluation"} <= set(d)
        latest = max((s for s in stored.values() if s["domain_id"] == 1), key=lambda s: s["started_at"])
        assert summaries[DEMO]["score"] == latest["score"] and summaries[DEMO]["grade"] == latest["grade"]


@pytest.mark.parametrize("version", ["v0.3.0", "v0.4.0"])
def test_backup_and_restore_of_a_migrated_instance(tmp_path, version):
    folder = legacy(tmp_path, version)
    app = create_app(Config(data_dir=folder))
    out = io.BytesIO()
    manifest = backup.create(folder, out)
    assert manifest["counts"] == {"users": 2, "domains": 2, "scans": 2}
    app.state.services.db.close()
    out.seek(0)
    backup.restore(tmp_path / "restored", out)
    restored = create_app(Config(data_dir=tmp_path / "restored"))
    with TestClient(restored) as client:
        assert log_in(client).status_code == 303
        assert DEMO in client.get("/domains").text


def test_a_schema_3_backup_restored_into_0_4_1_is_migrated_at_start(tmp_path):
    folder = legacy(tmp_path, "v0.3.0")
    out = io.BytesIO()
    assert backup.create(folder, out)["schema"] == 3  # made without starting the instance
    out.seek(0)
    backup.restore(tmp_path / "new", out)
    app = create_app(Config(data_dir=tmp_path / "new"))
    assert app.state.services.db.schema_version == 5
    with TestClient(app) as client:
        assert log_in(client).status_code == 303
