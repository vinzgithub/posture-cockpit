# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.4.1, counter-review point 5: what an existing installation must find unchanged."""

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from helpers import log_in
from posture_cockpit.config import Config
from posture_cockpit.web.app import create_app
from posture_cockpit.web.routes.api import _summary

DATA = Path(__file__).parent / "data"
SETTINGS = ["NAMESERVERS", "DATA_DIR", "COOKIE_SECURE", "FRAME_ANCESTORS", "DEFAULT_LOCALE", "SESSION_MAX_AGE",
            "CHECK_TIMEOUT", "INTERNAL_SCANS", "MAX_CONCURRENT_SCANS", "SCANS_PER_HOUR", "SESSION_COOKIE",
            "SETUP_CODE", "DKIM_SELECTORS", "TIMEZONE"]


@pytest.mark.parametrize("empty", ["", "   "])
def test_empty_settings_keep_their_defaults(monkeypatch, empty):
    """A .env line left empty (NAME=) must behave as no line at all: in 0.4.0, an empty
    POSTURE_COCKPIT_FRAME_ANCESTORS broke the CSP and an empty number stopped the start."""
    for name in SETTINGS:
        monkeypatch.delenv(f"POSTURE_COCKPIT_{name}", raising=False)
    monkeypatch.delenv("TZ", raising=False)
    defaults = Config.from_env()
    for name in SETTINGS:
        monkeypatch.setenv(f"POSTURE_COCKPIT_{name}", empty)
    assert Config.from_env() == defaults
    assert defaults.frame_ancestors == "'self'" and defaults.max_concurrent_scans == 4 and defaults.setup_code == ""


def test_set_values_are_still_read(monkeypatch):
    monkeypatch.setenv("POSTURE_COCKPIT_FRAME_ANCESTORS", "https://ha.example.org")
    monkeypatch.setenv("POSTURE_COCKPIT_COOKIE_SECURE", "true")
    monkeypatch.setenv("POSTURE_COCKPIT_MAX_CONCURRENT_SCANS", "2")
    config = Config.from_env()
    assert (config.frame_ancestors, config.cookie_secure, config.max_concurrent_scans) == (
        "https://ha.example.org", True, 2)


def structure(path):
    with sqlite3.connect(path) as conn:
        tables = conn.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").fetchall()
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    return tables, meta


def test_a_0_4_0_database_keeps_its_structure_for_a_rollback(tmp_path):
    """0.4.1 adds no table, column, index nor meta key to a 0.4.0 database: the 0.4.0 image opens
    it again as it left it (the CI starts it again: tests.yml, upgrade (v0.4.0))."""
    with sqlite3.connect(tmp_path / "posture_cockpit.db") as conn:
        conn.executescript((DATA / "database-v0.4.0.sql").read_text())
    before = structure(tmp_path / "posture_cockpit.db")
    app = create_app(Config(data_dir=tmp_path))
    with TestClient(app) as client:
        assert log_in(client).status_code == 303
        client.get("/domains")
    app.state.services.db.close()
    assert structure(tmp_path / "posture_cockpit.db") == before
    assert not (tmp_path / "backups").exists()  # nothing migrated, so no copy either


# The fields of /api/v1/domains in 0.4.0: none removed, none added, same types (precision aside).
API_FIELDS = {
    "domain": str, "score": (int, type(None)), "grade": (str, type(None)), "evaluation": str, "coverage": float,
    "diagnostic_coverage": (float, type(None)), "checks_blocked": (int, type(None)),
    "score_raw": (float, type(None)), "score_cap": (float, type(None)), "score_final": (float, type(None)),
    "cap_reasons": list, "grade_withheld_reason": (str, type(None)), "addresses": dict,
    "addresses_discovered": (int, type(None)), "addresses_attempted": (int, type(None)),
    "addresses_conclusive": (int, type(None)), "address_sampling_limited": (bool, type(None)),
    "address_discovery_complete": (bool, type(None)), "checks_evaluated": int, "checks_applicable": int,
    "scanned_at": str, "perimeter": (str, type(None)), "critical": int, "to_improve": int, "not_evaluated": int,
    "certificate_days_left": (int, type(None)),
}


@pytest.mark.parametrize("version", ["v0.3.0", "v0.4.0"])
def test_the_api_contract_is_the_one_of_0_4_0(tmp_path, version):
    with sqlite3.connect(tmp_path / "posture_cockpit.db") as conn:
        conn.executescript((DATA / f"database-{version}.sql").read_text())
    app = create_app(Config(data_dir=tmp_path))
    scans = app.state.services.scans
    for row in scans.domains(internal=True):
        summary = _summary(scans.get(row["scan_id"]))
        assert set(summary) == set(API_FIELDS)
        for name, kind in API_FIELDS.items():
            assert isinstance(summary[name], kind), (name, summary[name])
        for ratio in ("coverage", "diagnostic_coverage"):
            assert summary[ratio] is None or summary[ratio] == round(summary[ratio], 3)
    app.state.services.db.close()
