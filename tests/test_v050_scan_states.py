# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: the timeline of measured states (scan_states), rows only ever added.

A scan writes its first state when it is saved, and each recheck adds one, in the same
transaction as the change; no state is ever changed or deleted (except with its scan)."""

import asyncio
import json
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from helpers import DEMO, post, setup_account
from posture_cockpit.core import engine, generation, scoring
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.registry import Registry
from posture_cockpit.storage import Database, Scans, schema
from posture_cockpit.storage import scans as scans_module
from test_v050_generation import WORLDS
from worlds import NOW, healthy, one

SOURCE = Path(__file__).parent.parent / "src" / "posture_cockpit"
DMARC = f"_dmarc.{DEMO} TXT"


@pytest.fixture
def signed_in(client):
    setup_account(client)
    return client


def stored(scans: Scans, scan_id: int) -> tuple[dict, list[dict]]:
    row = scans.db.one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    return dict(row), [dict(s) for s in scans.states(scan_id)]


def expected_state(scan: dict, checks: dict) -> dict:
    """What a state holds, deduced from the stored columns of its scan as migration 5 does."""
    return {"engine": scan["engine"], "score": scan["score"], "grade": scan["grade"], "coverage": scan["coverage"],
            "evaluation": schema.stored_evaluation(scan["score"], scan["coverage"], scan["grade_withheld_reason"]),
            "metrics": {**{name: scan[name] for name in schema.METRICS},
                        "cap_reasons": json.loads(scan["cap_reasons"])},
            "checks": checks}


def as_compared(state: dict) -> dict:
    return {**{k: state[k] for k in ("engine", "score", "grade", "coverage", "evaluation")},
            "metrics": json.loads(state["metrics"]), "checks": json.loads(state["checks"])}


def test_a_scan_writes_a_complete_first_state(signed_in):
    post(signed_in, "/domains", "/domains", domain=DEMO)
    scans = signed_in.app.state.services.scans
    scan = scans.latest(scans.domain(DEMO)["id"])
    row, states = stored(scans, scan.id)
    assert len(states) == 1
    [state] = states
    assert (state["origin"], state["at"], state["engine"]) == ("scan", scan.started_at, generation.GENERATION)
    assert row["engine"] == generation.GENERATION
    checks = {f.check_id: f.status.value for f in scan.findings}
    assert len(checks) == 20 and json.loads(state["checks"]) == checks  # every check, its status
    assert as_compared(state) == expected_state(row, checks)
    assert state["evaluation"] == scan.assessment().evaluation == "complete"
    assert (state["score"], state["grade"]) == (57, "C")


def test_each_recheck_adds_a_state_at_its_time_and_the_earlier_ones_never_change(signed_in, world, monkeypatch):
    post(signed_in, "/domains", "/domains", domain=DEMO)
    scans = signed_in.app.state.services.scans
    scan_id = scans.latest_id(scans.domain(DEMO)["id"])
    first = scans.db.all("SELECT * FROM scan_states WHERE scan_id = ?", (scan_id,))
    started = datetime.fromisoformat(first[0]["at"])
    later = [(started + timedelta(hours=n)).isoformat() for n in (1, 2)]
    times = iter(later)
    monkeypatch.setattr(scans_module, "utcnow", lambda: next(times))
    world[DEMO]["dns"][DMARC] = [f"v=DMARC1; p=none; rua=mailto:dmarc@{DEMO}"]
    post(signed_in, f"/domains/{DEMO}/verify/mail.dmarc", f"/domains/{DEMO}")
    world[DEMO]["dns"][DMARC] = [f"v=DMARC1; p=reject; rua=mailto:dmarc@{DEMO}"]
    post(signed_in, f"/domains/{DEMO}/verify/mail.dmarc", f"/domains/{DEMO}")
    row, states = stored(scans, scan_id)
    assert [(s["origin"], s["at"]) for s in states] == [
        ("scan", row["started_at"]), ("recheck", later[0]), ("recheck", later[1])]
    assert [tuple(r) for r in first] == [tuple(r) for r in
                                         scans.db.all("SELECT * FROM scan_states WHERE scan_id = ? AND origin = 'scan'",
                                                      (scan_id,))]  # unchanged, column for column
    statuses = [json.loads(s["checks"])["mail.dmarc"] for s in states]
    assert statuses == ["fail", "warn", "ok"]
    scores = [s["score"] for s in states]
    assert scores[0] == 57 and scores[0] < scores[1] < scores[2] == row["score"]
    checks = {f.check_id: f.status.value for f in scans.get(scan_id).current()}
    assert as_compared(states[-1]) == expected_state(row, checks)  # the last state is the stored scan


def test_a_state_cannot_be_changed(signed_in):
    post(signed_in, "/domains", "/domains", domain=DEMO)
    db = signed_in.app.state.services.db
    for change in ("UPDATE scan_states SET score = 100", "UPDATE scan_states SET checks = '{}'",
                   "UPDATE scan_states SET at = '2000-01-01T00:00:00+00:00'"):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute(change)
    assert db.value("SELECT score FROM scan_states") == 57


def test_the_live_state_and_the_migrated_state_agree_on_every_world(tmp_path):
    """A state written by a scan equals the one migration 5 deduces from the stored columns of the
    same scan: an old scan and a new one are described in the same way."""
    scans = Scans(Database(tmp_path / "posture_cockpit.db"))
    registry = Registry.discover()
    evaluations = set()
    for name, (domain, make) in WORLDS.items():
        result = asyncio.run(engine.scan(domain, registry.checks(), FixtureNetwork(make(), NOW), timeout=5,
                                         now=NOW))
        scan_id = scans.save(scans.add_domain(f"{name.replace('_', '-')}.example", None), result, "0.5.0", None)
        row, [state] = stored(scans, scan_id)
        checks = {f.check_id: f.status.value for f in result.findings}
        assert as_compared(state) == expected_state(row, checks), name
        assert state["evaluation"] == scoring.assess(result.findings).evaluation, name
        evaluations.add(state["evaluation"])
    assert evaluations == {"complete", "partial", "undetermined", "not_evaluated"}


def test_a_recheck_of_a_scan_judged_by_other_rules_has_no_generation(tmp_path):
    scans = Scans(Database(tmp_path / "posture_cockpit.db"))
    result = asyncio.run(engine.scan("example.org", Registry.discover().checks(), FixtureNetwork(healthy(), NOW),
                                     timeout=5, now=NOW))
    scan_id = scans.save(scans.add_domain("example.org", None), result, "0.3.1", None)
    scans.db.execute("UPDATE scans SET engine = NULL WHERE id = ?", (scan_id,))  # as a scan of 0.3.1 after migration
    scans.save_rechecks(scan_id, [one(healthy(), "mail.spf")])
    assert [(s["origin"], s["engine"]) for s in scans.states(scan_id)] == [
        ("scan", generation.GENERATION), ("recheck", None)]


def test_no_code_deletes_or_changes_a_state():
    found = []
    for path in sorted(SOURCE.rglob("*.py")):
        text = path.read_text()
        for pattern in (r"DELETE\s+FROM\s+scan_states", r"UPDATE\s+scan_states", r"DROP\s+TABLE\s+scan_states",
                        r"REPLACE\s+INTO\s+scan_states"):
            found += [f"{path.relative_to(SOURCE)}: {m.group(0)}" for m in re.finditer(pattern, text, re.I)]
    assert found == []


def test_every_scan_has_a_state(signed_in, world):
    post(signed_in, "/domains", "/domains", domain=DEMO)
    post(signed_in, f"/domains/{DEMO}/scan", f"/domains/{DEMO}")
    post(signed_in, f"/domains/{DEMO}/verify/mail.dmarc", f"/domains/{DEMO}")
    db = signed_in.app.state.services.db
    assert db.value("SELECT COUNT(*) FROM scans WHERE id NOT IN (SELECT scan_id FROM scan_states)") == 0
    assert db.value("SELECT COUNT(*) FROM scan_states") == 3
