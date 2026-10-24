# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MC-3 phase 1: synthetic observations, first steps, pure combined scenarios."""
from __future__ import annotations

import copy
import inspect
import json
import socket
from dataclasses import asdict, replace
from unittest.mock import Mock

import pytest

import https_worlds as H
from posture_cockpit.core import engine, scoring
from posture_cockpit.core.extension import Extension
from posture_cockpit.core.model import CREDIT, Effort, Finding, Outcome, Remedy, Role, Status
from posture_cockpit.core.registry import Registry
from posture_cockpit.core.remediation import expected_status
from posture_cockpit.storage import Database, Scans
from worlds import DOMAIN, NOW, changed, healthy, run

REGISTRY = Registry.discover()
ROOT = "web.https_redirect"


def with_status(f, status, remedy=None):
    return replace(f, outcome=Outcome(status, "fixture", remedy=remedy))


def test_t23_dmarc_first_step_is_six_points_not_twelve():
    observations = list(run(changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": []})).values())
    result = scoring.simulate(observations, ["mail.dmarc"], REGISTRY)
    assert result.now.score == 88
    assert result.worst.score == result.best.score == 94
    assert result.worst.coverage == 1
    assert result.assumptions[0].expected is Status.WARN
    assert not result.conditional
    plan = scoring.plan(observations)
    assert plan.priorities[0].gain == 6 and plan.target.score == 94


def test_t24_worst_reads_verdicts_not_cap_floor():
    findings = list(run(H.site({H.V4A: H.REFUSED})).values())
    result = scoring.simulate(findings, [ROOT], REGISTRY)
    assert (result.now.score, result.worst.score, result.best.score) == (79, 66, 100)
    assert result.conditional and len(result.unmeasured) == 10
    # tls.key's cap floor is 1, but its declared worst verdict is FAIL.
    assert REGISTRY.get("tls.key").floor == 1
    assert result.worst.coverage == result.best.coverage == 1
    assert {a.check_id for a in result.assumptions if a.kind == "future_measurement"} == set(result.unmeasured)
    # The model and its assumptions never assert that ERROR cannot happen later.
    errors = [with_status(f, Status.ERROR) if f.role is Role.DEPENDENT else
              with_status(f, Status.OK) if f.check_id == ROOT else f for f in findings]
    assert scoring.assess(errors).partial


@pytest.mark.parametrize("missing", [True, False])
def test_registry_missing_or_without_verdicts_has_announced_fail_fallback(missing):
    findings = list(run(H.site({H.V4A: H.REFUSED})).values())
    registry = Mock()
    registry.get.return_value = None if missing else replace(REGISTRY.get("web.hsts"), verdicts=None)
    result = scoring.simulate(findings, [ROOT], registry)
    assert result.worst.score < 66
    assert result.best.score == 100
    assert len([a for a in result.assumptions if a.kind == "registry_fallback"]) == 10
    assert all(a.expected is Status.FAIL for a in result.assumptions if a.kind == "registry_fallback")
    assert registry.get.call_count == 10


def test_registry_best_uses_allowed_verdict_even_when_ok_is_not_declared():
    findings = list(run(H.site({H.V4A: H.REFUSED})).values())
    registry = Mock()
    registry.get.side_effect = lambda key: replace(REGISTRY.get(key), verdicts=frozenset({Status.WARN}))
    result = scoring.simulate(findings, [ROOT], registry)
    assert result.worst == result.best
    assert result.best.score != 100
    assert scoring.plan(findings, registry).provisional  # identical numbers still depend on a future measurement


def test_only_dependents_missing_by_https_dependency_are_unblocked():
    findings = list(run(H.site({H.V4A: H.REFUSED})).values())
    findings = [replace(f, outcome=Outcome(Status.ERROR, "timeout", evidence={"cause": "network"}))
                if f.check_id == "web.hsts" else f for f in findings]
    result = scoring.simulate(findings, [ROOT], REGISTRY)
    assert "web.hsts" not in result.unmeasured
    assert result.best.coverage < 1
    assert result.best.evaluated == 18


def test_t10_no_score_is_not_zero_or_raw_hundred():
    observations = list(run(changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": []})).values())
    observations = [f if f.check_id == "mail.dmarc" else with_status(f, Status.ERROR) for f in observations]
    result = scoring.simulate(observations, ["mail.dmarc"], REGISTRY)
    assert result.now.score is result.worst.score is result.best.score is None
    assert result.worst.coverage < .5
    assert scoring.plan(observations).priorities[0].gain is None
    for name in ("raw_score", "final_score", "score", "assess", "_assess", "cap_value", "cap_reasons",
                 "withheld_reason"):
        assert "fixed" not in inspect.signature(getattr(scoring, name)).parameters
    assert not hasattr(scoring, "_projected_score")


def test_combined_remedies_are_not_sum_of_standalone_gains():
    observations = list(run(H.site({H.V4A: H.REFUSED},
                                  dns={f"_dmarc.{DOMAIN} TXT": []})).values())
    base = scoring.assess(observations).score
    root = scoring.simulate(observations, [ROOT], REGISTRY)
    dmarc = scoring.simulate(observations, ["mail.dmarc"], REGISTRY)
    both = scoring.simulate(observations, [ROOT, "mail.dmarc"], REGISTRY)
    assert both.worst.score - base != root.worst.score - base + dmarc.worst.score - base
    assert both == scoring.simulate(observations, ["mail.dmarc", ROOT], REGISTRY)


@pytest.mark.parametrize("selection", [["unknown"], [ROOT, ROOT], ["x"] * 21])
def test_invalid_selections_are_rejected(selection):
    with pytest.raises(ValueError):
        scoring.simulate(list(run(healthy()).values()), selection, REGISTRY)


@pytest.mark.parametrize("status", [Status.OK, Status.NA, Status.INFO, Status.ERROR, Status.BLOCKED])
def test_only_problematic_checks_with_a_real_remedy_are_candidates(status):
    f = Finding("example.a", "dns", 1, Outcome(status, "fixture", remedy=Remedy(1, Effort.EASY)))
    with pytest.raises(ValueError):
        scoring.simulate([f], [f.check_id], REGISTRY)
    f = replace(f, outcome=Outcome(Status.FAIL, "fixture"))
    with pytest.raises(ValueError):
        scoring.simulate([f], [f.check_id], REGISTRY)


@pytest.mark.parametrize(("key", "record", "parent"), [
    ("missing", None, None),
    ("invalid", "v=DMARC1; p=invalid", None),
    ("monitoring_inherited", None, "v=DMARC1; p=none; rua=mailto:r@example.net"),
    ("monitoring_no_reports", "v=DMARC1; p=none", None),
    ("malformed", "p=reject; v=DMARC1", None),
])
def test_t29_old_dmarc_json_is_adapted_without_database_migration(key, record, parent):
    data = healthy()
    data["dns"][f"_dmarc.{DOMAIN} TXT"] = [record] if record else []
    if parent:
        data["dns"]["_dmarc.org TXT"] = [parent]
    original = run(data, "mail.dmarc")["mail.dmarc"]
    assert original.outcome.summary == f"mail.dmarc.{key}"
    payload = original.outcome_json()
    payload["remedy"].pop("expect", None)
    frozen = copy.deepcopy(payload)
    decoded = Finding.from_stored(original.check_id, original.category, original.weight, original.status, payload)
    assert expected_status(decoded) is Status.WARN
    assert payload == frozen
    assert decoded.status == original.status
    assert decoded.outcome.evidence == original.outcome.evidence


@pytest.mark.parametrize(("record", "expected"), [
    ("v=DMARC1; p=none; rua=mailto:r@example.org", Status.OK),
    ("v=DMARC1; p=none; rua=mailto:r@example.org; sp=none", Status.WARN),
    ("v=DMARC1; p=reject; t=y; pct=50; rua=mailto:r@example.org", Status.WARN),
    ("v=DMARC1; p=reject; pct=50; sp=none; rua=mailto:r@example.org", Status.WARN),
])
def test_dmarc_next_step_keeps_other_anomalies(record, expected):
    f = run(changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": [record]}), "mail.dmarc")["mail.dmarc"]
    assert expected_status(f) is expected


def test_unknown_historic_action_has_no_numeric_effect():
    payload = {"summary": "oldextension.problem", "remedy": {"minutes": 1, "effort": "easy"}}
    f = Finding.from_stored("oldextension.a", "dns", 1, "fail", payload)
    result = scoring.simulate([f], [f.check_id], REGISTRY)
    assert result.unknown == (f.check_id,)
    assert result.worst.score is result.best.score is None
    assert scoring.plan([f]).priorities[0].gain is None


def test_explicit_expectation_roundtrip_and_default_omission():
    for expectation in (Status.OK, Status.WARN, Status.INFO, None):
        f = Finding("extension.a", "dns", 1,
                    Outcome(Status.FAIL, "extension.problem", remedy=Remedy(1, Effort.EASY, expect=expectation)))
        payload = f.outcome_json()
        assert ("expect" in payload["remedy"]) == (expectation is not Status.OK)
        if expectation is not Status.OK:
            assert Finding.from_stored(f.check_id, f.category, f.weight, f.status, payload) == f
    with pytest.raises(ValueError):
        Remedy(1, Effort.EASY, expect="ok")


def test_t12_fifty_simulations_have_no_network_or_database_writes(tmp_path, monkeypatch):
    findings = list(run(H.site({H.V4A: H.REFUSED})).values())
    original = copy.deepcopy(findings)
    db = Database(tmp_path / "isolated.db")
    scans = Scans(db)
    domain_id = scans.add_domain(DOMAIN, None)
    scan_id = scans.save(domain_id, engine.ScanResult(DOMAIN, NOW, 1, findings), "0.5.0", None)
    scans.save_recheck(scan_id, findings[0])
    db.execute("INSERT INTO events(domain_id,category,kind,subject,state,severity,opened_at,updated_at) "
               "VALUES(?,'security','check','fixture','open','warning',?,?)", (domain_id, NOW.isoformat(),
                                                                            NOW.isoformat()))
    before = list(db._conn.iterdump())
    monkeypatch.setattr(socket.socket, "connect", Mock(side_effect=AssertionError("network forbidden")))
    monkeypatch.setattr(socket, "getaddrinfo", Mock(side_effect=AssertionError("DNS forbidden")))
    monkeypatch.setattr(Database, "execute", Mock(side_effect=AssertionError("write forbidden")))
    monkeypatch.setattr(Registry, "discover", Mock(side_effect=AssertionError("discovery forbidden")))
    for _ in range(50):
        assert scoring.simulate(findings, [ROOT], REGISTRY).worst.score == 66
    assert findings == original
    assert list(db._conn.iterdump()) == before
    assert not socket.socket.connect.called and not socket.getaddrinfo.called
    assert not Database.execute.called
    db.close()


def test_hypothetical_outcomes_do_not_copy_observational_proofs(monkeypatch):
    observations = list(run(changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": []})).values())
    captured = []
    assess = scoring.assess

    def watch(findings):
        captured.extend(f for f in findings if f.outcome.summary == "simulation.hypothesis")
        return assess(findings)

    monkeypatch.setattr(scoring, "assess", watch)
    scoring.simulate(observations, ["mail.dmarc"], REGISTRY)
    assert len(captured) == 2
    assert all(not f.outcome.evidence and not f.outcome.params and not f.outcome.signals for f in captured)
    assert all(f.outcome.remedy is None for f in captured)


def test_registry_is_read_only_and_observation_metadata_survives():
    ext = Extension("extra", name="extra", version="1")

    @ext.check("thing", category="dns", weight=2, requires="https", verdicts=(Status.OK, Status.FAIL))
    async def thing(ctx):
        raise AssertionError("a check must never run during simulation")

    registry = Registry([ext])
    dependent = engine.finding(registry.get("extra.thing"), Outcome(Status.BLOCKED, "fixture"))
    root = engine.finding(REGISTRY.get(ROOT), Outcome(Status.FAIL, "fixture", remedy=Remedy(1, Effort.EASY)))
    before = json.dumps(asdict(dependent), default=str, sort_keys=True)
    scoring.simulate([root, dependent], [ROOT], registry)
    assert json.dumps(asdict(dependent), default=str, sort_keys=True) == before
    assert registry.get("extra.thing").verdicts == frozenset({Status.OK, Status.FAIL})
    assert registry.get("extra.thing").floor == CREDIT[Status.OK]
