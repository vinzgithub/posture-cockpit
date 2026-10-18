# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Event generation must not turn missing observations into security claims."""
from __future__ import annotations

from posture_cockpit.core.compare import Snapshot
from posture_cockpit.core.events import derive


def state(check="ok", score=90, coverage=1.0, engine=4, origin="scan"):
    return Snapshot("2026-10-18T18:00:00+00:00", origin, engine, score, coverage,
                    "complete" if coverage >= .90 else "partial", {"tls.cert": check})


def test_regression_and_confirmed_resolution():
    [alert] = derive(state("ok"), state("fail", 70))
    assert (alert.kind, alert.subject, alert.action, alert.severity) == (
        "check", "tls.cert", "open", "critical")
    [fixed] = derive(state("fail", 70), state("ok"))
    assert (fixed.action, fixed.severity) == ("resolve", "info")


def test_partial_improvement_does_not_claim_resolution():
    [change] = derive(state("fail", 50), state("warn", 75))
    assert (change.action, change.severity) == ("downgrade", "warning")


def test_inconclusive_results_do_not_create_or_resolve_security_alert():
    assert derive(state("fail"), state("blocked", coverage=.89)) == (
        # Coverage concerns are separate from the check's security status.
        derive(state("fail"), state("blocked", coverage=.89))[0],
    )
    assert all(item.kind != "check" for item in derive(state("error"), state("ok")))
    assert all(item.kind != "check" for item in derive(state("fail"), state("na")))


def test_incompatible_generation_and_legacy_are_silent():
    assert derive(state(), state("fail", engine=5)) == ()
    assert derive(state(origin="legacy"), state("fail")) == ()


def test_score_drop_without_duplicate_check_alert():
    [only] = derive(state("ok", 95), state("ok", 84))
    assert (only.kind, only.action) == ("score_drop", "open")
    assert all(item.kind != "score_drop" for item in derive(state("ok", 95), state("fail", 70)))


def test_coverage_loss_and_recovery():
    items = derive(state(coverage=1.0), state(coverage=.7))
    assert any(item.kind == "coverage_loss" and item.action == "open" for item in items)
    items = derive(state(coverage=.7), state(coverage=1.0))
    assert any(item.kind == "coverage_loss" and item.action == "resolve" for item in items)


def test_first_state_and_uncomparable_checks_do_not_alert():
    assert derive(None, state("fail")) == ()
    different = Snapshot("2026-10-18T18:00:00Z", "scan", 4, 60, 1.0, "complete", {"new": "fail"})
    assert derive(state(), different) == ()
