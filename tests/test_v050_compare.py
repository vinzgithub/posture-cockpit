# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Contract for conservative v0.5.0 comparisons, without network or database I/O."""

import json

import pytest

from posture_cockpit.core.compare import Snapshot, compare, compare_check


def state(
    score=80, *, at="2026-10-17T10:00:00+00:00", origin="scan",
    engine=4, coverage=1.0, evaluation="complete", checks=None,
):
    return Snapshot(
        at=at, origin=origin, engine=engine, score=score, coverage=coverage,
        evaluation=evaluation, checks=checks if checks is not None else {"mail.spf": "ok", "mail.dmarc": "fail"},
    )


def test_first_state_has_no_comparison():
    result = compare(None, state())
    assert not result.comparable and result.reason == "no_previous"
    assert result.score_delta is None and result.reference_at is None


@pytest.mark.parametrize(("override", "reason"), [
    ({"origin": "legacy"}, "legacy"),
    ({"engine": None}, "engine"),
    ({"engine": 3}, "engine"),
    ({"checks": {"mail.spf": "ok"}}, "checks"),
    ({"score": None, "evaluation": "not_evaluated"}, "not_evaluated"),
    ({"evaluation": "undetermined"}, "undetermined"),
    ({"coverage": 0.89, "evaluation": "partial"}, "partial"),
])
def test_uncomparable_states_never_expose_delta(override, reason):
    previous = state()
    current = state(**override, at="2026-10-18T10:00:00+00:00")
    result = compare(previous, current)
    assert result.comparable is False
    assert result.reason == reason
    assert result.score_delta is None
    assert result.changes == ()


def test_historical_legacy_is_not_claimed_to_have_original_score():
    result = compare(state(origin="legacy"), state(score=92))
    assert not result.comparable and result.reason == "legacy"


def test_comparable_score_and_conclusive_changes():
    result = compare(
        state(score=70),
        state(score=82, at="2026-10-18T10:00:00+00:00", checks={"mail.spf": "ok", "mail.dmarc": "warn"}),
    )
    assert result.comparable and result.reason is None
    assert result.reference_at == "2026-10-17T10:00:00+00:00"
    assert result.score_delta == 12
    assert [(c.check_id, c.kind) for c in result.changes] == [("mail.dmarc", "improved")]


@pytest.mark.parametrize(("before", "after", "kind"), [
    ("fail", "warn", "improved"),
    ("warn", "ok", "improved"),
    ("ok", "fail", "regressed"),
    ("warn", "fail", "regressed"),
    ("fail", "na", "not_applicable"),
    ("na", "fail", "new_issue"),
    ("na", "ok", "unchanged"),
    ("error", "ok", "unmeasured"),
    ("fail", "error", "unmeasured"),
    ("blocked", "fail", "unmeasured"),
    ("fail", "blocked", "unmeasured"),
])
def test_check_transitions(before, after, kind):
    assert compare_check("tls.certificate", before, after).kind == kind


def test_snapshot_reads_json_without_recalculation():
    snapshot = Snapshot.from_row({
        "at": "2026-10-17", "origin": "recheck", "engine": 4, "score": 77,
        "coverage": 0.97, "evaluation": "complete",
        "checks": json.dumps({"mail.spf": "ok"}),
    })
    assert snapshot.score == 77 and snapshot.checks == {"mail.spf": "ok"}


def test_corrupted_check_statuses_are_refused():
    with pytest.raises(ValueError, match="invalid stored"):
        Snapshot.from_row({
            "at": "now", "origin": "scan", "engine": 4, "score": 75,
            "coverage": 1.0, "evaluation": "complete", "checks": '["not a mapping"]',
        })
