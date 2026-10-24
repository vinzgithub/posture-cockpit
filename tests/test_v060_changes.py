# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MC01 pure helpers: identities, observation gaps and bounded status history."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from posture_cockpit.core.compare import Snapshot, check_changes, compare, last_conclusive
from posture_cockpit.core.events import derive


def state(status, n, **overrides):
    at = (datetime(2026, 10, 24, tzinfo=UTC) + timedelta(minutes=n)).isoformat()
    base = Snapshot(at, "recheck", 4, 80, 1., "complete", {"mail.dmarc": status}, 1, "", n)
    return replace(base, **overrides)


def test_partial_score_does_not_hide_a_proven_check_transition():
    before = state("ok", 1, coverage=.6, evaluation="partial")
    after = state("fail", 2, coverage=.6, evaluation="partial")
    assert not compare(before, after).comparable
    changes = check_changes(before, after)
    assert changes.available and changes.reason is None
    assert changes.changes[0].kind == "regressed"
    assert not hasattr(changes, "score_delta")


@pytest.mark.parametrize(("override", "reason"), [
    ({"domain_id": None}, "identity_unknown"), ({"perimeter": None}, "identity_unknown"),
    ({"domain_id": 2}, "identity"), ({"perimeter": "internal"}, "identity"),
    ({"engine": 5}, "engine"), ({"engine": None}, "engine"),
    ({"checks": {"other": "fail"}}, "checks"), ({"origin": "legacy"}, "legacy"),
])
def test_unknown_or_different_context_never_proves_changes(override, reason):
    before, after = state("ok", 1), state("fail", 2, **override)
    assert check_changes(before, after).reason == reason
    assert check_changes(before, after).changes == ()
    assert last_conclusive([after, before], "mail.dmarc").reason == (
        "check_unknown" if reason == "checks" else reason)


@pytest.mark.parametrize(("before", "after", "kind"), [
    ("ok", "error", "unmeasured"), ("blocked", "fail", "unmeasured"),
    ("fail", "na", "not_applicable"), ("na", "ok", "unchanged"),
])
def test_missing_measurements_and_na_are_not_successes(before, after, kind):
    result = check_changes(state(before, 1), state(after, 2))
    assert result.available
    assert [c.kind for c in result.changes] == ([] if kind == "unchanged" else [kind])


@pytest.mark.parametrize(("first", "last"), [("ok", "fail"), ("fail", "ok")])
def test_t26_last_conclusion_and_gap_are_visible_but_events_unchanged(first, last):
    old, gap, current = state(first, 1), state("error", 2), state(last, 3)
    result = last_conclusive([current, gap, old], "mail.dmarc")
    assert result.state == old and result.missed == (gap,)
    assert result.state.origin == "recheck" and result.state.at == old.at
    assert not any(c.kind == "check" for c in derive(old, gap) + derive(gap, current))


def test_na_is_an_applicability_boundary_not_a_repair_or_gap_to_skip():
    result = last_conclusive([state("ok", 3), state("na", 2), state("fail", 1)], "mail.dmarc")
    assert result.state is None and result.reason == "not_applicable"


def test_depth_is_bounded_including_current_and_never_scans_beyond_it():
    states = [state("error", n) for n in range(35, 0, -1)]
    states[-1] = state("ok", 1)
    result = last_conclusive(states, "mail.dmarc")
    assert result.state is None and result.reason == "depth" and result.truncated
    assert len(result.missed) == 29
    for invalid in (0, -1, 31):
        with pytest.raises(ValueError):
            last_conclusive(states, "mail.dmarc", limit=invalid)


def test_order_is_required_and_equal_dates_use_state_ids():
    before = state("fail", 1)
    after = replace(before, state_id=2, checks={"mail.dmarc": "ok"})
    assert check_changes(before, after).available
    assert last_conclusive([after, before], "mail.dmarc").state == before
    assert check_changes(after, before).reason == "order"
    assert check_changes(before, replace(after, state_id=None)).reason == "order"
    assert last_conclusive([before, after], "mail.dmarc").reason == "order"


def test_no_previous_and_missing_check_are_explicit():
    assert check_changes(None, state("ok", 1)).reason == "no_previous"
    assert last_conclusive([], "mail.dmarc").reason == "no_current"
    assert last_conclusive([state("ok", 1)], "unknown").reason == "check_unknown"
    assert last_conclusive([state("ok", 1)], "mail.dmarc").reason == "no_previous_conclusive"


def test_snapshot_identity_is_only_taken_from_explicit_joined_fields():
    row = dict(at="2026-10-24T00:00:00+00:00",origin="scan",engine=4,score=80,
               coverage=1,evaluation="complete",checks={"mail.dmarc":"ok"},id=2,scan_id=5)
    assert Snapshot.from_row(row).domain_id is None
    row.update(domain_id=1,perimeter="")
    snapshot = Snapshot.from_row(row)
    assert (snapshot.domain_id,snapshot.perimeter,snapshot.state_id)==(1,"",2)
