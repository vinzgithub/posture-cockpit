# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pure, conservative comparisons of immutable scan states (v0.5.0).

This module never recalculates a historic score or turns a failed measurement into a
security improvement. The caller supplies consecutive states of *one domain*.
A later step may look farther back for the last conclusive check observation.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

CONCLUSIVE = frozenset({"ok", "warn", "fail", "na"})
NOT_MEASURED = frozenset({"error", "blocked"})
MIN_SCORING_COVERAGE = 0.90


@dataclass(frozen=True)
class Snapshot:
    """The facts frozen in one scan_states row, not a reconstructed assessment."""

    at: str
    origin: str
    engine: int | None
    score: int | None
    coverage: float
    evaluation: str
    checks: Mapping[str, str]
    # Optional joined identity for Mission Control helpers; never guessed from a scan id.
    domain_id: int | None = None
    perimeter: str | None = None
    state_id: int | None = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> Snapshot:
        checks = json.loads(row["checks"]) if isinstance(row["checks"], str) else row["checks"]
        if not isinstance(checks, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in checks.items()
        ):
            raise ValueError("invalid stored check statuses")
        return cls(
            at=str(row["at"]), origin=str(row["origin"]),
            engine=int(row["engine"]) if row["engine"] is not None else None,
            score=int(row["score"]) if row["score"] is not None else None,
            coverage=float(row["coverage"]), evaluation=str(row["evaluation"]),
            checks=checks,
            domain_id=int(row["domain_id"]) if "domain_id" in row and row["domain_id"] is not None else None,
            perimeter=str(row["perimeter"]) if "perimeter" in row and row["perimeter"] is not None else None,
            state_id=int(row["id"]) if "id" in row else None,
        )


@dataclass(frozen=True)
class CheckChange:
    check_id: str
    previous: str | None
    current: str | None
    kind: str  # improved, regressed, new_issue, not_applicable, unmeasured, unchanged


@dataclass(frozen=True)
class Comparison:
    comparable: bool
    reason: str | None
    reference_at: str | None
    score_delta: int | None
    changes: tuple[CheckChange, ...] = ()


def compare(previous: Snapshot | None, current: Snapshot) -> Comparison:
    """Compare consecutive states, refusing a score delta unless defensible.

    No inference about a "fixed" check is made when it disappears, becomes N/A,
    is blocked or errors. Legacy states lack their initial measurement and are
    intentionally not compared to other states.
    """
    if previous is None:
        return Comparison(False, "no_previous", None, None)
    reason: str | None = None
    if previous.origin == "legacy" or current.origin == "legacy":
        reason = "legacy"
    elif previous.engine is None or current.engine is None or previous.engine != current.engine:
        reason = "engine"
    elif set(previous.checks) != set(current.checks):
        reason = "checks"
    elif previous.score is None or current.score is None or (
        previous.evaluation == "not_evaluated" or current.evaluation == "not_evaluated"
    ):
        reason = "not_evaluated"
    elif previous.evaluation == "undetermined" or current.evaluation == "undetermined":
        reason = "undetermined"
    elif (previous.coverage < MIN_SCORING_COVERAGE or current.coverage < MIN_SCORING_COVERAGE
          or previous.evaluation == "partial" or current.evaluation == "partial"):
        reason = "partial"
    if reason:
        return Comparison(False, reason, previous.at, None)

    changes = tuple(
        change
        for check_id in sorted(current.checks)
        if (change := compare_check(check_id, previous.checks[check_id], current.checks[check_id])).kind
        != "unchanged"
    )
    return Comparison(True, None, previous.at, current.score - previous.score, changes)  # type: ignore[operator]


def compare_check(check_id: str, previous: str, current: str) -> CheckChange:
    """Report only conclusive changes; N/A never masquerades as a correction."""
    if previous == current:
        kind = "unchanged"
    elif (current in NOT_MEASURED or previous in NOT_MEASURED
          or current not in CONCLUSIVE or previous not in CONCLUSIVE):
        kind = "unmeasured"
    elif current == "na":
        kind = "not_applicable"
    elif previous == "na":
        kind = "new_issue" if current == "fail" else "unchanged"
    else:
        order = {"fail": 0, "warn": 1, "ok": 2}
        kind = "improved" if order[current] > order[previous] else "regressed"
    return CheckChange(check_id, previous, current, kind)


@dataclass(frozen=True)
class Changes:
    """Permission to describe check transitions, never permission to show a score delta."""

    available: bool
    reason: str | None
    changes: tuple[CheckChange, ...] = ()


def _identity_reason(previous: Snapshot, current: Snapshot) -> str | None:
    if previous.domain_id is None or current.domain_id is None or (
        previous.perimeter is None or current.perimeter is None
    ):
        return "identity_unknown"
    if previous.domain_id != current.domain_id or previous.perimeter != current.perimeter:
        return "identity"
    if previous.origin == "legacy" or current.origin == "legacy":
        return "legacy"
    if previous.engine is None or previous.engine != current.engine:
        return "engine"
    if set(previous.checks) != set(current.checks):
        return "checks"
    return None


def _earlier(previous: Snapshot, current: Snapshot) -> bool:
    try:
        before, after = datetime.fromisoformat(previous.at), datetime.fromisoformat(current.at)
        if before < after:
            return True
        return (before == after and previous.state_id is not None and current.state_id is not None
                and previous.state_id < current.state_id)
    except (ValueError, TypeError):
        return False


def check_changes(previous: Snapshot | None, current: Snapshot) -> Changes:
    if previous is None:
        return Changes(False, "no_previous")
    reason = _identity_reason(previous, current)
    if reason:
        return Changes(False, reason)
    if not _earlier(previous, current):
        return Changes(False, "order")
    return Changes(True, None, tuple(
        change for check_id in sorted(current.checks)
        if (change := compare_check(check_id, previous.checks[check_id], current.checks[check_id])).kind
        != "unchanged"
    ))


HISTORY_DEPTH = 30


@dataclass(frozen=True)
class LastConclusive:
    """Previous conclusive verdict and missed measurements before the newest observation."""

    state: Snapshot | None
    missed: tuple[Snapshot, ...] = ()
    reason: str | None = None
    truncated: bool = False


def last_conclusive(states: Sequence[Snapshot], check_id: str, *, limit: int = HISTORY_DEPTH) -> LastConclusive:
    """Newest first, including the current observation; at most limit states inspected.

    Returns an older OK/WARN/FAIL and intervening ERROR/BLOCKED states. N/A,
    inventories, rules and identities are boundaries, never successes to skip over.
    Detailed proofs are intentionally absent from this status-only history.
    """
    if not 1 <= limit <= HISTORY_DEPTH:
        raise ValueError("invalid history depth")
    if not states:
        return LastConclusive(None, reason="no_current")
    current = states[0]
    reason = _identity_reason(current, current)
    if reason:
        return LastConclusive(None, reason=reason)
    if check_id not in current.checks:
        return LastConclusive(None, reason="check_unknown")
    missed: list[Snapshot] = []
    later = current
    for state in states[1:limit]:
        reason = _identity_reason(state, current)
        if reason:
            return LastConclusive(None, tuple(missed), reason)
        if not _earlier(state, later):
            return LastConclusive(None, tuple(missed), "order")
        status = state.checks[check_id]
        if status in ("ok", "warn", "fail"):
            return LastConclusive(state, tuple(missed))
        if status not in NOT_MEASURED:
            return LastConclusive(None, tuple(missed), "not_applicable" if status == "na" else "status")
        missed.append(state)
        later = state
    return LastConclusive(None, tuple(missed), "depth" if len(states) > limit else "no_previous_conclusive",
                          truncated=len(states) > limit)
