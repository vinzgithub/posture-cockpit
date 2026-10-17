# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pure, conservative comparisons of immutable scan states (v0.5.0).

This module never recalculates a historic score or turns a failed measurement into a
security improvement. The caller supplies consecutive states of *one domain*.
A later step may look farther back for the last conclusive check observation.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
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
