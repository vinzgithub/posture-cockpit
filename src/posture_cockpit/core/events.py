# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Conservative event candidates from consecutive immutable scan states (v0.5.0).

No alert is inferred from unknown measurements or incompatible scoring rules.
Candidates are facts, not notifications: storage handles their life cycle.
"""
from __future__ import annotations

from dataclasses import dataclass

from .compare import Comparison, Snapshot, compare


@dataclass(frozen=True)
class Candidate:
    category: str
    kind: str
    subject: str
    severity: str
    action: str  # open, resolve, downgrade
    detail: dict[str, str]


def derive(previous: Snapshot | None, current: Snapshot) -> tuple[Candidate, ...]:
    """Returns security and measurement changes, without inventing missing evidence."""
    if previous is None or previous.origin == "legacy" or current.origin == "legacy":
        return ()
    # Incomparable inventories or engines cannot prove a security change.
    if previous.engine is None or current.engine is None or previous.engine != current.engine:
        return ()
    if set(previous.checks) != set(current.checks):
        return ()

    result: list[Candidate] = []
    order = {"fail": 0, "warn": 1, "ok": 2}
    for check_id in sorted(current.checks):
        before, after = previous.checks[check_id], current.checks[check_id]
        if before not in order or after not in order or before == after:
            continue
        detail = {"previous": before, "current": after}
        if order[after] < order[before]:
            result.append(Candidate("security", "check", check_id,
                                    "critical" if after == "fail" else "warning", "open", detail))
        elif after == "ok":
            result.append(Candidate("security", "check", check_id, "info", "resolve", detail))
        else:  # critical issue became a warning, not yet a full resolution.
            result.append(Candidate("security", "check", check_id, "warning", "downgrade", detail))

    comparison: Comparison = compare(previous, current)
    if comparison.comparable and comparison.score_delta is not None:
        if comparison.score_delta <= -10 and not any(c.action == "open" for c in result):
            result.append(Candidate("security", "score_drop", "", "warning", "open",
                                    {"delta": str(comparison.score_delta)}))
        elif comparison.score_delta >= 0:
            result.append(Candidate("security", "score_drop", "", "info", "resolve", {}))
    # Coverage loss and recovery are measurement concerns, not vulnerabilities.
    if current.coverage < .90 and previous.coverage >= .90:
        result.append(Candidate("measurement", "coverage_loss", "", "warning", "open",
                                {"previous": str(previous.coverage), "current": str(current.coverage)}))
    elif previous.coverage < .90 and current.coverage >= .90:
        result.append(Candidate("measurement", "coverage_loss", "", "info", "resolve", {}))
    return tuple(result)
