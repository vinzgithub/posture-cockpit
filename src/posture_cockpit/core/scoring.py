# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""From findings to a score, a grade and a plan of fixes.

The score is the share of the weight of the scored checks that is earned:
an OK check earns its whole weight, a WARN half of it, a FAIL nothing. INFO
and ERROR findings are left out, so a check that could not run neither helps
nor hurts. The result is a whole number from 0 to 100.

The *plan* lists what to fix, the checks that FAIL first ("priorities"),
then those that only WARN ("improvements"), each with the points it brings.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass

from .model import CREDIT, Finding, Status

# (lowest score, grade, translation key of its label)
GRADES = (
    (85, "A", "grade.A"),  # solide
    (70, "B", "grade.B"),  # correct
    (55, "C", "grade.C"),  # à surveiller
    (40, "D", "grade.D"),  # fragile
    (25, "E", "grade.E"),  # exposé
    (0, "F", "grade.F"),   # critique
)


def score(findings: Iterable[Finding], fixed: Collection[str] = ()) -> int:
    """Score of these findings; ``fixed`` check ids are counted as OK (to project a plan)."""
    earned = possible = 0.0
    for f in findings:
        if not f.status.scored:
            continue
        possible += f.weight
        earned += f.weight * (1.0 if f.check_id in fixed else CREDIT[f.status])
    if possible == 0:
        return 100
    return round(100 * earned / possible)


def grade(value: int) -> str:
    return next(letter for floor, letter, _ in GRADES if value >= floor)


def grade_label(value: int) -> str:
    """Translation key of the grade's label, e.g. ``grade.C`` → "À surveiller"."""
    return next(key for floor, _, key in GRADES if value >= floor)


def by_category(findings: Iterable[Finding]) -> dict[str, int]:
    """Score of each category, in the order categories first appear."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.category, []).append(f)
    return {category: score(items) for category, items in groups.items()
            if any(f.status.scored for f in items)}


def counts(findings: Iterable[Finding]) -> Counter[Status]:
    return Counter(f.status for f in findings)


@dataclass(frozen=True)
class PlanItem:
    finding: Finding
    gain: int  # points the global score gains once this one is fixed (after the items before it)


@dataclass(frozen=True)
class Plan:
    priorities: list[PlanItem]    # FAIL findings, by effect on the score
    improvements: list[PlanItem]  # WARN findings, by effect on the score
    score: int
    target: int                   # score once every priority is fixed

    @property
    def items(self) -> list[PlanItem]:
        return self.priorities + self.improvements


def _ranked(findings: Sequence[Finding], status: Status, already_fixed: list[str]) -> list[PlanItem]:
    """Findings of ``status`` that have a remedy, biggest effect first, quickest first when equal."""
    candidates = [f for f in findings if f.status is status and f.outcome.remedy is not None]
    candidates.sort(key=lambda f: (-f.weight * (1 - CREDIT[status]), f.outcome.remedy.minutes, f.check_id))  # type: ignore[union-attr]
    items = []
    for f in candidates:
        before = score(findings, already_fixed)
        already_fixed.append(f.check_id)
        # Cumulative gains: the points shown always add up to the projected score.
        items.append(PlanItem(f, score(findings, already_fixed) - before))
    return items


def plan(findings: Sequence[Finding]) -> Plan:
    fixed: list[str] = []
    priorities = _ranked(findings, Status.FAIL, fixed)
    target = score(findings, fixed)
    improvements = _ranked(findings, Status.WARN, fixed)
    return Plan(priorities, improvements, score(findings), target)
