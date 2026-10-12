# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""From findings to a score, a grade, a coverage and a plan of fixes.

The rules, in order:

1. **Which checks count.** A check that produced a verdict (OK, WARN, FAIL) is
   *evaluated*. A check that should have produced one but could not (ERROR:
   timeout, unreachable server, destination refused) is *applicable but not
   evaluated*. A check that does not apply (NA: no website, no mail, internal
   audit) or only informs (INFO) is left out entirely.

2. **Coverage** is the weight of the evaluated checks divided by the weight of
   the applicable ones. It says how much of what should have been checked was
   actually checked.

3. **Score**: an OK check earns its whole weight, a WARN half of it, a FAIL
   nothing; the score is the share earned, from 0 to 100. Only evaluated
   checks take part. The weights are those declared by the checks.

4. **Not evaluated.** When the coverage is below :data:`MIN_COVERAGE`, there
   is no score and no grade: "Non évalué". A domain must never look secure
   because most of its checks could not run (version 0.1.0 gave 100/A when
   nothing could be evaluated).

5. **Partial evaluation.** Below :data:`FULL_COVERAGE`, the score is given with
   its coverage and the grade cannot be better than :data:`PARTIAL_BEST_GRADE`:
   an "A" asserts that the domain was checked, not only that what could be
   checked was fine.

The *plan* lists what to fix: the checks that FAIL first ("priorities"), then
those that only WARN ("improvements"), each with the points it brings.
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
LETTERS = [letter for _, letter, _ in GRADES]

MIN_COVERAGE = 0.5          # below: no score ("Non évalué")
FULL_COVERAGE = 0.9         # below: partial evaluation, grade capped
PARTIAL_BEST_GRADE = "B"


def score(findings: Iterable[Finding], fixed: Collection[str] = ()) -> int | None:
    """Share of the weight earned by the evaluated findings, 0 to 100; None when none is evaluated.

    ``fixed`` check ids are counted as OK (to project the effect of a plan)."""
    earned = possible = 0.0
    for f in findings:
        if not f.status.scored:
            continue
        possible += f.weight
        earned += f.weight * (1.0 if f.check_id in fixed else CREDIT[f.status])
    if possible == 0:
        return None
    return round(100 * earned / possible)


def coverage(findings: Iterable[Finding]) -> float:
    """Weight of the evaluated findings over the weight of the applicable ones, 0.0 to 1.0.

    0.0 when nothing applies at all: there is then nothing to grade either."""
    evaluated = applicable = 0
    for f in findings:
        if f.status.applicable:
            applicable += f.weight
            if f.status.scored:
                evaluated += f.weight
    return evaluated / applicable if applicable else 0.0


def grade(value: int) -> str:
    """The letter of a score, without any coverage rule (see :func:`assess`)."""
    return next(letter for floor, letter, _ in GRADES if value >= floor)


def grade_label(letter: str) -> str:
    """Translation key of a grade's label, e.g. ``"C"`` → ``grade.C`` ("À surveiller")."""
    return f"grade.{letter}"


@dataclass(frozen=True)
class Assessment:
    """What a set of findings is worth: the result shown everywhere (pages, API, PDF, history)."""

    score: int | None    # None: not evaluated
    grade: str | None    # None: not evaluated
    coverage: float      # 0.0 to 1.0
    evaluated: int       # number of checks with a verdict
    applicable: int      # number of checks that should have had one (verdict or error)

    @property
    def evaluated_ok(self) -> bool:
        """False for "Non évalué"."""
        return self.score is not None

    @property
    def partial(self) -> bool:
        """Scored, but on part of what applies: shown with its coverage, grade capped."""
        return self.evaluated_ok and self.coverage < FULL_COVERAGE

    @property
    def coverage_percent(self) -> int:
        """Coverage as a whole percentage, rounded down: 89.6 % shows as 89, never as a full 90."""
        return int(self.coverage * 100 + 1e-9)


def _capped(letter: str, partial: bool) -> str:
    if partial and LETTERS.index(letter) < LETTERS.index(PARTIAL_BEST_GRADE):
        return PARTIAL_BEST_GRADE
    return letter


def assess(findings: Sequence[Finding], fixed: Collection[str] = ()) -> Assessment:
    """Score, grade and coverage of these findings, with the rules of the module documentation."""
    share = coverage(findings)
    evaluated = sum(1 for f in findings if f.status.scored)
    applicable = sum(1 for f in findings if f.status.applicable)
    value = score(findings, fixed)
    if value is None or share < MIN_COVERAGE:
        return Assessment(None, None, share, evaluated, applicable)
    return Assessment(value, _capped(grade(value), share < FULL_COVERAGE), share, evaluated, applicable)


def by_category(findings: Iterable[Finding]) -> dict[str, Assessment]:
    """Assessment of each category, in the order categories first appear (categories with nothing
    applicable are left out)."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.category, []).append(f)
    return {category: assess(items) for category, items in groups.items()
            if any(f.status.applicable for f in items)}


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
    now: Assessment
    target: Assessment            # once every priority is fixed

    @property
    def items(self) -> list[PlanItem]:
        return self.priorities + self.improvements


def _ranked(findings: Sequence[Finding], status: Status, already_fixed: list[str]) -> list[PlanItem]:
    """Findings of ``status`` that have a remedy, biggest effect first, quickest first when equal."""
    candidates = [f for f in findings if f.status is status and f.outcome.remedy is not None]
    candidates.sort(key=lambda f: (-f.weight * (1 - CREDIT[status]), f.outcome.remedy.minutes, f.check_id))  # type: ignore[union-attr]
    items = []
    for f in candidates:
        before = score(findings, already_fixed) or 0
        already_fixed.append(f.check_id)
        # Cumulative gains: the points shown always add up to the projected score.
        items.append(PlanItem(f, (score(findings, already_fixed) or 0) - before))
    return items


def plan(findings: Sequence[Finding]) -> Plan:
    fixed: list[str] = []
    priorities = _ranked(findings, Status.FAIL, fixed)
    target = assess(findings, list(fixed))
    improvements = _ranked(findings, Status.WARN, fixed)
    return Plan(priorities, improvements, assess(findings), target)
