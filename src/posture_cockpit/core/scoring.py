# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""From findings to a score, a grade, a coverage and a plan of fixes.

The rules, in order:

1. **Which checks count.** A check that produced a verdict (OK, WARN, FAIL) is
   *evaluated*. A check that should have produced one but could not (ERROR:
   timeout, unreachable server, destination refused) is *applicable but not
   evaluated*. A check that does not apply (NA: no website, no mail, internal
   audit) or only informs (INFO) is left out entirely. A *blocked* check
   (version 0.4: what it measures does not exist, for a confirmed reason) is
   left out of the score and of the scoring coverage, and counted in the
   diagnostic coverage.

2. **Coverage** is the weight of the evaluated checks divided by the weight of
   the applicable ones. It says how much of what should have been checked was
   actually checked. The *diagnostic coverage* also counts the blocked checks in
   the denominator: it says how much of the domain was measured.

3. **Score**: an OK check earns its whole weight, a WARN half of it, a FAIL
   nothing; the score is the share earned, from 0 to 100. Only evaluated
   checks take part. The weights are those declared by the checks. This is the
   *raw* score.

4. **Caps** (version 0.4). When HTTPS cannot be used safely, what the checks
   of the HTTPS family measured must not lift the score above a reference:
   the same domain, everything outside the family unchanged, the HTTPS root
   check compliant and each dependent at its *floor* (its lowest declared
   verdict that is not critical). Three reasons trigger it, each with its own
   justification; the cap is applied once, whatever the number of reasons:

   - *dependency*: a dependent is blocked, nothing it measures exists (every
     address refuses HTTPS);
   - *authentication*: a certificate a browser cannot authenticate (expired,
     unknown authority, wrong name): what is measured behind it does not
     protect the visitor, who can click through the warning;
   - *protocol*: every address was tested, none accepts TLS 1.2 or later, one
     at least only TLS 1.0 or 1.1: no current browser connects.

   The cap counts every dependent that is blocked or evaluated, at its floor,
   and the root at its full weight; dependents not evaluated (whatever the
   reason) and not applicable are left out of it, as they are of the reference.
   The *final* score is the lower of the raw score and the cap. Both are kept
   unrounded; only the score shown is rounded, once, at the end.

5. **Not evaluated.** When the coverage is below :data:`MIN_COVERAGE`, there
   is no score and no grade: "Non évalué". A domain must never look secure
   because most of its checks could not run (version 0.1.0 gave 100/A when
   nothing could be evaluated).

6. **Partial evaluation.** Below :data:`FULL_COVERAGE`, the score is given with
   its coverage and the grade cannot be better than :data:`PARTIAL_BEST_GRADE`:
   an "A" asserts that the domain was checked, not only that what could be
   checked was fine.

7. **Grade withheld** (version 0.4). When whether HTTPS can be used is not
   established (no address answers in TLS 1.2 or later, one shows a confirmed
   failure, another gave no conclusive answer), the score is given, provisional,
   without a grade: a letter would compare what cannot be compared. The
   assessments by category keep their grades.

The *plan* lists what to fix: the checks that FAIL first ("priorities"), then
those that only WARN ("improvements"), each with the points it brings. When
fixing the HTTPS root would let checks that could not be measured be measured,
the gain is a range: those checks at their floor for the lower bound, compliant
for the upper one; the target is then provisional.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, replace
from fractions import Fraction

from .model import (
    CAUSE_DEPENDENCY,
    CERTIFICATE_CHECK,
    CREDIT,
    HTTPS_FAMILY,
    HTTPS_ROOT_CHECK,
    Finding,
    Outcome,
    Role,
    Signal,
    Status,
)

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

HTTPS = HTTPS_FAMILY        # the family of checks that need HTTPS

# Why a score is capped (several may apply; the cap is applied once).
CAP_DEPENDENCY = "dependency"          # a dependent is blocked: nothing it measures exists
CAP_AUTHENTICATION = "authentication"  # a certificate a browser cannot authenticate
CAP_PROTOCOL = "protocol"              # only obsolete TLS, on every address tested
CAP_ORDER = (CAP_DEPENDENCY, CAP_AUTHENTICATION, CAP_PROTOCOL)

# Why a grade is withheld.
WITHHELD_HTTPS_UNDETERMINED = "https_availability_undetermined"


# ------------------------------------------------------------------ helpers
def _credit(f: Finding, fixed: Collection[str]) -> Fraction:
    return Fraction(1) if f.check_id in fixed else Fraction(CREDIT[f.status])


def _signals(f: Finding, fixed: Collection[str]) -> frozenset[str]:
    """A fixed check no longer reports what made it a problem."""
    return frozenset() if f.check_id in fixed else f.outcome.signals


def _in_family(f: Finding) -> bool:
    return f.family == HTTPS and f.role is not None


def _root(findings: Iterable[Finding]) -> Finding | None:
    """The HTTPS root: only web.https_redirect, as the certificate signal is read on tls.certificate only."""
    return next((f for f in findings
                 if f.check_id == HTTPS_ROOT_CHECK and f.family == HTTPS and f.role is Role.ROOT), None)


def raw_score(findings: Iterable[Finding], fixed: Collection[str] = ()) -> Fraction | None:
    """Share of the weight earned by the evaluated findings, 0 to 1, unrounded; None when none is evaluated."""
    earned, possible = Fraction(0), 0
    for f in findings:
        if f.status.scored:
            possible += f.weight
            earned += f.weight * _credit(f, fixed)
    return earned / possible if possible else None


def cap_reasons(findings: Sequence[Finding], fixed: Collection[str] = ()) -> tuple[str, ...]:
    """Why the score is capped, in a fixed order; empty when it is not."""
    found = set()
    if any(_in_family(f) and f.status is Status.BLOCKED for f in findings):
        found.add(CAP_DEPENDENCY)
    # Signals are read on the checks allowed to report them only (Finding refuses them elsewhere).
    if any(f.check_id == CERTIFICATE_CHECK and _in_family(f)
           and Signal.CERTIFICATE_UNAUTHENTICATED in _signals(f, fixed) for f in findings):
        found.add(CAP_AUTHENTICATION)
    root = _root(findings)
    if root is not None and Signal.HTTPS_OBSOLETE_ONLY in _signals(root, fixed):
        found.add(CAP_PROTOCOL)
    return tuple(reason for reason in CAP_ORDER if reason in found)


def cap_value(findings: Sequence[Finding], fixed: Collection[str] = ()) -> Fraction | None:
    """The score of the reference: same checks outside the family, the root compliant, each
    dependent that is blocked or evaluated at its floor. None without an HTTPS root."""
    root = _root(findings)
    if root is None:
        return None
    earned, possible = Fraction(root.weight), root.weight
    for f in findings:
        if not _in_family(f):
            if f.status.scored:
                possible += f.weight
                earned += f.weight * _credit(f, fixed)
        elif f.role is Role.DEPENDENT and (f.status.scored or f.status is Status.BLOCKED):
            if f.floor is None:  # Finding refuses it already: never guess a floor
                raise ValueError(f"{f.check_id}: a dependent without a floor cannot be part of a cap")
            possible += f.weight
            earned += f.weight * Fraction(f.floor)
    return earned / possible


def final_score(findings: Sequence[Finding], fixed: Collection[str] = ()) -> Fraction | None:
    """The raw score, lowered to the cap when a reason applies; unrounded."""
    raw = raw_score(findings, fixed)
    if raw is None or not cap_reasons(findings, fixed):
        return raw
    cap = cap_value(findings, fixed)
    return raw if cap is None else min(raw, cap)


def withheld_reason(findings: Sequence[Finding], fixed: Collection[str] = ()) -> str | None:
    """Why the grade is withheld, or None."""
    root = _root(findings)
    if root is not None and Signal.HTTPS_UNDETERMINED in _signals(root, fixed):
        return WITHHELD_HTTPS_UNDETERMINED
    return None


def _points(value: Fraction) -> int:
    """A share as the score shown: 0 to 100, rounded to the nearest, halves to even (as Python's round)."""
    return round(100 * value)


def score(findings: Iterable[Finding], fixed: Collection[str] = ()) -> int | None:
    """The score shown, 0 to 100 (caps applied); None when no finding is evaluated.

    ``fixed`` check ids are counted as OK (to project the effect of a plan)."""
    value = final_score(list(findings), fixed)
    return None if value is None else _points(value)


def coverage(findings: Iterable[Finding]) -> float:
    """Weight of the evaluated findings over the weight of the applicable ones, 0.0 to 1.0.

    0.0 when nothing applies at all: there is then nothing to grade either. Blocked
    findings are not applicable here (see :func:`diagnostic_coverage`)."""
    evaluated = applicable = 0
    for f in findings:
        if f.status.applicable:
            applicable += f.weight
            if f.status.scored:
                evaluated += f.weight
    return evaluated / applicable if applicable else 0.0


def diagnostic_coverage(findings: Iterable[Finding]) -> float:
    """Weight of the evaluated findings over the weight of the applicable and blocked ones, 0.0 to 1.0."""
    evaluated = measurable = 0
    for f in findings:
        if f.status.diagnostic:
            measurable += f.weight
            if f.status.scored:
                evaluated += f.weight
    return evaluated / measurable if measurable else 0.0


def grade(value: int) -> str:
    """The letter of a score, without any coverage rule (see :func:`assess`)."""
    return next(letter for floor, letter, _ in GRADES if value >= floor)


def grade_label(letter: str) -> str:
    """Translation key of a grade's label, e.g. ``"C"`` → ``grade.C`` ("À surveiller")."""
    return f"grade.{letter}"


def _capped(letter: str, partial: bool) -> str:
    if partial and LETTERS.index(letter) < LETTERS.index(PARTIAL_BEST_GRADE):
        return PARTIAL_BEST_GRADE
    return letter


def letter_for(value: int, share: float) -> str | None:
    """The grade of a score shown with a coverage: None below :data:`MIN_COVERAGE`, at most
    :data:`PARTIAL_BEST_GRADE` below :data:`FULL_COVERAGE`. Rises with the score and with the coverage."""
    if share < MIN_COVERAGE:
        return None
    return _capped(grade(value), share < FULL_COVERAGE)


@dataclass(frozen=True)
class Assessment:
    """What a set of findings is worth: the result shown everywhere (pages, API, PDF, history).

    The fields after ``applicable`` were added in version 0.4; they default to what a
    scan without any blocked check, cap or withheld grade has."""

    score: int | None    # None: not evaluated
    grade: str | None    # None: not evaluated, or grade withheld (see grade_withheld_reason)
    coverage: float      # 0.0 to 1.0: the scoring coverage
    evaluated: int       # number of checks with a verdict
    applicable: int      # number of checks that should have had one (verdict or error)
    score_raw: float | None = None    # 0 to 1, unrounded, before the cap
    score_cap: float | None = None    # 0 to 1, unrounded; None when no reason caps the score
    score_final: float | None = None  # 0 to 1, unrounded: min(raw, cap)
    diagnostic_coverage: float | None = None  # 0.0 to 1.0: blocked checks counted as not measured
    blocked: int = 0                  # number of blocked checks
    cap_reasons: tuple[str, ...] = ()
    grade_withheld_reason: str | None = None

    @property
    def evaluated_ok(self) -> bool:
        """False for "Non évalué"."""
        return self.score is not None

    @property
    def partial(self) -> bool:
        """Scored, but on part of what applies: shown with its coverage, grade capped."""
        return self.evaluated_ok and self.coverage < FULL_COVERAGE

    @property
    def undetermined(self) -> bool:
        """Scored, provisional, without a grade: whether HTTPS can be used is not established."""
        return self.evaluated_ok and self.grade_withheld_reason is not None

    @property
    def capped(self) -> bool:
        """Whether the cap lowered the score (a reason may apply without lowering it)."""
        return (self.score_cap is not None and self.score_raw is not None
                and self.score_final is not None and self.score_final < self.score_raw)

    @property
    def evaluation(self) -> str:
        """``not_evaluated``, ``undetermined``, ``partial`` or ``complete``."""
        if not self.evaluated_ok:
            return "not_evaluated"
        if self.undetermined:
            return "undetermined"
        return "partial" if self.partial else "complete"

    @property
    def coverage_percent(self) -> int:
        """Coverage as a whole percentage, rounded down: 89.6 % shows as 89, never as a full 90."""
        return int(self.coverage * 100 + 1e-9)


def _assess(findings: Sequence[Finding], fixed: Collection[str], caps: bool) -> Assessment:
    share = coverage(findings)
    evaluated = sum(1 for f in findings if f.status.scored)
    applicable = sum(1 for f in findings if f.status.applicable)
    blocked = sum(1 for f in findings if f.status is Status.BLOCKED)
    diagnostic = diagnostic_coverage(findings)
    raw = raw_score(findings, fixed)
    if raw is None or share < MIN_COVERAGE:
        return Assessment(None, None, share, evaluated, applicable, diagnostic_coverage=diagnostic, blocked=blocked)
    reasons = cap_reasons(findings, fixed) if caps else ()
    cap = cap_value(findings, fixed) if reasons else None
    final = raw if cap is None else min(raw, cap)
    value = _points(final)
    withheld = withheld_reason(findings, fixed) if caps else None
    letter = None if withheld else letter_for(value, share)
    return Assessment(value, letter, share, evaluated, applicable, float(raw),
                      float(cap) if cap is not None else None, float(final), diagnostic, blocked,
                      reasons if cap is not None else (), withheld)


def assess(findings: Sequence[Finding], fixed: Collection[str] = ()) -> Assessment:
    """Score, grade and coverage of these findings, with the rules of the module documentation."""
    return _assess(findings, fixed, caps=True)


def by_category(findings: Iterable[Finding]) -> dict[str, Assessment]:
    """Assessment of each category, in the order categories first appear (categories with nothing
    applicable or blocked are left out). The caps and the withheld grade concern the whole domain:
    they do not apply here."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.category, []).append(f)
    return {category: _assess(items, (), caps=False) for category, items in groups.items()
            if any(f.status.diagnostic for f in items)}


def counts(findings: Iterable[Finding]) -> Counter[Status]:
    return Counter(f.status for f in findings)


# ------------------------------------------------------------------ plan
def _unmeasured(f: Finding) -> bool:
    """A dependent of the HTTPS root that its root kept from being measured."""
    return (f.family == HTTPS and f.role is Role.DEPENDENT
            and (f.status is Status.BLOCKED
                 or (f.status is Status.ERROR and f.outcome.evidence.get("cause") == CAUSE_DEPENDENCY)))


def _floor_status(f: Finding) -> Status:
    """The verdict whose credit is the dependent's floor."""
    return Status.OK if (f.floor or 0) >= 1 else Status.WARN if (f.floor or 0) > 0 else Status.FAIL


def _projected(findings: Sequence[Finding], fixed: Collection[str], best: bool) -> list[Finding]:
    """The findings once ``fixed`` are fixed. When the HTTPS root is among them, the dependents
    it kept from being measured are counted at their floor, or compliant when ``best``."""
    root = _root(findings)
    unblocks = root is not None and root.check_id in fixed
    projected = []
    for f in findings:
        if f.check_id in fixed:
            f = replace(f, outcome=replace(f.outcome, status=Status.OK, signals=frozenset()))
        elif unblocks and _unmeasured(f):
            status = Status.OK if best else _floor_status(f)
            f = replace(f, outcome=Outcome(status, f.outcome.summary, f.outcome.params, f.outcome.evidence))
        projected.append(f)
    return projected


def _projected_score(findings: Sequence[Finding], fixed: Collection[str], best: bool) -> int:
    return score(_projected(findings, fixed, best)) or 0


@dataclass(frozen=True)
class PlanItem:
    finding: Finding
    gain: int  # points the global score gains once this one is fixed (after the items before it)
    # Version 0.4: upper bound of the gain when fixing it lets unmeasured checks be measured
    # (they may turn out compliant); None when the gain is exact.
    gain_max: int | None = None


@dataclass(frozen=True)
class Plan:
    priorities: list[PlanItem]    # FAIL findings, by effect on the score
    improvements: list[PlanItem]  # WARN findings, by effect on the score
    now: Assessment
    target: Assessment            # once every priority is fixed (unmeasured checks at their floor)
    # Version 0.4: the target if the checks measured after the fixes are compliant; None when
    # nothing is left unmeasured. The target is then provisional.
    target_max: Assessment | None = None

    @property
    def items(self) -> list[PlanItem]:
        return self.priorities + self.improvements

    @property
    def provisional(self) -> bool:
        return self.target_max is not None


def _ranked(findings: Sequence[Finding], status: Status, already_fixed: list[str]) -> list[PlanItem]:
    """Findings of ``status`` that have a remedy, biggest effect first, quickest first when equal."""
    candidates = [f for f in findings if f.status is status and f.outcome.remedy is not None]
    candidates.sort(key=lambda f: (-f.weight * (1 - CREDIT[status]), f.outcome.remedy.minutes, f.check_id))  # type: ignore[union-attr]
    items = []
    for f in candidates:
        low_before = _projected_score(findings, already_fixed, best=False)
        high_before = _projected_score(findings, already_fixed, best=True)
        already_fixed.append(f.check_id)
        # Cumulative gains: the points shown always add up to the projected score.
        gain = _projected_score(findings, already_fixed, best=False) - low_before
        gain_max = _projected_score(findings, already_fixed, best=True) - high_before
        items.append(PlanItem(f, gain, gain_max if gain_max != gain else None))
    return items


def plan(findings: Sequence[Finding]) -> Plan:
    fixed: list[str] = []
    priorities = _ranked(findings, Status.FAIL, fixed)
    target = assess(_projected(findings, fixed, best=False))
    best = assess(_projected(findings, fixed, best=True))
    improvements = _ranked(findings, Status.WARN, fixed)
    return Plan(priorities, improvements, assess(findings), target, best if best != target else None)
