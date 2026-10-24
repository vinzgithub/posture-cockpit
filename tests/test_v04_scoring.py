# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Version 0.4 scoring: the three caps, the withheld grade, the two coverages, the plan ranges.

The weights and floors come from the registry, so a change of weight re-runs these
properties with the new values; the numbers quoted (67/C, 79/B…) are those of the
current weights and of the test worlds' mail and DNS."""

from __future__ import annotations

from fractions import Fraction
from itertools import product

import pytest

from posture_cockpit.core import Effort, Finding, Outcome, Remedy, Role, Signal, Status, scoring
from posture_cockpit.core.engine import finding
from posture_cockpit.core.model import CAUSE_DEPENDENCY, CREDIT
from posture_cockpit.core.registry import Registry
from posture_cockpit.core.scoring import CAP_AUTHENTICATION, CAP_DEPENDENCY, CAP_PROTOCOL, HTTPS
from worlds import healthy, http_only_with_redirect_elsewhere, run

REGISTRY = Registry.discover()
ROOT = next(c for c in REGISTRY.checks() if c.family == HTTPS and c.role is Role.ROOT)
DEPENDENTS = [c for c in REGISTRY.checks() if c.family == HTTPS and c.role is Role.DEPENDENT]
CERTIFICATE, PROTOCOLS = "tls.certificate", "tls.protocols"
PAGE = [c.id for c in DEPENDENTS if c.id.startswith("web.")]
FIX = Remedy(15, Effort.DELEGATE)


def _outside(world) -> list[Finding]:
    return [f for f in run(world()).values() if f.family != HTTPS]


def _floor_status(check) -> Status:
    return Status.OK if check.floor == 1 else Status.WARN


def family(root: Status = Status.OK, root_signals=(), default: Status = Status.OK, **deps) -> list[Finding]:
    """The HTTPS root and its ten dependents. ``deps`` maps a check id (dots as __) to a status,
    or to (status, signals); ERROR is a dependency error unless given as (ERROR, "network")."""
    findings = [finding(ROOT, Outcome(root, "lab.root", remedy=FIX if root is Status.FAIL else None,
                                      signals=frozenset(root_signals)))]
    for check in DEPENDENTS:
        value = deps.get(check.id.replace(".", "__"), default)
        status, extra = value if isinstance(value, tuple) else (value, ())
        if status == "floor":
            status = _floor_status(check)
        signals = frozenset(s for s in extra if isinstance(s, Signal))
        cause = "network" if "network" in extra else CAUSE_DEPENDENCY
        evidence = {"cause": cause} if status is Status.ERROR else {}
        findings.append(finding(check, Outcome(status, "lab.dep", evidence=evidence, signals=signals,
                                               remedy=FIX if status in (Status.FAIL, Status.WARN) else None)))
    return findings


TEST_MAIL = http_only_with_redirect_elsewhere   # mail and DNS earn 29.5 of 36
PERFECT_MAIL = healthy                          # mail and DNS earn 36 of 36
BLOCKED_ALL = {c.id.replace(".", "__"): Status.BLOCKED for c in DEPENDENTS}
UNMEASURED_ALL = {c.id.replace(".", "__"): Status.ERROR for c in DEPENDENTS}
UNAUTHENTICATED = (Status.FAIL, (Signal.CERTIFICATE_UNAUTHENTICATED,))


# ------------------------------------------------------------------ reference cases
def test_m18_fournet_established_refusal_scores_67_c_on_full_scoring_coverage():
    result = scoring.assess(_outside(TEST_MAIL) + family(Status.FAIL, **BLOCKED_ALL))
    assert (result.score, result.grade, result.blocked) == (67, "C", 10)
    assert result.coverage == 1.0 and result.diagnostic_coverage == pytest.approx(44 / 81)
    assert result.cap_reasons == (CAP_DEPENDENCY,) and not result.capped
    assert result.score_raw == pytest.approx(29.5 / 44) and result.score_cap == pytest.approx(57.5 / 81)
    assert result.evaluation == "complete"


def test_m18b_undetermined_keeps_its_score_without_a_grade():
    findings = _outside(TEST_MAIL) + family(Status.FAIL, (Signal.HTTPS_UNDETERMINED,), **UNMEASURED_ALL)
    result = scoring.assess(findings)
    assert (result.score, result.grade) == (67, None)
    assert result.grade_withheld_reason == scoring.WITHHELD_HTTPS_UNDETERMINED
    assert result.evaluation == "undetermined" and result.undetermined and result.partial
    assert result.coverage == pytest.approx(44 / 81) and result.blocked == 0 and result.cap_reasons == ()


def test_a_perfect_domain_that_refuses_https_is_capped_at_79_b():
    result = scoring.assess(_outside(PERFECT_MAIL) + family(Status.FAIL, **BLOCKED_ALL))
    assert (result.score, result.grade) == (79, "B") and result.capped
    assert result.score_raw == pytest.approx(36 / 44) and result.score_final == pytest.approx(64 / 81)


def test_an_unauthenticated_certificate_caps_a_perfect_domain_at_79_b():
    capped = scoring.assess(_outside(PERFECT_MAIL) + family(tls__certificate=UNAUTHENTICATED))
    assert (capped.score, capped.grade, capped.cap_reasons) == (79, "B", (CAP_AUTHENTICATION,))
    # The same verdict without the 0.4 signal (a scan stored by 0.3, or a certificate expiring soon): no cap.
    plain = scoring.assess(_outside(PERFECT_MAIL) + family(tls__certificate=Status.FAIL))
    assert (plain.score, plain.grade, plain.cap_reasons) == (88, "A", ())


def test_only_obsolete_tls_caps_a_perfect_domain_at_79_b():
    findings = _outside(PERFECT_MAIL) + family(Status.FAIL, (Signal.HTTPS_OBSOLETE_ONLY,), tls__protocols=Status.FAIL)
    result = scoring.assess(findings)
    assert (result.score, result.grade, result.cap_reasons) == (79, "B", (CAP_PROTOCOL,))
    plain = scoring.assess(_outside(PERFECT_MAIL) + family(Status.FAIL, tls__protocols=Status.FAIL))
    assert (plain.score, plain.grade) == (84, "B")


def test_caps_do_not_add_up():
    findings = _outside(PERFECT_MAIL) + family(Status.FAIL, (Signal.HTTPS_OBSOLETE_ONLY,), tls__protocols=Status.FAIL,
                                               tls__certificate=UNAUTHENTICATED)
    result = scoring.assess(findings)
    assert result.cap_reasons == (CAP_AUTHENTICATION, CAP_PROTOCOL)
    assert result.score_cap == pytest.approx(64 / 81)
    assert result.score_final == min(result.score_raw, result.score_cap)  # type: ignore[type-var]
    assert result.score_final == pytest.approx(58 / 81)  # the raw score, already below the one cap


def test_the_cap_counts_the_root_even_when_it_could_not_be_evaluated():
    """A2: the certificate is expired on the domain, www gave no conclusive answer."""
    findings = _outside(PERFECT_MAIL) + family(Status.ERROR, tls__certificate=UNAUTHENTICATED)
    result = scoring.assess(findings)
    assert result.score_cap == pytest.approx(64 / 81) and result.score == 79
    assert result.score_raw == pytest.approx(63 / 73)


def test_dependents_not_evaluated_are_left_out_of_the_cap():
    """A3: the address with an invalid certificate negotiates TLS but never answers in HTTP."""
    pages = {name.replace(".", "__"): (Status.ERROR, ("network",)) for name in PAGE}
    result = scoring.assess(_outside(PERFECT_MAIL) + family(tls__certificate=UNAUTHENTICATED, **pages))
    assert result.score_cap == pytest.approx(54.5 / 62)  # 36 + 8 + 10.5 over 36 + 8 + 18
    assert result.score_final == result.score_raw == pytest.approx(52 / 62)


def test_categories_keep_their_own_results_without_caps_or_withheld_grades():
    established = scoring.by_category(_outside(TEST_MAIL) + family(Status.FAIL, **BLOCKED_ALL))
    assert established["tls"].score is None and established["tls"].blocked == 3
    assert (established["web"].score, established["web"].grade) == (0, "F")
    undetermined = scoring.by_category(
        _outside(TEST_MAIL) + family(Status.FAIL, (Signal.HTTPS_UNDETERMINED,), **UNMEASURED_ALL))
    assert undetermined["mail"].grade is not None and undetermined["mail"].grade_withheld_reason is None
    assert all(a.cap_reasons == () for a in undetermined.values())


def test_a_scan_stored_by_0_3_is_never_capped_nor_withheld():
    """No signal, no family, no blocked check in 0.3 data: the 0.3 rules apply unchanged."""
    stored = []
    for f in run(TEST_MAIL()).values():
        data = f.outcome_json()
        data.pop("family", None)
        stored.append(Finding.from_stored(f.check_id, f.category, f.weight, f.status.value, data))
    result = scoring.assess(stored)
    assert (result.score, result.grade, result.cap_reasons, result.grade_withheld_reason) == (None, None, (), None)
    assert result.diagnostic_coverage == pytest.approx(result.coverage)


# ------------------------------------------------------------------ plan
def test_fixing_the_refused_https_shows_a_range_and_a_provisional_target():
    plan = scoring.plan(_outside(PERFECT_MAIL) + family(Status.FAIL, **BLOCKED_ALL))
    root = next(item for item in plan.priorities if item.finding.check_id == ROOT.id)
    assert (plan.now.score, root.gain, root.gain_max) == (79, -13, 21)  # declared worst: 66; all compliant: 100
    assert plan.provisional and plan.target.score == 66 and plan.target_max is not None
    assert plan.target_max.score == 100


def test_fixing_an_unauthenticated_certificate_lifts_the_cap_exactly():
    plan = scoring.plan(_outside(PERFECT_MAIL) + family(tls__certificate=UNAUTHENTICATED))
    item = next(i for i in plan.priorities if i.finding.check_id == CERTIFICATE)
    assert (plan.now.score, item.gain, item.gain_max, plan.target.score) == (79, 21, None, 100)
    assert not plan.provisional


def test_blocked_and_dependency_errors_are_never_tasks():
    for deps in (BLOCKED_ALL, UNMEASURED_ALL):
        plan = scoring.plan(_outside(TEST_MAIL) + family(Status.FAIL, **deps))
        assert all(item.finding.status in (Status.FAIL, Status.WARN) for item in plan.items)


# ------------------------------------------------------------------ properties
def test_the_letter_rises_with_the_score_and_with_the_coverage():
    rank = {letter: len(scoring.LETTERS) - i for i, letter in enumerate(scoring.LETTERS)} | {None: 0}
    shares = [i / 1000 for i in range(1001)]
    for share in shares:
        letters = [rank[scoring.letter_for(n, share)] for n in range(101)]
        assert letters == sorted(letters), share
    for n in range(101):
        letters = [rank[scoring.letter_for(n, share)] for share in shares]
        assert letters == sorted(letters), n


def test_the_rounding_rises():
    values = sorted({Fraction(k, 2 * p) for p in range(1, 82) for k in range(0, 2 * p + 1)})
    shown = [scoring._points(v) for v in values]
    assert shown == sorted(shown)


def _outside_pairs():
    """Every (points earned, points possible) the mail and DNS checks of the registry can give,
    with each check OK, WARN, FAIL or not evaluated."""
    weights = [c.weight for c in REGISTRY.checks() if c.family is None and c.category in ("mail", "dns")
               and c.id != "mail.mx"]
    pairs = set()
    for states in product((1, 0.5, 0, None), repeat=len(weights)):
        earned = sum(Fraction(w) * Fraction(s) for w, s in zip(weights, states, strict=True) if s is not None)
        possible = sum(w for w, s in zip(weights, states, strict=True) if s is not None)
        pairs.add((earned, possible))
    return sorted(pairs)


def _synthetic_outside(earned: Fraction, possible: int) -> list[Finding]:
    """Three findings outside the family that earn exactly ``earned`` of ``possible`` points."""
    halves = int(2 * earned) % 2
    full = int(earned - Fraction(halves, 2))
    rest = possible - full - halves
    parts = [(Status.OK, full), (Status.WARN, halves), (Status.FAIL, rest)]
    return [Finding(f"lab.{status.value}", "mail", weight, Outcome(status, "lab"))
            for status, weight in parts if weight > 0]


def _reference(findings: list[Finding]) -> list[Finding]:
    """The lowest configuration of R(S): outside unchanged, root compliant, every dependent blocked
    or evaluated at its floor, the other dependents unchanged."""
    out = []
    for f in findings:
        if f.family == HTTPS and f.role is Role.ROOT:
            f = Finding(f.check_id, f.category, f.weight, Outcome(Status.OK, "lab.root"), f.family, f.role, f.floor)
        elif f.family == HTTPS and (f.status.scored or f.status is Status.BLOCKED):
            status = Status.OK if f.floor == 1 else Status.WARN
            f = Finding(f.check_id, f.category, f.weight, Outcome(status, "lab.dep"), f.family, f.role, f.floor)
        out.append(f)
    return out


SCENARIOS = {
    "refused everywhere": [family(Status.FAIL, **BLOCKED_ALL)],
    "certificate, root compliant": [
        family(tls__certificate=UNAUTHENTICATED, default=d) for d in (Status.OK, "floor")
    ] + [family(tls__certificate=UNAUTHENTICATED, tls__protocols=Status.FAIL, tls__key=Status.FAIL, default="floor")],
    "certificate, root not evaluated": [family(Status.ERROR, tls__certificate=UNAUTHENTICATED, default=d)
                                        for d in (Status.OK, "floor")],
    "certificate, pages not evaluated": [family(tls__certificate=UNAUTHENTICATED, default=Status.OK,
                                                **{p.replace(".", "__"): (Status.ERROR, ("network",)) for p in PAGE})],
    "certificate, partial refusal": [family(Status.FAIL, tls__certificate=UNAUTHENTICATED, default=d)
                                     for d in (Status.OK, "floor")],
    "obsolete only": [family(Status.FAIL, (Signal.HTTPS_OBSOLETE_ONLY,), tls__protocols=Status.FAIL, default=d,
                             tls__certificate=c) for d in (Status.OK, "floor") for c in (Status.OK, Status.WARN)],
    "obsolete only, certificate": [family(Status.FAIL, (Signal.HTTPS_OBSOLETE_ONLY,), tls__protocols=Status.FAIL,
                                          tls__certificate=UNAUTHENTICATED)],
}


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_a_capped_scan_never_beats_its_reference(scenario):
    """The proof of section 6, checked on every mail and DNS combination of the registry's weights:
    exact values, shown scores and grades."""
    rank = {letter: len(scoring.LETTERS) - i for i, letter in enumerate(scoring.LETTERS)} | {None: 0}
    pairs = _outside_pairs()
    assert len(pairs) > 100
    for earned, possible in pairs:
        outside = _synthetic_outside(earned, possible)
        for family_findings in SCENARIOS[scenario]:
            scan = outside + family_findings
            assert scoring.cap_reasons(scan), scenario
            reference = _reference(scan)
            assert not scoring.cap_reasons(reference)
            s, r = scoring.assess(scan), scoring.assess(reference)
            assert scoring.final_score(scan) <= scoring.final_score(reference)  # type: ignore[operator]
            if s.score is not None:
                assert r.score is not None and s.score <= r.score
                assert rank[s.grade] <= rank[r.grade]
            assert s.coverage <= r.coverage + 1e-12


def test_the_cap_never_raises_a_score():
    for earned, possible in _outside_pairs()[::7]:
        for family_findings in (f for group in SCENARIOS.values() for f in group):
            scan = _synthetic_outside(earned, possible) + family_findings
            result = scoring.assess(scan)
            if result.score_raw is not None:
                assert result.score_final <= result.score_raw  # type: ignore[operator]


def test_without_a_reason_the_score_is_the_raw_one():
    findings = _outside(TEST_MAIL) + family(Status.FAIL, tls__certificate=Status.FAIL)  # no signal, nothing blocked
    result = scoring.assess(findings)
    assert result.score_cap is None and result.score_final == result.score_raw
    assert CREDIT[Status.WARN] == 0.5  # the floors above assume the 0.3 credits
