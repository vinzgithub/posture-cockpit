# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Version 0.4, step 2: the points of the code review.

1. Plan gains when several fixes are planned, the HTTPS root among them.
2. Priority between ``trusted`` and ``problem`` in the recorded network.
3. Floors that are never guessed (nor NaN or infinite), signals reported only by the check allowed to.
4. web.https_redirect, the only HTTPS root: declared, reporting its signals and read by the score.
"""

from __future__ import annotations

import asyncio
import json
import math
from itertools import islice, product

import pytest

from posture_cockpit.core import (
    Check,
    Effort,
    Finding,
    Outcome,
    Remedy,
    Role,
    Signal,
    Status,
    UntrustedCertificate,
    registry,
    scoring,
)
from posture_cockpit.core.engine import run_check
from posture_cockpit.core.extension import CheckContext, Extension
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import HTTPS_FAMILY, HTTPS_ROOT_CHECK
from posture_cockpit.core.registry import Registry
from test_v04_scoring import BLOCKED_ALL, REGISTRY, UNMEASURED_ALL, family
from worlds import DOMAIN, NOW, with_certificate

FIX = Remedy(15, Effort.DELEGATE)
MAIL_DNS = [c for c in REGISTRY.checks() if c.family is None and c.category in ("mail", "dns") and c.id != "mail.mx"]


def _mail(**statuses: Status) -> list[Finding]:
    """The mail and DNS checks of the registry, OK unless given (dots as __)."""
    out = []
    for c in MAIL_DNS:
        status = statuses.get(c.id.replace(".", "__"), Status.OK)
        out.append(Finding(c.id, c.category, c.weight,
                           Outcome(status, "lab", remedy=FIX if status is not Status.OK else None)))
    return out


def _check_sums(plan: scoring.Plan) -> None:
    """The gains shown add up to the targets: the floor scenario to ``target``, the compliant one to
    ``target_max`` (or ``target`` when nothing is left unmeasured)."""
    now = plan.now.score or 0
    assert sum(i.gain for i in plan.priorities) == plan.target.score - now  # type: ignore[operator]
    top = plan.target_max.score if plan.target_max else plan.target.score
    assert sum(i.gain if i.gain_max is None else i.gain_max for i in plan.priorities) == top - now  # type: ignore[operator]
    assert all(i.gain_max is None or i.gain_max > i.gain for i in plan.items)


# ------------------------------------------------------------------ 1. plan
def test_a_bigger_fix_before_the_https_root():
    """DMARC (10 points) is ranked before the HTTPS root (8), whose ten dependents are blocked."""
    plan = scoring.plan(_mail(mail__dmarc=Status.FAIL) + family(Status.FAIL, **BLOCKED_ALL))
    steps = [(i.finding.check_id, i.gain, i.gain_max) for i in plan.priorities]
    assert plan.now.score == 59
    assert steps == [("mail.dmarc", 20, None), ("web.https_redirect", 0, 21)]
    assert (plan.target.score, plan.target_max.score) == (79, 100)  # type: ignore[union-attr]
    _check_sums(plan)


def test_a_smaller_fix_after_the_https_root():
    """DKIM (4 points) comes after the root: its gain is the same in both scenarios, hence exact."""
    plan = scoring.plan(_mail(mail__dkim=Status.FAIL) + family(Status.FAIL, **BLOCKED_ALL))
    steps = [(i.finding.check_id, i.gain, i.gain_max) for i in plan.priorities]
    assert plan.now.score == 73
    assert steps == [("web.https_redirect", 1, 22), ("mail.dkim", 5, None)]
    assert (plan.target.score, plan.target_max.score) == (79, 100)  # type: ignore[union-attr]
    _check_sums(plan)


def test_the_lower_bound_can_be_negative_only_on_a_provisional_score():
    """Undetermined: the score shown (82, no grade) leaves out the dependents; once HTTPS is
    restored, they count, at their floor in the lower bound: 79. The range is -3 to +18."""
    plan = scoring.plan(_mail() + family(Status.FAIL, (Signal.HTTPS_UNDETERMINED,), **UNMEASURED_ALL))
    root = plan.priorities[0]
    assert (plan.now.score, plan.now.grade) == (82, None)
    assert (root.finding.check_id, root.gain, root.gain_max) == ("web.https_redirect", -3, 18)
    assert (plan.target.score, plan.target_max.score) == (79, 100)  # type: ignore[union-attr]
    _check_sums(plan)


@pytest.mark.parametrize("root", ["blocked", "undetermined"])
def test_gains_add_up_to_the_targets_over_many_plans(root):
    fam = (family(Status.FAIL, **BLOCKED_ALL) if root == "blocked"
           else family(Status.FAIL, (Signal.HTTPS_UNDETERMINED,), **UNMEASURED_ALL))
    combos = product((Status.OK, Status.WARN, Status.FAIL), repeat=len(MAIL_DNS))
    for states in islice(combos, 0, None, 17):  # 386 plans out of 6 561
        statuses = {c.id.replace(".", "__"): s for c, s in zip(MAIL_DNS, states, strict=True)}
        plan = scoring.plan(_mail(**statuses) + fam)
        _check_sums(plan)
        if any(i.gain < 0 for i in plan.items):
            assert plan.now.grade is None and plan.now.grade_withheld_reason  # only on a provisional score


# ------------------------------------------------------------------ 2. trusted and problem
def _fixture(**values):
    net = FixtureNetwork(with_certificate(**values), NOW)

    async def main():
        cert = await net.certificate(f"www.{DOMAIN}")
        try:
            await net.http_get(f"https://www.{DOMAIN}/", verify=True)
            refused = ""
        except UntrustedCertificate as e:
            refused = e.problem
        return cert, refused

    return asyncio.run(main())


@pytest.mark.parametrize("values, problem", [
    ({"problem": "self-signed certificate"}, "self-signed certificate"),            # a problem alone is enough
    ({"trusted": False}, "certificate not trusted"),                                # trusted: false alone
    ({"trusted": False, "problem": "self-signed certificate"}, "self-signed certificate"),
    ({"problem": "hostname mismatch", "expires_in_days": -3}, "hostname mismatch"),  # the given problem first
    ({"trusted": True, "expires_in_days": -3}, "certificate has expired"),          # trusted never beats the dates
    ({"trusted": True}, ""),
])
def test_what_makes_a_recorded_certificate_untrusted(values, problem):
    cert, refused = _fixture(**values)
    assert (cert.trusted, cert.problem, refused) == (not problem, problem, problem)


# ------------------------------------------------------------------ 3. floors and signals
def _dependent(check_id="tls.key", status=Status.OK, floor=1.0, signals=()):
    return Finding(check_id, "tls", 3, Outcome(status, "lab", signals=frozenset(signals)),
                   HTTPS_FAMILY, Role.DEPENDENT, floor)


@pytest.mark.parametrize("floor", [None, 0, 0.0, -0.5, 1.5, math.nan, math.inf, -math.inf])
def test_a_dependent_needs_a_usable_floor(floor):
    with pytest.raises(ValueError, match="floor"):
        _dependent(floor=floor)


@pytest.mark.parametrize("stored", ["NaN", "Infinity", "-Infinity", '"nan"', '"inf"', '"-inf"', '"x"'])
def test_a_stored_floor_that_is_not_a_number_from_0_to_1_is_refused(stored):
    """Python's json reads NaN and Infinity, which strict JSON does not have; a text is turned into a number
    first. Every one of them is refused, as in the database the outcome is JSON read back with json.loads."""
    text = json.dumps({"summary": "lab", "family": {"name": "https", "role": "dependent", "floor": "FLOOR"}})
    data = json.loads(text.replace('"FLOOR"', stored))
    with pytest.raises(ValueError, match=r"float|floor"):
        Finding.from_stored("tls.key", "tls", 3, "ok", data)


def test_a_family_needs_a_role_and_a_role_a_family():
    with pytest.raises(ValueError, match="role"):
        Finding("tls.key", "tls", 3, Outcome(Status.OK, "lab"), HTTPS_FAMILY, None, 1.0)
    with pytest.raises(ValueError, match="family"):
        Finding("tls.key", "tls", 3, Outcome(Status.OK, "lab"), None, Role.DEPENDENT, 1.0)


def test_a_stored_dependent_without_a_floor_is_refused():
    data = {"summary": "lab", "family": {"name": "https", "role": "dependent", "floor": None}}
    with pytest.raises(ValueError, match="floor"):
        Finding.from_stored("tls.key", "tls", 3, "ok", data)


def test_the_cap_never_guesses_a_floor():
    """Defence in depth: even a finding forced past its checks is not given a floor of zero."""
    findings = family(Status.FAIL, **BLOCKED_ALL)
    object.__setattr__(findings[1], "floor", None)
    with pytest.raises(ValueError, match="floor"):
        scoring.cap_value(findings)


@pytest.mark.parametrize("floor", [math.nan, math.inf, -math.inf])
def test_a_floor_forced_to_nan_or_infinity_gives_no_cap_at_all(floor):
    """Forced past the checks of Finding, a floor that is not a number stops the computation of the cap
    (the exact fractions refuse it) instead of giving one."""
    findings = family(Status.FAIL, **BLOCKED_ALL)
    object.__setattr__(findings[1], "floor", floor)
    with pytest.raises((ValueError, OverflowError)):
        scoring.cap_value(findings)


@pytest.mark.parametrize("check_id, family_, role, status, signal", [
    ("tls.key", HTTPS_FAMILY, Role.DEPENDENT, Status.FAIL, Signal.CERTIFICATE_UNAUTHENTICATED),
    ("lab.certificate", None, None, Status.FAIL, Signal.CERTIFICATE_UNAUTHENTICATED),
    ("tls.certificate", HTTPS_FAMILY, Role.DEPENDENT, Status.WARN, Signal.CERTIFICATE_UNAUTHENTICATED),
    ("tls.protocols", HTTPS_FAMILY, Role.DEPENDENT, Status.FAIL, Signal.HTTPS_OBSOLETE_ONLY),
    ("mail.dmarc", None, None, Status.FAIL, Signal.HTTPS_UNDETERMINED),
    ("web.https_redirect", HTTPS_FAMILY, Role.ROOT, Status.OK, Signal.HTTPS_OBSOLETE_ONLY),
    ("web.https_redirect", HTTPS_FAMILY, Role.ROOT, Status.ERROR, Signal.HTTPS_UNDETERMINED),
])
def test_a_signal_is_reported_only_by_the_check_allowed_to(check_id, family_, role, status, signal):
    outcome = Outcome(status, "lab", signals=frozenset({signal}))
    floor = 1.0 if role is not None else None
    with pytest.raises(ValueError, match=r"signal|reported|critical"):
        Finding(check_id, "tls", 3, outcome, family_, role, floor)


def test_signals_are_checked_again_when_read_from_storage():
    wrong = {"summary": "lab", "signals": ["tls.certificate.unauthenticated"],
             "family": {"name": "https", "role": "dependent", "floor": 1.0}}
    with pytest.raises(ValueError, match=r"tls\.certificate"):
        Finding.from_stored("tls.key", "tls", 3, "fail", wrong)
    unknown = {"summary": "lab", "signals": ["https.everything_is_fine"],
               "family": {"name": "https", "role": "root", "floor": 1.0}}
    with pytest.raises(ValueError, match="unknown signal"):
        Finding.from_stored("web.https_redirect", "web", 8, "fail", unknown)
    right = dict(wrong)
    assert Finding.from_stored("tls.certificate", "tls", 10, "fail", right).outcome.signals == {
        Signal.CERTIFICATE_UNAUTHENTICATED}


def test_a_check_reporting_a_signal_it_may_not_is_not_evaluated():
    """The engine turns it into an internal error instead of a verdict, and the scan goes on."""
    async def says_too_much(ctx):
        return Outcome(Status.FAIL, "lab.oops", signals=frozenset({Signal.CERTIFICATE_UNAUTHENTICATED}))

    check = Check("lab.key", "tls", 3, says_too_much, "lab", True, HTTPS_FAMILY, Role.DEPENDENT,
                  frozenset({Status.OK, Status.FAIL}))
    ctx = CheckContext(domain=DOMAIN, net=FixtureNetwork({}, NOW), now=NOW)
    result = asyncio.run(run_check(check, ctx, timeout=5))
    assert result.status is Status.ERROR and result.outcome.summary == "check.error.internal"
    assert "tls.certificate" in result.outcome.evidence["error"] and not result.outcome.signals


# ------------------------------------------------------------------ 4. the only HTTPS root
ROOT_SIGNALS = [Signal.HTTPS_OBSOLETE_ONLY, Signal.HTTPS_UNDETERMINED]
ROOT_ONLY = r"may only be reported by web\.https_redirect"
TWO_VERDICTS = frozenset({Status.OK, Status.FAIL})


def _root(check_id: str, signal: Signal) -> Finding:
    return Finding(check_id, "web", 8, Outcome(Status.FAIL, "lab", signals=frozenset({signal})),
                   HTTPS_FAMILY, Role.ROOT, 1.0)


@pytest.mark.parametrize("signal", ROOT_SIGNALS)
def test_another_check_declared_root_may_not_report_the_root_signals(signal):
    """Same family, same role, same critical verdict: only the identity differs."""
    assert _root(HTTPS_ROOT_CHECK, signal).outcome.signals == {signal}
    with pytest.raises(ValueError, match=ROOT_ONLY):
        _root("lab.root", signal)


@pytest.mark.parametrize("signal", ROOT_SIGNALS)
def test_another_root_read_from_storage_may_not_carry_them(signal):
    data = {"summary": "lab", "signals": [signal.value], "family": {"name": "https", "role": "root", "floor": 1.0}}
    assert Finding.from_stored(HTTPS_ROOT_CHECK, "web", 8, "fail", data).outcome.signals == {signal}
    with pytest.raises(ValueError, match=ROOT_ONLY):
        Finding.from_stored("lab.root", "web", 8, "fail", data)


@pytest.mark.parametrize("signal", ROOT_SIGNALS)
def test_another_root_reporting_them_is_not_evaluated(signal):
    """Built by hand (the extension API refuses it, see below): the engine turns it into an internal error."""
    async def impostor(ctx):
        return Outcome(Status.FAIL, "lab.root", signals=frozenset({signal}))

    check = Check("lab.root", "web", 8, impostor, "lab", True, HTTPS_FAMILY, Role.ROOT, TWO_VERDICTS)
    ctx = CheckContext(domain=DOMAIN, net=FixtureNetwork({}, NOW), now=NOW)
    result = asyncio.run(run_check(check, ctx, timeout=5))
    assert result.status is Status.ERROR and result.outcome.summary == "check.error.internal"
    assert HTTPS_ROOT_CHECK in result.outcome.evidence["error"] and not result.outcome.signals


async def _nothing(ctx):
    return Outcome(Status.OK, "lab")


def test_no_other_check_can_be_declared_the_https_root():
    lab = Extension("lab", name="Lab", version="1")
    with pytest.raises(ValueError, match=r"lab\.root cannot provide 'https'"):
        lab.check("root", category="web", weight=8, provides="https", verdicts=TWO_VERDICTS)
    lab.check("key", category="tls", weight=3, requires="https", verdicts=TWO_VERDICTS)(_nothing)  # dependents: open
    web = Extension("web", name="Web", version="1")
    web.check("https_redirect", category="web", weight=8, provides="https", verdicts=TWO_VERDICTS)(_nothing)
    assert [(c.id, c.role) for c in lab.checks + web.checks] == [
        ("lab.key", Role.DEPENDENT), (HTTPS_ROOT_CHECK, Role.ROOT)]


def test_an_installed_extension_declaring_another_root_is_reported_not_loaded(monkeypatch):
    def impostor_extension():
        extension = Extension("impostor", name="Impostor", version="1")
        extension.check("root", category="web", weight=8, provides="https", verdicts=TWO_VERDICTS)(_nothing)
        return extension

    class EntryPoint:
        name, value, load = "impostor", "impostor:extension", staticmethod(impostor_extension)

    monkeypatch.setattr(registry, "entry_points", lambda group: [EntryPoint()])
    found = Registry.discover()
    assert [e.source.split(" =")[0] for e in found.errors] == ["impostor"]
    assert "cannot provide 'https'" in found.errors[0].error
    assert [c.id for c in found.checks() if c.role is Role.ROOT] == [HTTPS_ROOT_CHECK]


def test_the_score_reads_the_root_signals_on_web_https_redirect_only():
    """A finding presented as another HTTPS root and listed first (corrupted data, a check built by hand)
    neither takes the place of the root nor hides its signals."""
    impostor = Finding("lab.root", "web", 8, Outcome(Status.OK, "lab"), HTTPS_FAMILY, Role.ROOT, 1.0)
    undetermined = [impostor, *_mail(), *family(Status.FAIL, (Signal.HTTPS_UNDETERMINED,), **UNMEASURED_ALL)]
    assert scoring.withheld_reason(undetermined) == scoring.WITHHELD_HTTPS_UNDETERMINED
    obsolete = [impostor, *_mail(), *family(Status.FAIL, (Signal.HTTPS_OBSOLETE_ONLY,))]
    assert scoring.cap_reasons(obsolete) == (scoring.CAP_PROTOCOL,)
