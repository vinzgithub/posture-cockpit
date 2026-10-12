# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The engine: domain names, check execution, extensions, scoring."""

import asyncio

import pytest

from posture_cockpit.core import engine, registry, scoring
from posture_cockpit.core.extension import CheckContext, Extension
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import Effort, Finding, Outcome, Remedy, Status, fail, ok, warn
from posture_cockpit.core.network import NetworkError
from posture_cockpit.core.registry import Registry
from worlds import NOW


# ------------------------------------------------------------- domain names
@pytest.mark.parametrize(("typed", "expected"), [
    ("Example.ORG", "example.org"),
    ("  example.org.  ", "example.org"),
    ("https://www.example.org/contact?x=1", "example.org"),
    ("www.example.org:8443", "example.org"),
    ("mail.example.co.uk", "mail.example.co.uk"),
    ("café.fr", "xn--caf-dma.fr"),
])
def test_normalize_domain(typed, expected):
    assert engine.normalize_domain(typed) == expected


@pytest.mark.parametrize("typed", ["", "localhost", "exa mple.org", "-bad.org", "192.0.2.1", "a" * 64 + ".org",
                                   "example..org"])
def test_normalize_domain_refuses(typed):
    with pytest.raises(ValueError):
        engine.normalize_domain(typed)


# ---------------------------------------------------------- running checks
def make_extension() -> Extension:
    ext = Extension("demo", name="Demo", version="1")

    @ext.check("fine", category="dns", weight=2)
    async def fine(ctx):
        return ok("demo.fine")

    @ext.check("slow", category="dns", weight=2)
    async def slow(ctx):
        await asyncio.sleep(5)
        return ok("demo.slow")

    @ext.check("broken", category="dns", weight=2)
    async def broken(ctx):
        raise KeyError("oops")

    @ext.check("offline", category="dns", weight=2)
    async def offline(ctx):
        raise NetworkError("DNS TXT x: Timeout")

    return ext


def test_a_failing_check_does_not_stop_the_others():
    result = asyncio.run(engine.scan("example.org", make_extension().checks, FixtureNetwork({}), timeout=0.2))
    found = {f.check_id: f.outcome for f in result.findings}
    assert found["demo.fine"].status is Status.OK
    assert (found["demo.slow"].status, found["demo.slow"].summary) == (Status.ERROR, "check.error.timeout")
    assert found["demo.broken"].summary == "check.error.internal"
    assert "KeyError" in found["demo.broken"].evidence["error"]
    assert found["demo.offline"].summary == "check.error.network"


def test_shared_values_are_computed_once():
    calls = []

    async def compute():
        calls.append(1)
        await asyncio.sleep(0)
        return 42

    async def main():
        ctx = CheckContext("example.org", FixtureNetwork({}), NOW)
        return await asyncio.gather(*(ctx.shared("x", compute) for _ in range(5)))

    assert asyncio.run(main()) == [42] * 5 and calls == [1]


def test_preflight():
    net = FixtureNetwork({"dns": {"nope.example SOA": None, "example.org SOA": ["ns1.example.net. h. 1 2 3 4 5"],
                                  "mail.example.org A": ["192.0.2.1"]}})
    assert asyncio.run(engine.preflight(net, "nope.example")) == "unknown"
    assert asyncio.run(engine.preflight(net, "example.org")) is None
    assert asyncio.run(engine.preflight(net, "mail.example.org")) is None  # a subdomain has no SOA of its own
    # A resolver that answers everything with nothing: refuse rather than report false failures.
    assert asyncio.run(engine.preflight(net, "sinkholed.example.org")) == "empty"


# --------------------------------------------------------------- extensions
def test_extension_ids_and_weights_are_checked():
    with pytest.raises(ValueError):
        Extension("Bad Id", name="x", version="1")
    ext = Extension("ok", name="x", version="1")
    with pytest.raises(ValueError):
        ext.check("x", category="dns", weight=11)
    ext.check("x", category="dns", weight=1)(make_extension().checks[0].run)
    with pytest.raises(ValueError):
        ext.check("x", category="dns", weight=1)(make_extension().checks[0].run)


def test_two_extensions_cannot_share_an_id():
    with pytest.raises(ValueError):
        Registry([make_extension(), make_extension()])


def test_builtin_extensions_load():
    reg = Registry.discover()
    assert reg.errors == []
    assert [e.id for e in reg.extensions] == ["mail", "tls", "web", "dns"]
    assert len(reg.checks()) == 20
    assert all(c.category == "tls" for c in reg.checks() if c.extension == "tls")
    assert "mail.dmarc" not in {c.id for c in reg.checks(disabled={"mail"})}


class FakeEntryPoint:
    def __init__(self, name, value, load):
        self.name, self.value, self.load = name, value, load


def test_a_broken_extension_is_reported_not_raised(monkeypatch):
    def broken():
        raise ImportError("No module named 'posture_cockpit_ext'")

    eps = [FakeEntryPoint("broken", "posture_cockpit_ext:extension", broken),
           FakeEntryPoint("demo", "demo:extension", make_extension),
           FakeEntryPoint("wrong", "wrong:extension", lambda: object())]
    monkeypatch.setattr(registry, "entry_points", lambda group: eps)
    reg = Registry.discover()
    assert "demo" in [e.id for e in reg.extensions]
    assert [e.source.split(" =")[0] for e in reg.errors] == ["broken", "wrong"]
    assert "ImportError" in reg.errors[0].error


# ------------------------------------------------------------------ scoring
def finding(check_id, status, weight, minutes=10):
    remedy = Remedy(minutes, Effort.EASY) if status in (Status.FAIL, Status.WARN) else None
    return Finding(check_id, "dns", weight, Outcome(status, "x", {}, {}, remedy))


def test_score_weights_and_ignores_unchecked():
    findings = [finding("a", Status.OK, 6), finding("b", Status.WARN, 2), finding("c", Status.FAIL, 2),
                finding("d", Status.INFO, 9), finding("e", Status.NA, 9)]
    assert scoring.score(findings) == 70  # (6 + 1 + 0) / 10: the weights of 0.1.0, unchanged
    assert scoring.score(findings, fixed={"c"}) == 90
    assert scoring.score([]) is None      # nothing evaluated: no score at all


@pytest.mark.parametrize("findings", [
    [],                                                                          # no check at all
    [finding(f"e{i}", Status.ERROR, 5) for i in range(19)] + [finding("ok", Status.OK, 1)],  # 1 OK, 19 errors
    [finding("i", Status.INFO, 5), finding("n", Status.NA, 5)],                  # nothing applies
    [finding("e", Status.ERROR, 10)],                                            # everything failed to run
], ids=["empty", "one_ok_among_errors", "nothing_applies", "only_errors"])
def test_nothing_or_too_little_evaluated_is_never_an_a(findings):
    """The anomaly reported by the external review: 0.1.0 gave 100/A to each of these."""
    result = scoring.assess(findings)
    assert (result.score, result.grade) == (None, None)
    assert not result.evaluated_ok


def test_coverage_is_weighted_and_leaves_out_what_does_not_apply():
    findings = [finding("a", Status.OK, 6), finding("b", Status.FAIL, 2), finding("x", Status.ERROR, 2),
                finding("n", Status.NA, 10), finding("i", Status.INFO, 10)]
    result = scoring.assess(findings)
    assert result.coverage == pytest.approx(0.8)     # 8 of the 10 applicable weight points evaluated
    assert (result.evaluated, result.applicable) == (2, 3)
    assert result.score == 75 and result.partial


@pytest.mark.parametrize(("ok_weight", "error_weight", "expected"), [
    (10, 0, (100, "A")),     # full coverage
    (9, 1, (100, "A")),      # 90 %: complete enough
    (89, 11, (100, "B")),    # 89 %: partial, an A becomes a B
    (5, 5, (100, "B")),      # 50 %: still scored
    (49, 51, (None, None)),  # 49 %: not evaluated
])
def test_coverage_thresholds(ok_weight, error_weight, expected):
    findings = [finding("ok", Status.OK, ok_weight)]
    if error_weight:
        findings.append(finding("err", Status.ERROR, error_weight))
    result = scoring.assess(findings)
    assert (result.score, result.grade) == expected


def test_a_partial_evaluation_only_caps_the_best_grades():
    findings = [finding("ok", Status.OK, 6), finding("bad", Status.FAIL, 4), finding("err", Status.ERROR, 2)]
    result = scoring.assess(findings)
    assert result.partial and (result.score, result.grade) == (60, "C")  # C stays C
    assert result.coverage_percent == 83


def test_coverage_percent_never_rounds_up_to_a_threshold():
    findings = [finding("ok", Status.OK, 896), finding("err", Status.ERROR, 104)]
    result = scoring.assess(findings)
    assert result.coverage_percent == 89 and result.grade == "B"


@pytest.mark.parametrize(("value", "grade"), [(100, "A"), (85, "A"), (84, "B"), (70, "B"), (69, "C"),
                                              (55, "C"), (40, "D"), (25, "E"), (24, "F"), (0, "F")])
def test_grades(value, grade):
    assert scoring.grade(value) == grade


def test_plan_orders_by_effect_then_speed_and_gains_add_up():
    findings = [finding("small", Status.FAIL, 2), finding("big_slow", Status.FAIL, 8, minutes=30),
                finding("big_quick", Status.FAIL, 8, minutes=5), finding("meh", Status.WARN, 4),
                finding("fine", Status.OK, 6)]
    plan = scoring.plan(findings)
    assert [i.finding.check_id for i in plan.priorities] == ["big_quick", "big_slow", "small"]
    assert [i.finding.check_id for i in plan.improvements] == ["meh"]
    assert plan.now.score + sum(i.gain for i in plan.priorities) == plan.target.score
    assert plan.target.score + sum(i.gain for i in plan.improvements) == 100


def test_categories_are_assessed_separately():
    findings = [finding("a", Status.OK, 2), Finding("w", "web", 3, Outcome(Status.ERROR, "x")),
                Finding("m", "mail", 3, Outcome(Status.NA, "x"))]
    categories = scoring.by_category(findings)
    assert list(categories) == ["dns", "web"]  # mail: nothing applies
    assert categories["dns"].score == 100 and categories["web"].score is None


def test_findings_round_trip_through_json():
    original = Finding("mail.dmarc", "mail", 10, fail("mail.dmarc.missing", Remedy(10, Effort.EASY), {"a": [1]}, n=2))
    copy = Finding.from_stored("mail.dmarc", "mail", 10, "fail", original.outcome_json())
    assert copy == original
    stored = Finding("x", "dns", 1, warn("w")).outcome_json()
    assert Finding.from_stored("x", "dns", 1, "warn", stored).outcome.remedy is None


def test_a_check_that_times_out_does_not_cancel_shared_work_for_the_others():
    ext = Extension("share", name="Share", version="1")

    async def slow_answer():
        await asyncio.sleep(0.3)
        return 7

    @ext.check("impatient", category="dns", weight=1)
    async def impatient(ctx):
        return ok("x", value=await ctx.shared("answer", slow_answer))

    @ext.check("patient", category="dns", weight=1)
    async def patient(ctx):
        await asyncio.sleep(0.05)  # starts waiting after "impatient" started the work
        return ok("x", value=await ctx.shared("answer", slow_answer))

    async def main():
        ctx = CheckContext("example.org", FixtureNetwork({}), NOW)
        first, second = ext.checks
        # "impatient" gives up after 0.1 s, while the shared work is still running
        return await asyncio.gather(engine.run_check(first, ctx, 0.1), engine.run_check(second, ctx, 2))

    impatient_result, patient_result = asyncio.run(main())
    assert impatient_result.status is Status.ERROR
    assert patient_result.outcome.params == {"value": 7}
