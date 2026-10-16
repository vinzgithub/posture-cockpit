# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Version 0.4, T1: the HTTPS decision matrix of the specification (section 5), one test per line.

Each line is a recorded world described address by address. The test checks the situation of each
host, the verdict of the root, the state of the three TLS dependents and of the seven page
dependents, the caps and the withheld grade, and that every text it produces exists in French and
in English. Lines M11, M21, M32 and M33 follow the rule on obsolete TLS decided after revision 3
(an address that speaks only TLS 1.0 or 1.1 is measured, nothing is blocked because of it, the
protocol cap applies when no address speaks anything newer); the others follow revision 3 as written.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from https_worlds import (
    ALERT,
    CLOSE,
    DOMAIN,
    ELSEWHERE,
    HANG,
    NO_OLD_TLS_HERE,
    NO_ROUTE,
    OBSOLETE,
    OK,
    PAGE_CHECKS,
    POLICY,
    REFUSED,
    RESET,
    TIMEOUT,
    TLS_CHECKS,
    V4A,
    V4B,
    V4C,
    V4D,
    V4E,
    V4F,
    V6A,
    WWW,
    Result,
    fournet_mail,
    scan,
    site,
)
from posture_cockpit.core import scoring
from posture_cockpit.core.model import Signal, Status
from posture_cockpit.core.registry import Registry
from posture_cockpit.i18n import LOCALES, Catalog

CATALOG = Catalog(Registry.discover().messages)
EXPIRED = {"certificate": {"expires_in_days": -3}}
SIX = (V4A, V4B, V4C, V4D, V4E, V4F)
MEASURED = {"ok", "warn", "fail"}
DEADLINE = 0.3  # the probe's deadline in the lines that reach it (9 s in production)


@dataclass
class Line:
    world: Callable[[], dict]
    situations: dict[str, str]
    root: tuple[Status, str]
    tls: str | dict[str, str]    # one state for the three, or by check ("measured": ok, warn or fail)
    page: str | dict[str, str]
    caps: tuple[str, ...] = ()
    withheld: bool = False
    signal: str | None = None
    deadline: float | None = None
    extra: dict = field(default_factory=dict)


LINES: dict[str, Line] = {
    # ---- absent
    "M1": Line(lambda: site(None, None), {}, (Status.NA, "web.no_website"), "na", "na"),
    # ---- available
    "M2": Line(lambda: site({V4A: OK}), {DOMAIN: "available", WWW: "absent"},
               (Status.OK, "web.https_redirect.ok"), "ok", "ok"),
    "M3": Line(lambda: site({V4A: {"80": {"status": 200}}}), {DOMAIN: "available"},
               (Status.FAIL, "web.https_redirect.missing"), "ok", "ok"),
    "M4": Line(lambda: site({V4A: {"80": ELSEWHERE}}), {DOMAIN: "available"},
               (Status.OK, "web.https_redirect.ok"), "ok", "ok"),
    "M5": Line(lambda: site({V4A: {"80": "refused"}}), {DOMAIN: "available"},
               (Status.OK, "web.https_redirect.ok"), "ok", "ok"),
    "M6": Line(lambda: site({V4A: {"80": "timeout"}}), {DOMAIN: "available"},
               (Status.ERROR, "web.https_redirect.http_unknown"), "ok", "ok"),
    "M7": Line(lambda: site({V4A: {"https": "timeout"}}), {DOMAIN: "unknown"},
               (Status.ERROR, "web.https_redirect.unknown"), "ok", "error"),
    "M8": Line(lambda: site({V4A: {"443": ["reset", "ok"]}}), {DOMAIN: "available"},
               (Status.OK, "web.https_redirect.ok"), "ok", "ok"),
    # ---- invalid certificate
    "M9-expired": Line(lambda: site({V4A: EXPIRED}), {DOMAIN: "available"}, (Status.OK, "web.https_redirect.ok"),
                       {"tls.certificate": "fail", "*": "ok"}, "ok", caps=("authentication",)),
    "M9-authority": Line(lambda: site({V4A: {"certificate": {"problem": "unable to get local issuer certificate"}}}),
                         {DOMAIN: "available"}, (Status.OK, "web.https_redirect.ok"),
                         {"tls.certificate": "fail", "*": "ok"}, "ok", caps=("authentication",)),
    "M9-name": Line(lambda: site({V4A: {"certificate": {"names": ["other.example"],
                                                        "problem": "Hostname mismatch"}}}),
                    {DOMAIN: "available"}, (Status.OK, "web.https_redirect.ok"),
                    {"tls.certificate": "fail", "*": "ok"}, "ok", caps=("authentication",)),
    "M10": Line(lambda: site({V4A: OK, V4B: EXPIRED}), {DOMAIN: "available"}, (Status.OK, "web.https_redirect.ok"),
                {"tls.certificate": "fail", "*": "ok"}, "ok", caps=("authentication",)),
    # ---- obsolete TLS
    "M11": Line(lambda: site({V4A: OBSOLETE}), {DOMAIN: "obsolete"}, (Status.FAIL, "web.https_redirect.obsolete"),
                {"tls.protocols": "fail", "*": "ok"}, "ok", caps=("protocol",), signal=Signal.HTTPS_OBSOLETE_ONLY),
    "M12": Line(lambda: site({V4A: NO_OLD_TLS_HERE}), {DOMAIN: "untestable"},
                (Status.ERROR, "web.https_redirect.legacy_untestable"), "dependency", "dependency"),
    # ---- refused
    "M13": Line(lambda: site({V4A: REFUSED}), {DOMAIN: "refused"}, (Status.FAIL, "web.https_redirect.refused"),
                "blocked", "blocked", caps=("dependency",)),
    "M14-reset": Line(lambda: site({V4A: RESET}), {DOMAIN: "refused"}, (Status.FAIL, "web.https_redirect.refused"),
                      "blocked", "blocked", caps=("dependency",)),
    "M14-close": Line(lambda: site({V4A: CLOSE}), {DOMAIN: "refused"}, (Status.FAIL, "web.https_redirect.refused"),
                      "blocked", "blocked", caps=("dependency",)),
    "M15": Line(lambda: site({V4A: ALERT}), {DOMAIN: "refused"}, (Status.FAIL, "web.https_redirect.refused"),
                "blocked", "blocked", caps=("dependency",)),
    "M16": Line(lambda: site({V4A: {"443": "refused", "80": "refused"}}), {DOMAIN: "refused"},
                (Status.FAIL, "web.https_redirect.no_service"), "blocked", "blocked", caps=("dependency",)),
    "M17": Line(lambda: site({V4A: {"443": "refused", "80": {"status": 200}}}), {DOMAIN: "refused"},
                (Status.FAIL, "web.https_redirect.refused"), "blocked", "blocked", caps=("dependency",),
                extra={"notes": ["web.https_redirect.missing"]}),
    "M18": Line(lambda: site({"213.186.33.5": {**RESET, "80": ELSEWHERE}}, {"213.186.33.5": {**RESET, "80": ELSEWHERE}},
                             mail=fournet_mail),
                {DOMAIN: "refused", WWW: "refused"}, (Status.FAIL, "web.https_redirect.external"),
                "blocked", "blocked", caps=("dependency",)),
    "M18b": Line(lambda: site({"213.186.33.5": {**RESET, "80": ELSEWHERE}, V6A: TIMEOUT},
                              {"213.186.33.5": {**RESET, "80": ELSEWHERE}}, mail=fournet_mail),
                 {DOMAIN: "undetermined", WWW: "refused"}, (Status.FAIL, "web.https_redirect.refused_undetermined"),
                 "dependency", "dependency", withheld=True, signal=Signal.HTTPS_UNDETERMINED),
    # ---- partly available
    "M19": Line(lambda: site({V4A: OK, V6A: REFUSED}), {DOMAIN: "partial"},
                (Status.FAIL, "web.https_redirect.refused_partial"), "ok", "ok"),
    "M20": Line(lambda: site({V4A: OK, V4B: REFUSED}), {DOMAIN: "partial"},
                (Status.FAIL, "web.https_redirect.refused_partial"), "ok", "ok"),
    "M21": Line(lambda: site({V4A: OK, V6A: OBSOLETE}), {DOMAIN: "partial"},
                (Status.FAIL, "web.https_redirect.obsolete_partial"), {"tls.protocols": "fail", "*": "ok"}, "ok"),
    "M22": Line(lambda: site({V4A: OK, V6A: TIMEOUT}), {DOMAIN: "available_incomplete"},
                (Status.OK, "web.https_redirect.ok"), "ok", "ok"),
    # ---- timeouts and untestable
    "M23": Line(lambda: site({V4A: TIMEOUT}), {DOMAIN: "unknown"}, (Status.ERROR, "web.https_redirect.unknown"),
                "dependency", "dependency"),
    "M24": Line(lambda: site({V4A: {"443": ["reset", "timeout"]}}), {DOMAIN: "unknown"},
                (Status.ERROR, "web.https_redirect.unknown"), "dependency", "dependency"),
    "M25": Line(lambda: site({V4A: REFUSED, V6A: TIMEOUT}), {DOMAIN: "undetermined"},
                (Status.FAIL, "web.https_redirect.refused_undetermined"), "dependency", "dependency",
                withheld=True, signal=Signal.HTTPS_UNDETERMINED),
    "M26": Line(lambda: site({V6A: NO_ROUTE}), {DOMAIN: "untestable"}, (Status.ERROR, "web.https_redirect.untestable"),
                "dependency", "dependency"),
    "M27": Line(lambda: site({V4A: POLICY}), {DOMAIN: "untestable"}, (Status.ERROR, "check.error.blocked.private"),
                "dependency", "dependency"),
    "M28": Line(lambda: site(dict.fromkeys((*SIX, "192.0.2.16"), REFUSED)), {DOMAIN: "undetermined"},
                (Status.FAIL, "web.https_redirect.refused_undetermined"), "dependency", "dependency",
                withheld=True, signal=Signal.HTTPS_UNDETERMINED),
    # ---- the domain and www
    "M29": Line(lambda: site({V4A: REFUSED}, {V4B: OK}), {DOMAIN: "refused", WWW: "available"},
                (Status.FAIL, "web.https_redirect.refused"), "ok", "ok"),
    "M30": Line(lambda: site({V4A: REFUSED}, {V4B: TIMEOUT}), {DOMAIN: "refused", WWW: "unknown"},
                (Status.FAIL, "web.https_redirect.refused"), "dependency", "dependency",
                withheld=True, signal=Signal.HTTPS_UNDETERMINED),
    "M31": Line(lambda: site(None, {V4B: REFUSED}), {DOMAIN: "absent", WWW: "refused"},
                (Status.FAIL, "web.https_redirect.refused"), "blocked", "blocked", caps=("dependency",)),
    "M32": Line(lambda: site({V4A: OK}, {V4B: OBSOLETE}), {DOMAIN: "available", WWW: "obsolete"},
                (Status.FAIL, "web.https_redirect.obsolete"), {"tls.protocols": "fail", "*": "ok"}, "ok"),
    "M33": Line(lambda: site({V4A: OBSOLETE}, {V4B: REFUSED}), {DOMAIN: "obsolete", WWW: "refused"},
                (Status.FAIL, "web.https_redirect.obsolete"), {"tls.protocols": "fail", "*": "ok"}, "ok",
                caps=("protocol",), signal=Signal.HTTPS_OBSOLETE_ONLY),
    # ---- added in revision 3
    "M34": Line(lambda: site(dict.fromkeys(SIX, OK)), {DOMAIN: "available_incomplete"},
                (Status.OK, "web.https_redirect.ok"), "ok", "ok", extra={"notes": ["web.https_redirect.note.sample"]}),
    "M35": Line(lambda: site({V4A: OK, V4B: OK, V4C: REFUSED, V4D: REFUSED, V4E: OK, V4F: OK}), {DOMAIN: "partial"},
                (Status.FAIL, "web.https_redirect.refused_partial"), "ok", "ok"),
    "M36": Line(lambda: site({V4A: OK, V6A: NO_ROUTE}), {DOMAIN: "available_incomplete"},
                (Status.OK, "web.https_redirect.ok"), "ok", "ok",
                extra={"notes": ["web.https_redirect.note.no_route"]}),
    "M37": Line(lambda: site({V4A: REFUSED, V6A: NO_ROUTE}), {DOMAIN: "undetermined"},
                (Status.FAIL, "web.https_redirect.refused_undetermined"), "dependency", "dependency",
                withheld=True, signal=Signal.HTTPS_UNDETERMINED),
    "M38": Line(lambda: site({V4A: {"versions": {"TLSv1.3": False}}}), {DOMAIN: "available"},
                (Status.OK, "web.https_redirect.ok"), {"tls.protocols": "warn", "*": "ok"}, "ok"),
    "M39": Line(lambda: site({V4A: EXPIRED}), {DOMAIN: "available"}, (Status.OK, "web.https_redirect.ok"),
                {"tls.certificate": "fail", "*": "ok"}, "ok", caps=("authentication",)),
    "M40": Line(lambda: site({V4A: {**EXPIRED, "80": {"status": 200}}}), {DOMAIN: "available"},
                (Status.FAIL, "web.https_redirect.missing"), {"tls.certificate": "fail", "*": "ok"}, "ok",
                caps=("authentication",)),
    "M41": Line(lambda: site({V4A: {"443": {"TLSv1": "timeout"},
                                    "http": {f"https://{DOMAIN}/.well-known/security.txt": "reset"}}}),
                {DOMAIN: "available"}, (Status.OK, "web.https_redirect.ok"),
                {"tls.protocols": "error", "*": "ok"}, {"web.security_txt": "error", "*": "ok"}),
    "M42": Line(lambda: site({V4A: {**TIMEOUT, "80": ELSEWHERE}}), {DOMAIN: "unknown"},
                (Status.ERROR, "web.https_redirect.unknown"), "dependency", "dependency"),
    "M43": Line(lambda: site({V4A: {"certificate": {"problem": "self-signed certificate"}, "80": ELSEWHERE}}),
                {DOMAIN: "available"}, (Status.OK, "web.https_redirect.ok"),
                {"tls.certificate": "fail", "*": "ok"}, "ok", caps=("authentication",)),
    "M44": Line(lambda: site({V4A: OK, V4B: HANG}), {DOMAIN: "available_incomplete"},
                (Status.OK, "web.https_redirect.ok"), "ok", "ok", deadline=DEADLINE,
                extra={"notes": ["web.https_redirect.note.deadline"]}),
    "M45": Line(lambda: site({V4A: {**HANG, "80": "hang"}}), {DOMAIN: "untestable"},
                (Status.ERROR, "web.https_redirect.budget"), "dependency", "dependency", deadline=DEADLINE),
    "M46": Line(lambda: site({V4A: REFUSED, V4B: HANG}), {DOMAIN: "undetermined"},
                (Status.FAIL, "web.https_redirect.refused_undetermined"), "dependency", "dependency",
                withheld=True, signal=Signal.HTTPS_UNDETERMINED, deadline=DEADLINE),
}


def _expected(spec: str | dict[str, str], check_id: str) -> str:
    return spec if isinstance(spec, str) else spec.get(check_id, spec["*"])


def _texts(result: Result) -> list[str]:
    """Every text key the scan produced: summaries, notes, remedies."""
    keys = []
    for f in result.findings.values():
        keys.append(f.outcome.summary)
        keys += [n["key"] for n in f.outcome.evidence.get("notes", []) if isinstance(n, dict)]
        if f.outcome.remedy is not None and f.outcome.remedy.message:
            keys.append(f.outcome.remedy.message)
        if f.status.scored and f.status is not Status.OK and f.outcome.remedy is not None:
            keys.append(next(k for k in (f"{f.outcome.summary}.action", f"{f.check_id}.action")
                             if CATALOG.has("fr", k)))
    return keys


@pytest.mark.parametrize("name", LINES)
def test_matrix(name):
    line = LINES[name]
    result = scan(line.world(), deadline=line.deadline)
    root = result.root
    assert (root.status, root.outcome.summary) == line.root
    for host, situation in line.situations.items():
        assert result.situation(host) == situation, host
    for check_id in TLS_CHECKS:
        assert result.state(check_id) == _expected(line.tls, check_id), check_id
    for check_id in PAGE_CHECKS:
        assert result.state(check_id) == _expected(line.page, check_id), check_id
    assert result.assessment.cap_reasons == line.caps
    assert (result.assessment.grade_withheld_reason is not None) == line.withheld
    assert root.outcome.signals == ({line.signal} if line.signal else set())
    for key in line.extra.get("notes", []):
        assert key in [n["key"] for n in root.outcome.evidence.get("notes", [])], key
    missing = [(lang, key) for key in _texts(result) for lang in LOCALES if not CATALOG.has(lang, key)]
    assert missing == []


@pytest.mark.parametrize("name", [n for n, line in LINES.items() if line.withheld])
def test_an_undetermined_case_never_says_unavailable(name):
    """Six points, §6: no text says "indisponible" or "unavailable" when the refusal is not established."""
    result = scan(LINES[name].world(), deadline=LINES[name].deadline)
    for lang in LOCALES:
        for f in result.findings.values():
            text = CATALOG.text(lang, f.outcome.summary, {"domain": DOMAIN, **f.outcome.params}).lower()
            assert "indisponible" not in text and "unavailable" not in text, (lang, f.check_id)


def test_the_refusal_on_one_address_names_it():
    """M20, M35: the address that refuses is named, never hidden by those that answer."""
    root = scan(LINES["M35"].world()).root
    assert root.outcome.params == {"host": DOMAIN, "addresses": f"{V4C}, {V4D}"}
    certificate = scan(LINES["M10"].world()).findings["tls.certificate"]
    assert certificate.outcome.params["host"] == f"{DOMAIN} ({V4B})"


def test_a_cleartext_page_beside_a_refusal_is_named_too():
    """M17: one critical for the root, whose text names each cause observed."""
    root = scan(LINES["M17"].world()).root
    assert root.outcome.summary == "web.https_redirect.refused"
    assert {"key": "web.https_redirect.missing", "params": {"host": DOMAIN}} in root.outcome.evidence["notes"]


@pytest.mark.parametrize("name, measured", [("M21", [V4A, V6A]), ("M32", [DOMAIN, WWW])])
def test_an_obsolete_address_is_measured_beside_a_modern_one(name, measured):
    """M21, M32: the TLS and page checks keep the worst verdict of both; tls.protocols is critical."""
    result = scan(LINES[name].world())
    accepted = result.findings["tls.protocols"].outcome.evidence["accepted"]
    assert len(accepted) == 2 and all(any(m in label for m in measured) for label in accepted)
    assert result.findings["web.hsts"].status is Status.OK
    notes = [n["key"] for n in result.findings["web.hsts"].outcome.evidence.get("notes", [])]
    assert "web.note.obsolete_page" in notes


def test_m11_measures_everything_over_the_old_version():
    """Obsolete TLS only: 10 dependents measured, none blocked, the root and tls.protocols critical."""
    result = scan(LINES["M11"].world())
    assert result.assessment.blocked == 0
    assert all(result.state(c) in MEASURED for c in (*TLS_CHECKS, *PAGE_CHECKS))
    certificate = result.findings["tls.certificate"]
    assert "tls.certificate.note.seclevel" in [n["key"] for n in certificate.outcome.evidence["notes"]]
    assert [n["key"] for n in result.findings["tls.protocols"].outcome.evidence["notes"]] == \
        ["tls.protocols.note.no_modern"]


def test_m9_mentions_what_a_page_read_behind_an_invalid_certificate_is_worth():
    """Section 4: HSTS ignored by browsers, a page that may be the default site, security.txt not verifiable."""
    result = scan(LINES["M9-name"].world())
    hsts = [n["key"] for n in result.findings["web.hsts"].outcome.evidence["notes"]]
    assert "web.hsts.note.invalid_certificate" in hsts and "web.note.name_mismatch" in hsts
    assert "web.security_txt.note.unverifiable" in [
        n["key"] for n in result.findings["web.security_txt"].outcome.evidence["notes"]]
    assert "web.https_redirect.note.certificate" in [n["key"] for n in result.root.outcome.evidence["notes"]]


def test_m41_a_failure_after_the_probe_is_never_critical():
    """M41: the checks hit by the intermittent failure are not evaluated (network), the others measured."""
    result = scan(LINES["M41"].world())
    assert result.findings["tls.protocols"].outcome.summary == "check.error.network_timeout"
    assert result.findings["web.security_txt"].outcome.summary == "check.error.reset"
    assert result.findings["tls.protocols"].outcome.evidence.get("cause") != "dependency"


def test_m8_notes_the_instability():
    notes = scan(LINES["M8"].world()).root.outcome.evidence["notes"]
    assert {"key": "web.https_redirect.note.instability", "params": {"addresses": f"{DOMAIN} ({V4A})"}} in notes


# ------------------------------------------------------------- T2: fournet.one
def test_t2_fournet_m18_scores_67_c_on_full_scoring_coverage():
    result = scan(LINES["M18"].world())
    a = result.assessment
    assert (a.score, a.grade, a.blocked, a.coverage) == (67, "C", 10, 1.0)
    assert a.diagnostic_coverage == pytest.approx(44 / 81)
    assert a.cap_reasons == (scoring.CAP_DEPENDENCY,) and not a.capped  # the cap (70.99) stays above 67.05
    evidence = result.root.outcome.evidence
    assert evidence["announced"]["level"] == "not_announced"  # a redirect to another site is no announcement
    assert {"key": "web.https_redirect.note.external",
            "params": {"host": DOMAIN, "target": "https://github.com/vinzgithub"}} in evidence["notes"]


def test_t2_fournet_m18b_scores_67_without_a_grade():
    a = scan(LINES["M18b"].world()).assessment
    assert (a.score, a.grade, a.blocked) == (67, None, 0)
    assert a.coverage == pytest.approx(44 / 81) and a.diagnostic_coverage == pytest.approx(44 / 81)
    assert a.evaluation == "undetermined" and a.grade_withheld_reason == scoring.WITHHELD_HTTPS_UNDETERMINED


def test_t2_fournet_attribution_is_localised_when_mta_sts_negotiates_tls():
    """Section 7: the MTA-STS host of the domain negotiated TLS from here: the refusal is specific to the address."""
    evidence = scan(LINES["M18"].world()).root.outcome.evidence
    assert evidence["attribution"]["level"] == "destination"
    assert evidence["attribution"]["elements"] == [f"mta-sts.{DOMAIN} (192.0.2.10)"]
    assert any(n["key"] == "web.https_redirect.attribution.destination" for n in evidence["notes"])


def test_the_remedy_follows_the_attribution_and_the_announcement():
    """Section 7: localised and not announced, serve HTTPS or stop publishing the address; announced,
    restore it; not localised, check from another network first. The external redirection keeps its own."""
    assert scan(LINES["M18"].world()).root.outcome.remedy.message == "web.https_redirect.external.message"
    localised = scan(LINES["M13"].world())  # www has no address: nothing else negotiated but mta-sts
    assert localised.root.outcome.evidence["attribution"]["level"] == "destination"
    assert localised.root.outcome.evidence["announced"]["level"] == "announced"  # http:// → https:// same host
    assert localised.root.outcome.remedy.message == "web.https_redirect.restore.message"
    quiet = LINES["M16"].world()  # port 80 closed: nothing announced
    assert scan(quiet).root.outcome.remedy.message == "web.https_redirect.refused.message"
    quiet["http"][f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt"] = "timeout"
    assert scan(quiet).root.outcome.remedy.message == "web.https_redirect.verify.message"


def test_t2_fournet_attribution_stays_undetermined_without_another_negotiation():
    """The only other TLS negotiation of the domain went over IPv6: it says nothing of the IPv4 path."""
    data = LINES["M18"].world()
    data["dns"][f"mta-sts.{DOMAIN} A"] = []
    data["dns"][f"mta-sts.{DOMAIN} AAAA"] = ["2001:db8::25"]
    result = scan(data)
    evidence = result.root.outcome.evidence
    assert evidence["attribution"] == {"level": "undetermined", "elements": []}
    assert any(n["key"] == "web.https_redirect.attribution.undetermined" for n in evidence["notes"])
    # Neither the attribution nor the announcement changes a status or the score (I7).
    assert (result.root.status, result.assessment.score) == (Status.FAIL, 67)


# ------------------------------------------------------------------ T4, engine
def test_t4_no_check_gives_a_verdict_it_did_not_declare():
    """H6, on every line of the matrix: a dependent's floor is only right if it keeps to its verdicts."""
    registry = Registry.discover()
    for name, line in LINES.items():
        result = scan(line.world(), deadline=line.deadline)
        for f in result.findings.values():
            check = registry.get(f.check_id)
            if check is not None and check.verdicts is not None and f.status.scored:
                assert f.status in check.verdicts, (name, f.check_id, f.status)


def test_a_blocked_dependent_is_not_run():
    """M13: the engine writes the ten results; no check connects anywhere after the probe."""
    result = scan(LINES["M13"].world())
    probe_attempts = [t for a in [result.root.outcome.evidence["observation"]["hosts"][DOMAIN]["addresses"][V4A]]
                      for t in a["attempts"]]
    tls = [c for c in result.net.connections if c["kind"] == "tls"]
    assert len(tls) == len(probe_attempts) == 3  # the three confirmation attempts, nothing else
    assert not any("security.txt" in q for q in result.net.asked)
    assert all(result.findings[c].outcome.evidence["blocked_by"] == "web.https_redirect"
               for c in (*TLS_CHECKS, *PAGE_CHECKS))


def test_every_result_can_be_stored():
    """The database keeps outcomes as JSON: the probe's observation included."""
    import json

    for line in LINES.values():
        for f in scan(line.world(), deadline=line.deadline).findings.values():
            json.dumps(f.outcome_json())


@pytest.mark.parametrize("page, deadline", [("timeout", None), ("reset", None), ("close", None), ("hang", DEADLINE)])
def test_an_old_version_negotiated_without_a_page_leaves_the_page_checks_not_evaluated(page, deadline):
    """TLS 1.0 negotiates but the page does not come (no answer, reset, closed, interrupted at the
    deadline): the TLS checks are measured, the page checks are not evaluated for a network cause,
    as M7 for TLS 1.2: never judged compliant, never blocked (nothing proves HTTPS refused)."""
    result = scan(site({V4A: {**OBSOLETE, "https": page}}), deadline=deadline)
    assert (result.root.status, result.root.outcome.summary) == (Status.FAIL, "web.https_redirect.obsolete")
    assert all(result.state(c) in MEASURED for c in TLS_CHECKS)
    for check_id in PAGE_CHECKS:
        f = result.findings[check_id]
        assert f.status is Status.ERROR and f.outcome.evidence["cause"] == "network", check_id
    assert result.assessment.blocked == 0
