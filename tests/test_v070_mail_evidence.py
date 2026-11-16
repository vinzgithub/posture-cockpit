# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The evidence and the texts of mail.mx and mail.mta_sts, bounded (version 0.7.0, correction 4).

checks/mail_evidence.py bounds what the two checks store and show: 16 entries per list, those that make the
verdict first, the number left out exactly; 255 characters per string of the policy and of the TXT records;
16 names then "…" in the messages (D1); 65,536 bytes at most for the evidence as the database holds it. The
verdicts are decided before, on everything. What is checked here:

- an ordinary domain, within the bounds, keeps its outcome byte for byte; the corpus of correction 2 and the
  extreme worlds keep their statuses, messages, remedies, signals, ``n``, ``mode``, ``max_age``, the whole
  SMTP outcome (F05/F06), the score, the categories, the projections and ``measurement_scope``; GENERATION
  is 5 and the checks are 21;
- 3,001 MX; a null MX, an address given as MX, an MX without address, an invalid pattern, an MX the policy
  does not cover, beyond the 16th entry; duplicates, names of 250 characters, TXT records and a policy line
  of 60,000 characters, an empty record; the JSON of the database within 65,536 bytes;
- the analyses and the rechecks stored before this correction: shown bounded, never rewritten, their
  original downloaded whole (A7: authorizations and audit), their score unchanged (D2);
- the PDF of the largest worlds in 5 pages at most, the details, the API.
"""

from __future__ import annotations

import json
import re

import pytest

from helpers import post
from pdf_server import worlds as pdf_worlds
from posture_cockpit.checks import mail_evidence
from posture_cockpit.checks.mail_evidence import HOSTS, bound, bound_params
from posture_cockpit.checks.smtp_evidence import LIMIT_BYTES, size
from posture_cockpit.core import generation, remediation, scoring
from posture_cockpit.core.compare import measurement_scope
from posture_cockpit.core.registry import Registry
from posture_cockpit.report import REPORT_DIR, render_html
from posture_cockpit.web.routes.api import _summary
from smtp_reference import CHECK, URL, build, corpus, observed, v4
from test_v070_smtp_display import Instance
from worlds import DOMAIN, scan_smtp

MX1 = "mx.example.net"
MAIL = mail_evidence.CHECKS
NAMES = [f"a{i}.example.org" for i in range(3000)]


def unbounded(patch: pytest.MonkeyPatch) -> None:
    """The checks as they were before this correction: nothing bounded."""
    patch.setattr(mail_evidence, "bounded", lambda check_id, outcome: outcome)


def both(world: dict, probe: bool = True) -> tuple[dict, dict]:
    """The findings of every check, bounded, then as they were before this correction."""
    bounded_findings, _ = scan_smtp(world, probe=probe)
    with pytest.MonkeyPatch.context() as patch:
        unbounded(patch)
        whole, _ = scan_smtp(world, probe=probe)
    return bounded_findings, whole


def resolved(names: list[str]) -> dict[str, list[str]]:
    return {name: [v4(1000 + i)] for i, name in enumerate(names)}


def policy(lines: list[str], mode: str = "enforce") -> dict:
    body = "version: STSv1\nmode: " + mode + "\n" + "".join(f"mx: {line}\n" for line in lines) + "max_age: 604800\n"
    return {URL: {"status": 200, "body": body}}


def with_policy(world: dict, lines: list[str], mode: str = "enforce") -> dict:
    world["http"].update(policy(lines, mode))
    return world


def mx_world(records: list[str], addresses: dict[str, list[str]] | None = None, covered: list[str] | None = None,
             **dns: object) -> dict:
    """The healthy domain with these MX records, as written, these addresses and a policy covering ``covered``."""
    world = build([(9000, MX1)], {MX1: ["192.0.2.25"], **(addresses or {})}, {MX1: {"192.0.2.25": "tls_verified"}},
                  covered=covered if covered is not None else [MX1], **dns)
    world["dns"][f"{DOMAIN} MX"] = records
    return world


# Worlds whose lists exceed every bound, with what makes the verdict beyond the 16th entry.
EXTREMES = {
    "3,001 MX (the report of 117 pages)": lambda: pdf_worlds(3000)[DOMAIN],
    "a null MX at the 2,001st entry": lambda: mx_world(
        [f"{i + 1} {n}." for i, n in enumerate(NAMES[:2000])] + ["0 ."] + [f"{i + 1} {n}." for i, n in
                                                                          enumerate(NAMES[2000:])]),
    "an address as MX at the 2,501st entry": lambda: mx_world(
        [f"10 {n}." for n in NAMES[:2500]] + ["10 192.0.2.99."] + [f"10 {n}." for n in NAMES[2500:]]),
    "one MX without address, the 3,000th": lambda: mx_world(
        [f"10 {n}." for n in NAMES], resolved(NAMES[:2999]), covered=["*.example.org"]),
    "an invalid pattern at the 901st line": lambda: with_policy(
        mx_world([f"10 {MX1}."]), [MX1, *NAMES[:899], "bad_pattern!.example", *NAMES[899:999]]),
    "an MX not covered, the 1,501st": lambda: mx_world(
        [f"10 {n}." for n in NAMES[:2000]], resolved(NAMES[:2000]), covered=NAMES[:1500] + NAMES[1501:2000]),
    "two MTA-STS records among 100 TXT": lambda: mx_world(
        [f"10 {MX1}."], **{f"_mta-sts.{DOMAIN} TXT": [f"site-verification={i}" for i in range(49)]
                           + ["v=STSv1; id=1"] + [f"site-verification={i}" for i in range(49, 98)]
                           + ["v=STSv1; id=2"]}),
    "3,000 times the same MX without address": lambda: mx_world([f"10 {NAMES[0]}."] * 3000, covered=[]),
    "245 MX of 250 characters": lambda: mx_world(
        [f"10 {(f'm{i:03d}.' + 'h' * 63 + '.' + 'i' * 63 + '.' + 'j' * 63 + '.')[:242]}example.org."
         for i in range(245)]),
    "TXT records of 60,000 characters": lambda: mx_world(
        [f"10 {MX1}."], **{f"_mta-sts.{DOMAIN} TXT": [f"{i}" + "é" * 60_000 for i in range(20)]}),
    "a policy line of 60,000 characters": lambda: with_policy(
        mx_world([f"10 {MX1}."]), [MX1, *NAMES[:20], "x" * 60_000]),
}
CORPUS = {name: (world, probe) for name, world, probe in corpus()}


def comparable(finding) -> dict:
    """What the bounding must never change: everything but the evidence and the list of the message."""
    data = {"status": finding.status.value, **finding.outcome_json()}
    data.pop("evidence")
    data["params"] = {k: v for k, v in data["params"].items() if k not in ("hosts", "omitted")}
    return data


def same_decisions(bounded_findings: dict, whole: dict) -> None:
    """The bounding changed no verdict, message, remedy or signal of any check, no SMTP outcome, no score, no
    projection, no plan (the evidence of the other checks holds durations, measured anew at each scan)."""
    assert bounded_findings.keys() == whole.keys()
    for check_id, finding in whole.items():
        assert comparable(bounded_findings[check_id]) == comparable(finding), check_id
        assert remediation.expected_status(bounded_findings[check_id]) == remediation.expected_status(finding)
    smtp = [observed({"status": f[CHECK].status.value, **f[CHECK].outcome_json()}) for f in (bounded_findings, whole)]
    assert smtp[0] == smtp[1]  # F05, F06: the whole SMTP outcome, as the reference of correction 2 compares it
    ours, theirs = list(bounded_findings.values()), list(whole.values())
    assert scoring.assess(ours) == scoring.assess(theirs)
    assert scoring.by_category(ours) == scoring.by_category(theirs)
    verdicts = Registry.discover()
    fixes = [f.check_id for f in theirs if f.status.value in ("fail", "warn") and f.outcome.remedy is not None]
    assert scoring.simulate(ours, fixes, verdicts) == scoring.simulate(theirs, fixes, verdicts)
    assert plan(scoring.plan(ours, verdicts)) == plan(scoring.plan(theirs, verdicts))
    scope = [measurement_scope(f[CHECK].outcome.evidence, internal=False) for f in (bounded_findings, whole)]
    assert scope[0] == scope[1]


def plan(found: scoring.Plan) -> dict:
    """The plan of fixes, each step by its check: its order, its gains, the targets."""
    def steps(items: list) -> list:
        return [(i.finding.check_id, i.finding.status, i.gain, i.gain_max, i.gain_worst, i.gain_best) for i in items]

    return {"priorities": steps(found.priorities), "improvements": steps(found.improvements), "now": found.now,
            "target": found.target, "target_max": found.target_max}


def within(evidence: dict) -> bool:
    lists = [v for v in evidence.values() if isinstance(v, list)]
    return all(len(v) <= 16 and all(not isinstance(s, str) or len(s) <= 255 for s in v) for v in lists)


# ------------------------------------------------------------------ verdicts, scores, ordinary domains
def test_generation_and_the_21_checks():
    """Correction 4 changes neither the generation of the engine nor the checks."""
    assert generation.GENERATION == 5 and len(Registry.discover().checks()) == 21


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_the_corpus_keeps_its_decisions_and_ordinary_outcomes_byte_for_byte(name):
    """D1, non-regression: on every world of the corpus of correction 2 (F05, F06, drawn, large), the bounding
    changes no decision, no SMTP outcome, no score; the outcome of mail.mx and mail.mta_sts within the bounds
    is the same, byte for byte."""
    world, probe = CORPUS[name]
    bounded_findings, whole = both(world, probe)
    same_decisions(bounded_findings, whole)
    for check_id in MAIL:
        hosts = str(whole[check_id].outcome.params.get("hosts", "")).split(", ")
        if within(dict(whole[check_id].outcome.evidence)) and len(hosts) <= HOSTS:
            assert bounded_findings[check_id].outcome_json() == whole[check_id].outcome_json()


@pytest.mark.parametrize("name", sorted(EXTREMES))
def test_the_extreme_worlds_keep_their_decisions(name):
    """Non-regression on the extreme worlds, probe on: the same decisions, the same score; the evidence of both
    checks within 65,536 bytes."""
    bounded_findings, whole = both(EXTREMES[name]())
    same_decisions(bounded_findings, whole)
    for check_id in MAIL:
        assert size(bounded_findings[check_id].outcome.evidence) <= LIMIT_BYTES


def mail_mx(world: dict, whole: bool = False):
    with pytest.MonkeyPatch.context() as patch:
        if whole:
            unbounded(patch)
        return scan_smtp(world, "mail.mx", probe=False)[0]["mail.mx"]


def test_16_is_kept_17_is_cut():
    """The bounds: 16 records and 16 names are kept as they are, byte for byte; the 17th is left out of its
    list, and counted, a record that makes the verdict kept before the others; in a message, the 17th name
    becomes "…", ``n`` exact, ``omitted`` 1."""
    sixteen = mx_world([f"10 {n}." for n in NAMES[:15]] + [f"10 {MX1}."])  # 16 records, 15 without address
    assert mail_mx(sixteen).outcome_json() == mail_mx(sixteen, whole=True).outcome_json()
    seventeen = mail_mx(mx_world([f"10 {n}." for n in NAMES[:16]] + [f"10 {MX1}."])).outcome
    assert seventeen.evidence["mx"] == [f"10 {n}." for n in NAMES[:16]] and seventeen.evidence["mx_omitted"] == 1
    assert seventeen.evidence["unresolved"] == NAMES[:16] and "unresolved_omitted" not in seventeen.evidence
    assert seventeen.params == {"hosts": ", ".join(NAMES[:16]), "n": 16}
    eighteen = mail_mx(mx_world([f"10 {n}." for n in NAMES[:17]] + [f"10 {MX1}."])).outcome
    assert eighteen.params == {"hosts": ", ".join(NAMES[:16]) + ", …", "n": 17, "omitted": 1}
    assert eighteen.evidence["unresolved_omitted"] == 1 and eighteen.evidence["mx_omitted"] == 2


# ------------------------------------------------------------------ what is kept
def kept(name: str) -> dict:
    findings, _ = scan_smtp(EXTREMES[name](), "mail.mx", "mail.mta_sts", probe=False)
    return findings


def test_3001_mx():
    """3,001 MX, 3,000 without address, a policy covering 1,001: the verdicts on all of them; 16 of each list
    kept with the exact number left out; the message names 16 MX then "…", ``n`` exact."""
    found = kept("3,001 MX (the report of 117 pages)")
    mx, sts = found["mail.mx"].outcome, found["mail.mta_sts"].outcome
    assert (found["mail.mx"].status.value, mx.summary, mx.params["n"]) == ("warn", "mail.mx.unresolved", 3000)
    assert mx.params["hosts"] == ", ".join(NAMES[:16]) + ", …" and mx.params["omitted"] == 2984
    assert mx.evidence["unresolved"] == NAMES[:16] and mx.evidence["unresolved_omitted"] == 2984
    assert mx.evidence["mx"] == [f"{i + 1} {n}." for i, n in enumerate(NAMES[:16])]
    assert mx.evidence["mx_omitted"] == 2985
    assert (found["mail.mta_sts"].status.value, sts.summary) == ("fail", "mail.mta_sts.mx_mismatch")
    assert (sts.params["n"], sts.params["mode"], sts.evidence["max_age"]) == (2000, "enforce", 604800)
    assert sts.params["hosts"] == ", ".join(NAMES[1000:1016]) + ", …" and sts.params["omitted"] == 1984
    assert sts.evidence["uncovered"] == NAMES[1000:1016] and sts.evidence["uncovered_omitted"] == 1984
    assert sts.evidence["mx_patterns"] == [MX1, *NAMES[:15]] and sts.evidence["mx_patterns_omitted"] == 985
    assert size(mx.evidence) < 1_000 and size(sts.evidence) < 1_000


@pytest.mark.parametrize(("name", "check_id", "summary", "key", "entry", "total"), [
    ("a null MX at the 2,001st entry", "mail.mx", "mail.mx.null_mixed", "mx", "0 .", 3001),
    ("an address as MX at the 2,501st entry", "mail.mx", "mail.mx.address", "mx", "10 192.0.2.99.", 3001),
    ("one MX without address, the 3,000th", "mail.mx", "mail.mx.unresolved", "mx", f"10 {NAMES[2999]}.", 3000),
    ("an invalid pattern at the 901st line", "mail.mta_sts", "mail.mta_sts.bad_policy", "mx_patterns",
     "bad_pattern!.example", 1001),
    ("an MX not covered, the 1,501st", "mail.mta_sts", "mail.mta_sts.mx_mismatch", "uncovered", NAMES[1500], 1),
    ("two MTA-STS records among 100 TXT", "mail.mta_sts", "mail.mta_sts.bad_record", "records", "v=STSv1; id=2", 2),
])
def test_what_makes_the_verdict_is_kept_beyond_the_16th_entry(name, check_id, summary, key, entry, total):
    """The entry that makes the verdict, far beyond the 16th, is kept (with the others in their order), and the
    list with what it left out counts every entry."""
    finding = kept(name)[check_id]
    evidence = finding.outcome.evidence
    assert finding.outcome.summary == summary and entry in evidence[key]
    assert len(evidence[key]) <= 16 and len(evidence[key]) + evidence.get(f"{key}_omitted", 0) == total
    if summary == "mail.mx.address":
        assert finding.outcome.params["hosts"] == "192.0.2.99"
    if summary == "mail.mx.unresolved":
        assert (finding.outcome.params["hosts"], finding.outcome.params["n"]) == (NAMES[2999], 1)
        assert evidence["unresolved"] == [NAMES[2999]] and "unresolved_omitted" not in evidence
    if key == "records":
        assert len(evidence["ignored"]) == 16 and evidence["ignored_omitted"] == 82


def test_duplicates_long_names_long_strings_and_an_empty_record():
    """Each duplicate is an entry, counted; names of 250 characters are kept whole; a TXT record or a policy
    line of 60,000 characters keeps 255, the last "…"; an empty record is an entry like another."""
    same = kept("3,000 times the same MX without address")["mail.mx"].outcome
    assert (same.params["n"], same.params["omitted"], same.evidence["unresolved_omitted"]) == (3000, 2984, 2984)
    assert same.params["hosts"] == ", ".join([NAMES[0]] * 16) + ", …" and same.evidence["mx_omitted"] == 2984
    long_names = kept("245 MX of 250 characters")["mail.mx"].outcome.evidence
    assert long_names["mx"] == EXTREMES["245 MX of 250 characters"]()["dns"][f"{DOMAIN} MX"][:16]
    assert long_names["mx_omitted"] == 229 and all(len(r) > 200 and "…" not in r for r in long_names["mx"])
    txt = kept("TXT records of 60,000 characters")["mail.mta_sts"].outcome.evidence
    assert [len(r) for r in txt["ignored"]] == [255] * 16 and txt["ignored_omitted"] == 4
    assert all(r.endswith("…") for r in txt["ignored"]) and size(txt) <= LIMIT_BYTES
    line = kept("a policy line of 60,000 characters")["mail.mta_sts"].outcome
    assert line.summary == "mail.mta_sts.bad_policy" and "x" * 254 + "…" in line.evidence["mx_patterns"]
    empty = bound("mail.mx", {"mx": [""] + [f"10 {n}." for n in NAMES[:19]], "unresolved": [NAMES[18]]})
    assert empty["mx"] == [""] + [f"10 {n}." for n in NAMES[:14]] + [f"10 {NAMES[18]}."]
    assert empty["mx_omitted"] == 4  # an empty record (the check itself fails on it) names nothing


def test_any_evidence_fits_and_the_bounding_is_idempotent():
    """Lists no DNS answer can carry, of strings full of escaped characters: the evidence still fits in 65,536
    bytes (the strings shortened, then the lists), every list counted exactly; bounded again, nothing more
    changes; neither do the parameters."""
    hostile = {"mx": ["é" * 300] * 5000, "unresolved": ["\x01" * 300] * 5000}
    policy_lists = {k: ["é" * 5000] * 5000 for k in ("records", "ignored", "mx_patterns", "uncovered")}
    for check_id, evidence in (("mail.mx", hostile), ("mail.mta_sts", {**policy_lists, "mode": "enforce"})):
        once = bound(check_id, evidence)
        assert size(once) <= LIMIT_BYTES and bound(check_id, once) == once
        for key, values in evidence.items():
            if isinstance(values, list):
                assert len(once[key]) + once.get(f"{key}_omitted", 0) == len(values)
    params = bound_params({"hosts": ", ".join(NAMES), "n": 3000})
    assert bound_params(params) == params and params["omitted"] == 2984 and params["n"] == 3000


# ------------------------------------------------------------------ stored, before and after this correction
def row(i: Instance, check_id: str, table: str = "findings") -> str:
    scan_id = i.scans.latest_id(i.scans.domain(DOMAIN)["id"])
    return i.scans.db.one(f"SELECT outcome FROM {table} WHERE scan_id=? AND check_id=?",  # noqa: S608 - a test table
                          (scan_id, check_id))["outcome"]


def older(i: Instance, world: dict) -> str:
    """A scan stored as before this correction: the lists whole in the database."""
    with pytest.MonkeyPatch.context() as patch:
        unbounded(patch)
        return i.scan(world)


@pytest.fixture
def instance(tmp_path):
    made = []

    def make(probe: bool = False) -> Instance:
        made.append(Instance(tmp_path / f"i{len(made)}", probe))
        return made[-1]

    yield make
    for i in made:
        i.close()


def test_the_json_written_in_the_database_is_within_the_limit(instance):
    """65,536 bytes at most, measured on the JSON the database holds, for every extreme world; the outcome
    written whole stays small too."""
    i = instance()
    for name in sorted(EXTREMES):
        i.scan(EXTREMES[name]())
        for check_id in MAIL:
            evidence = json.loads(row(i, check_id))["evidence"]
            assert len(json.dumps(evidence).encode()) <= LIMIT_BYTES, (name, check_id)


def test_an_older_scan_is_shown_bounded_never_rewritten_and_its_original_downloaded(instance):
    """D2: a scan of 3,001 MX stored before this correction (lists whole, 141 and 62 KB) is shown bounded (the
    details, the JSON panel, the text, the history, the PDF in 5 pages at most, the API), with a link to its
    original, which comes back byte for byte; the database is never rewritten; the score is the one of the same
    scan made now."""
    i = instance()
    world = EXTREMES["3,001 MX (the report of 117 pages)"]()
    older(i, world)
    rows = {check_id: row(i, check_id) for check_id in MAIL}
    assert size(json.loads(rows["mail.mx"])["evidence"]) > 2 * LIMIT_BYTES
    s = i.app.state.services
    scan_id = i.scans.latest_id(i.scans.domain(DOMAIN)["id"])
    page = i.client.get(f"/domains/{DOMAIN}/history/{scan_id}").text
    details = i.client.get(f"/domains/{DOMAIN}/details").text
    for shown in (page, details):
        assert "a2999.example.org" not in shown and f"{NAMES[15]}, …" in shown
        for check_id in MAIL:
            assert f"/domains/{DOMAIN}/history/{scan_id}/evidence/{check_id}" in shown
    scan = s.scans.get(scan_id)
    for check_id in MAIL:
        finding = next(f for f in scan.findings if f.check_id == check_id)
        stored_evidence = json.loads(rows[check_id])["evidence"]
        assert finding.outcome.evidence["bounds"] == {"limit_bytes": LIMIT_BYTES, "source": "display",
                                                      "original_bytes": size(stored_evidence)}
        assert size(finding.outcome.evidence) <= LIMIT_BYTES and finding.outcome.params["omitted"] > 0
        response = i.client.get(f"/domains/{DOMAIN}/history/{scan_id}/evidence/{check_id}")
        assert response.status_code == 200 and response.json() == stored_evidence
        assert response.content == json.dumps(stored_evidence).encode()
    assert {check_id: row(i, check_id) for check_id in MAIL} == rows  # never rewritten
    assert pages(render_html(s.catalog, "fr", scan, historical=True)) <= 5
    summary = _summary(scan)
    i.scan(world)
    now = s.scans.get(i.scans.latest_id(i.scans.domain(DOMAIN)["id"]))
    assert (scan.assessment(), summary["score"]) == (now.assessment(), _summary(now)["score"])
    assert [f.status for f in scan.findings] == [f.status for f in now.findings]
    assert "/evidence/mail.mx" not in i.client.get(f"/domains/{DOMAIN}/details").text  # nothing left out


def test_an_older_recheck_is_shown_bounded_and_its_original_downloaded(instance):
    """D2: a recheck of mail.mx stored before this correction is shown bounded, its original downloaded."""
    i = instance()
    world = EXTREMES["3,001 MX (the report of 117 pages)"]()
    i.scan(world)
    with pytest.MonkeyPatch.context() as patch:
        unbounded(patch)
        post(i.client, f"/domains/{DOMAIN}/verify/mail.mx", f"/domains/{DOMAIN}?task=mail.mx")
    stored = row(i, "mail.mx", "rechecks")
    assert len(json.loads(stored)["evidence"]["mx"]) == 3001
    scan_id = i.scans.latest_id(i.scans.domain(DOMAIN)["id"])
    finding = i.scans.get(scan_id).rechecks["mail.mx"].finding
    assert len(finding.outcome.evidence["mx"]) == 16 and finding.outcome.evidence["bounds"]["source"] == "display"
    response = i.client.get(f"/domains/{DOMAIN}/history/{scan_id}/evidence/mail.mx")
    assert response.json() == json.loads(stored)["evidence"] and row(i, "mail.mx", "rechecks") == stored


def test_the_original_of_both_checks_is_given_as_for_smtp(instance):
    """A7 (correction 2) for mail.mx and mail.mta_sts: a 404 for any other check; an internal domain to an
    administrator only, audited."""
    from posture_cockpit.storage.perimeters import parse_form

    i = instance()
    i.scan(EXTREMES["3,001 MX (the report of 117 pages)"]())
    s = i.app.state.services
    scan_id = s.scans.latest_id(s.scans.domain(DOMAIN)["id"])
    base = f"/domains/{DOMAIN}/history/{scan_id}/evidence"
    for check_id in (*MAIL, CHECK):
        assert i.client.get(f"{base}/{check_id}").status_code == 200, check_id
    for check_id in ("mail.spf", "mail.dmarc", "dns.caa", "mail.tls_rpt"):
        assert i.client.get(f"{base}/{check_id}").status_code == 404, check_id
    perimeter = s.perimeters.create(parse_form("Lab", "10.20.0.0/16", "", "443", ""), None)
    s.db.execute("UPDATE domains SET perimeter_id=? WHERE name=?", (perimeter, DOMAIN))
    assert i.client.get(f"{base}/mail.mta_sts").status_code == 200
    entry = s.audit.latest(1)[0]
    assert (entry["action"], entry["detail"]["perimeter"], entry["detail"]["scan"]) == (
        "evidence.internal", "Lab", scan_id)


# ------------------------------------------------------------------ PDF, details, API
def pages(html: str) -> int:
    from weasyprint import HTML

    return len(HTML(string=html, base_url=str(REPORT_DIR)).render().pages)


@pytest.mark.parametrize(("name", "most"), [("3,001 MX (the report of 117 pages)", 5),
                                           ("3,000 times the same MX without address", 5),
                                           ("an MX not covered, the 1,501st", 5), ("245 MX of 250 characters", 12)])
def test_the_pdf_of_the_largest_worlds_holds_in_5_pages(instance, name, most):
    """The report of 117 pages is 4 now: 5 pages at most for the largest worlds of reference; 12 for 16 names of
    200 characters and more, which the narrow columns of the PDF wrap line after line (77 pages before). The
    details page names 16 MX and its JSON panel says what it left out; the API answers as before."""
    i = instance()
    details = i.scan(EXTREMES[name]())
    s = i.app.state.services
    scan = s.scans.get(s.scans.latest_id(s.scans.domain(DOMAIN)["id"]))
    assert pages(render_html(s.catalog, "fr", scan)) <= most
    assert len(re.findall(r"a2\d\d\d\.example\.org", details)) == 0
    assert "_omitted" in details and _summary(scan)["score"] == scan.assessment().score
