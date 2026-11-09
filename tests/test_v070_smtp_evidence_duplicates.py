# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Duplicates in the evidence of mail.smtp_starttls (version 0.7.0, correction 2, review of PR #50).

R1: the discovery keeps every invalid MX record, so a thousand MX may carry the same invalid name, each its
own entry. The evidence keeps the MX the message names once (its first entry), every MX measured, one MX
for each other cause, then the order: sixteen entries at most at every stage, ``mx_omitted`` and
``silent_mx_omitted`` exact, the MX named with its cause, the verdict as decide() gave it.

R2: a certificate may repeat a name. The MX name is moved first (one occurrence), every other occurrence stays
where it was, then sixteen names are kept: kept and omitted add up to the names of the certificate, and
nothing of its verification changes.
"""

import json

import pytest

from posture_cockpit.checks import smtp_evidence
from posture_cockpit.checks.smtp_evidence import EVIDENCE_MX, LIMIT_BYTES, STAGES, size
from posture_cockpit.report import render_html
from posture_cockpit.web.routes.api import _summary
from smtp_reference import CHECK, build, certificate
from test_v070_smtp_display import Instance, rows, smtp_part
from test_v070_smtp_evidence_bounds import add_up, certificates, descend, measured, stored
from worlds import DOMAIN, scan_smtp

MX1 = "mx.example.net"
BAD = "bad_name_.example"
OTHER = "other_.example"
ADDRESS = "192.0.2.25"


def thousand() -> dict:
    """A thousand MX records carrying the same invalid name, then MX1, verified."""
    return build([(10, BAD)] * 1000 + [(20, MX1)], {MX1: [ADDRESS]}, {MX1: {ADDRESS: "tls_verified"}})


def spread() -> dict:
    """700 records of the invalid name at seven preferences (5 to 65), MX1 verified at 30, another invalid
    name at 40: in the order of the probe, MX1 comes after 300 of them."""
    published = [(5 + (i % 7) * 10, BAD) for i in range(700)] + [(30, MX1), (40, OTHER)]
    return build(published, {MX1: [ADDRESS]}, {MX1: {ADDRESS: "tls_verified"}})


def named_elsewhere() -> dict:
    """The same 700 records, MX1 verified, and a valid MX without any address, which F05.08 names
    (no_address comes before invalid_name): the invalid name stands for its cause, once."""
    published = [(5 + (i % 7) * 10, BAD) for i in range(700)] + [(30, MX1), (50, "noaddr.example.net")]
    return build(published, {MX1: [ADDRESS]}, {MX1: {ADDRESS: "tls_verified"}})


def whole_verdict(world: dict):
    """The finding when nothing is bounded: the verdict decide() gives, before any bounding."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(smtp_evidence, "bound", lambda evidence, **_: dict(evidence))
        findings, _ = scan_smtp(world, CHECK)
    return findings[CHECK]


def verdict(finding) -> tuple:
    o = finding.outcome
    return finding.status, o.summary, o.params, o.remedy, o.signals


@pytest.fixture
def instance(tmp_path):
    made = []

    def make() -> Instance:
        made.append(Instance(tmp_path / f"i{len(made)}", True, "fr"))
        return made[-1]

    yield make
    for i in made:
        i.close()


# ------------------------------------------------------------------ R1: invalid MX carrying the same name
def test_r1_a_thousand_invalid_mx_of_one_name_keep_sixteen_entries():
    """F05.08, F06, R1 (review of PR #50): a thousand invalid MX of one name then MX1 verified: the verdict is
    the one decide() gives (F05.08, the invalid name, n = 1000), and the evidence keeps sixteen entries: MX1,
    the one named first, then fourteen more in their order; 985 MX and 985 silent entries are counted, the
    one named listed with its cause; 5 KB where it was 146 KB beyond its limit."""
    whole, finding = measured(thousand())
    assert verdict(finding) == verdict(whole_verdict(thousand()))
    assert (finding.status.value, finding.outcome.params) == ("error", {"host": BAD, "n": 1000})
    kept = finding.outcome.evidence
    assert [m["name"] for m in kept["mx"]] == [BAD] * 15 + [MX1]
    assert (kept["mx_omitted"], kept["silent_mx_omitted"]) == (985, 985)
    assert kept["silent_mx"] == [{"name": BAD, "cause": "invalid_name"}] * 15
    assert kept["bounds"] == {"limit_bytes": LIMIT_BYTES, "stage": "limits", "complete": False}
    assert size(kept) < 6000
    add_up(whole, kept, BAD)


def test_r1_every_stage_keeps_sixteen_entries_at_most_down_to_the_core():
    """F05.08, R1 (review of PR #50): within ever smaller limits, each stage reached keeps sixteen entries at
    most and counts the others exactly; the stage of the MX keeps MX1 and the one named, once; the core keeps
    the one named, once, with its cause, within the limit."""
    whole, _ = measured(thousand())
    found = descend(whole, BAD)
    stages = [e["bounds"]["stage"] for e in found]
    assert stages[0] == "limits" and stages[-1] == "core" and stages == [s for s in STAGES if s in stages]
    assert "mx" in stages
    for evidence in found:
        assert len(evidence["mx"]) <= EVIDENCE_MX and len(evidence["mx"]) + evidence["mx_omitted"] == 1001
        assert len(evidence["silent_mx"]) + evidence["silent_mx_omitted"] == 1000
        assert len(evidence["silent_mx"]) <= sum(m["name"] == BAD for m in evidence["mx"])
        assert {"name": BAD, "cause": "invalid_name"} in evidence["silent_mx"]
        assert (evidence["rule"], evidence["readiness"]["state"], evidence["readiness"]["causes"]) == (
            whole["rule"], whole["readiness"]["state"], whole["readiness"]["causes"])
        assert size(evidence) <= evidence["bounds"]["limit_bytes"] and "within_limit" not in evidence["bounds"]
    assert [m["name"] for m in found[stages.index("mx")]["mx"]] == [BAD, MX1]
    core = found[-1]
    assert core["mx"] == [{"name": BAD, "preference": 10, "valid": False, "addresses_omitted": 0}]
    assert core["silent_mx"] == [{"name": BAD, "cause": "invalid_name"}]
    assert (core["mx_omitted"], core["silent_mx_omitted"], core["rule"]) == (1000, 999, "F05.08")
    assert core["readiness"]["state"] == whole["readiness"]["state"]


def test_r1_duplicates_at_several_preferences():
    """F05.08, R1 (review of PR #50): 700 records of one invalid name at seven preferences around MX1: the
    one named is its first entry (preference 5), MX1 is kept wherever it comes, sixteen entries in the order
    of the probe; the other invalid name is left out and counted, in ``mx_omitted`` and ``silent_mx_omitted``."""
    whole, finding = measured(spread())
    assert verdict(finding) == verdict(whole_verdict(spread()))
    assert finding.outcome.params == {"host": BAD, "n": 701}
    kept = finding.outcome.evidence
    assert [(m["name"], m["preference"]) for m in kept["mx"]] == [(BAD, 5)] * 15 + [(MX1, 30)]
    assert (kept["mx_omitted"], len(kept["silent_mx"]), kept["silent_mx_omitted"]) == (686, 15, 686)
    assert OTHER not in {s["name"] for s in kept["silent_mx"]}
    add_up(whole, kept, BAD)
    core = descend(whole, BAD)[-1]
    assert [(m["name"], m["preference"]) for m in core["mx"]] == [(BAD, 5)]


def test_r1_a_duplicated_name_stands_once_for_its_cause_when_another_mx_is_named():
    """F05.08, R1 (review of PR #50): F05.08 names a valid MX without address (no_address before invalid_name):
    it is kept as measured, MX1 too, the invalid name once for its cause, then the order; never all of it."""
    whole, finding = measured(named_elsewhere())
    assert verdict(finding) == verdict(whole_verdict(named_elsewhere()))
    assert finding.outcome.params == {"host": "noaddr.example.net", "n": 701}
    kept = finding.outcome.evidence
    names = [m["name"] for m in kept["mx"]]
    assert len(names) == EVIDENCE_MX and names.count(BAD) == 14 and names[-2:] == [MX1, "noaddr.example.net"]
    assert {"name": "noaddr.example.net", "cause": "no_address"} in kept["silent_mx"]
    add_up(whole, kept, "noaddr.example.net")
    found = descend(whole, "noaddr.example.net")
    mx_stage = next(e for e in found if e["bounds"]["stage"] == "mx")
    assert [m["name"] for m in mx_stage["mx"]] == [BAD, MX1, "noaddr.example.net"]
    assert found[-1]["mx"][0]["name"] == "noaddr.example.net" and len(found[-1]["mx"]) == 1


def test_r1_the_database_the_api_the_page_and_the_pdf(instance):
    """F05.08, R5, S04 (review of PR #50): a thousand invalid MX of one name: the JSON written in the database
    is within the limit with sixteen entries; the API gives the measure; the page and the PDF list sixteen
    rows and say the 985 others; a recheck is bounded alike."""
    whole, _ = measured(thousand())
    i = instance()
    page = i.scan(thousand())
    evidence = json.loads(stored(i))["evidence"]
    assert len(json.dumps(evidence).encode()) <= LIMIT_BYTES and len(evidence["mx"]) == EVIDENCE_MX
    scan = i.scans.get(i.scans.latest_id(i.scans.domain(DOMAIN)["id"]))
    probe = _summary(scan)["smtp_probe"]
    assert (probe["status"], probe["rule"], probe["mx"], probe["verified"]) == (
        "error", "F05.08", whole["exhaustivity"]["mx"], 1)
    assert len(rows(page)) == EVIDENCE_MX and "985 autres MX publiés" in smtp_part(page)
    html = render_html(i.app.state.services.catalog, "fr", scan)
    annex = html[html.index('class="smtp-annex"'):]
    assert annex.count("<tr>") == 1 + EVIDENCE_MX and "985 autres MX publiés" in annex
    from helpers import post

    post(i.client, f"/domains/{DOMAIN}/verify/{CHECK}", f"/domains/{DOMAIN}?task={CHECK}")
    again = json.loads(stored(i, "rechecks"))["evidence"]
    assert len(again["mx"]) == EVIDENCE_MX and again["mx_omitted"] == 985 and size(again) <= LIMIT_BYTES


# ------------------------------------------------------------------ R2: a certificate repeating a name
def with_names(names: list[str]) -> dict:
    return build([(10, MX1)], {MX1: [ADDRESS]}, {MX1: {ADDRESS: certificate(60, names)}})


@pytest.mark.parametrize(("names", "kept", "omitted"), [
    ([MX1, MX1, "other.example.net"], [MX1, MX1, "other.example.net"], 0),
    (["a.example.net", MX1, "b.example.net", MX1], [MX1, "a.example.net", "b.example.net", MX1], 0),
    (["a.example.net", *[MX1] * 20, *["b.example.net"] * 5], [MX1, "a.example.net", *[MX1] * 14], 10),
    ([*["c.example.net"] * 30, MX1, MX1], [MX1, *["c.example.net"] * 15], 16),
])
def test_r2_repeated_names_of_a_certificate_are_kept_and_counted(names, kept, omitted):
    """F05.10, F03, R2 (review of PR #50): the MX name is moved first, one occurrence; every other occurrence
    stays in its place; sixteen names at most; kept and omitted add up to the names of the certificate; the
    verification of the certificate is the same."""
    whole, finding = measured(with_names(names))
    assert verdict(finding) == verdict(whole_verdict(with_names(names)))
    [cut], [full] = certificates(finding.outcome.evidence["mx"][0]), certificates(whole["mx"][0])
    assert full["names"] == names
    assert cut["names"] == kept and cut.get("names_omitted", 0) == omitted
    assert len(cut["names"]) + cut.get("names_omitted", 0) == len(names)
    assert {k: v for k, v in cut.items() if k not in ("names", "names_omitted")} == {
        k: v for k, v in full.items() if k != "names"}
    add_up(whole, finding.outcome.evidence, "")


def test_r2_repeated_names_stay_counted_when_the_diagnostics_go():
    """F05.10, R2 (review of PR #50): at the stage of the diagnostics, four names stay, the MX name first, and
    the omitted count still adds up to the 26 names of the certificate."""
    names = ["a.example.net", *[MX1] * 20, *["b.example.net"] * 5]
    whole, _ = measured(with_names(names))
    diagnostics = next(e for e in descend(whole, "") if e["bounds"]["stage"] == "diagnostics")
    [cut] = certificates(diagnostics["mx"][0])
    assert cut["names"] == [MX1, "a.example.net", MX1, MX1] and cut["names_omitted"] == 22
