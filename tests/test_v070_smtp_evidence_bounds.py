# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The evidence of mail.smtp_starttls is stored within its limit (version 0.7.0, correction 2).

decide() assembles the whole evidence, ``silent_mx`` included; checks/smtp_evidence.py bounds what is stored
of it (64 KiB at most, as storage/scans.py writes it), and the details, the history, the PDF and the API read
that. What is checked here, against the whole evidence the same probe gave:

- the MX kept (every MX measured, the MX F05.08 names, one for each other cause, then the order), the
  addresses (every attempt, four more), the names of a certificate and of a policy, the aliases, the lists of
  the notes, each with the exact count of what it left out: kept and left out add up to the measure;
- the stages beyond the limits, in their order, each keeping the verdict, its causes and the counts, the core
  beyond the limit said as such; the evidence near the limit; the same evidence twice (determinism);
- the database, the API (``verified`` as the measure counted it), the page and the PDF saying the same;
- an older evidence (stored before the bounding, without counts): never rewritten, shown bounded, its
  original downloadable, the API exact; and the probe off, an internal perimeter, an engine error;
- the memory the bounding takes, and the size of the evidence of mail.mx and mail.mta_sts (measured, left as
  they are: arbitration A6).

The verdicts themselves (F05, F06, the score, the scope) are compared with those recorded before the bounding
in test_v070_smtp_evidence_reference.py.
"""

import copy
import functools
import html as markup
import json
import re
import tracemalloc

import pytest

from helpers import PASSWORD, log_in, log_out, post
from posture_cockpit.checks import smtp_evidence
from posture_cockpit.checks.smtp_evidence import LIMIT_BYTES, STAGES, bound, size
from posture_cockpit.report import render_html
from posture_cockpit.report.smtp import view
from posture_cockpit.web.routes.api import _summary
from smtp_reference import CHECK, build, certificate, corpus, large, v4
from test_v070_smtp_display import Instance, result, rows, smtp_part
from worlds import DOMAIN, scan_smtp

MX1 = "mx.example.net"
WORLDS = {name: (world, probe) for name, world, probe in corpus()}
LARGE = {name: world for name, world, _ in large()}


def measured(world: dict, probe: bool = True) -> tuple[dict, object]:
    """The evidence decide() assembled, whole, and the finding as it is stored (its evidence bounded)."""
    captured: dict = {}
    real = smtp_evidence.bound

    def capture(evidence, **options):
        captured["whole"] = copy.deepcopy(dict(evidence))
        return real(evidence, **options)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(smtp_evidence, "bound", capture)
        findings, _ = scan_smtp(world, CHECK, probe=probe)
    return captured["whole"], findings[CHECK]


def attempted(address: dict) -> bool:
    return bool(address.get("observations") or address.get("interrupted"))


def certificates(mx: dict) -> list[dict]:
    return [o["dialogue"]["certificate"] for a in mx.get("addresses", []) for o in a.get("observations", [])
            if isinstance(o.get("dialogue"), dict) and isinstance(o["dialogue"].get("certificate"), dict)]


def embedded(part: list[dict], whole: list[dict]) -> list[int]:
    """The positions in ``whole`` of the MX of ``part``, matched in order by name: ``part`` is a part of
    ``whole`` in its order (several invalid MX may carry the same name, each its own entry)."""
    found, start = [], 0
    for mx in part:
        at = next(i for i in range(start, len(whole)) if whole[i]["name"] == mx["name"])
        found.append(at)
        start = at + 1
    return found


def add_up(whole: dict, kept: dict, named: str) -> None:
    """Every list of ``kept`` is a part of the same list of ``whole``, in its order, and what it left out is
    counted exactly; every attempt is kept as it was; the counts are those of the measure; sixteen MX at most,
    and a silent MX listed once for each of its entries kept, never more."""
    assert size(kept) <= LIMIT_BYTES
    assert kept["rule"] == whole["rule"] and kept["readiness"]["state"] == whole["readiness"]["state"]
    assert kept["readiness"]["causes"] == whole["readiness"]["causes"]
    assert kept["exhaustivity"] == whole["exhaustivity"]
    names = [m["name"] for m in whole["mx"]]
    kept_names = [m["name"] for m in kept["mx"]]
    places = embedded(kept["mx"], whole["mx"])  # the order of the probe
    assert len(kept_names) <= smtp_evidence.EVIDENCE_MX
    assert len(kept_names) + kept["mx_omitted"] == len(names)
    assert all(m["name"] in kept_names for m in whole["mx"] if m.get("valid", True) and not m.get("cause"))
    if named:
        assert named in kept_names
    for mx, at in zip(kept["mx"], places, strict=True):
        origin = whole["mx"][at]
        found = origin["addresses"]
        assert len(mx["addresses"]) + mx.get("addresses_omitted", 0) == len(found)
        assert [a["address"] for a in mx["addresses"]] == [a["address"] for a in found
                                                          if a["address"] in {k["address"] for k in mx["addresses"]}]
        tried = [a for a in found if attempted(a)]
        assert [(a["address"], a["seen"], a.get("unmeasured")) for a in mx["addresses"] if attempted(a)] == [
            (a["address"], a["seen"], a.get("unmeasured")) for a in tried]
        assert all(a["seen"] == "unmeasured" for a in mx["addresses"] if not attempted(a))
        assert len(mx.get("cname", [])) + mx.get("cname_omitted", 0) == len(origin.get("cname", []))
        for cut, full in zip(certificates(mx), certificates(origin), strict=True):
            assert len(cut["names"]) <= smtp_evidence.CERTIFICATE_NAMES
            assert len(cut["names"]) + cut.get("names_omitted", 0) == len(full["names"])
            if mx["name"] in full["names"]:
                assert cut["names"][0] == mx["name"]
    counts = kept["counts"]["addresses"]
    every = [a for m in whole["mx"] for a in m["addresses"]]
    assert counts["discovered"] == len(every) == whole["exhaustivity"]["addresses"]
    assert counts["attempted"] == sum(map(attempted, every))
    assert counts["verified"] == sum(a["seen"] == "verified" for a in every)
    assert counts["conclusive"] == sum(a["seen"] != "unmeasured" for a in every)
    assert counts["represented"] == sum(len(m["addresses"]) for m in kept["mx"])
    assert counts["omitted"] == counts["discovered"] - counts["represented"]
    if "silent_mx" in whole:
        assert len(kept["silent_mx"]) + kept.get("silent_mx_omitted", 0) == len(whole["silent_mx"])
        assert {s["name"]: s["cause"] for s in kept["silent_mx"]}.items() <= {
            s["name"]: s["cause"] for s in whole["silent_mx"]}.items()
        listed = [s["name"] for s in kept["silent_mx"]]
        assert all(listed.count(n) <= kept_names.count(n) for n in set(listed))
        if named:
            assert named in {s["name"] for s in kept["silent_mx"]}
    policy, full = (kept["readiness"].get("policy") or {}), (whole["readiness"].get("policy") or {})
    for key in ("covered", "uncovered", "mx_patterns"):
        if key in full:
            assert len(policy[key]) <= smtp_evidence.POLICY_NAMES
            assert len(policy[key]) + policy.get(f"{key}_omitted", 0) == len(full[key])
    assert [(n["key"], n["params"].get("n")) for n in kept.get("notes", [])] == [
        (n["key"], n["params"].get("n")) for n in whole.get("notes", [])]


# ------------------------------------------------------------------ every list bounded, exactly (F05, F06)
@pytest.mark.parametrize("name", sorted(WORLDS))
def test_kept_and_left_out_add_up_to_the_measure_in_every_world(name):
    """F05, F06, R1 (correction 2, A2 A3 A5): in every world of the reference corpus, the stored evidence is a
    part of the whole one, in its order, within 64 KiB: every MX measured, the MX F05.08 names, every attempt
    as it was; what it left out counted exactly, the counts those of the measure. The probe off: as it was."""
    world, probe = WORLDS[name]
    whole, finding = measured(world, probe)
    kept = finding.outcome.evidence
    if "exhaustivity" not in whole:
        assert kept == whole and "bounds" not in kept
        return
    add_up(whole, kept, str(finding.outcome.params.get("host", "")) if kept["rule"] == "F05.08" else "")
    assert kept["bounds"]["stage"] == "limits"  # no world of the corpus needs more than the bounded lists


def test_r1_the_mx_f05_08_names_after_the_sample_is_kept_with_its_cause():
    """F05.08, R1 (correction 2, A1 A2): the MX the message names comes after eight MX measured and thirty beyond
    the sample: the evidence keeps it, in ``mx`` and in ``silent_mx`` with its own cause, then the first MX
    beyond the sample for that cause, then the others in their order, counting the rest. Before the bounding,
    the evidence kept the sixteen first MX and left it out."""
    whole, finding = measured(LARGE["F05.08 named after the sample"])
    kept = finding.outcome.evidence
    assert (finding.status.value, kept["rule"], finding.outcome.params) == (
        "error", "F05.08", {"host": "bad_name_.example", "n": 9})
    names = [m["name"] for m in kept["mx"]]
    assert names[:8] == [f"m{i}.example.net" for i in range(8)] and names[-1] == "bad_name_.example"
    assert names[8:15] == [f"s{i}.example.net" for i in range(7)] and len(names) == 16
    assert kept["mx_omitted"] == 39 - 16
    assert {"name": "bad_name_.example", "cause": "invalid_name"} in kept["silent_mx"]
    add_up(whole, kept, "bad_name_.example")


def test_hundreds_of_silent_mx_keep_the_one_named_and_count_the_others():
    """F05.08, F01, R1 (correction 2, A1 A2): three hundred invalid MX before a valid one that verifies: the MX
    measured, the MX named and fifteen in all of the invalid ones are kept, each with its cause; the 285 others
    are counted, in ``mx_omitted`` and ``silent_mx_omitted``."""
    whole, finding = measured(LARGE["300 silent MX"])
    kept = finding.outcome.evidence
    named = finding.outcome.params["host"]
    assert (kept["rule"], named, finding.outcome.params["n"]) == ("F05.08", "silent000_.example", 300)
    assert [m["name"] for m in kept["mx"]] == [f"silent{i:03d}_.example" for i in range(15)] + [MX1]
    assert (kept["mx_omitted"], len(kept["silent_mx"]), kept["silent_mx_omitted"]) == (285, 15, 285)
    add_up(whole, kept, named)


def test_the_limits_of_each_list():
    """F05.12, F03, S04 (correction 2, A3): 4,000 addresses keep their sixteen attempts then four more, never
    shown as measured; a certificate of 1,001 names keeps sixteen, the MX name first; a policy keeps sixteen
    names, the MX kept first; an MX keeps four aliases; a note lists eight items then "…", its count exact."""
    whole, finding = measured(LARGE["4,000 addresses on one MX"])
    mx = finding.outcome.evidence["mx"][0]
    assert len(mx["addresses"]) == 16 + smtp_evidence.EXTRA_ADDRESSES and mx["addresses_omitted"] == 3980
    extra = [a for a in mx["addresses"] if not attempted(a)]
    assert [a["address"] for a in extra] == [a["address"] for a in whole["mx"][0]["addresses"]
                                             if not attempted(a)][:4]
    assert all(a["seen"] == "unmeasured" and a["unmeasured"] == "sample" for a in extra)
    note = next(n for n in finding.outcome.evidence["notes"] if n["key"].endswith("untested.sample"))
    assert note["params"]["addresses"].count(", ") == 8 and note["params"]["addresses"].endswith(", …")
    assert (note["params"]["n"], note["params"]["omitted"]) == (3984, 3976)

    _, finding = measured(LARGE["1,001 certificate names on 16 addresses"])
    for cut in certificates(finding.outcome.evidence["mx"][0]):
        assert cut["names"][0] == MX1 and len(cut["names"]) == 16 and cut["names_omitted"] == 985

    _, finding = measured(LARGE["several limits at once"])
    kept = finding.outcome.evidence
    policy = kept["readiness"]["policy"]
    assert len(policy["covered"]) == 16 and policy["covered_omitted"] == 41 - 16 and policy["covered"][0] == MX1
    assert len(kept["mx"][0]["cname"]) == smtp_evidence.ALIASES and kept["mx"][0]["cname_omitted"] == 6
    assert kept["bounds"] == {"limit_bytes": LIMIT_BYTES, "stage": "limits", "complete": False}


# ------------------------------------------------------------------ the stages beyond the limits (A4)
def rich(invalid: list[tuple[int, str]] | None = None) -> dict:
    """One MX measured: 4,000 addresses, seven verified with a certificate of 41 long names, four refused (one
    read for the diagnosis, with as many names), four silent; 200 invalid MX (or ``invalid``), 40 beyond the
    sample; a policy covering 41 MX; ten aliases. Each stage beyond the limits has something to take from it."""
    names = [MX1] + [f"n{i:02d}." + "a" * 60 + "." + "b" * 60 + "." + "c" * 60 + ".example" for i in range(40)]
    refused = {"verify": {"reason": "certificate_refused", "verify_code": 62, "verify_message": "Hostname mismatch"},
               "read_certificate": {"reason": "tls_unverified", "certificate": {"names": names}}}
    found = [v4(i) for i in range(4000)]
    outcomes = {**{v4(i): certificate(60, names) for i in range(7)}, **{v4(i): refused for i in range(7, 11)},
                **{v4(i): "timeout" for i in range(11, 15)}}
    far = [f"far{i}.example.net" for i in range(40)]
    invalid = invalid if invalid is not None else [(i + 2, f"x{i}_.example") for i in range(200)]
    return build([(1, MX1), *invalid, *((300 + i, f) for i, f in enumerate(far))],
                 {MX1: found}, {MX1: outcomes}, policy="testing", covered=[MX1, *far],
                 **{f"{MX1} CNAME": [f"alias{i}.example.org." for i in range(10)]})


def descend(whole: dict, named: str) -> list[dict]:
    """The evidence bounded within ever smaller limits, each just below the size the previous one reached: one
    evidence for each stage reached (the marker says the limit, so a limit of fewer digits may fit one byte
    sooner, at the same stage)."""
    found, limit = [], LIMIT_BYTES
    while True:
        evidence = bound(whole, named=named, limit=limit)
        if not found or evidence["bounds"]["stage"] != found[-1]["bounds"]["stage"]:
            found.append(evidence)
        if evidence["bounds"]["stage"] == "core":
            return found
        limit = size(evidence) - 1


def dialogues(evidence: dict) -> list[dict]:
    return [o["dialogue"] for m in evidence.get("mx", []) for a in m.get("addresses", [])
            for o in a.get("observations", []) if isinstance(o.get("dialogue"), dict)]


def test_each_stage_in_its_order_keeps_the_verdict_and_the_counts():
    """F05, F06, F03 (correction 2, A4): within ever smaller limits, the stages apply in their order, each only
    when the previous one is still beyond the limit: the addresses not attempted, the MX kept for their order,
    the optional diagnostics, the observations of what showed nothing, all but the essentials, all but the
    core. Each keeps the verdict as recorded, its causes, the counts and the MX named; each says its stage and
    that the evidence is not complete."""
    whole, finding = measured(rich())
    assert finding.outcome.evidence["bounds"]["stage"] == "limits"
    named = str(finding.outcome.params.get("host", ""))
    found = descend(whole, named)
    assert [e["bounds"]["stage"] for e in found] == list(STAGES)
    counts = found[0]["counts"]["addresses"]
    for evidence in found:
        assert size(evidence) <= evidence["bounds"]["limit_bytes"] and "within_limit" not in evidence["bounds"]
        assert (evidence["rule"], evidence["readiness"]["state"], evidence["readiness"]["causes"]) == (
            whole["rule"], whole["readiness"]["state"], whole["readiness"]["causes"])
        assert evidence["exhaustivity"] == whole["exhaustivity"]
        assert {k: v for k, v in evidence["counts"]["addresses"].items() if k not in ("represented", "omitted")} == {
            k: v for k, v in counts.items() if k not in ("represented", "omitted")}
        kept = evidence["counts"]["addresses"]
        assert kept["represented"] + kept["omitted"] == kept["discovered"] == 4000
        assert len(evidence["mx"]) + evidence["mx_omitted"] == len(whole["mx"])
        assert evidence["bounds"]["complete"] is False
    _, extras, mx, diagnostics, observations, essentials, core = found
    assert all(attempted(a) for m in extras["mx"] for a in m["addresses"])
    # F05.06 names MX1 (a certificate refused). The eight MX resolved: MX1, far0 to far6 (the invalid names are
    # not in the sample); then the first MX of each other cause: an invalid name, beyond the sample.
    far = [f"far{n}.example.net" for n in range(8)]
    assert (whole["rule"], named) == ("F05.06", MX1)
    assert [m["name"] for m in whole["mx"] if m.get("valid", True) and not m.get("cause")] == [MX1, *far[:7]]
    assert [m["name"] for m in mx["mx"]] == [MX1, "x0_.example", *far]
    for dialogue in dialogues(diagnostics):
        assert not {"capabilities", "partial", "quit_reply"} & set(dialogue)
        assert all(len(dialogue[k].get("text", [])) <= 1 for k in ("banner", "ehlo", "starttls") if k in dialogue)
        assert len(dialogue.get("certificate", {}).get("names", [])) <= 4
    silent = [a for a in observations["mx"][0]["addresses"] if a["seen"] == "unmeasured"]
    assert silent and all(set(o) <= {"purpose", "consumed", "socket", "cause", "reason", "dialogue"}
                          and set(o.get("dialogue", {})) <= {"stage", "reason"}
                          for a in silent for o in a["observations"])
    assert all("cname" not in m for m in essentials["mx"]) and essentials["mx"][0]["cname_omitted"] == 10
    policy = essentials["readiness"]["policy"]
    assert not policy["covered"] and policy["covered_omitted"] == 41
    verified = [a for a in essentials["mx"][0]["addresses"] if a["seen"] == "verified"]
    assert len(verified) == 7
    assert all(o["dialogue"]["certificate"]["names"] for a in verified for o in a["observations"])
    assert set(core) <= {*smtp_evidence._CORE, "readiness", "mx", "silent_mx", "notes", "bounds"}
    assert [m["name"] for m in core["mx"]] == [named] and "silent_mx" not in core
    assert core["mx_omitted"] == len(whole["mx"]) - 1
    assert core["mx"][0]["addresses_omitted"] == 4000 and core["counts"]["addresses"]["omitted"] == 4000
    whole, finding = measured(LARGE["F05.08 named after the sample"])  # F05.08: the MX named keeps its cause
    core = descend(whole, "bad_name_.example")[-1]
    assert [m["name"] for m in core["mx"]] == ["bad_name_.example"] and core["mx_omitted"] == 38
    assert core["silent_mx"] == [{"name": "bad_name_.example", "cause": "invalid_name"}]
    assert core["silent_mx_omitted"] == 8 and core["rule"] == "F05.08"


def test_a_core_still_beyond_the_limit_is_said_never_lost_and_changes_no_verdict(monkeypatch):
    """F05.08, F06 (correction 2, A4): when even the core does not fit, the evidence keeps it and says so
    (``within_limit``: false, ``complete``: false), never pretending to be complete; the verdict, its message
    and its parameters are those of the whole probe, and the page says the evidence was reduced beyond."""
    whole, finding = measured(rich())
    tiny = bound(whole, named=finding.outcome.params["host"], limit=200)
    assert tiny["bounds"] == {"limit_bytes": 200, "stage": "core", "complete": False, "within_limit": False}
    exact = bound(whole, named=finding.outcome.params["host"])["counts"]["addresses"]
    assert tiny["counts"]["addresses"] == {**exact, "represented": 0, "omitted": 4000}
    monkeypatch.setattr(smtp_evidence, "bound", functools.partial(bound, limit=200))
    findings, _ = scan_smtp(rich(), CHECK)
    small = findings[CHECK]
    assert (small.status, small.outcome.summary, small.outcome.params, small.outcome.remedy) == (
        finding.status, finding.outcome.summary, finding.outcome.params, finding.outcome.remedy)
    assert small.outcome.evidence["bounds"]["within_limit"] is False
    shown = view(small.outcome.evidence, lambda key, **p: key)
    assert shown["core"] and shown["reduced"] == "smtp.reduced smtp.over_limit"


def near(names: int) -> dict:
    """Eight MX of 240 characters, two addresses each, verified with a certificate of ``names`` names of about
    250 characters besides the MX name: eleven fit within 64 KiB, twelve do not."""
    mx, addresses, smtp = [], {}, {}
    for i in range(8):
        name = (f"m{i}" + "a" * 60 + "." + "b" * 63 + "." + "c" * 63 + ".example.net")[:240]
        long = [f"n{j:03d}." + "s" * 60 + "." + "t" * 60 + "." + "u" * 50 + ".example" for j in range(names)]
        mx.append((10 + i, name))
        addresses[name] = [v4(70000 + 2 * i), v4(70001 + 2 * i)]
        smtp[name] = {a: certificate(60, [name, *long]) for a in addresses[name]}
    return build(mx, addresses, smtp)


def test_an_evidence_near_the_limit():
    """F05.10, F03 (correction 2, A4): sixteen verified addresses whose certificates fill the evidence to 769
    bytes under 64 KiB are stored whole (``complete``); one name more on each and it goes beyond: the optional
    diagnostics go, every attempt and its verification stay. At the byte, the limit is the evidence's size."""
    _, finding = measured(near(11))
    evidence = finding.outcome.evidence
    assert size(evidence) == LIMIT_BYTES - 769
    assert evidence["bounds"] == {"limit_bytes": LIMIT_BYTES, "stage": "limits", "complete": True}
    whole, beyond = measured(near(12))
    exact = size(bound(whole, limit=99_999))  # a limit of as many digits as the size, said in the marker
    assert exact > LIMIT_BYTES
    kept = beyond.outcome.evidence
    assert kept["bounds"]["stage"] == "diagnostics" and size(kept) <= LIMIT_BYTES
    assert (beyond.status.value, kept["rule"]) == ("ok", "F05.10")
    assert kept["counts"]["addresses"]["verified"] == 16 == sum(
        a["seen"] == "verified" for m in kept["mx"] for a in m["addresses"])
    assert all(len(c["names"]) == 4 and c["names_omitted"] == 9 for m in kept["mx"] for c in certificates(m))
    assert bound(whole, limit=exact)["bounds"]["stage"] == "limits"
    assert bound(whole, limit=exact - 1)["bounds"]["stage"] != "limits"


def test_the_same_evidence_twice_and_bounded_once():
    """Q05 (correction 2, A4): the bounding is deterministic (the same bytes from the same probe) and bounds
    once: an evidence already bounded is returned as it is."""
    whole, finding = measured(rich())
    first = bound(whole, named="x0_.example")
    assert json.dumps(first) == json.dumps(bound(whole, named="x0_.example"))
    assert bound(first, named="x0_.example") == first
    assert json.dumps(finding.outcome.evidence) == json.dumps(measured(rich())[1].outcome.evidence)


def test_the_bounding_takes_little_memory():
    """S04 (correction 2): bounding the evidence of 4,000 addresses (590 KB whole) takes a few times its size
    and well under a second; what is stored is a hundredth of it."""
    whole, _ = measured(LARGE["4,000 addresses on one MX"])
    tracemalloc.start()
    kept = bound(whole)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert size(whole) > 500_000 and size(kept) < size(whole) // 50
    assert peak < 8 * size(whole) < 8 * 2**20


def test_the_bounding_decides_nothing_and_each_stage_has_its_words():
    """Q04, Q03, Q05 (correction 2): checks/smtp_evidence.py imports the standard library only, so it builds no
    verdict (the matrix F05 stays in decide()); each stage beyond the limits has its text in French and in
    English, and the stages are those the module names, in its order."""
    import ast
    from pathlib import Path

    from posture_cockpit.i18n import Catalog

    tree = ast.parse(Path(smtp_evidence.__file__).read_text())
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert imported == {"__future__", "copy", "json", "collections.abc", "typing"}
    assert [f.__name__.lstrip("_") for f in smtp_evidence._REDUCTIONS] == list(STAGES[1:])
    catalog = Catalog()
    for lang in ("fr", "en"):
        for key in [f"smtp.stage.{stage}" for stage in STAGES[1:]] + [
                "smtp.reduced", "smtp.over_limit", "smtp.display_bounded", "smtp.counts", "smtp.addresses_untried",
                "smtp.addresses_omitted", "smtp.omitted_core", "smtp.names_omitted", "details.evidence_original",
                "audit.action.evidence.internal"]:
            assert catalog.has(lang, key), (lang, key)


# ------------------------------------------------------------------ the database, the API, the page, the PDF
@pytest.fixture
def instance(tmp_path):
    made = []

    def make(probe: bool = True, lang: str = "fr") -> Instance:
        made.append(Instance(tmp_path / f"i{len(made)}", probe, lang))
        return made[-1]

    yield make
    for i in made:
        i.close()


def stored(i: Instance, table: str = "findings") -> str:
    scan_id = i.scans.latest_id(i.scans.domain(DOMAIN)["id"])
    return i.scans.db.one(f"SELECT outcome FROM {table} WHERE scan_id=? AND check_id=?", (scan_id, CHECK))["outcome"]  # noqa: S608 - a table name of this test


@pytest.mark.parametrize("name", [*sorted(LARGE), "near the limit", "beyond the limits", "rich"])
def test_the_json_written_in_the_database_is_within_the_limit(instance, name):
    """S04, F05 (correction 2, A4): what the database holds of the evidence, read back as it was written, is 64
    KiB at most for every large world, near the limit and beyond the limits."""
    worlds = {**LARGE, "near the limit": near(11), "beyond the limits": near(12), "rich": rich()}
    i = instance()
    i.scan(worlds[name])
    evidence = json.loads(stored(i))["evidence"]
    assert len(json.dumps(evidence).encode()) == size(evidence) <= LIMIT_BYTES


def test_the_api_the_page_and_the_pdf_say_the_same_counts(instance):
    """F05.09, R5, T05 (correction 2, A5): 4,000 addresses on one MX: the API gives the measure (1 MX, 4,000
    addresses, 1 verified); the page and the PDF list the twenty addresses kept and say the 3,980 others in one
    row, never as measured, then the addresses discovered, attempted, conclusive, listed and left out."""
    i = instance()
    page = i.scan(LARGE["4,000 addresses on one MX"])
    scan = i.scans.get(i.scans.latest_id(i.scans.domain(DOMAIN)["id"]))
    assert _summary(scan)["smtp_probe"] == {"scope": "on", "status": "ok", "rule": "F05.09", "mx": 1,
                                            "addresses": 4000, "verified": 1}
    counts = json.loads(stored(i))["evidence"]["counts"]["addresses"]
    assert (counts["discovered"], counts["attempted"], counts["verified"], counts["represented"],
            counts["omitted"]) == (4000, 16, 1, 20, 3980)
    found = rows(page)
    assert len(found) == 21 and found[-1].endswith(
        "3980 adresses publiées, non tentées, ne sont pas reprises dans ce tableau.")
    line = ("Adresses : 4000 découvertes, 16 tentées dont 1 avec un résultat concluant, 20 reprises dans ce tableau, "
            "3980 omises.")
    assert line in smtp_part(page) and "4000 adresses publiées" in smtp_part(page)
    html = render_html(i.app.state.services.catalog, "fr", scan)
    annex = html[html.index('class="smtp-annex"'):]
    assert line in annex and "3980 adresses publiées, non tentées, ne sont pas reprises dans ce tableau." in annex
    assert annex.count("<tr>") == 1 + 21  # the header, then the rows of the page
    english = instance(lang="en")
    assert ("Addresses: 4000 discovered, 16 attempted of which 1 with a conclusive result, 20 listed in this "
            "table, 3980 left out.") in smtp_part(english.scan(LARGE["4,000 addresses on one MX"]))


def test_the_pdf_of_a_large_world_stays_short(instance):
    """T05, R3 (correction 2): the PDF of 4,000 addresses on one MX lays out its twenty-one rows in a few pages,
    none of them split, where it took twenty-two pages before the bounding."""
    weasyprint = pytest.importorskip("weasyprint")
    from posture_cockpit.report import REPORT_DIR
    from test_v070_smtp_display import split_rows

    i = instance()
    i.scan(LARGE["4,000 addresses on one MX"])
    html = render_html(i.app.state.services.catalog, "fr", i.scans.get(i.scans.latest_id(i.scans.domain(DOMAIN)["id"])))
    document = weasyprint.HTML(string=html, base_url=str(REPORT_DIR)).render()
    assert len(document.pages) <= 6 and split_rows(document) == []


def test_the_history_and_a_recheck_are_bounded_alike(instance):
    """R6, F05.10 (correction 2, A7): a recheck of the SMTP check is stored bounded like a scan; the details show
    it, the history of the scan shows it too, and keeps the first measure in the database."""
    i = instance()
    i.scan(LARGE["4,000 addresses on one MX"])
    first = stored(i)
    i.data.clear()
    i.data.update(LARGE["1,001 certificate names on 16 addresses"])
    post(i.client, f"/domains/{DOMAIN}/verify/{CHECK}", f"/domains/{DOMAIN}?task={CHECK}")
    again = json.loads(stored(i, "rechecks"))["evidence"]
    assert size(again) <= LIMIT_BYTES and again["rule"] == "F05.10" and stored(i) == first
    scan_id = i.scans.latest_id(i.scans.domain(DOMAIN)["id"])
    for page in (i.client.get(f"/domains/{DOMAIN}/details").text,
                 i.client.get(f"/domains/{DOMAIN}/history/{scan_id}").text):
        assert 'data-rule="F05.10"' in smtp_part(page) and len(rows(page)) == 16
        shown, more = re.search(r"Noms : (mx\.example\.net(?:, san\d{4}\.hosting\.example)*) et (\d+) autres",
                                smtp_part(page)).groups()
        assert len(shown.split(", ")) + int(more) == 1001  # the names shown, then all the others, counted


# ------------------------------------------------------------------ an evidence stored before the bounding (A7)
def older(evidence, *, named: str = "", **_) -> dict:
    """The evidence as 0042c80 stored it, before the bounding: no counts; every MX resolved, then the others up
    to sixteen in their order; every address and every name of what it kept, the lists of the notes whole
    (with ``listed`` below). Checked equal to what 0042c80 stores, for every fixed and large world."""
    if "exhaustivity" not in evidence:
        return dict(evidence)
    found = copy.deepcopy(dict(evidence))
    found.pop("counts", None)
    mx = found.get("mx", [])
    resolved = [n for n, m in enumerate(mx) if m.get("valid", True) and not m.get("cause")]
    others = [n for n in range(len(mx)) if n not in resolved]
    kept = sorted(resolved + others[:max(16 - len(resolved), 0)])
    found["mx"] = [mx[n] for n in kept]
    found["mx_omitted"] = len(mx) - len(kept)
    return found


def scan_older(i: Instance, data: dict) -> str:
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(smtp_evidence, "bound", older)
        patch.setattr(smtp_evidence, "listed", lambda items, most=8: (", ".join(items), 0))
        return i.scan(data)


def test_an_older_large_evidence_is_shown_bounded_and_kept_whole(instance):
    """F05.09, R5, S05 (correction 2, A7): an evidence of 4,000 addresses stored before the bounding (631 KiB,
    no counts, checked equal to what 0042c80 stores) is never rewritten: the details, the history and the PDF
    show it bounded, the JSON panel within 64 KiB, the text of the finding without its 4,000 addresses; they
    say so, and the page links its original, which comes back byte for byte; the API gives the counts of the
    measure."""
    i = instance()
    scan_older(i, LARGE["4,000 addresses on one MX"])
    raw = stored(i)
    original = json.loads(raw)["evidence"]
    assert size(original) > 600_000 and "counts" not in original and "bounds" not in original
    kib = f"{size(original) / 1024:.0f}"
    scan_id = i.scans.latest_id(i.scans.domain(DOMAIN)["id"])
    for path in (f"/domains/{DOMAIN}/details", f"/domains/{DOMAIN}/history/{scan_id}"):
        page = i.client.get(path).text
        assert len(page) < 2 * LIMIT_BYTES  # the evidence alone was ten times that
        part = smtp_part(page)
        notice = f"Preuve enregistrée avant le bornage des preuves ({kib} Kio) : elle est présentée ici bornée à 64 Kio"
        assert notice in part
        assert "3980 adresses publiées, non tentées, ne sont pas reprises dans ce tableau." in part
        panel = re.search(rf'id="{re.escape(CHECK)}".*?<pre class="evidence">(.*?)</pre>', page, re.S).group(1)
        shown = json.loads(markup.unescape(panel))
        assert size(shown) <= LIMIT_BYTES and shown["bounds"]["source"] == "display"
        assert shown["bounds"]["original_bytes"] == size(original) and shown["counts"]["addresses"]["source"] == "rows"
        link = f'href="/domains/{DOMAIN}/history/{scan_id}/evidence/{CHECK}" download>Télécharger la preuve originale'
        assert link in page
    response = i.client.get(f"/domains/{DOMAIN}/history/{scan_id}/evidence/{CHECK}")
    assert response.status_code == 200 and response.headers["content-type"] == "application/json"
    assert response.headers["content-disposition"] == (
        f'attachment; filename="posture-{DOMAIN}-scan-{scan_id}-{CHECK}.json"')
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.content == json.dumps(original).encode() == json.dumps(json.loads(raw)["evidence"]).encode()
    scan = i.scans.get(scan_id)
    assert _summary(scan)["smtp_probe"] == {"scope": "on", "status": "ok", "rule": "F05.09", "mx": 1,
                                            "addresses": 4000, "verified": 1}
    html = render_html(i.app.state.services.catalog, "fr", scan)
    annex = html[html.index('class="smtp-annex"'):]
    assert f"Preuve enregistrée avant le bornage des preuves ({kib} Kio)" in annex and annex.count("<tr>") == 22
    assert len(html) < 2 * LIMIT_BYTES
    assert stored(i) == raw  # read, shown, downloaded: never rewritten


def test_an_older_recheck_is_shown_bounded_and_its_original_is_the_recheck(instance):
    """R6, F05.10 (correction 2, A7): a recheck stored before the bounding, beyond the limit, is shown bounded
    like a scan; the original the page links is the recheck's, the one the page shows."""
    i = instance()
    i.scan(LARGE["F05.08 named after the sample"])
    i.data.clear()
    i.data.update(LARGE["1,001 certificate names on 16 addresses"])
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(smtp_evidence, "bound", older)
        post(i.client, f"/domains/{DOMAIN}/verify/{CHECK}", f"/domains/{DOMAIN}?task={CHECK}")
    raw = json.loads(stored(i, "rechecks"))["evidence"]
    assert size(raw) > LIMIT_BYTES and raw["rule"] == "F05.10"
    page = i.client.get(f"/domains/{DOMAIN}/details").text
    assert 'data-rule="F05.10"' in smtp_part(page) and "Preuve enregistrée avant le bornage" in smtp_part(page)
    scan_id = i.scans.latest_id(i.scans.domain(DOMAIN)["id"])
    assert i.client.get(f"/domains/{DOMAIN}/history/{scan_id}/evidence/{CHECK}").content == json.dumps(raw).encode()


def test_an_older_small_evidence_is_shown_as_stored(instance):
    """F05.09, R5 (correction 2, A5 A7): an evidence stored before the bounding and within the limit is shown as
    it was stored, without notice nor link; the API counts its verified addresses from its rows."""
    from test_v070_smtp_display import V4, V6, world

    i = instance()
    page = scan_older(i, world({MX1: {V4: "tls_verified", V6: "no_ipv6"}}))
    evidence = json.loads(stored(i))["evidence"]
    assert "counts" not in evidence and "bounds" not in evidence
    assert "avant le bornage" not in page and "/evidence/" not in page
    scan = i.scans.get(i.scans.latest_id(i.scans.domain(DOMAIN)["id"]))
    assert _summary(scan)["smtp_probe"] == {"scope": "on", "status": "ok", "rule": "F05.09", "mx": 1,
                                            "addresses": 2, "verified": 1}


def test_hostile_names_of_an_older_evidence_stay_text(instance):
    """S04, S05, R2 (correction 2, A7): hostile MX names in an older evidence beyond the limit are shown bounded
    as escaped text, in the table and in the JSON panel; the original is a JSON attachment, never a page."""
    hostile = '<script>alert("smtp")</script>'
    names = [f"{hostile}{i:04d}_.example" for i in range(3000)]
    i = instance()
    page = scan_older(i, build([(i + 1, n) for i, n in enumerate(names)] + [(9000, MX1)], {MX1: ["192.0.2.25"]},
                               {MX1: {"192.0.2.25": "tls_verified"}}))
    assert size(json.loads(stored(i))["evidence"]) > LIMIT_BYTES
    assert "<script>alert" not in page and "&lt;script&gt;alert(&#34;smtp&#34;)&lt;/script&gt;0000_.example" in page
    scan_id = i.scans.latest_id(i.scans.domain(DOMAIN)["id"])
    response = i.client.get(f"/domains/{DOMAIN}/history/{scan_id}/evidence/{CHECK}")
    assert response.headers["content-type"] == "application/json"
    assert response.headers["content-disposition"].startswith("attachment;")


def test_the_original_is_given_to_those_who_see_the_scan_only(instance):
    """S05, P4 (correction 2, A7): the original evidence is a page of the history: a 404 for any other check, a
    scan of another domain or none, an internal domain to anyone but an administrator (who is audited), and a
    login first."""
    from posture_cockpit.security import hash_password
    from posture_cockpit.storage.perimeters import parse_form

    i = instance()
    i.scan(LARGE["300 silent MX"])
    s = i.app.state.services
    scan_id = s.scans.latest_id(s.scans.domain(DOMAIN)["id"])
    base = f"/domains/{DOMAIN}/history"
    assert i.client.get(f"{base}/{scan_id}/evidence/{CHECK}").status_code == 200  # a new evidence too
    for path in (f"{base}/{scan_id}/evidence/mail.mx", f"{base}/{scan_id + 1}/evidence/{CHECK}",
                 f"{base}/0/evidence/{CHECK}", f"{base}/abc/evidence/{CHECK}",
                 f"/domains/other.example/history/{scan_id}/evidence/{CHECK}"):
        assert i.client.get(path).status_code == 404, path
    perimeter = s.perimeters.create(parse_form("Lab", "10.20.0.0/16", "", "443", ""), None)
    s.db.execute("UPDATE domains SET perimeter_id=? WHERE name=?", (perimeter, DOMAIN))
    assert i.client.get(f"{base}/{scan_id}/evidence/{CHECK}").status_code == 200
    entry = s.audit.latest(1)[0]
    assert (entry["action"], entry["target"], entry["detail"]["perimeter"], entry["detail"]["scan"]) == (
        "evidence.internal", DOMAIN, "Lab", scan_id)
    s.accounts.create("reader", hash_password(PASSWORD))
    log_out(i.client)
    assert i.client.get(f"{base}/{scan_id}/evidence/{CHECK}", follow_redirects=False).status_code in (302, 303)
    log_in(i.client, "reader")
    assert i.client.get(f"{base}/{scan_id}/evidence/{CHECK}").status_code == 404


# ------------------------------------------------------------------ the probe off, internal, an engine error
def test_the_probe_off_an_internal_perimeter_and_an_engine_error_are_as_they_were(instance, monkeypatch):
    """F05.01, S05, R5 (correction 2): the probe off stores its evidence as it was (no counts, no bounds); a scan
    of an internal perimeter has no SMTP evidence to bound; an error of the engine neither: no SMTP block, no
    link to an original."""
    off = instance(probe=False)
    page = off.scan(WORLDS["F05.01 probe off"][0])
    evidence = json.loads(stored(off))["evidence"]
    assert evidence["rule"] == "F05.01" and not {"counts", "bounds", "mx"} & set(evidence)
    assert "/evidence/" not in page
    internal = result(WORLDS["F05.10 OK enforce"][0], probe=True, internal=True)
    finding = next(f for f in internal.findings if f.check_id == CHECK)
    assert finding.status.value == "na" and "bounds" not in finding.outcome.evidence
    from posture_cockpit.checks import smtp_verdict

    monkeypatch.setattr(smtp_verdict, "decide", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    broken = instance()
    page = broken.scan(WORLDS["F05.10 OK enforce"][0])
    assert smtp_part(page) == "" and "/evidence/" not in page
    assert "bounds" not in json.loads(stored(broken))["evidence"]


# ------------------------------------------------------------------ A6: mail.mx and mail.mta_sts, measured
def hostile_mx(names: list[str], covered: int) -> dict:
    return build([(i + 1, name) for i, name in enumerate(names)] + [(9000, MX1)], {MX1: ["192.0.2.25"]},
                 {MX1: {"192.0.2.25": "tls_verified"}}, covered=[MX1, *names[:covered]])


@pytest.mark.parametrize(("name", "data", "mx", "mta_sts"), [
    ("3,000 short MX: the most a DNS answer of 64 KiB holds", lambda: hostile_mx(
        [f"a{i}.example.org" for i in range(3000)], 1000), 140721, 62092),
    ("245 MX of 250 characters: the longest it holds", lambda: hostile_mx(
        [(f"m{i:03d}." + "h" * 63 + "." + "i" * 63 + "." + "j" * 63 + ".")[:242] + "example.org" for i in range(245)],
        245), 105045, 52127),
    ("3,000 hostile MX of 250 characters: beyond what a DNS answer holds", lambda: hostile_mx(
        [(f"<b>x{i:04d}</b>" + "h" * 250)[:250] + ".example" for i in range(3000)], 1000), 1588941, 262187),
])
def test_the_evidence_of_mail_mx_and_mail_mta_sts_is_measured_and_left_as_it_was(name, data, mx, mta_sts):
    """F01, Q05 (correction 2, A6): mail.mx and mail.mta_sts are not bounded by this correction: their evidence
    is the size it was on 0042c80 (measured there, byte for byte), up to 137 KiB and 61 KiB for the most a DNS
    answer can publish, 1.5 MiB for lists no DNS answer can carry; the SMTP evidence of the same world stays
    within its limit."""
    findings, _ = scan_smtp(data())
    sizes = {k: size(findings[k].outcome.evidence) for k in ("mail.mx", "mail.mta_sts", CHECK)}
    assert (sizes["mail.mx"], sizes["mail.mta_sts"]) == (mx, mta_sts) and sizes[CHECK] <= LIMIT_BYTES
