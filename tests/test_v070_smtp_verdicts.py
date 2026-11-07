# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The verdict of mail.smtp_starttls (matrix F05) and the readiness for enforce (F06), PR-C.

Each line of matrix F05 (revision 3 of the specification, §3) has its test, named after the line,
on a recorded world run through the engine with the probe on: what the probe observes is what the
recorded network answers (core/fixture.py), and the verdict is what checks/smtp_verdict.py decides.
Then: the rules of the plan (R1 with D1b, R2 with D3a, R3 with D2b, R4, MTA-STS with D4a), the
priorities (a defect is never hidden by a missing measure), the distinctions of prerequisite P3
(a failed MX question is not "no MX", an untested MX is not a compliant one...), the indicator F06,
the scoring of T08 (36/41), the texts of every stage and reason (Q03), and a test of the syntax
tree: no other module builds a verdict of this check (Q04).
"""

import ast
from datetime import timedelta
from pathlib import Path

import pytest

from posture_cockpit.checks import smtp_verdict
from posture_cockpit.core import scoring, smtp
from posture_cockpit.core.registry import Registry
from posture_cockpit.i18n import LOCALES, Catalog
from worlds import DOMAIN, NOW, changed, healthy, scan_smtp, without_website

SRC = Path(__file__).resolve().parents[1] / "src" / "posture_cockpit"
CHECK = "mail.smtp_starttls"
URL = f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt"


def world(mx: dict[str, dict], *, policy: str | None = "enforce", patterns: list[str] | None = None,
          base: dict | None = None, **dns) -> dict:
    """A domain whose MX are ``mx`` (name → {address: outcome}), in preference order 10, 20…, each name
    publishing the addresses listed; the MTA-STS policy in ``policy`` mode covering ``patterns`` (all the
    MX by default), None for no policy, "unreadable" for one that times out."""
    data = base or healthy()
    records = {f"{DOMAIN} MX": [f"{10 * (i + 1)} {name}." for i, name in enumerate(mx)]}
    for name, by_address in mx.items():
        v4 = [a for a in by_address if ":" not in a]
        v6 = [a for a in by_address if ":" in a]
        records[f"{name} A"], records[f"{name} AAAA"] = v4, v6
    data = changed(data, dns={**records, **dns})
    data["smtp"] = {name: dict(by_address) for name, by_address in mx.items()}
    if policy is None:
        data["dns"].pop(f"_mta-sts.{DOMAIN} TXT")
    elif policy == "unreadable":
        data["http"][URL] = "timeout"
    else:
        lines = "".join(f"mx: {p}\n" for p in (patterns if patterns is not None else mx))
        data["http"][URL] = {"status": 200, "body": f"version: STSv1\nmode: {policy}\n{lines}max_age: 604800\n"}
    return data


MX1, MX2 = "mx.example.net", "mx2.example.net"
V4, V4B, V6 = "192.0.2.25", "192.0.2.26", "2001:db8::25"


def check(data: dict, **kwargs):
    """The finding of mail.smtp_starttls alone, probe on, and the network."""
    findings, net = scan_smtp(data, CHECK, **kwargs)
    return findings[CHECK], net


def verdict(finding) -> tuple[str, str, str]:
    return finding.status.value, finding.outcome.summary.removeprefix(CHECK + "."), finding.outcome.evidence.get("rule")


def readiness(finding) -> tuple[str, list[str]]:
    r = finding.outcome.evidence["readiness"]
    return r["state"], r["causes"]


def notes(finding) -> list[str]:
    return [n["key"].removeprefix(CHECK + ".note.") for n in finding.outcome.evidence.get("notes", [])]


# ------------------------------------------------------------------ matrix F05, line by line
def test_f05_01_probe_off_is_na_and_asks_nothing():
    """F05.01, A1a: the probe off on the instance gives NA, "probe off", and the check asks nothing at all:
    no DNS question (not even the MX), no SMTP attempt, no policy. The evidence still says probe_enabled."""
    finding, net = check(world({MX1: {V4: "tls_verified"}}), probe=False)
    assert verdict(finding) == ("na", "probe_off", "F05.01")
    assert net.asked == []
    assert finding.outcome.evidence["probe_enabled"] is False
    assert readiness(finding) == ("unconfirmed", ["probe_off"])


def test_f05_01_a_full_scan_with_the_probe_off_asks_what_it_asked_before():
    """F05.01, T05: with the probe off, a full scan asks exactly the questions it asks without the SMTP check."""
    data = world({MX1: {V4: "tls_verified"}})
    registry = Registry.discover()
    others = [c.id for c in registry.checks() if c.id != CHECK]
    _, with_check = scan_smtp(data, probe=False)
    _, without = scan_smtp(data, *others, probe=False)
    assert sorted(with_check.asked) == sorted(without.asked)


@pytest.mark.parametrize("mx", [[], ["0 ."]])
def test_f05_02_no_inbound_mail_is_na(mx):
    """F05.02: no MX, or a valid null MX alone (RFC 7505): the domain receives no mail, NA, readiness
    not applicable, no SMTP attempt."""
    finding, net = check(changed(healthy(), dns={f"{DOMAIN} MX": mx}))
    assert verdict(finding) == ("na", "mail.no_inbound", "F05.02")
    assert readiness(finding) == ("not_applicable", [])
    assert not [q for q in net.asked if q.startswith("smtp ")]


def test_f05_03_starttls_absent_is_fail():
    """F05.03: STARTTLS not announced after a complete greeting and EHLO, keywords not masked: FAIL, with the
    host and the address where it was observed; readiness to fix."""
    finding, _ = check(world({MX1: {V4: "starttls_absent"}}))
    assert verdict(finding) == ("fail", "starttls_absent", "F05.03")
    assert dict(finding.outcome.params) == {"host": MX1, "address": V4, "n": 1}
    assert readiness(finding) == ("to_fix", ["starttls_absent"])
    assert finding.outcome.remedy is not None and finding.outcome.remedy.expect is None  # no projected gain


def test_f05_04_certificate_refused_with_enforce_in_force_is_fail():
    """F05.04, F03: the certificate refused (PKIX or name) while a valid policy is in force in enforce mode:
    FAIL; the refusal (code and message) is kept in the evidence; readiness to fix."""
    finding, _ = check(world({MX1: {V4: {"reason": "certificate_refused", "verify_code": 62,
                                         "verify_message": "Hostname mismatch"}}}))
    assert verdict(finding) == ("fail", "certificate_enforce", "F05.04")
    dialogue = finding.outcome.evidence["mx"][0]["addresses"][0]["observations"][0]["dialogue"]
    assert (dialogue["reason"], dialogue["verify_code"], dialogue["verify_message"]) == (
        "certificate_refused", 62, "Hostname mismatch")
    assert readiness(finding) == ("to_fix", ["certificate_invalid"])


def test_f05_05_no_tls_version_fail_in_0_7_d1b():
    """F05.05, D1b, R1: a TLS version refused is never a FAIL in 0.7.0: ERROR (F05.08), the technical
    evidence kept, no reconnection with an older version (one verifying attempt only)."""
    finding, net = check(world({MX1: {V4: {"reason": "tls_version_refused", "detail": "protocol_version"}}}))
    assert verdict(finding) == ("error", "unmeasured.tls_version", "F05.08")
    assert [q for q in net.asked if q.startswith("smtp ")] == [f"smtp {MX1} {V4} verify"]
    dialogue = finding.outcome.evidence["mx"][0]["addresses"][0]["observations"][0]["dialogue"]
    assert (dialogue["stage"], dialogue["detail"]) == ("tls", "protocol_version")


@pytest.mark.parametrize("policy", [None, "testing", "none", "unreadable"])
def test_f05_06_certificate_refused_without_enforce_in_force_is_warn(policy):
    """F05.06, R4: the certificate refused and no policy in force in enforce mode (missing, testing, none,
    unreadable): WARN, never FAIL; readiness to fix."""
    finding, _ = check(world({MX1: {V4: "certificate_refused"}}, policy=policy))
    assert verdict(finding) == ("warn", "certificate_invalid", "F05.06")
    assert readiness(finding)[0] == "to_fix"


@pytest.mark.parametrize(("days", "expected"), [(21, ("ok", "ok", "F05.10")),
                                                (20, ("warn", "certificate_expiring", "F05.07")),
                                                (11, ("warn", "certificate_expiring", "F05.07")),
                                                (10, ("warn", "certificate_expiring_urgent", "F05.07")),
                                                (0, ("warn", "certificate_expiring_urgent", "F05.07"))])
def test_f05_07_a_valid_certificate_expiring_soon_is_warn_d3a(days, expected):
    """F05.07, D3a, R2: a valid certificate is OK beyond 20 days, WARN within 20 days and urgent within 10,
    the bounds of checks/tls.py; still valid, never FAIL, readiness unchanged (here: compatible)."""
    finding, _ = check(world({MX1: {V4: {"reason": "tls_verified", "certificate": {"expires_in_days": days}}}}))
    assert verdict(finding) == expected
    if expected[0] == "warn":
        assert finding.outcome.params["days"] == days
    assert readiness(finding) == ("compatible", [])


def test_f05_07_days_use_the_time_of_the_scan_r2():
    """F05.07, R2: the days left are counted from the time of the scan (ctx.now), never the wall clock: the
    same certificate, 15 days left at the recording, is urgent for a scan made 5 days later."""
    data = world({MX1: {V4: {"reason": "tls_verified", "certificate": {"expires_in_days": 15}}}})
    import asyncio

    from posture_cockpit.core import engine
    from posture_cockpit.core.extension import SmtpSettings
    from posture_cockpit.core.fixture import FixtureNetwork
    from worlds import EHLO

    later = NOW + timedelta(days=5)
    net = FixtureNetwork(data, NOW, domain=DOMAIN, ehlo_name=EHLO)
    result = asyncio.run(engine.scan(DOMAIN, [Registry.discover().get(CHECK)], net, timeout=5, now=later,
                                     smtp=SmtpSettings(True, EHLO)))
    finding = result.findings[0]
    assert verdict(finding) == ("warn", "certificate_expiring_urgent", "F05.07")
    assert finding.outcome.params["days"] == 10


def test_f05_07_an_expired_certificate_is_invalid_not_expiring_r2():
    """F05.07, F05.04, R2: an expired certificate is refused by the verification (code 10): invalid (F05.04
    with enforce), never "expiring"."""
    finding, _ = check(world({MX1: {V4: {"reason": "certificate_refused", "verify_code": 10,
                                         "verify_message": "certificate has expired"}}}))
    assert verdict(finding) == ("fail", "certificate_enforce", "F05.04")


@pytest.mark.parametrize(("outcome", "cause"), [
    ("timeout", "network"), ("refused", "network"), ("unreachable", "no_route"), ("no_ipv6", "no_route"),
    ("policy", "policy"), ("banner_refused", "smtp_refused"), ("ehlo_refused", "smtp_refused"),
    ("esmtp_altered", "altered"), ("tls_handshake_error", "tls"), ("tls_dialogue_error", "tls"),
    ("closed@tls", "network"), ("timeout@ehlo", "network"), ("malformed_reply", "protocol"),
    ("deadline@banner", "deadline"), ("hang", "deadline")])
def test_f05_08_nothing_conclusive_is_error_with_its_cause(outcome, cause):
    """F05.08, D2b, S05, T03: network, port 25, no route, the anti-SSRF rule, SMTP refusals (421/554, EHLO),
    masked keywords, TLS not concluded, the deadline: ERROR (not evaluated), the cause said, the
    observations kept, readiness unconfirmed. Never a defect of the server."""
    finding, _ = check(world({MX1: {V4: outcome}}), timeout=4 if outcome == "hang" else 5)
    assert verdict(finding) == ("error", f"unmeasured.{cause}", "F05.08")
    assert finding.outcome.params["host"] == MX1
    assert finding.outcome.evidence["mx"][0]["addresses"][0]["unmeasured"] == cause
    state, causes = readiness(finding)
    assert state == "unconfirmed" and "incomplete" in causes
    # "hang": the probe used all its time; the policy, read after it, is not waited for (P1): unreadable.
    assert causes == (["policy_unreadable", "incomplete"] if outcome == "hang" else ["incomplete"])


def test_f05_08_an_mx_without_any_conclusion_is_error_even_when_another_verifies():
    """F05.08, A2b: one MX verified, the other gives nothing conclusive: ERROR, the verified observations
    kept in the evidence."""
    finding, _ = check(world({MX1: {V4: "tls_verified"}, MX2: {V4B: "timeout"}}))
    assert verdict(finding) == ("error", "unmeasured.network", "F05.08")
    assert finding.outcome.params == {"host": MX2, "n": 1}
    assert [a["seen"] for m in finding.outcome.evidence["mx"] for a in m["addresses"]] == ["verified", "unmeasured"]


def test_f05_09_one_verified_address_per_mx_is_ok_with_notes_a2b():
    """F05.09, A2b, T03: the IPv4 address verified, the IPv6 one untestable from here (no route): OK with the
    coverage notes, and readiness unconfirmed while a published address is not evaluated."""
    finding, _ = check(world({MX1: {V4: "tls_verified", V6: "no_ipv6"}}))
    assert verdict(finding) == ("ok", "ok_partial", "F05.09")
    assert notes(finding) == ["coverage", "untested.no_route"]
    assert readiness(finding) == ("unconfirmed", ["incomplete"])


def test_f05_10_complete_and_valid_is_ok():
    """F05.10: every MX and address published measured and verified: OK, no note, readiness compatible with the
    enforce policy in force."""
    finding, _ = check(world({MX1: {V4: "tls_verified", V6: "tls_verified"}, MX2: {V4B: "tls_verified"}}))
    assert verdict(finding) == ("ok", "ok", "F05.10")
    assert notes(finding) == []
    assert readiness(finding) == ("compatible", [])


def test_f05_10_ok_without_a_policy_d4a():
    """F05.10, D4a, F06: no MTA-STS policy, the servers all verify: OK; readiness unconfirmed, policy_missing."""
    finding, _ = check(world({MX1: {V4: "tls_verified"}}, policy=None))
    assert verdict(finding) == ("ok", "ok", "F05.10")
    assert readiness(finding) == ("unconfirmed", ["policy_missing"])


def test_f05_11_mx_beyond_the_sample_are_a_note_never_a_verdict():
    """F05.11, F04: ten MX published, eight measured and verified: the verdict follows F05.09 (OK with notes),
    the note names the MX beyond the sample, readiness unconfirmed (never ready on a sample)."""
    mx = {f"mx{i}.example.net": {f"192.0.2.{30 + i}": "tls_verified"} for i in range(10)}
    finding, net = check(world(mx))
    assert verdict(finding) == ("ok", "ok_partial", "F05.09")
    assert "sample" in notes(finding)
    assert readiness(finding) == ("unconfirmed", ["incomplete"])
    assert len([q for q in net.asked if q.startswith("smtp ")]) == 8


def test_f05_11_an_incomplete_dns_answer_is_a_note():
    """F05.11, F01: the AAAA question of the MX fails, its A address verifies: OK with notes (DNS incomplete),
    readiness unconfirmed."""
    finding, _ = check(world({MX1: {V4: "tls_verified"}}, **{f"{MX1} AAAA": "timeout"}))
    assert verdict(finding) == ("ok", "ok_partial", "F05.09")
    assert "dns_incomplete" in notes(finding)
    assert readiness(finding) == ("unconfirmed", ["incomplete"])


def test_f05_12_an_mx_that_is_a_cname_is_a_note_without_a_tls_defect():
    """F05.12, F01, F03: the MX name is an alias: a note says so (RFC 2181 §10.3), the verdict stays the one
    of the observations (here OK), no TLS defect is invented; readiness to look into (mx_cname)."""
    finding, _ = check(world({MX1: {V4: "tls_verified"}}, **{f"{MX1} CNAME": ["mail.provider.example."]}))
    assert verdict(finding) == ("ok", "ok", "F05.10")
    assert notes(finding) == ["cname"]
    assert readiness(finding) == ("unconfirmed", ["mx_cname"])


# ------------------------------------------------------------------ priorities
def test_a_proven_fail_is_never_hidden_by_a_missing_measure():
    """F05.03, F05.08, F05.11: STARTTLS absent on one MX, the other unreachable, MX beyond nothing: FAIL."""
    finding, _ = check(world({MX1: {V4: "timeout"}, MX2: {V4B: "starttls_absent"}}))
    assert verdict(finding) == ("fail", "starttls_absent", "F05.03")
    assert "untested.network" in notes(finding)


def test_a_proven_warn_is_never_hidden_by_an_mx_without_conclusion():
    """F05.06, F05.08: a certificate refused (no enforce) on one MX, nothing conclusive on the other: WARN."""
    finding, _ = check(world({MX1: {V4: "timeout"}, MX2: {V4B: "certificate_refused"}}, policy="testing"))
    assert verdict(finding) == ("warn", "certificate_invalid", "F05.06")


def test_fail_starttls_comes_before_fail_certificate():
    """F05.03, F05.04: both defects proven: the first line of the matrix applies (STARTTLS absent)."""
    finding, _ = check(world({MX1: {V4: "certificate_refused"}, MX2: {V4B: "starttls_absent"}}))
    assert verdict(finding) == ("fail", "starttls_absent", "F05.03")
    assert readiness(finding) == ("to_fix", ["starttls_absent", "certificate_invalid"])


# ------------------------------------------------------------------ R3 and D2b: replies to STARTTLS
@pytest.mark.parametrize("outcome", ["starttls_temporary", "starttls_dialogue_error", "starttls_policy_refusal",
                                     "starttls_unavailable"])
def test_r3_every_refusal_of_starttls_is_error_d2b(outcome):
    """R3, D2b, F05.08: a reply to STARTTLS other than 220 (4xx, 501/503/504, 5.7.x, 500/502 after announcing
    it) is ERROR, never FAIL; only STARTTLS not announced is a FAIL (F05.03)."""
    finding, _ = check(world({MX1: {V4: outcome}}))
    assert verdict(finding) == ("error", "unmeasured.starttls_refused", "F05.08")


# ------------------------------------------------------------------ P3: no verdict from an incomplete discovery
def test_p3_a_failed_mx_question_is_not_no_mx():
    """F05.02, F05.08, F01: the MX question times out: ERROR (DNS), never NA as for a domain without MX."""
    finding, _ = check(changed(healthy(), dns={f"{DOMAIN} MX": "timeout"}))
    assert verdict(finding) == ("error", "unmeasured.dns", "F05.08")
    assert finding.outcome.evidence["discovery_error"]


def test_p3_an_invalid_mx_name_is_not_a_null_mx():
    """F05.02, F05.08, F01: an MX whose name is not a host name is kept, never contacted, never NA: ERROR."""
    finding, net = check(changed(healthy(), dns={f"{DOMAIN} MX": ["10 bad_name!.example."]}))
    assert verdict(finding) == ("error", "unmeasured.invalid_name", "F05.08")
    assert not [q for q in net.asked if q.startswith("smtp ")]


def test_p3_an_untested_mx_is_not_a_compliant_mx():
    """F05.08, F05.09, A2b: one MX verified, the second published without any address: ERROR, not OK."""
    finding, _ = check(world({MX1: {V4: "tls_verified"}, MX2: {}}))
    assert verdict(finding) == ("error", "unmeasured.no_address", "F05.08")


def test_p3_ipv6_without_route_is_not_a_tls_defect():
    """F05.08, T03, S05: the only address is IPv6 and this machine has no IPv6: ERROR (no route), no defect."""
    finding, _ = check(world({MX1: {V6: "no_ipv6"}}))
    assert verdict(finding) == ("error", "unmeasured.no_route", "F05.08")


def test_p3_masked_keywords_are_not_starttls_absent():
    """F05.03, F05.08, F02 bis: keywords masked on the path (XXXXXXXA): inspection probable, ERROR, never the
    FAIL of a confirmed absence."""
    finding, _ = check(world({MX1: {V4: "esmtp_altered"}}))
    assert verdict(finding) == ("error", "unmeasured.altered", "F05.08")


def test_p3_an_anti_ssrf_refusal_is_not_a_defect_of_the_target():
    """F05.08, S02: the address refused by the egress rule: a measure not made, ERROR (policy), no socket."""
    finding, _ = check(world({MX1: {V4: "policy"}}))
    assert verdict(finding) == ("error", "unmeasured.policy", "F05.08")
    observation = finding.outcome.evidence["mx"][0]["addresses"][0]["observations"][0]
    assert (observation["cause"], observation["socket"], observation["consumed"]) == ("policy", False, False)


# ------------------------------------------------------------------ F06: readiness for enforce
def test_f06_testing_policy_complete_measure_is_ready():
    """F06: a valid testing policy covering every MX, every address verified: ready according to the measures
    made from this instance; the policy evaluated is kept (mode, patterns, MX covered)."""
    finding, _ = check(world({MX1: {V4: "tls_verified"}}, policy="testing"))
    assert readiness(finding) == ("ready", [])
    policy = finding.outcome.evidence["readiness"]["policy"]
    assert (policy["state"], policy["mode"]) == ("testing", "testing")
    assert (policy["covered"], policy["uncovered"]) == ([MX1], [])


def test_f06_enforce_policy_complete_measure_is_compatible_r7():
    """F06, R7: a valid enforce policy, every address verified: compatible with the enforce policy in force."""
    finding, _ = check(world({MX1: {V4: "tls_verified"}}))
    assert readiness(finding) == ("compatible", [])


def test_f06_an_mx_the_policy_does_not_cover_is_to_fix():
    """F06: the valid policy does not cover the MX: to fix (senders in enforce would refuse it), whatever SMTP."""
    finding, _ = check(world({MX1: {V4: "tls_verified"}}, policy="testing", patterns=["other.example"]))
    assert verdict(finding) == ("ok", "ok", "F05.10")
    assert readiness(finding) == ("to_fix", ["mx_uncovered"])


@pytest.mark.parametrize(("policy", "cause"), [(None, "policy_missing"), ("none", "policy_disabled"),
                                               ("unreadable", "policy_unreadable")])
def test_f06_a_policy_missing_disabled_or_unreadable_is_unconfirmed(policy, cause):
    """F06, R4, D4a: whatever the SMTP measure, a policy missing, in none mode or unreadable leaves the
    readiness unconfirmed, with its cause; the verdict stays the one of the observations (OK)."""
    finding, _ = check(world({MX1: {V4: "tls_verified"}}, policy=policy))
    assert verdict(finding)[0] == "ok"
    assert readiness(finding) == ("unconfirmed", [cause])


def test_f06_the_policy_served_behind_an_untrusted_certificate_is_invalid():
    """F06, R4: a policy served with an untrusted certificate is ignored by senders: unconfirmed, invalid."""
    data = changed(world({MX1: {V4: "tls_verified"}}), certificates={f"mta-sts.{DOMAIN}": {"trusted": False}})
    finding, _ = check(data)
    assert readiness(finding) == ("unconfirmed", ["policy_invalid"])


def test_f06_an_ok_is_never_ready_by_itself():
    """F06, A2b: an OK on part of the addresses (F05.09) is never ready, even with a valid enforce policy."""
    finding, _ = check(world({MX1: {V4: "tls_verified", V6: "timeout"}}))
    assert verdict(finding)[1] == "ok_partial"
    assert readiness(finding) == ("unconfirmed", ["incomplete"])


def test_f06_the_budget_spent_leaves_the_readiness_unconfirmed():
    """F06, F04, T03: the 16 attempts spent on 8 dual-stack MX, a ninth MX beyond the sample: unconfirmed."""
    mx = {f"mx{i}.example.net": {f"192.0.2.{30 + i}": "tls_verified", f"2001:db8::{30 + i:x}": "tls_verified"}
          for i in range(9)}
    finding, net = check(world(mx))
    assert len([q for q in net.asked if q.startswith("smtp ")]) == 16
    assert readiness(finding) == ("unconfirmed", ["incomplete"])


def test_f06_scope_sentence_never_promises_delivery():
    """F06: the readiness texts say what was measured from this instance, never a delivery from the Internet."""
    catalog = Catalog(Registry.discover().messages)
    assert "instance" in catalog.text("fr", f"{CHECK}.readiness.ready", {})
    assert "garantie" in catalog.text("fr", f"{CHECK}.readiness.scope", {})
    assert "guarantee" in catalog.text("en", f"{CHECK}.readiness.scope", {})


# ------------------------------------------------------------------ evidence (F05, R5)
@pytest.mark.parametrize("data", [world({MX1: {V4: "tls_verified"}}), world({MX1: {V4: "timeout"}}),
                                  changed(healthy(), dns={f"{DOMAIN} MX": []})])
def test_every_line_writes_probe_enabled_and_its_rule(data):
    """F05.01, F05.02, F05.08, F05.10, R5: every outcome of the check carries the structured probe_enabled the
    measurement scope reads, its line of the matrix and the perspective (this instance)."""
    for probe in (True, False):
        finding, _ = check(data, probe=probe)
        evidence = finding.outcome.evidence
        assert evidence["probe_enabled"] is probe and evidence["rule"].startswith("F05.")
        assert evidence["perspective"] == "instance"


# ------------------------------------------------------------------ T08: scoring
def weights(findings: dict) -> tuple[int, int]:
    """(evaluated, expected) weights: OK/WARN/FAIL count in both, ERROR in the expected one only."""
    scored = sum(f.weight for f in findings.values() if f.status.value in ("ok", "warn", "fail"))
    return scored, scored + sum(f.weight for f in findings.values() if f.status.value == "error")


def test_t08_probe_on_unmeasurable_is_36_of_41():
    """T08, F05.08: no website, port 25 blocked, probe on: the SMTP check (weight 5) is ERROR, counted in the
    expected weight and not in the evaluated one: coverage 36/41 (87.8 %), under 90 %: grade B at best."""
    findings, _ = scan_smtp(world({MX1: {V4: "timeout"}}, base=without_website(healthy())))
    a = scoring.assess(list(findings.values()))
    assert findings[CHECK].status.value == "error"
    assert weights(findings) == (36, 41)
    assert a.coverage == pytest.approx(36 / 41) and a.grade == "B" and a.evaluation == "partial"


def test_t08_probe_off_is_out_of_the_score_and_of_the_coverage():
    """T08, F05.01, A1a: the same domain with the probe off: the check is NA, its weight out of both: 36/36."""
    findings, _ = scan_smtp(world({MX1: {V4: "timeout"}}, base=without_website(healthy())), probe=False)
    a = scoring.assess(list(findings.values()))
    assert findings[CHECK].status.value == "na"
    assert weights(findings) == (36, 36)
    assert (a.coverage, a.grade) == (1.0, "A")


# ------------------------------------------------------------------ texts (Q03), one place for the verdict (Q04)
def test_every_stage_reason_cause_and_note_has_its_texts():
    """Q03, F07: every stage and every reason of the dialogue, every cause, note and readiness state of the
    check has its text in French and in English."""
    catalog = Catalog(Registry.discover().messages)
    keys = [f"{CHECK}.stage.{s.value}" for s in smtp.Stage] + [f"{CHECK}.reason.{r.value}" for r in smtp.Reason]
    keys += [f"{CHECK}.unmeasured.{c}" for c in smtp_verdict.CAUSE_ORDER]
    keys += [f"{CHECK}.note.untested.{c}" for c in smtp_verdict.CAUSE_ORDER]
    keys += [f"{CHECK}.readiness.{r.value}" for r in smtp_verdict.Readiness]
    keys += [f"{CHECK}.policy.{p.value}" for p in smtp_verdict.PolicyState]
    keys += [f"{CHECK}.note.{n}" for n in ("coverage", "sample", "dns_incomplete", "cname", "verify_only",
                                           "reading_interrupted", "deadline")]
    missing = [(lang, k) for k in keys for lang in LOCALES if not catalog.has(lang, k)]
    assert missing == []


VERDICTS = {"ok", "warn", "fail", "info", "na", "not_evaluated", "blocked", "Outcome"}


def test_only_smtp_verdict_builds_a_verdict_of_the_check():
    """Q04, F05: no module but checks/smtp_verdict.py builds an outcome whose message is one of
    mail.smtp_starttls; the check itself only returns what smtp_verdict.decide() gives."""
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "smtp_verdict.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) in VERDICTS
                    and any("smtp_starttls" in ast.unparse(arg) for arg in node.args)):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert offenders == []
    mail = ast.parse((SRC / "checks" / "mail.py").read_text(encoding="utf-8"))
    function = next(n for n in mail.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "smtp_starttls")
    returns = [n.value for n in ast.walk(function) if isinstance(n, ast.Return)]
    assert returns and all(ast.unparse(r).startswith("smtp_verdict.decide(") for r in returns)  # type: ignore[arg-type]
