# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The SMTP probe of a scan: discovery, fair selection, budget, deadline, observations kept (version 0.7, T03).

Most tests use recorded worlds (FixtureNetwork), which refuse exactly what the real
network refuses and answer at once, or never (``"hang"``). The last ones run on the real
network (LabNetwork) against fake SMTP servers on this machine, through the engine, to
show that a blocked MX costs nothing to a fast one and that the probe returns before the
engine stops the check.

Each docstring names the requirement it covers: specification 0.7 revision 3 (T03, F01,
F02, F03, S02, Q02) and the decisions of the review of PR-B2 (A to E).
"""

import asyncio
import datetime as dt
import time
from pathlib import Path

import pytest

from local_servers import LOOPBACK, TestPki, dns_server
from posture_cockpit.checks import smtp_measure
from posture_cockpit.config import SMTP_CHECK_MARGIN
from posture_cockpit.core import engine
from posture_cockpit.core.extension import CheckContext, Extension, SmtpSettings
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import Status, info
from posture_cockpit.core.network import DnsAnswer, SmtpPurpose
from posture_cockpit.core.smtp import Reason
from smtp_lab import LabNetwork
from smtp_servers import SILENT, Script, smtp_server

DOMAIN = "example.org"
EHLO = "probe.example.org"


def world(*mx: tuple[str, int, list[str], object], extra: dict | None = None) -> dict:
    """A recorded world: each MX as (name, preference, addresses, outcome for every address)."""
    dns: dict = {f"{DOMAIN} MX": [f"{preference} {name}." for name, preference, _, _ in mx]}
    smtp: dict = {}
    for name, _, addresses, outcome in mx:
        for address in addresses:
            dns.setdefault(f"{name} {'AAAA' if ':' in address else 'A'}", []).append(address)
            smtp.setdefault(name, {})[address] = outcome
    data = {"dns": dns, "smtp": smtp}
    for section, values in (extra or {}).items():
        data.setdefault(section, {}).update(values)
    return data


def dual(index: int, outcome: object = "tls_verified", v4: int = 1, v6: int = 1) -> tuple[str, int, list[str], object]:
    addresses = [f"192.0.2.{index * 10 + n}" for n in range(v4)] + [f"2001:db8::{index:x}:{n}" for n in range(v6)]
    return f"mx{index}.{DOMAIN}", 10 * (index + 1), addresses, outcome


def context(net, *, enabled: bool = True, internal: bool = False, check_timeout: float = 15.0) -> CheckContext:
    return CheckContext(DOMAIN, net, dt.datetime.now(dt.UTC), internal=internal,
                        smtp=SmtpSettings(enabled, EHLO if enabled else None), check_timeout=check_timeout)


def measured(data: dict, **options) -> tuple[smtp_measure.ProbeResult, FixtureNetwork, float]:
    net = FixtureNetwork(data, domain=DOMAIN, ehlo_name=EHLO, internal=options.get("internal", False))
    start = time.monotonic()
    probe = asyncio.run(smtp_measure.measure(context(net, **options)))
    return probe, net, time.monotonic() - start


def smtp_asked(net: FixtureNetwork) -> list[str]:
    return [q for q in net.asked if q.startswith("smtp ")]


# ------------------------------------------------------------------ the deadline (T03, F02)
@pytest.mark.parametrize(("check_timeout", "seconds"), [(15, 12), (10, 8), (4, 2), (30, 12), (14, 12), (13.5, 11.5)])
def test_the_deadline_is_min_12_and_check_timeout_minus_2(check_timeout, seconds):
    """T03, F02: the probe's time is min(12 s, CHECK_TIMEOUT − 2 s): 12, 8 and 2 s for 15, 10 and 4."""
    assert smtp_measure.deadline_seconds(check_timeout) == seconds
    assert (smtp_measure.DEADLINE_CAP, SMTP_CHECK_MARGIN) == (12.0, 2.0)
    probe, _, _ = measured(world(dual(0)), check_timeout=check_timeout)
    assert probe.deadline == seconds and probe.deadline_reached is False  # nothing cut: everything answered


# ------------------------------------------------------------------ selection and budget (T03, decision C)
def test_8_dual_stack_mx_make_16_attempts_without_a_reading():
    """T03: 8 MX with an IPv4 and an IPv6 address each: the 16 attempts, one per address, and no certificate
    reading, even after refusals, since none is left."""
    probe, net, _ = measured(world(*(dual(i, {"verify": "certificate_refused", "read_certificate": "tls_unverified"})
                                     for i in range(8))))
    assert len(smtp_asked(net)) == 16 and all(q.endswith(" verify") for q in smtp_asked(net))
    summary = probe.exhaustivity()
    assert (summary["planned"], summary["attempted"], summary["certificate_readings"]) == (16, 16, 0)


def test_one_attempt_left_gives_one_reading_never_two_per_mx():
    """T03, decision C: 15 addresses selected leave one attempt: one reading after a refused certificate, never
    two; and one MX with two refused addresses gets one reading, on the address that failed."""
    refusing = {"verify": "certificate_refused", "read_certificate": "tls_unverified"}
    probe, net, _ = measured(world(*(dual(i, refusing) for i in range(7)), dual(7, refusing, v6=0)))
    readings = [q for q in smtp_asked(net) if q.endswith("read_certificate")]
    assert len(smtp_asked(net)) == 16 and len(readings) == 1
    probe, net, _ = measured(world(dual(0, refusing, v4=2, v6=0)))
    readings = [q for q in smtp_asked(net) if q.endswith("read_certificate")]
    assert len(readings) == 1
    read = next(a for a in probe.addresses if a.reading is not None)
    assert readings[0] == f"smtp mx0.{DOMAIN} {read.address} read_certificate"
    assert read.verification.dialogue.reason is Reason.CERTIFICATE_REFUSED  # the refusal is kept beside it
    assert read.reading.dialogue.reason is Reason.TLS_UNVERIFIED and not read.reading.dialogue.certificate.trusted


def test_the_fair_pass_order():
    """T03: round by round, one address of each MX in preference order, IPv4 and IPv6 in turn within an MX;
    beyond 16, the addresses are listed, not tried (sample)."""
    probe, net, _ = measured(world(
        (f"a.{DOMAIN}", 10, ["192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::2", "2001:db8::3"],
         "tls_verified"),
        (f"b.{DOMAIN}", 20, ["192.0.2.11", "192.0.2.12"], "tls_verified"),
        (f"c.{DOMAIN}", 5, ["2001:db8::21"], "tls_verified")))
    order = [q.split()[1:3] for q in smtp_asked(net)]
    assert order == [[f"c.{DOMAIN}", "2001:db8::21"], [f"a.{DOMAIN}", "192.0.2.1"], [f"b.{DOMAIN}", "192.0.2.11"],
                     [f"a.{DOMAIN}", "2001:db8::1"], [f"b.{DOMAIN}", "192.0.2.12"], [f"a.{DOMAIN}", "192.0.2.2"],
                     [f"a.{DOMAIN}", "2001:db8::2"], [f"a.{DOMAIN}", "192.0.2.3"], [f"a.{DOMAIN}", "2001:db8::3"]]
    probe, net, _ = measured(world(*(dual(i, v4=4, v6=4) for i in range(3))))
    assert len(smtp_asked(net)) == 16
    assert sorted({(a.cause, a.reason) for a in probe.addresses if not a.observations}) == [("budget", "sample")]
    assert sum(not a.observations for a in probe.addresses) == 8


def test_beyond_8_mx_are_listed_and_never_resolved():
    """T03, F01: 8 MX at most, by preference; the others are kept in the evidence (sample), without a question."""
    probe, net, _ = measured(world(*(dual(i, v6=0) for i in range(10))))
    assert [m.name for m in probe.mx] == [f"mx{i}.{DOMAIN}" for i in range(10)]
    assert [(m.cause, m.reason) for m in probe.mx[8:]] == [("budget", "sample")] * 2
    assert not any(q.startswith(("dns mx8.", "dns mx9.")) for q in net.asked)
    assert len(smtp_asked(net)) == 8


# ------------------------------------------------------------------ discovery (F01, decision A)
def test_an_invalid_mx_name_is_kept_and_never_resolved():
    """Decision A, F01, S02: an MX published with an invalid name stays in the evidence, not testable
    (invalid_mx_name), never resolved nor contacted; the valid MX are probed."""
    data = world(dual(0))
    data["dns"][f"{DOMAIN} MX"] = ["5 bad_mx.example.org.", "10 mx0.example.org."]
    data["dns"]["bad_mx.example.org A"] = ["192.0.2.99"]
    probe, net, _ = measured(data)
    bad = probe.mx[0]
    assert (bad.name, bad.valid, bad.cause, bad.reason, bad.addresses) == ("bad_mx.example.org", False,
                                                                           "invalid_mx_name", "syntax", [])
    assert not any("bad_mx" in q for q in net.asked if not q.startswith(f"dns {DOMAIN}"))
    assert probe.exhaustivity()["mx_invalid"] == 1 and len(smtp_asked(net)) == 2


def test_an_mx_that_is_a_cname_is_reported_and_probed_under_its_published_name():
    """F01, F03: an MX that is an alias (RFC 2181 §10.3) is reported, and probed under the published name."""
    probe, net, _ = measured(world(dual(0, v6=0), extra={"dns": {f"mx0.{DOMAIN} CNAME": ["host.provider.example."]}}))
    assert probe.mx[0].cname == ("host.provider.example",)
    assert smtp_asked(net) == [f"smtp mx0.{DOMAIN} 192.0.2.0 verify"]


def test_null_mx_and_no_mx_are_told_apart():
    """F01: a null MX ("0 .") alone means no mail and nothing to probe; among other MX it is reported and the
    others probed; no MX at all, or a name that does not exist, is neither."""
    alone, net, _ = measured({"dns": {f"{DOMAIN} MX": ["0 ."]}})
    assert (alone.null_mx, alone.mx, smtp_asked(net)) == (True, [], [])
    mixed, net, _ = measured(world(dual(0, v6=0), extra={"dns": {f"{DOMAIN} MX": ["0 .", f"10 mx0.{DOMAIN}."]}}))
    assert mixed.null_mx and len(smtp_asked(net)) == 1
    for records in ([], None):
        none, net, _ = measured({"dns": {f"{DOMAIN} MX": records}})
        assert (none.null_mx, none.mx, none.discovery_error, smtp_asked(net)) == (False, [], "", [])


def test_a_failed_mx_question_leaves_nothing_known():
    """F01, T03: an MX question that fails is not "no MX": the error is kept, nothing is attempted."""
    probe, net, _ = measured({"dns": {f"{DOMAIN} MX": "timeout"}})
    assert probe.discovery_error and probe.mx == [] and smtp_asked(net) == []
    assert probe.exhaustivity()["discovery_complete"] is False


def test_duplicates_are_tried_once_at_their_best_preference():
    """F01: a name published twice is one MX, at its lowest preference."""
    data = world(dual(0, v6=0))
    data["dns"][f"{DOMAIN} MX"] = [f"30 mx0.{DOMAIN}.", f"10 MX0.{DOMAIN}.", f"20 mx0.{DOMAIN}"]
    probe, net, _ = measured(data)
    assert [(m.name, m.preference) for m in probe.mx] == [(f"mx0.{DOMAIN}", 10)] and len(smtp_asked(net)) == 1


def test_an_address_error_is_kept_per_family():
    """F01, T03: an AAAA question that fails leaves the MX's discovery incomplete; its IPv4 is still probed."""
    probe, net, _ = measured(world(dual(0, v6=0), extra={"dns": {f"mx0.{DOMAIN} AAAA": "timeout"}}))
    assert probe.mx[0].dns_errors and probe.mx[0].discovery_complete is False and len(smtp_asked(net)) == 1


# ------------------------------------------------------------------ when nothing is attempted (A1a, decision D)
def test_the_probe_off_discovers_and_attempts_nothing():
    """A1a, F01: with the probe off, the MX are discovered (passive DNS) and nothing is attempted."""
    probe, net, _ = measured(world(dual(0)), enabled=False)
    assert smtp_asked(net) == [] and probe.enabled is False
    assert {(a.cause, a.reason) for a in probe.addresses} == {("policy", "probe_off")}


def test_an_internal_scan_attempts_nothing():
    """Decision D, T03, S02: in an internal perimeter the MX are discovered and nothing is attempted."""
    probe, net, _ = measured(world(dual(0)), internal=True)
    assert smtp_asked(net) == [] and probe.internal is True
    assert {(a.cause, a.reason) for a in probe.addresses} == {("policy", "internal")}


# ------------------------------------------------------------------ observations (T03)
def test_no_route_for_ipv6_is_kept_as_such():
    """T03: an IPv6 address with no route from here is observed as no_route, the IPv4 one as it answered."""
    probe, _, _ = measured(world((f"mx0.{DOMAIN}", 10, ["192.0.2.1", "2001:db8::1"], None),
                                 extra={"smtp": {f"mx0.{DOMAIN}": {"192.0.2.1": "tls_verified",
                                                                   "2001:db8::1": "unreachable"}}}))
    ipv4, ipv6 = probe.mx[0].addresses
    assert ipv4.verification.dialogue.reason is Reason.TLS_VERIFIED
    assert (ipv6.verification.cause, ipv6.verification.reason) == ("network", "no_route")


def test_a_blocked_mx_costs_nothing_to_a_fast_one():
    """T03: with CHECK_TIMEOUT = 4, one MX answers at once and another never: the first is kept as observed, the
    second is marked deadline, and the probe returns at its deadline (2 s), well before the engine's 4 s."""
    probe, _, elapsed = measured(world(dual(0, "tls_verified", v6=0), dual(1, "hang", v6=0)), check_timeout=4)
    fast, blocked = probe.mx[0].addresses[0], probe.mx[1].addresses[0]
    assert fast.verification.dialogue.reason is Reason.TLS_VERIFIED
    assert (blocked.observations, blocked.cause, blocked.reason) == ([], "budget", "deadline")
    assert probe.deadline_reached and 2.0 <= elapsed < 2.0 + smtp_measure.SAFETY_SECONDS + 0.5 < 4


def test_observations_are_kept_when_the_probe_is_cut():
    """T03: what was observed before the deadline stays, address by address; nothing is lost to a timeout."""
    probe, _, _ = measured(world((f"mx0.{DOMAIN}", 10, ["192.0.2.1", "2001:db8::1"], None),
                                 extra={"smtp": {f"mx0.{DOMAIN}": {"192.0.2.1": "starttls_absent",
                                                                   "2001:db8::1": "hang"}}}), check_timeout=4)
    ipv4, ipv6 = probe.mx[0].addresses
    assert ipv4.verification.dialogue.reason is Reason.STARTTLS_ABSENT
    assert (ipv6.cause, ipv6.reason) == ("budget", "deadline")


def test_at_most_8_attempts_at_once_and_the_rest_marked_deadline():
    """R11, T03: 12 addresses that never answer: 8 at once, the 4 others wait; all are marked deadline."""
    probe, net, _ = measured(world((f"mx0.{DOMAIN}", 10, [f"192.0.2.{n}" for n in range(1, 13)], "hang")),
                             check_timeout=4)
    assert net.peak_connections == smtp_measure.CONNECTIONS == 8
    assert {(a.cause, a.reason) for a in probe.addresses} == {("budget", "deadline")}


def test_the_deadline_covers_the_dns_questions():
    """T03, F02: the deadline covers discovery too: a DNS question that never ends stops at the deadline, and
    nothing is attempted afterwards."""

    class SlowDns(FixtureNetwork):
        async def dns(self, name: str, rtype: str) -> DnsAnswer:
            if name.startswith("mx0.") and rtype == "AAAA":
                await asyncio.Event().wait()
            return await super().dns(name, rtype)

    net = SlowDns(world(dual(0)), domain=DOMAIN, ehlo_name=EHLO)
    start = time.monotonic()
    probe = asyncio.run(smtp_measure.measure(context(net, check_timeout=4)))
    assert probe.deadline_reached and smtp_asked(net) == [] and time.monotonic() - start < 2.5
    assert probe.mx[0].discovery_complete is False


def test_a_bug_in_one_attempt_does_not_stop_the_others():
    """Q02, T03: an unexpected error in one attempt is said as a bug of the probe (tool), never a fault of the
    server; the other attempts go on."""
    probe, _, _ = measured(world(dual(0, "nonsense", v6=0), dual(1, "tls_verified", v6=0)))
    broken, fine = probe.mx[0].addresses[0], probe.mx[1].addresses[0]
    assert broken.cause == "tool" and broken.reason.startswith("bug: ValueError")
    assert fine.verification.dialogue.reason is Reason.TLS_VERIFIED


def test_the_probe_is_shared_once_per_scan():
    """T03: the probe runs once per scan, whoever asks for it."""
    net = FixtureNetwork(world(dual(0)), domain=DOMAIN, ehlo_name=EHLO)
    ctx = context(net)

    async def twice():
        return await smtp_measure.result(ctx), await smtp_measure.result(ctx)

    first, second = asyncio.run(twice())
    assert first is second and len(smtp_asked(net)) == 2


def test_the_probe_decides_nothing():
    """F05 (one decision function, in the next step): the probe returns observations and never a status."""
    source = Path(smtp_measure.__file__).read_text(encoding="utf-8")
    assert "Status" not in source and "core.model" not in source and "Outcome" not in source


# ------------------------------------------------------------------ on the real network, through the engine (T03)
def test_a_real_blocked_mx_keeps_the_fast_one_and_returns_before_the_engine(tmp_path):
    """T03 (CHECK_TIMEOUT = 4, a fast MX and a blocked one), F02: on the real network, through the engine, the
    fast MX's verified dialogue is kept, the blocked one carries deadline with what it had sent, and the check
    returns before the engine's 4 s: no check.error.timeout."""
    pki = TestPki(tmp_path)
    fast_mx, slow_mx = f"mx1.{DOMAIN}", f"mx2.{DOMAIN}"
    extension = Extension("smtp_lab", name="SMTP lab", version="0")

    @extension.check("probe", category="mail", weight=1)
    async def probe_check(ctx: CheckContext):
        probe = await smtp_measure.result(ctx)
        return info("smtp_lab.done", {"probe": probe})

    async def main():
        zone = {DOMAIN: {"MX": [f"10 {fast_mx}.", f"20 {slow_mx}."]}, fast_mx: {"A": ["127.0.0.2"]},
                slow_mx: {"A": ["127.0.0.3"]}}
        async with dns_server(zone) as (_, dns_port), \
                smtp_server(Script(tls=pki.server_context(fast_mx)), "127.0.0.2") as (_, port), \
                smtp_server(Script(banner=(f"220-{slow_mx} ESMTP", SILENT)), "127.0.0.3", port):
            net = LabNetwork([LOOPBACK], timeout=2, dns_port=dns_port, smtp_port=port, pki=pki, domain=DOMAIN,
                             ehlo_name=EHLO)
            start = time.monotonic()
            result = await engine.scan(DOMAIN, extension.checks, net, timeout=4, smtp=SmtpSettings(True, EHLO))
            return result, time.monotonic() - start

    result, elapsed = asyncio.run(main())
    finding = result.findings[0]
    assert finding.outcome.status is Status.INFO and finding.outcome.summary == "smtp_lab.done"
    probe = finding.outcome.evidence["probe"]
    fast, slow = probe.mx[0].addresses[0].verification, probe.mx[1].addresses[0].verification
    assert fast.dialogue.reason is Reason.TLS_VERIFIED and fast.dialogue.certificate.trusted
    assert slow.dialogue.reason is Reason.DEADLINE and slow.dialogue.partial == (f"220-{slow_mx} ESMTP",)
    assert probe.deadline == 2.0 and probe.deadline_reached and elapsed < 4 - 1
    assert slow.purpose == SmtpPurpose.VERIFY
