# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Version 0.4: the HTTPS probe. T5 (addresses), T6 (confirmation), T11 (deadline), the exhaustivity
counters and the total refusal (six points, §2 and §6), obsolete TLS (§3), and the TLS guards.

Most tests use the recorded network, address by address; the last ones use the real network code
against servers started on this machine (nothing else is contacted)."""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
import struct
import time
import warnings
from ipaddress import ip_network
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from https_worlds import (
    DOMAIN,
    HANG,
    NO_OLD_TLS_HERE,
    NO_ROUTE,
    OBSOLETE,
    OK,
    POLICY,
    REFUSED,
    RESET,
    V4A,
    V4B,
    V4C,
    V4D,
    V4E,
    V4F,
    V6A,
    V6B,
    WWW,
    scan,
    site,
)
from local_servers import LOOPBACK, TestPki, dns_server, http_reply, http_server
from posture_cockpit.core import https_probe, scoring
from posture_cockpit.core.egress import DestinationBlocked, EgressPolicy
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.https_probe import Kind, ProbeResult
from posture_cockpit.core.model import Status
from posture_cockpit.core.network import LiveNetwork
from worlds import NOW

SRC = Path(__file__).parent.parent / "src" / "posture_cockpit"


def probe(data: dict, deadline: float | None = None) -> tuple[ProbeResult, FixtureNetwork]:
    net = FixtureNetwork(data, NOW)
    return asyncio.run(https_probe.run(net, DOMAIN, deadline=deadline)), net


def address(result: ProbeResult, value: str, host: str = DOMAIN) -> https_probe.AddressResult:
    return next(a for a in result.addresses if a.address == value and a.host == host)


def offers(result: ProbeResult, value: str) -> list[tuple[str, str]]:
    return [(t.offer, t.result) for t in address(result, value).attempts]


# ------------------------------------------------------------------ T5 addresses
def test_four_addresses_per_family_in_sorted_order_the_fifth_not_tested():
    v4 = ["192.0.2.30", "192.0.2.4", "192.0.2.200", "192.0.2.9", "192.0.2.17"]  # not sorted in the DNS
    v6 = ["2001:db8::50", "2001:db8::5", "2001:db8::a", "2001:db8::1", "2001:db8::ff"]
    data = site(dict.fromkeys(v4 + v6, OK))
    result, net = probe(data)
    tested = [a.address for a in result.addresses if a.launched]
    assert tested == ["192.0.2.4", "192.0.2.9", "192.0.2.17", "192.0.2.30",
                      "2001:db8::1", "2001:db8::5", "2001:db8::a", "2001:db8::50"]
    beyond = [a for a in result.addresses if not a.launched]
    assert [(a.address, a.kind, a.cause, a.reason) for a in beyond] == [
        ("192.0.2.200", Kind.UNTESTABLE, "tool", "sample"), ("2001:db8::ff", Kind.UNTESTABLE, "tool", "sample")]
    assert not any(c["address"] in ("192.0.2.200", "2001:db8::ff") for c in net.connections)


def test_every_connection_carries_the_audited_name():
    """SNI and Host: the name audited, whatever the address (the fixture logs both)."""
    _, net = probe(site({V4A: OK}, {V4B: OK}))
    assert {(c["host"], c["address"]) for c in net.connections} == {(DOMAIN, V4A), (WWW, V4B)}
    assert all(c["port"] in (80, 443) for c in net.connections)


def test_port_80_is_asked_on_every_address():
    _, net = probe(site({V4A: OK, V6A: OK}))
    assert sorted(c["address"] for c in net.connections if c["port"] == 80) == [V4A, V6A]


@pytest.mark.parametrize("world, deadline, counts", [
    # six points, §2: (discovered, attempted, conclusive)
    (lambda: site(dict.fromkeys((V4A, V4B, V4C, V4D, V4E, V4F), OK)), None, (6, 4, 4)),
    (lambda: site({V4A: OK, V6A: NO_ROUTE}), None, (2, 2, 1)),            # tried, no route: attempted
    (lambda: site({V4A: OK, V4B: POLICY}), None, (2, 1, 1)),              # refused by the rule: not attempted
    (lambda: site({V4A: OK, V4B: HANG}), 0.3, (2, 2, 1)),                 # interrupted: attempted, not conclusive
    (lambda: site({V4A: OK}, {V4A: OK}), None, (2, 2, 2)),                # one address, two names: twice
])
def test_the_exhaustivity_counts_name_address_pairs(world, deadline, counts):
    result, _ = probe(world(), deadline)
    e = result.exhaustivity()
    assert (e["discovered"], e["attempted"], e["conclusive"]) == counts


def test_a_sample_limit_never_says_every_address_was_evaluated():
    result, _ = probe(site(dict.fromkeys((V4A, V4B, V4C, V4D, V4E, V4F), OK)))
    assert result.exhaustivity()["sampling_limited"] and not result.complete
    root = scan(site(dict.fromkeys((V4A, V4B, V4C, V4D, V4E, V4F), OK))).root
    notes = {n["key"]: n["params"] for n in root.outcome.evidence["notes"]}
    assert notes["web.https_redirect.note.exhaustivity"] == {"discovered": 6, "attempted": 4, "conclusive": 4}
    assert notes["web.https_redirect.note.sample"]["count"] == 2


def test_a_failed_address_query_makes_the_discovery_incomplete():
    data = site({V4A: OK}, dns={f"{DOMAIN} AAAA": "timeout"})
    result, _ = probe(data)
    assert not result.exhaustivity()["discovery_complete"]
    assert result.hosts[0].situation == "available_incomplete"


# ------------------------------------------------------- six points, §6: total refusal
@pytest.mark.parametrize("addresses, dns, established", [
    ((V4A, V4B, V4C, V4D, V4E, V4F), {}, False),                  # 4 tested out of 6
    ((V4A, V4B, V4C, V4D), {}, True),                             # exactly 4, all tested
    ((V4A, V4B, V4C), {f"{DOMAIN} AAAA": "timeout"}, False),      # an address question failed
    ((V4A, V4B, V4C, V4D, V6A), {}, True),                        # the limit applies per family
    ((V4A, "2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4", "2001:db8::5"), {}, False),
])
def test_a_total_refusal_needs_every_published_address_tested(addresses, dns, established):
    data = site(dict.fromkeys(addresses, REFUSED), dns=dns)
    result = scan(data)
    a = result.assessment
    assert result.root.status is Status.FAIL
    if established:
        assert (a.blocked, a.cap_reasons, a.grade_withheld_reason) == (10, (scoring.CAP_DEPENDENCY,), None)
    else:
        assert (a.blocked, a.cap_reasons) == (0, ())
        assert a.grade_withheld_reason == scoring.WITHHELD_HTTPS_UNDETERMINED
        assert all(result.state(c) == "dependency" for c in ("tls.certificate", "web.hsts"))


def test_a_failed_address_question_is_said_as_such():
    root = scan(site(dict.fromkeys((V4A, V4B, V4C), REFUSED), dns={f"{DOMAIN} AAAA": "timeout"})).root
    assert root.outcome.summary == "web.https_redirect.refused_undetermined_discovery"
    assert root.outcome.params["tested"] == 3


def test_the_text_says_how_many_addresses_were_tested_out_of_how_many():
    root = scan(site(dict.fromkeys((V4A, V4B, V4C, V4D, V4E, V4F), REFUSED))).root
    assert root.outcome.summary == "web.https_redirect.refused_undetermined"
    assert {k: root.outcome.params[k] for k in ("tested", "published", "untested")} == \
        {"tested": 4, "published": 6, "untested": 2}


# ------------------------------------------------------------------ T6 confirmation
def test_three_tcp_refusals_confirm_without_trying_old_versions():
    result, _ = probe(site({V4A: REFUSED}))
    assert offers(result, V4A) == [("default", "refused"), ("TLSv1.3", "refused"), ("TLSv1.2", "refused")]
    assert address(result, V4A).kind is Kind.REFUSED


def test_a_refusal_at_the_tls_stage_tries_tls_1_1_then_1_0():
    result, _ = probe(site({V4A: RESET}))
    assert offers(result, V4A) == [("default", "reset"), ("TLSv1.3", "reset"), ("TLSv1.2", "reset"),
                                   ("TLSv1.1", "reset"), ("TLSv1", "reset")]
    assert address(result, V4A).kind is Kind.REFUSED


def test_a_refusal_then_an_answer_is_available_and_unstable():
    a = address(probe(site({V4A: {"443": ["reset", "ok"]}}))[0], V4A)
    assert (a.kind, a.instability, a.default_refused) == (Kind.AVAILABLE, True, False)


def test_a_refusal_then_no_answer_is_unknown():
    result, _ = probe(site({V4A: {"443": ["reset", "timeout"]}}))
    assert offers(result, V4A) == [("default", "reset"), ("TLSv1.3", "timeout")]
    assert (address(result, V4A).kind, address(result, V4A).cause) == (Kind.UNKNOWN, "network")


def test_a_timeout_is_never_tried_again():
    result, _ = probe(site({V4A: {"443": "timeout"}}))
    assert offers(result, V4A) == [("default", "timeout")]


def test_an_alert_then_tls_1_0_is_obsolete():
    a = address(probe(site({V4A: OBSOLETE}))[0], V4A)
    assert (a.kind, a.version, a.legacy) == (Kind.OBSOLETE, "TLSv1", {"TLSv1.1": False, "TLSv1": True})


def test_an_alert_without_old_versions_here_is_untestable_never_refused():
    a = address(probe(site({V4A: NO_OLD_TLS_HERE}))[0], V4A)
    assert (a.kind, a.cause, a.reason) == (Kind.UNTESTABLE, "tool", "legacy")
    assert scan(site({V4A: NO_OLD_TLS_HERE})).root.status is Status.ERROR


def test_old_versions_without_answer_are_unknown():
    data = site({V4A: {"versions": {"TLSv1.3": False, "TLSv1.2": False}, "443": {"TLSv1.1": "timeout"}}})
    result, _ = probe(data)
    assert offers(result, V4A)[-1] == ("TLSv1.1", "timeout")  # no TLS 1.0 attempt after no answer
    assert address(result, V4A).kind is Kind.UNKNOWN


def test_tls_1_2_and_1_0_accepted_is_available_and_protocols_critical():
    """Six points, §3: one success in TLS 1.2 or 1.3 excludes "obsolete only"."""
    data = site({V4A: {"versions": {"TLSv1": True}}})
    assert address(probe(data)[0], V4A).kind is Kind.AVAILABLE
    result = scan(data)
    assert (result.root.status, result.findings["tls.protocols"].status) == (Status.OK, Status.FAIL)
    assert result.assessment.cap_reasons == ()


def test_the_browser_offer_refused_and_tls_1_2_alone_accepted_is_available_with_a_mention():
    data = site({V4A: {"443": {"default": "alert:tlsv1_alert_protocol_version",
                               "TLSv1.3": "alert:tlsv1_alert_protocol_version"}, "versions": {"TLSv1.3": False}}})
    a = address(probe(data)[0], V4A)
    assert (a.kind, a.default_refused, a.instability) == (Kind.AVAILABLE, True, False)
    notes = [n["key"] for n in scan(data).root.outcome.evidence["notes"]]
    assert "web.https_redirect.note.default_offer" in notes


def test_tls_1_2_with_an_invalid_certificate_and_tls_1_0_is_available_with_the_authentication_cap():
    data = site({V4A: {"versions": {"TLSv1": True}, "certificate": {"expires_in_days": -3}}})
    a = address(probe(data)[0], V4A)
    assert a.kind is Kind.AVAILABLE and not a.certificate.trusted
    assert scan(data).assessment.cap_reasons == (scoring.CAP_AUTHENTICATION,)


def test_confirmation_attempts_are_at_least_one_second_apart(monkeypatch):
    monkeypatch.setattr(https_probe, "RETRY_PAUSE", 1.0)
    result, _ = probe(site({V4A: REFUSED}))
    times = [t.at for t in address(result, V4A).attempts]
    assert times[1] - times[0] >= 1.0 and times[2] - times[1] >= 1.0


# ------------------------------------------------------- obsolete TLS (plafond doc, §2)
def test_tls_1_0_only_is_measured_and_capped_by_the_protocol():
    """Perfect domain on TLS 1.0 only: 10 dependents measured, root and protocols critical, 79 B (84 B uncapped)."""
    result = scan(site({V4A: OBSOLETE}))
    a = result.assessment
    assert (a.score, a.grade, a.blocked, a.cap_reasons) == (79, "B", 0, (scoring.CAP_PROTOCOL,))
    assert round(100 * a.score_raw) == 84


def test_tls_1_0_only_with_an_expired_certificate_has_two_reasons_and_one_cap():
    """Two reasons shown, one value applied: the reference does not depend on why it applies. Here the
    expired certificate costs its 10 points: the raw score (72) is under the cap (79)."""
    alone = scan(site({V4A: OBSOLETE})).assessment
    both = scan(site({V4A: {**OBSOLETE, "certificate": {"expires_in_days": -3}}})).assessment
    assert both.cap_reasons == (scoring.CAP_AUTHENTICATION, scoring.CAP_PROTOCOL)
    assert both.score_cap == alone.score_cap and (both.score, alone.score) == (72, 79)


def test_tls_1_0_only_beside_a_silent_ipv6_is_undetermined_and_measured():
    result = scan(site({V4A: OBSOLETE, V6A: {"443": "timeout", "80": "timeout"}}))
    a = result.assessment
    assert (a.cap_reasons, a.blocked, a.grade) == ((), 0, None)
    assert a.grade_withheld_reason == scoring.WITHHELD_HTTPS_UNDETERMINED
    assert all(result.state(c) in ("ok", "warn", "fail") for c in ("tls.certificate", "web.hsts", "web.csp"))


def test_no_version_at_all_on_every_address_blocks_the_ten():
    result = scan(site({V4A: RESET}, {V4B: RESET}))
    assert (result.assessment.blocked, result.assessment.cap_reasons) == (10, (scoring.CAP_DEPENDENCY,))


# ------------------------------------------------------------------ T11 deadline
def test_the_probe_returns_at_its_deadline_with_every_connection_closed():
    """16 addresses that never answer: the probe stops at its deadline, 5 % allowed; every address is
    untestable for that reason, never refused; nothing stays open, no task is left, 8 at most at once."""
    v4 = (V4A, V4B, V4C, V4D)
    v6 = (V6A, V6B, "2001:db8::12", "2001:db8::13")
    silent = {**HANG, "80": "hang"}
    data = site({a: silent for a in v4 + v6}, {a: silent for a in v4 + v6})
    net = FixtureNetwork(data, NOW)

    async def main():
        clock = time.monotonic()
        result = await https_probe.run(net, DOMAIN, deadline=1.0)
        return result, time.monotonic() - clock, asyncio.all_tasks() - {asyncio.current_task()}

    result, seconds, left = asyncio.run(main())
    assert 1.0 <= seconds <= 1.05
    assert result.deadline_reached and len(result.addresses) == 16
    assert all((a.kind, a.cause) == (Kind.UNTESTABLE, "budget") for a in result.addresses)
    assert net.open_connections == 0 and net.peak_connections == https_probe.CONNECTIONS
    assert not left


def test_no_attempt_starts_after_the_deadline(monkeypatch):
    """Interrupted during the pause between two confirmation attempts."""
    monkeypatch.setattr(https_probe, "RETRY_PAUSE", 5.0)
    result, _ = probe(site({V4A: REFUSED}), deadline=0.3)
    a = address(result, V4A)
    assert offers(result, V4A) == [("default", "refused")]
    assert (a.kind, a.cause) == (Kind.UNTESTABLE, "budget")  # never refused on one attempt


def test_a_dependent_still_has_its_own_time_after_a_probe_at_its_deadline():
    """The scan takes the probe's deadline plus one check's time at most (24 s in production)."""
    data = site({V4A: {"http": {f"https://{DOMAIN}/.well-known/security.txt": "hang"}}, V4B: HANG})
    result = scan(data, deadline=0.3, timeout=0.6)
    assert result.seconds <= 0.3 + 0.6 + 0.2
    assert result.findings["web.security_txt"].outcome.summary == "check.error.timeout"
    assert result.findings["web.hsts"].status is Status.OK  # measured on the address that answered


def test_the_other_checks_do_not_wait_for_the_probe():
    """A mail check that takes nearly its whole time is not delayed by the probe running beside it."""
    from https_worlds import REGISTRY
    from posture_cockpit.core import Check, Outcome

    async def slow(ctx):
        await asyncio.sleep(0.5)
        return Outcome(Status.OK, "lab")

    check = Check("lab.slow", "mail", 1, slow, "lab")
    family = [c for c in REGISTRY.checks() if c.family is not None]
    result = scan(site({V4A: HANG}), deadline=0.3, timeout=0.6, checks=[check, *family])
    assert result.findings["lab.slow"].status is Status.OK


# ------------------------------------------------------------------ TLS guards
def _legacy(net: FixtureNetwork, addresses: set[str]) -> list[dict]:
    return [c for c in net.connections if c["legacy"] and c["address"] in addresses]


@pytest.mark.parametrize("world", [lambda: site({V4A: OK}), lambda: site({V4A: OK, V6A: OBSOLETE})])
def test_an_address_that_speaks_tls_1_2_only_sees_the_old_version_handshakes_of_tls_protocols(world):
    """Arbitrage, second precision: on an address that negotiated TLS 1.2 or 1.3, the only old-version
    connections are the handshakes of tls.protocols, one per version, closed at once: no page, no
    security.txt, no certificate read over an old version there."""
    result = scan(world())
    modern = {a for a in (V4A,)}
    legacy = _legacy(result.net, modern)
    assert sorted(c["offer"] for c in legacy) == ["TLSv1", "TLSv1.1"]
    assert all(c["kind"] == "tls" for c in legacy)
    if V6A in str(result.findings["tls.protocols"].outcome.evidence):
        assert any(c["kind"] == "http" for c in _legacy(result.net, {V6A}))  # the obsolete one is read


def test_only_one_module_builds_contexts_for_old_versions():
    """Arbitrage, first precision: security level 0 and TLS 1.0 / 1.1 contexts come from legacy_tls only."""
    users = sorted(str(path.relative_to(SRC)) for path in SRC.rglob("*.py")
                   if "SECLEVEL" in path.read_text() or "TLSVersion.TLSv1_1" in path.read_text()
                   or "TLSVersion.TLSv1," in path.read_text() or "TLSVersion.TLSv1}" in path.read_text())
    assert users == ["core/legacy_tls.py"]


# ------------------------------------------------------------- the real network
@pytest.fixture(autouse=True)
def no_proxy(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)


class LabNetwork(LiveNetwork):
    """The real network, with this machine's test servers standing for ports 443 and 80."""

    def __init__(self, dns_port: int, https_port: int, http_port: int, timeout: float = 2, trusted_ca: str = ""):
        policy = EgressPolicy(networks=(ip_network("127.0.0.1/32"),), ports=frozenset({https_port, http_port}),
                              name="lab")
        super().__init__([LOOPBACK], timeout, policy=policy, dns_port=dns_port, trusted_ca=trusted_ca)
        self.https_port, self.http_port = https_port, http_port

    async def tls_at(self, host, address, offer="default", *, port=443, verify=True):
        return await super().tls_at(host, address, offer, port=self.https_port if port == 443 else port,
                                    verify=verify)

    async def accepts_tls_at(self, host, address, version, *, port=443):
        return await super().accepts_tls_at(host, address, version, port=self.https_port)

    async def http_at(self, url, address, *, offer="default", cache=True):
        parts = urlsplit(url)
        port = self.https_port if parts.scheme == "https" else self.http_port
        return await super().http_at(parts._replace(netloc=f"{parts.hostname}:{port}").geturl(), address,
                                     offer=offer, cache=cache)


LAB = "lab.example"
ZONE = {LAB: {"A": [LOOPBACK]}, f"www.{LAB}": {}}


def _legacy_server_context(pki: TestPki) -> ssl.SSLContext | None:
    context = pki.server_context(LAB)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    return context


async def _probe_lab(https_handler, tls=None, deadline=None, trusted_ca=""):
    async with dns_server(ZONE) as (_, dns_port), \
            http_server(http_reply("301 Moved Permanently", {"Location": f"https://{LAB}/"})) as (_, http_port):
        server = await asyncio.start_server(https_handler, LOOPBACK, 0, ssl=tls)
        async with server:
            net = LabNetwork(dns_port, server.sockets[0].getsockname()[1], http_port, trusted_ca=trusted_ca)
            return await https_probe.run(net, LAB, deadline=deadline), net


async def _answer(reader, writer):
    with contextlib.suppress(Exception):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(http_reply("200 OK", {"Strict-Transport-Security": "max-age=31536000"}))
        await writer.drain()
    writer.close()


def test_real_network_available_address(tmp_path):
    pki = TestPki(tmp_path)
    result, _ = asyncio.run(_probe_lab(_answer, tls=pki.server_context(LAB), trusted_ca=pki.pem))
    a = result.hosts[0].addresses[0]
    assert (a.kind, a.certificate.trusted, a.page.status) == (Kind.AVAILABLE, True, 200)
    assert a.port80.reply.status == 301 and result.hosts[1].situation == "absent"


def test_real_network_reset_on_every_attempt_is_a_confirmed_refusal():
    async def reset(reader, writer):
        with contextlib.suppress(Exception):
            await reader.read(5)
        writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        writer.transport.abort()

    result, _ = asyncio.run(_probe_lab(reset))
    a = result.hosts[0].addresses[0]
    assert a.kind is Kind.REFUSED
    assert [t.offer for t in a.attempts] == ["default", "TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"]
    assert all(t.result == "reset" for t in a.attempts)


def test_real_network_tls_1_0_only_is_obsolete(tmp_path):
    pki = TestPki(tmp_path)
    context = _legacy_server_context(pki)
    if context is None:
        pytest.skip("this machine's TLS library cannot serve TLS 1.0")
    result, _ = asyncio.run(_probe_lab(_answer, tls=context, trusted_ca=pki.pem))
    a = result.hosts[0].addresses[0]
    if a.kind is Kind.UNTESTABLE and a.reason == "legacy":
        pytest.skip("this machine's TLS library cannot offer TLS 1.0")
    assert (a.kind, a.version, a.page.status) == (Kind.OBSOLETE, "TLSv1", 200)
    assert a.certificate.trusted  # verified with the legacy context, at security level 0


def test_real_network_the_deadline_closes_the_connection_on_the_server_side():
    """A server that accepts TCP and never answers in TLS: its socket is closed less than 1 s after
    the deadline (H5, T11)."""
    closed: list[float] = []

    async def silent(reader, writer):
        with contextlib.suppress(Exception):
            await reader.read()  # until the client goes away
        closed.append(time.monotonic())
        writer.close()

    async def main():
        start = time.monotonic()
        result, _ = await _probe_lab(silent, deadline=0.5)
        returned = time.monotonic()
        await asyncio.sleep(0.2)
        return result, start, returned

    result, start, returned = asyncio.run(main())
    assert returned - start <= 0.5 + 0.2
    assert closed and all(t - start <= 0.5 + 1.0 for t in closed)
    assert (result.hosts[0].addresses[0].kind, result.hosts[0].addresses[0].cause) == (Kind.UNTESTABLE, "budget")


def test_real_network_sni_and_host_are_the_audited_name(tmp_path):
    pki = TestPki(tmp_path)
    context = pki.server_context(LAB)
    names: list[str | None] = []
    context.sni_callback = lambda sock, name, ctx: names.append(name)
    heads: list[bytes] = []

    async def record(reader, writer):
        with contextlib.suppress(Exception):
            heads.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(http_reply("200 OK"))
            await writer.drain()
        writer.close()

    asyncio.run(_probe_lab(record, tls=context, trusted_ca=pki.pem))
    assert names and set(names) == {LAB}
    assert heads and all(f"host: {LAB}:".encode() in h.lower() for h in heads)


def test_real_network_old_version_requests_carry_nothing_but_the_essentials(tmp_path):
    """Arbitrage, first precision: no cookie, no credentials, no body over an old version."""
    pki = TestPki(tmp_path)
    context = _legacy_server_context(pki)
    if context is None:
        pytest.skip("this machine's TLS library cannot serve TLS 1.0")
    heads: list[str] = []

    async def record(reader, writer):
        with contextlib.suppress(Exception):
            heads.append((await reader.readuntil(b"\r\n\r\n")).decode("latin-1"))
            writer.write(http_reply("200 OK"))
            await writer.drain()
        writer.close()

    async def main():
        server = await asyncio.start_server(record, LOOPBACK, 0, ssl=context)
        async with server:
            port = server.sockets[0].getsockname()[1]
            policy = EgressPolicy(networks=(ip_network("127.0.0.1/32"),), ports=frozenset({port}), name="lab")
            net = LiveNetwork([LOOPBACK], 2, policy=policy)
            return await net.http_at(f"https://{LAB}:{port}/", LOOPBACK, offer="TLSv1")

    try:
        reply = asyncio.run(main())
    except Exception as e:
        if "cannot offer" in str(e):
            pytest.skip("this machine's TLS library cannot offer TLS 1.0")
        raise
    assert reply.status == 200
    lines = heads[0].split("\r\n")
    assert lines[0] == "GET / HTTP/1.1"
    assert sorted(line.split(":")[0].lower() for line in lines[1:] if line) == \
        ["accept", "connection", "host", "user-agent"]


def test_real_network_the_rule_is_checked_before_an_old_version_connection():
    async def main():
        count = 0

        async def handle(reader, writer):
            nonlocal count
            count += 1
            writer.close()

        server = await asyncio.start_server(handle, LOOPBACK, 0)
        async with server:
            port = server.sockets[0].getsockname()[1]
            net = LiveNetwork([LOOPBACK], 2)  # the Internet rule: the loopback is refused
            with pytest.raises(DestinationBlocked):
                await net.tls_at(LAB, LOOPBACK, "TLSv1", port=port)
            with pytest.raises(DestinationBlocked):
                await net.http_at(f"https://{LAB}:{port}/", LOOPBACK, offer="TLSv1")
        return count

    assert asyncio.run(main()) == 0


def test_real_network_an_address_without_route_is_untestable():
    """No IPv6 on this machine: the address could not be tested from here (cause tool), never refused."""
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()
        pytest.skip("this machine has IPv6: the case needs a machine without it")
    except OSError:
        pass
    policy = EgressPolicy(networks=(ip_network("fd00::/8"),), ports=frozenset({443}), name="lab")
    net = LiveNetwork([LOOPBACK], 2, policy=policy)
    from posture_cockpit.core.errors import Unreachable

    with pytest.raises(Unreachable):
        asyncio.run(net.tls_at(LAB, "fd00::1", "default"))
