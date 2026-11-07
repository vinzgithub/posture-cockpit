# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The SMTP attempt of the network layer: where it may go, and nowhere else (version 0.7, T04).

Every test runs on this machine: a DNS server and fake SMTP servers on the loopback
address. Two ways prove that nothing was opened:

- with the production network (:class:`LiveNetwork`, port 25 of public addresses), the
  socket module of core/network.py is replaced by one that fails the test if a socket
  is made: a refusal must happen before;
- with :class:`~smtp_lab.LabNetwork`, which may reach the loopback, the fake servers
  count their connections: zero, although the rule would let them through, proves the
  refusal comes from the other conditions (published MX, cache, budget…).

Each docstring names the requirement it covers: specification 0.7 revision 3 (T04, S01,
S02, S05, F01, F03) and the decisions of the review of PR-B2 (A to E).
"""

import ast
import asyncio
import contextlib
import errno
import inspect
import re
import socket
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest

import posture_cockpit
from local_servers import LOOPBACK, TestPki, dns_server
from posture_cockpit.config import Config
from posture_cockpit.core import network, smtp
from posture_cockpit.core.egress import SMTP_EGRESS, SMTP_PORT, DestinationBlocked, EgressPolicy
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.network import Limits, LiveNetwork, SmtpObservation, SmtpPurpose
from posture_cockpit.core.registry import Registry
from posture_cockpit.scanner import DEMO_DOMAIN, Scanner
from posture_cockpit.storage.perimeters import Perimeter
from smtp_lab import LabNetwork
from smtp_servers import Script, ehlo, smtp_server

DOMAIN = "lab.example"
MX = "mx.lab.example"
EHLO = "probe.example.org"
SRC = Path(posture_cockpit.__file__).parent
QUICK = Script(ehlo=ehlo("PIPELINING"))  # a nominal dialogue that stops at EHLO: STARTTLS absent
HOOKS = ("_smtp_policy", "_smtp_port", "_smtp_tls_context")


# ------------------------------------------------------------------ helpers
class NoSocket:
    """Stands in for the socket module of core/network.py: making a socket fails the test."""

    AF_INET, AF_INET6, SOCK_STREAM = socket.AF_INET, socket.AF_INET6, socket.SOCK_STREAM

    @staticmethod
    def socket(*_args):
        raise AssertionError("an SMTP socket was opened")


@pytest.fixture
def no_socket(monkeypatch):
    monkeypatch.setattr(network, "socket", NoSocket)


def zone(*addresses: str, name: str = MX, mx: tuple[str, ...] = (f"10 {MX}.",)) -> dict:
    """The audited domain publishing ``mx``, and ``name`` with these addresses."""
    records: dict[str, list[str]] = {}
    for address in addresses:
        records.setdefault("A" if ip_address(address).version == 4 else "AAAA", []).append(address)
    return {DOMAIN: {"MX": list(mx)}, name: records}


def live(dns_port: int, **options) -> LiveNetwork:
    return LiveNetwork([LOOPBACK], timeout=2, dns_port=dns_port, domain=DOMAIN, ehlo_name=EHLO, **options)


def lab(dns_port: int, smtp_port: int, **options) -> LabNetwork:
    return LabNetwork([LOOPBACK], timeout=2, dns_port=dns_port, smtp_port=smtp_port, domain=DOMAIN, ehlo_name=EHLO,
                      **options)


async def discovered(net: LiveNetwork, *names: str) -> None:
    """What the probe's discovery asks first: the domain's MX, then the A and AAAA of each name."""
    await asyncio.gather(net.dns(DOMAIN, "MX"), return_exceptions=True)
    for name in names:
        await asyncio.gather(net.dns(name, "A"), net.dns(name, "AAAA"), return_exceptions=True)


def soon(seconds: float = 10.0) -> float:
    return asyncio.get_running_loop().time() + seconds


def refused(observation: SmtpObservation, cause: str, reason: str) -> None:
    assert (observation.cause, observation.reason) == (cause, reason), observation
    assert observation.dialogue is None and observation.socket is False


# ------------------------------------------------------------------ the rule (S01)
PRIVATE = ["127.0.0.1", "10.0.0.25", "172.16.0.25", "192.168.0.25", "100.64.0.25", "192.0.2.25", "198.18.0.25",
           "::1", "fd00::25", "2001:db8::25", "2001::25", "::ffff:127.0.0.1", "::ffff:10.0.0.25"]
FORBIDDEN = ["0.0.0.0", "169.254.169.254", "169.254.0.25", "224.0.0.25", "240.0.0.25", "255.255.255.255",
             "100.100.100.200", "168.63.129.16", "fe80::25", "ff02::25", "fd00:ec2::254", "::ffff:169.254.169.254",
             "64:ff9b::a00:19", "64:ff9b::7f00:1", "2002:a00:19::"]


REFUSED = [(a, "private") for a in PRIVATE] + [(a, "forbidden") for a in FORBIDDEN]


@pytest.mark.parametrize(("address", "reason"), REFUSED)
def test_smtp_egress_refuses_every_address_that_is_not_public(address, reason):
    """S01, T04: private, loopback, CGNAT, documentation, link-local, cloud metadata, multicast, reserved,
    IPv6 ULA and link-local, IPv4-mapped and NAT64 or 6to4 translations of those: never port 25 of them."""
    with pytest.raises(DestinationBlocked) as caught:
        SMTP_EGRESS.check(MX, ip_address(address), SMTP_PORT)
    assert caught.value.reason == reason


def test_smtp_egress_is_public_addresses_on_port_25_only():
    """S01, T04: public IPv4 and IPv6 (a NAT64 translation of a public address too) on port 25, nothing else."""
    assert (SMTP_EGRESS.networks, SMTP_EGRESS.ports, SMTP_EGRESS.internal) == ((), frozenset({25}), False)
    for address in ("8.8.8.8", "2001:4860:4860::8888", "64:ff9b::808:808"):
        SMTP_EGRESS.check(MX, ip_address(address), 25)
    for port in (587, 465, 2525, 80, 443):
        with pytest.raises(DestinationBlocked) as caught:
            SMTP_EGRESS.check(MX, ip_address("8.8.8.8"), port)
        assert caught.value.reason == "port"


@pytest.mark.parametrize(("address", "reason"), [
    ("127.0.0.1", "private"), ("10.0.0.25", "private"), ("100.64.0.25", "private"), ("169.254.169.254", "forbidden"),
    ("224.0.0.25", "forbidden"), ("240.0.0.25", "forbidden"), ("::1", "private"), ("fd00::25", "private"),
    ("fe80::25", "forbidden"), ("::ffff:127.0.0.1", "private"), ("64:ff9b::a00:19", "forbidden"),
    ("fd00:ec2::254", "forbidden"),
])
def test_a_published_address_the_rule_refuses_opens_no_socket(no_socket, address, reason):
    """S01, S02, T04: an MX of the domain that resolves inside, to metadata or to a translation of them is
    published and in this scan's DNS, and still never contacted: the rule refuses it before any socket."""

    async def main() -> SmtpObservation:
        async with dns_server(zone(address)) as (_, dns_port):
            net = live(dns_port)
            await discovered(net, MX)
            return await net.smtp_attempt(MX, address, deadline=soon())

    refused(asyncio.run(main()), "policy", reason)


def test_a_port_other_than_25_is_refused_by_the_rule_itself(no_socket):
    """S01, T04: even a network whose port method were changed reaches no other port: the rule says 25 only."""

    class OtherPort(LiveNetwork):  # test only: nothing in src/ may do this (see the isolation tests)
        def _smtp_port(self) -> int:
            return 587

    async def main() -> SmtpObservation:
        async with dns_server(zone("8.8.8.8")) as (_, dns_port):
            net = OtherPort([LOOPBACK], timeout=2, dns_port=dns_port, domain=DOMAIN, ehlo_name=EHLO)
            await discovered(net, MX)
            return await net.smtp_attempt(MX, "8.8.8.8", deadline=soon())

    refused(asyncio.run(main()), "policy", "port")


def test_no_ipv6_on_this_machine_is_no_route(monkeypatch):
    """T03, T04: a machine that cannot make an IPv6 socket: the address is not testable from here (no_route),
    never a fault of the server."""

    class NoIpv6(NoSocket):
        @staticmethod
        def socket(*_args):
            raise OSError(errno.EAFNOSUPPORT, "Address family not supported by protocol")

    monkeypatch.setattr(network, "socket", NoIpv6)

    async def main() -> SmtpObservation:
        async with dns_server(zone("2001:4860:4860::8888")) as (_, dns_port):
            net = live(dns_port)
            await discovered(net, MX)
            return await net.smtp_attempt(MX, "2001:4860:4860::8888", deadline=soon())

    observation = asyncio.run(main())
    assert (observation.cause, observation.reason, observation.socket) == ("network", "no_route", False)


# ------------------------------------------------------- what the attempt is bound to (S02, decisions A, D, E)
@contextlib.asynccontextmanager
async def lab_servers(*hosts: str, script: Script = QUICK):
    """Fake SMTP servers on these loopback addresses, all on one port; yields (records, port)."""
    async with contextlib.AsyncExitStack() as stack:
        record, port = await stack.enter_async_context(smtp_server(script, hosts[0]))
        records = [record]
        for host in hosts[1:]:
            other, _ = await stack.enter_async_context(smtp_server(script, host, port))
            records.append(other)
        yield records, port


def test_an_mx_the_domain_does_not_publish_opens_no_socket():
    """S02, T04: a name the audited domain does not publish as MX, or an MX of another domain, is refused,
    although the rule would let the address through and the name resolves in this scan."""

    async def main() -> tuple[list[SmtpObservation], int]:
        records = zone("127.0.0.2") | {"other.lab.example": {"A": ["127.0.0.2"]},
                                       "evil.example": {"MX": ["10 mx.evil.example."]},
                                       "mx.evil.example": {"A": ["127.0.0.2"]}}
        async with dns_server(records) as (_, dns_port), lab_servers("127.0.0.2") as (servers, port):
            net = lab(dns_port, port)
            await discovered(net, MX, "other.lab.example", "mx.evil.example")
            await net.dns("evil.example", "MX")
            observations = [await net.smtp_attempt(name, "127.0.0.2", deadline=soon())
                            for name in ("other.lab.example", "mx.evil.example", "lab.example")]
        return observations, servers[0].connections

    observations, connections = asyncio.run(main())
    for observation in observations:
        refused(observation, "policy", "not_published")
    assert connections == 0


@pytest.mark.parametrize("name", ["bad_mx.lab.example", "-mx.lab.example", "localhost", "192.0.2.25",
                                  r"mx\032space.lab.example", r"mx\013\010rcpt.lab.example"])
def test_an_invalid_mx_name_opens_no_socket(name):
    """Decision A, S02, T04: an MX published with an invalid name, as the DNS gives it in text (dnspython writes
    a space or a CR LF inside a label as \\032 or \\013\\010), is refused (invalid_mx_name) before the question
    of whether it is published, before any socket; nothing is resolved for it."""

    async def main() -> tuple[SmtpObservation, int, int]:
        records = {DOMAIN: {"MX": [f"10 {name}."]}}
        async with dns_server(records) as (dns, dns_port), lab_servers("127.0.0.2") as (servers, port):
            net = lab(dns_port, port)
            await net.dns(DOMAIN, "MX")
            observation = await net.smtp_attempt(name, "127.0.0.2", deadline=soon())
            asked = sum(count for (_, rtype), count in dns.questions.items() if rtype in ("A", "AAAA"))
        return observation, asked, servers[0].connections

    observation, asked, connections = asyncio.run(main())
    refused(observation, "invalid_mx_name", "syntax")
    assert (asked, connections) == (0, 0)


@pytest.mark.parametrize("name", ["mx..lab.example", "mx.lab.example\r\nRCPT TO:<a@b.example>", " mx.lab.example",
                                  "mx.lab.example\x00", "mx.exämple.example", ""])
def test_names_no_dns_answer_can_carry_are_refused_too(name):
    """Decision A, S04: an empty label, CR LF, a space, NUL, a non-ASCII or empty name cannot come out of a DNS
    answer in text, but the attempt refuses them as well, whoever calls it (recorded world: same refusals)."""

    async def main() -> tuple[SmtpObservation, list]:
        world = {"dns": {f"{DOMAIN} MX": [f"10 {name}."], f"{name} A": ["192.0.2.25"]},
                 "smtp": {name: {"192.0.2.25": "tls_verified"}}}
        net = FixtureNetwork(world, domain=DOMAIN, ehlo_name=EHLO)
        return await net.smtp_attempt(name, "192.0.2.25", deadline=soon()), net.connections

    observation, connections = asyncio.run(main())
    refused(observation, "invalid_mx_name", "syntax")
    assert connections == []


def test_an_address_not_in_this_scans_dns_opens_no_socket():
    """Decision E, S02, T04: only an address this scan's DNS gave for that MX; a question not answered yet,
    or never asked, refuses the attempt (nothing is resolved here); no connection by default."""

    async def main() -> tuple[list[SmtpObservation], int, int]:
        async with dns_server(zone("127.0.0.2")) as (_, dns_port), \
                lab_servers("127.0.0.2", "127.0.0.3") as (servers, port):
            net = lab(dns_port, port)
            before_mx = await net.smtp_attempt(MX, "127.0.0.2", deadline=soon())
            await net.dns(DOMAIN, "MX")
            before_a = await net.smtp_attempt(MX, "127.0.0.2", deadline=soon())
            await discovered(net, MX)
            other = await net.smtp_attempt(MX, "127.0.0.3", deadline=soon())
            not_an_address = await net.smtp_attempt(MX, MX, deadline=soon())
        return [before_mx, before_a, other, not_an_address], servers[0].connections, servers[1].connections

    (before_mx, before_a, other, not_an_address), first, second = asyncio.run(main())
    refused(before_mx, "policy", "not_in_cache")
    refused(before_a, "policy", "not_in_cache")
    refused(other, "policy", "not_published")
    refused(not_an_address, "policy", "not_an_address")
    assert (first, second) == (0, 0)


def test_a_dns_question_that_failed_refuses_the_attempt(no_socket):
    """Decision E, T04: when this scan's DNS gave no answer (the question failed), nothing is known, and the
    attempt is refused rather than resolved again."""

    async def main() -> SmtpObservation:
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind((LOOPBACK, 0))  # a DNS server that never answers
        try:
            net = LiveNetwork([LOOPBACK], timeout=0.3, dns_port=silent.getsockname()[1], domain=DOMAIN,
                              ehlo_name=EHLO)
            await discovered(net, MX)
            return await net.smtp_attempt(MX, "8.8.8.8", deadline=soon())
        finally:
            silent.close()

    refused(asyncio.run(main()), "policy", "not_in_cache")


def test_dns_rebinding_cannot_move_an_attempt():
    """Decision E, T04 (rebinding): the MX resolves to one address at discovery and to another afterwards; the
    attempt goes to the first, the second is refused, and the name is never resolved again."""

    def first_then_other(asked: int) -> list[str]:
        return ["127.0.0.2"] if asked == 1 else ["127.0.0.3"]

    async def main():
        records = {DOMAIN: {"MX": [f"10 {MX}."]}, MX: {"A": first_then_other}}
        async with dns_server(records) as (dns, dns_port), \
                lab_servers("127.0.0.2", "127.0.0.3") as (servers, port):
            net = lab(dns_port, port)
            await discovered(net, MX)
            first = await net.smtp_attempt(MX, "127.0.0.2", deadline=soon())
            second = await net.smtp_attempt(MX, "127.0.0.3", deadline=soon())
            questions = dns.questions[(MX, "A")]
        return first, second, questions, servers[0].connections, servers[1].connections

    first, second, questions, connections_first, connections_second = asyncio.run(main())
    assert first.dialogue is not None and first.dialogue.reason is smtp.Reason.STARTTLS_ABSENT
    refused(second, "policy", "not_published")
    assert (questions, connections_first, connections_second) == (1, 1, 0)


def test_an_internal_perimeter_never_probes():
    """Decision D, T04: the SMTP probe never runs in an internal audit: said by the scanner (internal=True), or
    shown by the scan's rule, even when that rule would allow the address and the port."""

    async def main() -> tuple[list[SmtpObservation], int]:
        async with dns_server(zone("127.0.0.2")) as (_, dns_port), lab_servers("127.0.0.2") as (servers, port):
            said = lab(dns_port, port, internal=True)
            rule = EgressPolicy(networks=(ip_network("127.0.0.0/8"),), ports=frozenset({port, 25}), name="lab")
            shown = lab(dns_port, port, policy=rule)
            for net in (said, shown):
                await discovered(net, MX)
            observations = [await net.smtp_attempt(MX, "127.0.0.2", deadline=soon()) for net in (said, shown)]
        return observations, servers[0].connections

    observations, connections = asyncio.run(main())
    for observation in observations:
        refused(observation, "policy", "internal")
    assert connections == 0


def test_without_an_audited_domain_or_an_ehlo_name_nothing_goes(no_socket):
    """S02, S04, F02 bis: a network bound to no domain, or without the EHLO name (the probe is off), refuses."""

    async def main() -> list[SmtpObservation]:
        async with dns_server(zone("8.8.8.8")) as (_, dns_port):
            unbound = LiveNetwork([LOOPBACK], timeout=2, dns_port=dns_port, ehlo_name=EHLO)
            off = LiveNetwork([LOOPBACK], timeout=2, dns_port=dns_port, domain=DOMAIN)
            odd = live(dns_port)
            return [await unbound.smtp_attempt(MX, "8.8.8.8", deadline=soon()),
                    await off.smtp_attempt(MX, "8.8.8.8", deadline=soon()),
                    await odd.smtp_attempt(MX, "8.8.8.8", "deliver", deadline=soon())]

    unbound, off, odd = asyncio.run(main())
    refused(unbound, "policy", "not_bound")
    refused(off, "policy", "not_configured")
    refused(odd, "policy", "purpose")


# ------------------------------------------------------------------ budget and time (T03, T04, decision C)
def test_the_budget_is_16_attempts_per_scan():
    """T03, T04: 16 SMTP attempts per scan, then a refusal before any socket (budget)."""

    async def main() -> tuple[list[SmtpObservation], int]:
        async with dns_server(zone("127.0.0.2")) as (_, dns_port), lab_servers("127.0.0.2") as (servers, port):
            net = lab(dns_port, port)
            await discovered(net, MX)
            observations = [await net.smtp_attempt(MX, "127.0.0.2", deadline=soon()) for _ in range(17)]
        return observations, servers[0].connections

    observations, connections = asyncio.run(main())
    assert all(o.dialogue is not None for o in observations[:16]) and Limits().smtp_attempts == 16
    refused(observations[16], "budget", "attempts")
    assert connections == 16


def test_a_certificate_reading_needs_a_refused_certificate_and_happens_once_per_mx(tmp_path):
    """Decision C, F03, T04: a reading only after a real verification failure on that address, once per MX,
    counted in the 16; it reads the certificate and never claims trust."""

    async def main():
        (tmp_path / "lab").mkdir()
        (tmp_path / "other").mkdir()
        pki, other = TestPki(tmp_path / "lab"), TestPki(tmp_path / "other", "Other CA")
        records = zone("127.0.0.2", "127.0.0.3")
        async with dns_server(records) as (_, dns_port), \
                smtp_server(Script(tls=other.server_context(MX)), "127.0.0.2") as (refusing, port), \
                smtp_server(Script(tls=pki.server_context(MX)), "127.0.0.3", port) as (valid, _):
            net = lab(dns_port, port, pki=pki)
            await discovered(net, MX)
            read = SmtpPurpose.READ_CERTIFICATE
            too_early = await net.smtp_attempt(MX, "127.0.0.2", read, deadline=soon())
            verify = await net.smtp_attempt(MX, "127.0.0.2", deadline=soon())
            elsewhere = await net.smtp_attempt(MX, "127.0.0.3", read, deadline=soon())
            reading = await net.smtp_attempt(MX, "127.0.0.2", read, deadline=soon())
            again = await net.smtp_attempt(MX, "127.0.0.2", read, deadline=soon())
            spent = net._smtp_budget.spent
        return too_early, verify, elsewhere, reading, again, refusing.connections, valid.connections, spent

    too_early, verify, elsewhere, reading, again, refusing, valid, spent = asyncio.run(main())
    refused(too_early, "budget", "diagnostic_not_allowed")
    assert verify.dialogue is not None and verify.dialogue.reason is smtp.Reason.CERTIFICATE_REFUSED
    refused(elsewhere, "budget", "diagnostic_not_allowed")
    assert reading.dialogue is not None and reading.dialogue.reason is smtp.Reason.TLS_UNVERIFIED
    assert reading.dialogue.certificate is not None and not reading.dialogue.certificate.trusted
    assert reading.dialogue.certificate.issuer == "Other CA"
    refused(again, "budget", "diagnostic_used")
    assert (refusing, valid, spent) == (2, 0, 2)


def test_the_deadline_is_never_extended():
    """T03, R11, F02: no attempt after the deadline, none that outlasts it: a silent server is left at the
    deadline, with what was read."""

    async def main():
        async with dns_server(zone("127.0.0.2")) as (_, dns_port), \
                lab_servers("127.0.0.2", script=Script(banner=("220-mx.lab.example", 30.0, "220 late"))) as (
                    servers, port):
            net = lab(dns_port, port)
            await discovered(net, MX)
            late = await net.smtp_attempt(MX, "127.0.0.2", deadline=soon(-1))
            loop = asyncio.get_running_loop()
            start = loop.time()
            cut = await net.smtp_attempt(MX, "127.0.0.2", deadline=soon(0.5))
            elapsed = loop.time() - start
        return late, cut, elapsed, servers[0].connections

    late, cut, elapsed, connections = asyncio.run(main())
    refused(late, "budget", "deadline")
    assert cut.dialogue is not None and cut.dialogue.reason is smtp.Reason.DEADLINE
    assert cut.dialogue.partial == ("220-mx.lab.example",) and elapsed < 1.0 and connections == 1


def blocked_hand_over(monkeypatch) -> list[socket.socket]:
    """asyncio.open_connection(sock=...) never returns: the socket is connected, never handed over."""
    handed: list[socket.socket] = []

    async def never(*_args, sock: socket.socket, **_options):
        handed.append(sock)
        await asyncio.Event().wait()

    monkeypatch.setattr(asyncio, "open_connection", never)
    return handed


def test_a_socket_hand_over_that_blocks_ends_at_the_deadline(monkeypatch):
    """R1 of the review of PR-B2, R11, F02: the TCP connection and the hand-over of the socket to asyncio share one
    absolute limit. A hand-over that never ends stops at the deadline (budget, deadline), not later; the attempt
    stays counted; the socket is closed."""
    handed = blocked_hand_over(monkeypatch)

    async def main():
        async with dns_server(zone("127.0.0.2")) as (_, dns_port), lab_servers("127.0.0.2") as (servers, port):
            net = lab(dns_port, port)
            await discovered(net, MX)
            loop = asyncio.get_running_loop()
            start = loop.time()
            observation = await net.smtp_attempt(MX, "127.0.0.2", deadline=soon(0.5))
            elapsed = loop.time() - start
        return observation, elapsed, net._smtp_budget.spent, servers[0].connections

    observation, elapsed, spent, connections = asyncio.run(main())
    assert (observation.cause, observation.reason, observation.socket) == ("budget", "deadline", True)
    assert observation.dialogue is None and 0.4 < elapsed < 0.8
    assert (spent, connections) == (1, 1)  # counted, and the TCP connection had been made
    assert handed and handed[0].fileno() == -1  # closed


def test_a_socket_hand_over_that_blocks_ends_at_the_connection_limit(monkeypatch):
    """R1 of the review of PR-B2, R11: with time left before the deadline, the connection's own limit ends it,
    observed as a network timeout; the socket is closed."""
    handed = blocked_hand_over(monkeypatch)
    monkeypatch.setattr(network, "SMTP_CONNECT_SECONDS", 0.3)

    async def main():
        async with dns_server(zone("127.0.0.2")) as (_, dns_port), lab_servers("127.0.0.2") as (_, port):
            net = lab(dns_port, port)
            await discovered(net, MX)
            return await net.smtp_attempt(MX, "127.0.0.2", deadline=soon(10))

    observation = asyncio.run(main())
    assert (observation.cause, observation.reason, observation.socket) == ("network", "timeout", True)
    assert handed[0].fileno() == -1


def test_a_cancelled_hand_over_closes_the_socket(monkeypatch):
    """R1 of the review of PR-B2: an attempt cancelled while its socket is being handed over closes the socket,
    and the cancellation goes on."""
    handed = blocked_hand_over(monkeypatch)

    async def main() -> bool:
        async with dns_server(zone("127.0.0.2")) as (_, dns_port), lab_servers("127.0.0.2") as (_, port):
            net = lab(dns_port, port)
            await discovered(net, MX)
            task = asyncio.create_task(net.smtp_attempt(MX, "127.0.0.2", deadline=soon(10)))
            while not handed:
                await asyncio.sleep(0.01)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                return True
        return False

    assert asyncio.run(main()) and handed[0].fileno() == -1


def test_a_closed_port_is_a_network_observation():
    """T03, T04: a port that refuses the connection is observed as such (network, refused), socket opened."""

    async def main() -> SmtpObservation:
        async with dns_server(zone("127.0.0.2")) as (_, dns_port), lab_servers("127.0.0.3") as (_, port):
            net = lab(dns_port, port)  # nothing listens on 127.0.0.2
            await discovered(net, MX)
            return await net.smtp_attempt(MX, "127.0.0.2", deadline=soon())

    observation = asyncio.run(main())
    assert (observation.cause, observation.reason, observation.socket) == ("network", "refused", True)


def test_at_most_8_smtp_connections_at_once_per_scan():
    """R11, T03: whoever asks, one scan never has more than 8 SMTP connections open at once."""

    async def main() -> tuple[list[SmtpObservation], int]:
        slow = Script(banner=("220-mx.lab.example", 0.3, "220 ready"), ehlo=ehlo("PIPELINING"))
        async with dns_server(zone("127.0.0.2")) as (_, dns_port), lab_servers("127.0.0.2", script=slow) as (
                servers, port):
            net = lab(dns_port, port)
            await discovered(net, MX)
            observations = await asyncio.gather(*(net.smtp_attempt(MX, "127.0.0.2", deadline=soon())
                                                  for _ in range(12)))
        return list(observations), servers[0].peak

    observations, peak = asyncio.run(main())
    assert all(o.dialogue is not None for o in observations) and peak == network.SMTP_CONNECTIONS == 8


def test_concurrent_scans_have_independent_budgets():
    """T04, R11: the budget belongs to one scan's network: a scan that spent its 16 attempts leaves another
    scan's untouched; and SMTP attempts spend nothing of the HTTPS counts, nor they of it."""

    async def main():
        async with dns_server(zone("127.0.0.2")) as (_, dns_port), lab_servers("127.0.0.2") as (_, port):
            spent, other = lab(dns_port, port), lab(dns_port, port, limits=Limits(connections=0, probe_connections=0))
            await discovered(spent, MX)
            await discovered(other, MX)
            first = await asyncio.gather(*(spent.smtp_attempt(MX, "127.0.0.2", deadline=soon()) for _ in range(17)))
            second = await other.smtp_attempt(MX, "127.0.0.2", deadline=soon())
        return list(first), second, dict(spent._spent), dict(other._spent)

    first, second, counts, other_counts = asyncio.run(main())
    assert sum(o.dialogue is not None for o in first) == 16 and sum(o.reason == "attempts" for o in first) == 1
    assert second.dialogue is not None  # its own 16, although the other scan spent all of its
    assert (counts["connections"], counts["probe"], other_counts["connections"]) == (0, 0, 0)


def test_the_socket_goes_to_the_checked_address_with_the_mx_as_sni(tmp_path):
    """F01, F03, T04: the connection is made to the checked address (the fake server listens there only),
    the published MX is the SNI and the name checked, and the dialogue is the one of core/smtp.py."""

    async def main():
        pki = TestPki(tmp_path)
        async with dns_server(zone("127.0.0.2")) as (_, dns_port), \
                smtp_server(Script(tls=pki.server_context(MX)), "127.0.0.2") as (record, port):
            net = lab(dns_port, port, pki=pki)
            await discovered(net, MX)
            observation = await net.smtp_attempt(MX, "127.0.0.2", deadline=soon())
        return observation, record

    observation, record = asyncio.run(main())
    assert observation.socket and observation.dialogue is not None
    assert observation.dialogue.reason is smtp.Reason.TLS_VERIFIED and observation.dialogue.mx_name == MX
    assert record.connections == 1 and record.sessions[0].sni == [MX]


# ------------------------------------------------------------------ isolation of the test hooks (T04)
def test_smtp_production_hooks(tmp_path):
    """T04, S05, F03, decision D1b: the three methods of LiveNetwork give the production values: SMTP_EGRESS,
    port 25, the public verifying context (the system's authorities only, never the perimeter's), and a
    reading context that verifies nothing, TLS 1.2 to 1.3."""
    net = LiveNetwork(trusted_ca=TestPki(tmp_path).pem)
    assert net._smtp_policy() is SMTP_EGRESS and net._smtp_port() == 25
    verify = net._smtp_tls_context(SmtpPurpose.VERIFY)
    assert smtp.proves_trust(verify) is True
    assert verify.cert_store_stats() == smtp.public_smtp_context().cert_store_stats()
    reading = net._smtp_tls_context(SmtpPurpose.READ_CERTIFICATE)
    assert smtp.proves_trust(reading) is False
    assert (reading.minimum_version, reading.maximum_version) == (smtp.ssl.TLSVersion.TLSv1_2,
                                                                  smtp.ssl.TLSVersion.TLSv1_3)


def test_smtp_hooks_not_overridden_in_src():
    """T04: nothing in src/ redefines, calls or subclasses around the three hooks, outside core/network.py;
    the only redefinition is the test subclass LabNetwork."""
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        here = path.relative_to(SRC).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(
                    (isinstance(b, ast.Name) and b.id == "LiveNetwork")
                    or (isinstance(b, ast.Attribute) and b.attr == "LiveNetwork") for b in node.bases):
                offenders.append(f"{here}: class {node.name}(LiveNetwork)")
            if here == "core/network.py":
                continue
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name in HOOKS:
                offenders.append(f"{here}: def {node.name}")
            if isinstance(node, ast.Attribute) and node.attr in HOOKS:
                offenders.append(f"{here}: .{node.attr}")
    assert offenders == []


def test_scanner_uses_production_network(tmp_path):
    """T04, decision B and D: a scan of the Internet gets a LiveNetwork exactly, bound to the audited domain,
    with the EHLO name when the probe is on; an internal perimeter says so; the demo is recorded data."""
    on = Config(data_dir=tmp_path, smtp_probe=True, smtp_ehlo_name=EHLO, internal_scans=True)
    net = Scanner(Registry(), on).network_for("Example.ORG")
    assert type(net) is LiveNetwork
    assert (net._domain, net._ehlo_name, net._internal) == ("example.org", EHLO, False)
    off = Scanner(Registry(), Config(data_dir=tmp_path)).network_for("example.org")
    assert type(off) is LiveNetwork and off._ehlo_name is None
    perimeter = Perimeter(1, "lab", (ip_network("10.0.0.0/8"),), ("10.0.0.53",), frozenset({443}), "", "")
    inside = Scanner(Registry(), on).network_for("intranet.example.org", perimeter)
    assert type(inside) is LiveNetwork and inside._internal is True
    demo = Scanner(Registry(), on).network_for(DEMO_DOMAIN)
    assert type(demo) is FixtureNetwork and demo._domain == DEMO_DOMAIN


def test_no_smtp_network_setting():
    """T04, S01: no parameter, setting or environment variable changes the probe's rule, port or TLS context;
    the only SMTP settings are the switch and the EHLO name (PR-A)."""
    parameters = set(inspect.signature(LiveNetwork.__init__).parameters) - {"self"}
    assert parameters == {"nameservers", "timeout", "policy", "trusted_ca", "dns_port", "limits", "domain",
                          "ehlo_name", "internal"}
    fields = {name for name in Config.__dataclass_fields__ if "smtp" in name}
    assert fields == {"smtp_probe", "smtp_ehlo_name"}
    source = (SRC / "config.py").read_text(encoding="utf-8")
    variables = set(re.findall(r'_env(?:_bool)?\("([A-Z_]+)"', source))
    assert {v for v in variables if "SMTP" in v} == {"SMTP_PROBE", "SMTP_EHLO_NAME"}
    example = (SRC.parent.parent / ".env.example").read_text(encoding="utf-8")
    assert set(re.findall(r"POSTURE_COCKPIT_(SMTP_[A-Z_]+)", example)) == {"SMTP_PROBE", "SMTP_EHLO_NAME"}
