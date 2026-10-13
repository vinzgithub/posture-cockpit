# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The egress policy: where a scan may connect, in Internet mode and in an internal perimeter.

The first tests check the address tables. The others run the real network code
against servers started on this machine (tests/local_servers.py): a local DNS
server gives the names the test needs, so no other machine is ever contacted.
Each of these tests also checks that the refused server received nothing.
"""

import asyncio
import socket
import time
from ipaddress import ip_address, ip_network

import pytest

from local_servers import LOOPBACK, TestPki, counting_server, dns_server, http_reply, http_server
from posture_cockpit.core import engine
from posture_cockpit.core.egress import (
    INTERNET,
    DestinationBlocked,
    EgressPolicy,
    Zone,
    classify,
    parse_address,
    validate_internal_networks,
)
from posture_cockpit.core.extension import Extension
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import Status, ok
from posture_cockpit.core.network import Limits, LiveNetwork, NetworkError, UntrustedCertificate
from posture_cockpit.i18n import Catalog


@pytest.fixture(autouse=True)
def no_proxy(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)


def lab(*ports, networks=("127.0.0.1/32",)):
    """An internal perimeter made of this machine's loopback address, on the test servers' ports.

    Administrators cannot open the loopback (see validate_internal_networks): only tests build this."""
    return EgressPolicy(networks=tuple(ip_network(n) for n in networks), ports=frozenset(ports), name="lab")


def network(dns_port, policy=INTERNET, **kwargs):
    return LiveNetwork([LOOPBACK], 3, policy=policy, dns_port=dns_port, **kwargs)


async def blocked(awaitable):
    """The DestinationBlocked an awaitable raises."""
    with pytest.raises(DestinationBlocked) as caught:
        await awaitable
    return caught.value


# ------------------------------------------------------------- address tables
@pytest.mark.parametrize("text", ["8.8.8.8", "1.1.1.1", "2a00:1450:4007:80c::200e", "2606:4700::6810:84e5",
                                  "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1"])
def test_public_addresses(text):
    assert classify(ip_address(text)) is Zone.PUBLIC


@pytest.mark.parametrize("text", [
    "10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.1", "127.0.0.1", "127.255.0.9", "100.64.1.1",
    "192.0.2.1", "198.51.100.7", "203.0.113.9", "198.18.0.1", "192.0.0.8",
    "::1", "fc00::1", "fd12:3456::1", "2001:db8::1", "fec0::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    "::ffff:10.0.0.1", "::ffff:127.0.0.1", "::127.0.0.1",
])
def test_internal_addresses(text):
    assert classify(ip_address(text)) is Zone.INTERNAL


@pytest.mark.parametrize("text", [
    "0.0.0.0", "0.1.2.3", "169.254.169.254", "169.254.170.2", "224.0.0.1", "239.255.255.250",
    "240.0.0.1", "255.255.255.255", "100.100.100.200", "168.63.129.16", "192.0.0.192",
    "::", "fe80::1", "fe80::1%eth0", "ff02::1", "fd00:ec2::254", "100::1",
    "::ffff:169.254.169.254", "::ffff:0.0.0.0",
    "64:ff9b::a00:1", "64:ff9b::a9fe:a9fe", "2002:a00:1::1", "2002:7f00:1::1",  # translations to non-public IPv4
])
def test_forbidden_addresses(text):
    assert classify(ip_address(text)) is Zone.FORBIDDEN


@pytest.mark.parametrize(("text", "expected"), [
    ("192.0.2.1", "192.0.2.1"), ("[2001:db8::1]", "2001:db8::1"), ("2001:DB8::1", "2001:db8::1"),
    ("127.1", None), ("0x7f000001", None), ("2130706433", None), ("0177.0.0.1", None), ("localhost", None),
])
def test_only_canonical_addresses_are_addresses(text, expected):
    address = parse_address(text)
    assert (str(address) if address else None) == expected


def test_internet_mode_allows_public_addresses_on_web_ports_only():
    INTERNET.check("example.org", ip_address("8.8.8.8"), 443)
    INTERNET.check("example.org", ip_address("2606:4700::6810:84e5"), 80)
    reasons = {}
    for address, port in [("8.8.8.8", 22), ("10.0.0.1", 443), ("::1", 443), ("169.254.169.254", 80),
                          ("::ffff:192.168.0.1", 443)]:
        with pytest.raises(DestinationBlocked) as caught:
            INTERNET.check("x.example", ip_address(address), port)
        reasons[address] = caught.value.reason
    assert reasons == {"8.8.8.8": "port", "10.0.0.1": "private", "::1": "private", "169.254.169.254": "forbidden",
                       "::ffff:192.168.0.1": "private"}


def test_an_internal_perimeter_opens_its_networks_and_nothing_else():
    policy = EgressPolicy(networks=validate_internal_networks(["10.20.0.0/16", "fd00:1::/64"]),
                          ports=frozenset({443, 8443}), name="siège")
    for address in ("10.20.3.4", "::ffff:10.20.3.4", "fd00:1::5", "8.8.8.8"):
        policy.check("intranet", ip_address(address), 8443)
    reasons = {}
    for address in ("10.21.0.1", "192.168.1.1", "127.0.0.1", "fd00:2::5", "169.254.169.254", "fd00:ec2::254"):
        with pytest.raises(DestinationBlocked) as caught:
            policy.check("intranet", ip_address(address), 443)
        reasons[address] = caught.value.reason
    assert reasons == {"10.21.0.1": "outside", "192.168.1.1": "outside", "127.0.0.1": "outside",
                       "fd00:2::5": "outside", "169.254.169.254": "forbidden", "fd00:ec2::254": "forbidden"}
    with pytest.raises(DestinationBlocked, match="port"):
        policy.check("intranet", ip_address("10.20.3.4"), 22)


@pytest.mark.parametrize("text", ["10.0.0.0/8", "10.1.2.0/24", "172.16.0.0/12", "192.168.10.0/24", "100.64.0.0/10",
                                  "fd00:1234::/32", "fc00::/7", "10.0.0.5"])
def test_networks_an_administrator_may_open(text):
    assert validate_internal_networks([text])


@pytest.mark.parametrize("text", ["0.0.0.0/0", "::/0", "10.0.0.0/7", "127.0.0.0/8", "127.0.0.1", "169.254.0.0/16",
                                  "8.8.8.0/24", "192.0.2.0/24", "fe80::/10", "::1/128", "2001:db8::/32",
                                  "pas un réseau", "10.0.0.0/33"])
def test_networks_an_administrator_may_not_open(text):
    with pytest.raises(ValueError):
        validate_internal_networks([text])


# ------------------------------------------------------- real connections
def test_internet_mode_never_connects_to_a_name_that_points_inside():
    """SSRF through DNS: the name resolves to the loopback, nothing is sent to it."""

    async def main():
        zone = {"intranet.test": {"A": [LOOPBACK]}, "v6only.test": {"AAAA": ["::1"]},
                "metadata.test": {"A": ["169.254.169.254"]}, "mapped.test": {"AAAA": ["::ffff:127.0.0.1"]}}
        async with dns_server(zone) as (_, dns_port), counting_server() as (seen, port):
            net = network(dns_port)
            reasons = [
                (await blocked(net.http_get(f"http://intranet.test:{port}/"))).reason,
                (await blocked(net.http_get("https://intranet.test/"))).reason,
                (await blocked(net.certificate("intranet.test", port))).reason,
                (await blocked(net.accepts_tls("intranet.test", "TLSv1.2", port))).reason,
                (await blocked(net.http_get("http://v6only.test/"))).reason,
                (await blocked(net.http_get("http://mapped.test/"))).reason,
                (await blocked(net.http_get("http://metadata.test/latest/meta-data/"))).reason,
            ]
            return reasons, seen.connections

    reasons, connections = asyncio.run(main())
    assert reasons == ["private", "private", "private", "private", "private", "private", "forbidden"]
    assert connections == 0


@pytest.mark.parametrize(("url", "reason"), [
    ("http://127.0.0.1:{port}/", "private"),
    ("http://[::1]:{port}/", "private"),
    ("http://[::ffff:127.0.0.1]:{port}/", "private"),
    ("http://[::ffff:7f00:1]:{port}/", "private"),
    ("http://0.0.0.0:{port}/", "forbidden"),
    ("http://169.254.169.254/latest/meta-data/", "forbidden"),
    ("http://[fe80::1]/", "forbidden"),
    ("http://[64:ff9b::7f00:1]/", "forbidden"),
])
def test_addresses_written_in_the_url_are_checked_too(url, reason):
    async def main():
        async with dns_server({}) as (_, dns_port), counting_server() as (seen, port):
            error = await blocked(network(dns_port).http_get(url.format(port=port)))
            return error.reason, seen.connections

    assert asyncio.run(main()) == (reason, 0)


@pytest.mark.parametrize("host", ["127.1", "2130706433", "0x7f000001", "0177.0.0.1", "localhost"])
def test_unusual_notations_are_names_that_do_not_resolve(host):
    """The operating system would read "127.1" as 127.0.0.1; here it is only a name, unknown to the DNS.

    ("0177.0.0.1" is refused even earlier, as an invalid URL.)"""

    async def main():
        async with dns_server({}) as (_, dns_port), counting_server() as (seen, port):
            with pytest.raises(NetworkError) as caught:
                await network(dns_port, lab(port)).http_get(f"http://{host}:{port}/")
            return caught.value, seen.connections

    error, connections = asyncio.run(main())
    assert not isinstance(error, DestinationBlocked)
    assert "no address" in str(error) or "invalid URL" in str(error)
    assert connections == 0


def test_a_redirection_to_an_internal_address_is_refused():
    """Each hop of a redirection is a new question, checked like the first one."""

    async def main():
        zone = {"www.lab.test": {"A": [LOOPBACK]}, "evil.test": {"A": ["127.0.0.2"]},
                "metadata.test": {"A": ["169.254.169.254"]}}
        async with dns_server(zone) as (_, dns_port), counting_server() as (target, target_port):
            redirect = http_reply("302 Found", {"Location": f"http://evil.test:{target_port}/"})
            async with http_server(redirect) as (seen, port):
                net = network(dns_port, lab(port, target_port))
                first = await net.http_get(f"http://www.lab.test:{port}/")
                second = await blocked(net.http_get(first.header("location")))
                third = await blocked(net.http_get("http://metadata.test/"))
                return first.status, second.reason, third.reason, seen.connections, target.connections

    assert asyncio.run(main()) == (302, "outside", "forbidden", 1, 0)


def test_dns_rebinding_cannot_change_the_address_during_a_scan():
    """The name is resolved once per scan; later connections reuse the checked address."""

    def first_allowed_then_inside(asked):
        return [LOOPBACK] if asked == 1 else ["127.0.0.2"]

    def first_inside_then_allowed(asked):
        return ["127.0.0.2"] if asked == 1 else [LOOPBACK]

    async def main():
        zone = {"rebind.test": {"A": first_allowed_then_inside}, "rebind2.test": {"A": first_inside_then_allowed}}
        async with dns_server(zone) as (dns, dns_port), http_server(http_reply()) as (seen, port):
            net = network(dns_port, lab(port))
            statuses = [(await net.http_get(f"http://rebind.test:{port}/{path}")).status for path in ("a", "b", "c")]
            reasons = [(await blocked(net.http_get(f"http://rebind2.test:{port}/{path}"))).reason
                       for path in ("a", "b")]
            return statuses, reasons, seen.connections, dns.questions

    statuses, reasons, connections, questions = asyncio.run(main())
    assert statuses == [200, 200, 200] and connections == 3  # all three went to the address checked first
    assert reasons == ["outside", "outside"]                  # and the refusal does not change either
    assert questions[("rebind.test", "A")] == 1 and questions[("rebind2.test", "A")] == 1


def test_a_name_with_a_refused_and_an_allowed_address_only_uses_the_allowed_one():
    async def main():
        zone = {"mixed.test": {"A": ["127.0.0.2", LOOPBACK], "AAAA": ["::1"]}}
        async with dns_server(zone) as (_, dns_port), http_server(http_reply()) as (seen, port):
            reply = await network(dns_port, lab(port)).http_get(f"http://mixed.test:{port}/")
            return reply.status, seen.connections

    assert asyncio.run(main()) == (200, 1)


def test_a_port_outside_the_policy_is_refused():
    async def main():
        async with dns_server({"www.lab.test": {"A": [LOOPBACK]}}) as (_, dns_port), \
                counting_server() as (seen, port):
            error = await blocked(network(dns_port, lab(443)).http_get(f"http://www.lab.test:{port}/"))
            return error.reason, error.port == port, seen.connections

    assert asyncio.run(main()) == ("port", True, 0)


def test_proxy_settings_of_the_environment_are_ignored(monkeypatch):
    """A proxy would connect in our place, out of reach of the policy."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")

    async def main():
        async with dns_server({"www.lab.test": {"A": [LOOPBACK]}}) as (_, dns_port), \
                http_server(http_reply()) as (seen, port):
            reply = await network(dns_port, lab(port)).http_get(f"http://www.lab.test:{port}/")
            return reply.status, seen.connections

    assert asyncio.run(main()) == (200, 1)


def test_internal_dns_and_internal_certificate_authority(tmp_path):
    """An intranet site: its name only exists in the internal DNS, its certificate comes from an internal CA."""
    pki = TestPki(tmp_path)

    async def main():
        zone = {"intranet.lab": {"A": [LOOPBACK]}}
        async with dns_server(zone) as (_, dns_port), \
                http_server(http_reply(headers={"Strict-Transport-Security": "max-age=31536000"}),
                            tls=pki.server_context("intranet.lab")) as (seen, port):
            url = f"https://intranet.lab:{port}/"
            trusting = network(dns_port, lab(port), trusted_ca=pki.pem)
            cert = await trusting.certificate("intranet.lab", port)
            reply = await trusting.http_get(url, verify=True)
            host_header = seen.header(len(seen.heads) - 1, "host")

            plain = network(dns_port, lab(port))  # the same site, without the internal CA
            untrusted = await plain.certificate("intranet.lab", port)
            with pytest.raises(UntrustedCertificate) as refused:
                await plain.http_get(url, verify=True)
            headers_anyway = await plain.http_get(url)
            missing = await network(dns_port, lab(port)).dns("absent.lab", "A")
            return cert, reply, host_header, untrusted, refused.value, headers_anyway, missing

    cert, reply, host_header, untrusted, refused, headers_anyway, missing = asyncio.run(main())
    assert cert.trusted and cert.issuer == "Lab Internal CA" and cert.names == ("intranet.lab",)
    assert reply.status == 200 and reply.header("strict-transport-security") == "max-age=31536000"
    assert reply.url.startswith("https://intranet.lab:")   # the reply keeps the name, not the address
    assert host_header.startswith("intranet.lab:")         # the server saw the name, not the address
    assert not untrusted.trusted and "certificate" in untrusted.problem.lower()
    assert "certificate" in refused.problem.lower()
    assert headers_anyway.status == 200                    # headers are still read without verification
    assert missing.exists is False


def test_a_certificate_for_another_name_is_not_trusted(tmp_path):
    pki = TestPki(tmp_path)

    async def main():
        async with dns_server({"intranet.lab": {"A": [LOOPBACK]}}) as (_, dns_port), \
                http_server(http_reply(), tls=pki.server_context("other.lab")) as (_, port):
            return await network(dns_port, lab(port), trusted_ca=pki.pem).certificate("intranet.lab", port)

    cert = asyncio.run(main())
    assert not cert.trusted and "mismatch" in cert.problem.lower()


def test_an_unreachable_server_is_a_technical_error_not_an_invalid_certificate():
    async def main():
        async with dns_server({"down.lab": {"A": [LOOPBACK]}}) as (_, dns_port):
            async with counting_server() as (_, port):
                pass  # the port is closed again
            net = network(dns_port, lab(port))
            errors = []
            questions = (net.http_get(f"https://down.lab:{port}/", verify=True), net.certificate("down.lab", port))
            for awaitable in questions:
                with pytest.raises(NetworkError) as caught:
                    await awaitable
                errors.append(caught.value)
            return errors

    errors = asyncio.run(main())
    assert not any(isinstance(e, (UntrustedCertificate, DestinationBlocked)) for e in errors)


def test_a_scan_has_a_maximum_number_of_connections():
    async def main():
        async with dns_server({"www.lab.test": {"A": [LOOPBACK]}}) as (_, dns_port), \
                http_server(http_reply()) as (seen, port):
            net = network(dns_port, lab(port), limits=Limits(connections=2))
            await net.http_get(f"http://www.lab.test:{port}/a")
            await net.http_get(f"http://www.lab.test:{port}/b")
            await net.http_get(f"http://www.lab.test:{port}/a")  # answered from the cache: free
            with pytest.raises(NetworkError, match="limit"):
                await net.http_get(f"http://www.lab.test:{port}/c")
            return seen.connections

    assert asyncio.run(main()) == 2


def test_a_server_that_answers_too_slowly_is_cut_off():
    """A server sending one byte at a time keeps each read alive: the operation as a whole has a deadline."""

    async def main():
        async with dns_server({"slow.lab": {"A": [LOOPBACK]}}) as (_, dns_port), \
                http_server(http_reply(body=b"x" * 4000), slow=0.01) as (_, port):
            net = network(dns_port, lab(port), limits=Limits(operation_seconds=1))
            start = time.monotonic()
            with pytest.raises(NetworkError, match="no answer"):
                await net.http_get(f"http://slow.lab:{port}/")
            return time.monotonic() - start

    assert asyncio.run(main()) < 2.5


def test_a_check_that_hits_the_policy_is_not_evaluated_with_the_reason():
    extension = Extension("probe", name="Probe", version="1")

    async def main():
        async with dns_server({"intranet.test": {"A": [LOOPBACK]}}) as (_, dns_port), \
                counting_server() as (seen, port):

            @extension.check("page", category="web", weight=3)
            async def page(ctx):
                await ctx.net.http_get(f"http://{ctx.domain}:{port}/")
                return ok("probe.page.ok")

            result = await engine.scan("intranet.test", extension.checks, network(dns_port))
            return result.findings[0], seen.connections

    finding, connections = asyncio.run(main())
    assert connections == 0
    assert finding.status is Status.ERROR and finding.outcome.summary == "check.error.blocked.private"
    assert finding.outcome.params["address"] == LOOPBACK and finding.outcome.params["host"] == "intranet.test"
    for lang in ("fr", "en"):
        text = Catalog().text(lang, finding.outcome.summary, {**finding.outcome.params, "domain": "intranet.test"})
        assert LOOPBACK in text and "intranet.test" in text


def test_the_recorded_network_can_refuse_an_untrusted_certificate():
    data = {"certificates": {"mta-sts.example.org": {"trusted": False, "problem": "self-signed certificate"}},
            "http": {"https://mta-sts.example.org/.well-known/mta-sts.txt": {"status": 200}}}
    net = FixtureNetwork(data)
    url = "https://mta-sts.example.org/.well-known/mta-sts.txt"
    assert asyncio.run(net.http_get(url)).status == 200
    with pytest.raises(UntrustedCertificate, match="self-signed"):
        asyncio.run(net.http_get(url, verify=True))


def _has_ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _has_ipv6_loopback(), reason="this machine has no IPv6 loopback")
def test_an_allowed_ipv6_address_is_reached():
    async def main():
        async with dns_server({"v6.lab": {"AAAA": ["::1"]}}) as (_, dns_port), \
                http_server(http_reply(), host="::1") as (seen, port):
            policy = lab(port, networks=("::1/128",))
            reply = await network(dns_port, policy).http_get(f"http://v6.lab:{port}/")
            return reply.status, seen.connections, seen.header(0, "host")

    assert asyncio.run(main())[:2] == (200, 1)
