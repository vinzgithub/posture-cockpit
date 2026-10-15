# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The real network code, against servers started on this machine for the test.

A local DNS server gives the test names, and the scan runs in a perimeter made
of the loopback address (see test_egress.py for the policy itself)."""

import asyncio
import datetime as dt
import ssl
from ipaddress import ip_network

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from local_servers import LOOPBACK, dns_server
from posture_cockpit.core import network
from posture_cockpit.core.egress import DestinationBlocked, EgressPolicy
from posture_cockpit.core.network import LiveNetwork, NetworkError


@pytest.fixture(autouse=True)
def no_proxy(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    """A self-signed certificate for "localhost", valid 30 days."""
    folder = tmp_path_factory.mktemp("tls")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    (folder / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    return folder / "cert.pem", folder / "key.pem"


async def serve(handler, context=None):
    server = await asyncio.start_server(handler, LOOPBACK, 0, ssl=context)
    return server, server.sockets[0].getsockname()[1]


def lab_network(dns_port, port, timeout=3):
    """The real network, allowed to reach this machine's test server on ``port``."""
    policy = EgressPolicy(networks=(ip_network("127.0.0.1/32"),), ports=frozenset({port}), name="lab")
    return LiveNetwork([LOOPBACK], timeout, policy=policy, dns_port=dns_port)


async def say_nothing(reader, writer):
    await asyncio.sleep(0.2)
    writer.close()


def test_certificate_of_a_self_signed_server(certificate):
    cert_file, key_file = certificate
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)

    async def main():
        server, port = await serve(say_nothing, context)
        async with server, dns_server({"localhost": {"A": [LOOPBACK]}}) as (_, dns_port):
            net = lab_network(dns_port, port)
            cert = await net.certificate("localhost", port)
            tls13 = await net.accepts_tls("localhost", "TLSv1.3", port)
            tls10 = await net.accepts_tls("localhost", "TLSv1", port)
            again = await net.certificate("localhost", port)
            return cert, tls13, tls10, again

    cert, tls13, tls10, again = asyncio.run(main())
    assert cert.trusted is False and "self" in cert.problem.lower()
    assert (cert.key_type, cert.key_bits, cert.issuer, cert.names) == ("EC", 256, "Test CA", ("localhost",))
    assert 28 <= (cert.not_after - dt.datetime.now(dt.UTC)).days <= 30
    assert cert.protocol == "TLSv1.3"
    assert tls13 is True
    assert tls10 in (False, None)  # None when this machine's OpenSSL refuses TLS 1.0 itself
    assert again is cert  # the second question is answered from the cache


def test_closed_port_is_a_network_error():
    async def main():
        server, port = await serve(say_nothing)
        server.close()
        await server.wait_closed()
        async with dns_server({"localhost": {"A": [LOOPBACK]}}) as (_, dns_port):
            await lab_network(dns_port, port, timeout=2).certificate("localhost", port)

    with pytest.raises(NetworkError) as caught:
        asyncio.run(main())
    assert not isinstance(caught.value, DestinationBlocked)


def test_http_get_reads_headers_and_a_limited_body():
    async def handler(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        body = b"x" * (network.MAX_BODY * 2)
        writer.write(b"HTTP/1.1 301 Moved\r\nLocation: https://example.org/\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n"
                     b"Server: test/1.0\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        await writer.drain()
        writer.close()

    async def main():
        server, port = await serve(handler)
        async with server, dns_server({}) as (_, dns_port):
            return await lab_network(dns_port, port).http_get(f"http://127.0.0.1:{port}/")

    reply = asyncio.run(main())
    assert reply.status == 301 and reply.header("Location") == "https://example.org/"
    assert reply.header("set-cookie") == "a=1, b=2"
    assert len(reply.body) == network.MAX_BODY


def test_a_server_that_takes_the_request_and_never_answers_is_a_timeout():
    """0.3.1: a plain NetworkError ("ReadTimeout"), shown as "no answer (DNS or web server)"."""
    from posture_cockpit.core import engine
    from posture_cockpit.core.errors import ConnectionTimedOut
    from posture_cockpit.core.extension import Extension
    from posture_cockpit.core.model import Status, ok

    received: list[bytes] = []

    async def silent(reader, writer):
        received.append(await reader.readuntil(b"\r\n\r\n"))  # the connection and the request get through
        await asyncio.sleep(2)  # the reply comes after the read timeout of the client
        writer.close()

    ext = Extension("lab", name="Lab", version="1")

    async def main():
        server, port = await serve(silent)
        url = f"http://127.0.0.1:{port}/"

        @ext.check("page", category="web", weight=4)
        async def page(ctx):
            await ctx.net.http_get(url)
            return ok("never")

        async with server, dns_server({}) as (_, dns_port):
            # The rule of the scan allows this test server only: 127.0.0.1/32 and its port.
            with pytest.raises(ConnectionTimedOut, match="ReadTimeout"):
                await lab_network(dns_port, port, timeout=0.3).http_get(url)
            result = await engine.scan("lab.example", ext.checks, lab_network(dns_port, port, timeout=0.3))
        return result.findings[0]

    finding = asyncio.run(main())
    assert received and received[0].startswith(b"GET / HTTP/1.1")
    assert (finding.status, finding.outcome.summary) == (Status.ERROR, "check.error.network_timeout")
    assert not finding.status.scored


def test_dns_answers(monkeypatch):
    txt = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, '"v=spf1 include:_spf.example.net" " -all"')
    mx = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX, "10 mx.example.net.")
    assert network._record_text(txt) == "v=spf1 include:_spf.example.net -all"
    assert network._record_text(mx) == "10 mx.example.net."

    async def resolve(self, name, rtype, raise_on_no_answer=True):
        if name.startswith("missing"):
            raise dns.resolver.NXDOMAIN()
        raise dns.exception.Timeout()

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    net = LiveNetwork(nameservers=["192.0.2.53"])
    assert asyncio.run(net.dns("missing.example.org", "TXT")).exists is False
    with pytest.raises(NetworkError):
        asyncio.run(LiveNetwork(nameservers=["192.0.2.53"]).dns("slow.example.org", "TXT"))
