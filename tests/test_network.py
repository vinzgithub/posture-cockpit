# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The real network code, against servers started on this machine for the test."""

import asyncio
import datetime as dt
import ssl

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

from posture_cockpit.core import network
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
    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=context)
    return server, server.sockets[0].getsockname()[1]


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
        async with server:
            net = LiveNetwork(timeout=3)
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
        await LiveNetwork(timeout=2).certificate("localhost", port)

    with pytest.raises(NetworkError):
        asyncio.run(main())


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
        async with server:
            return await LiveNetwork(timeout=3).http_get(f"http://127.0.0.1:{port}/")

    reply = asyncio.run(main())
    assert reply.status == 301 and reply.header("Location") == "https://example.org/"
    assert reply.header("set-cookie") == "a=1, b=2"
    assert len(reply.body) == network.MAX_BODY


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
