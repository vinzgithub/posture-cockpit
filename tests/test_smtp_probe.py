# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""SMTP probe tests use fake streams, never real network."""

import asyncio
import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from posture_cockpit.checks.smtp_probe import _certificate_details, _reply, probe_smtp_ehlo
from posture_cockpit.core.network import DnsAnswer, Limits, LiveNetwork, NetworkError


class FakeWriter:
    def __init__(self):
        self.sent = []
        self.closed = False

    def write(self, data):
        self.sent.append(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def reader_with(*lines):
    reader = asyncio.StreamReader()
    for line in lines:
        reader.feed_data(line.encode("ascii") + b"\r\n")
    reader.feed_eof()
    return reader


@pytest.mark.asyncio
@pytest.mark.parametrize(("capability", "expected"), [
    ("250 STARTTLS", True),
    ("250 SIZE 1000", False),
])
async def test_probe_pins_public_ip_and_only_sends_ehlo(monkeypatch, capability, expected):
    writer = FakeWriter()
    called = []

    async def fake_open(ip, port):
        called.append((ip, port))
        return reader_with("220 mail.example.org ready", "250-mail.example.org", capability,
                           *(( "220 Ready to start TLS",) if expected else ())), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    result = await probe_smtp_ehlo(
        "mail.example.org", ("mail.example.org",), ("8.8.8.8",), reserve_connection=lambda: None,
    )
    assert called == [("8.8.8.8", 25)]
    assert writer.sent == ([b"EHLO posture-cockpit.invalid\r\n", b"STARTTLS\r\n"] if expected
                           else [b"EHLO posture-cockpit.invalid\r\n"])
    assert result.starttls_accepted is (True if expected else None)
    assert writer.closed
    assert result.starttls_advertised is expected


@pytest.mark.asyncio
async def test_probe_never_connects_to_private_ip(monkeypatch):
    async def must_not_connect(*args, **kwargs):
        pytest.fail("private destination reached socket layer")

    monkeypatch.setattr(asyncio, "open_connection", must_not_connect)
    with pytest.raises(ValueError):
        await probe_smtp_ehlo(
            "mail.example.org", ("mail.example.org",), ("192.168.1.100",), reserve_connection=lambda: None,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("lines", [
    ("250-starttls",),
    ("250-HELLO", "550 STARTTLS"),
    ("nonsense",),
])
async def test_smtp_reply_rejects_broken_framing(lines):
    with pytest.raises(ValueError):
        await _reply(reader_with(*lines))


@pytest.mark.asyncio
async def test_probe_closes_stream_after_invalid_greeting(monkeypatch):
    writer = FakeWriter()

    async def fake_open(*args):
        return reader_with("554 Service unavailable"), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    with pytest.raises(ValueError, match="greeting"):
        await probe_smtp_ehlo(
            "mail.example.org", ("mail.example.org",), ("8.8.8.8",), reserve_connection=lambda: None,
        )
    assert writer.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    b"250 STARTTLS\n",
    b"250 STARTTLS\r",
    b"250 STARTTLS\x00\r\n",
    b"250 STARTTLS\x1b\r\n",
    b"250 STARTTLS\x7f\r\n",
])
async def test_smtp_reply_rejects_noncanonical_or_control_bytes(payload):
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    with pytest.raises(ValueError):
        await _reply(reader)


@pytest.mark.asyncio
async def test_probe_refuses_exhausted_budget_before_socket(monkeypatch):
    async def must_not_connect(*args, **kwargs):
        pytest.fail("socket opened despite exhausted budget")

    def exhausted():
        raise RuntimeError("connection budget exhausted")

    monkeypatch.setattr(asyncio, "open_connection", must_not_connect)
    with pytest.raises(RuntimeError, match="budget exhausted"):
        await probe_smtp_ehlo(
            "mail.example.org", ("mail.example.org",), ("8.8.8.8",),
            reserve_connection=exhausted,
        )


@pytest.mark.asyncio
async def test_live_network_smtp_reuses_dns_and_connection_budget(monkeypatch):
    net = LiveNetwork(limits=Limits(connections=1))
    queries = []
    opened = []
    writer = FakeWriter()

    async def fake_dns(name, rtype):
        queries.append((name, rtype))
        return DnsAnswer(("8.8.8.8",)) if rtype == "A" else DnsAnswer(())

    async def fake_open(ip, port):
        opened.append((ip, port))
        return reader_with("220 mx.example.org ready", "250-mx.example.org", "250 STARTTLS",
                           "220 Ready to start TLS"), writer

    monkeypatch.setattr(net, "dns", fake_dns)
    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    result = await net.smtp_ehlo("mx.example.org", ("mx.example.org",))
    assert result.starttls_advertised
    assert queries == [("mx.example.org", "A"), ("mx.example.org", "AAAA")]
    assert opened == [("8.8.8.8", 25)]
    with pytest.raises(NetworkError, match="limit of 1 connections"):
        await net.smtp_ehlo("mx.example.org", ("mx.example.org",))
    assert opened == [("8.8.8.8", 25)]


@pytest.mark.asyncio
async def test_live_network_smtp_rejects_mixed_public_private_addresses(monkeypatch):
    net = LiveNetwork(limits=Limits(connections=1))

    async def fake_dns(name, rtype):
        return DnsAnswer(("8.8.8.8", "192.168.1.1")) if rtype == "A" else DnsAnswer(())

    async def must_not_connect(*args, **kwargs):
        pytest.fail("socket opened with a private MX address")

    monkeypatch.setattr(net, "dns", fake_dns)
    monkeypatch.setattr(asyncio, "open_connection", must_not_connect)
    with pytest.raises(ValueError, match="non-public"):
        await net.smtp_ehlo("mx.example.org", ("mx.example.org",))
    assert net._spent["connections"] == 0


@pytest.mark.asyncio
async def test_smtp_starttls_refusal_is_not_a_success(monkeypatch):
    writer = FakeWriter()

    async def fake_open(ip, port):
        return reader_with("220 mx.example.org ready", "250-mx.example.org", "250 STARTTLS",
                           "454 TLS temporarily unavailable"), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    result = await probe_smtp_ehlo(
        "mx.example.org", ("mx.example.org",), ("8.8.8.8",), reserve_connection=lambda: None,
    )
    assert result.starttls_advertised is True
    assert result.starttls_accepted is False
    assert writer.sent == [b"EHLO posture-cockpit.invalid\r\n", b"STARTTLS\r\n"]


@pytest.mark.asyncio
async def test_verified_starttls_handshake_uses_mx_hostname(monkeypatch):
    writer = FakeWriter()
    handshakes = []

    async def start_tls(context, *, server_hostname, ssl_handshake_timeout):
        handshakes.append((context.verify_mode, context.check_hostname, server_hostname, ssl_handshake_timeout))

    class TLS:
        def version(self):
            return "TLSv1.3"

        def getpeercert(self, binary_form=False):
            return b"fake DER"

    writer.start_tls = start_tls
    writer.get_extra_info = lambda name: TLS() if name == "ssl_object" else None

    async def fake_open(ip, port):
        return reader_with("220 mx.example.org ready", "250-mx.example.org", "250 STARTTLS",
                           "220 Ready to start TLS"), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    expires = datetime.now(UTC) + timedelta(days=20)
    monkeypatch.setattr("posture_cockpit.checks.smtp_probe._certificate_details",
                        lambda der: ("Test CA", expires, 20))
    result = await probe_smtp_ehlo(
        "mx.example.org", ("mx.example.org",), ("8.8.8.8",),
        reserve_connection=lambda: None, verify_tls=True,
    )
    assert result.certificate_issuer == "Test CA"
    assert result.certificate_not_after == expires
    assert result.certificate_days_remaining == 20
    assert result.tls_verified is True
    assert result.tls_protocol == "TLSv1.3"
    assert handshakes == [(ssl.CERT_REQUIRED, True, "mx.example.org", 5.0)]


@pytest.mark.asyncio
async def test_verified_starttls_reports_certificate_failure(monkeypatch):
    writer = FakeWriter()

    async def start_tls(context, *, server_hostname, ssl_handshake_timeout):
        raise ssl.SSLCertVerificationError("certificate verify failed")

    writer.start_tls = start_tls

    async def fake_open(ip, port):
        return reader_with("220 mx.example.org ready", "250-mx.example.org", "250 STARTTLS",
                           "220 Ready to start TLS"), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    result = await probe_smtp_ehlo(
        "mx.example.org", ("mx.example.org",), ("8.8.8.8",),
        reserve_connection=lambda: None, verify_tls=True,
    )
    assert result.starttls_accepted is True
    assert result.tls_verified is False
    assert "certificate verify failed" in result.tls_error



def test_certificate_details_from_der():
    key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MX Test Authority")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(issuer).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=31))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    name, expires, remaining = _certificate_details(der)
    assert name == "MX Test Authority"
    assert expires.tzinfo is not None
    assert 29 <= remaining <= 31


@pytest.mark.asyncio
async def test_live_network_verified_tls_is_explicit_opt_in(monkeypatch):
    net = LiveNetwork()
    writer = FakeWriter()
    tls_calls = []

    async def fake_dns(name, rtype):
        return DnsAnswer(("8.8.8.8",)) if rtype == "A" else DnsAnswer(())

    async def fake_open(ip, port):
        return reader_with("220 mx.example.org ready", "250-mx.example.org",
                           "250 STARTTLS", "220 Ready to start TLS"), writer

    async def start_tls(context, *, server_hostname, ssl_handshake_timeout):
        tls_calls.append(server_hostname)

    class TLS:
        def version(self):
            return "TLSv1.3"

        def getpeercert(self, binary_form=False):
            return b"DER"

    writer.start_tls = start_tls
    writer.get_extra_info = lambda name: TLS() if name == "ssl_object" else None
    monkeypatch.setattr(net, "dns", fake_dns)
    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    monkeypatch.setattr("posture_cockpit.checks.smtp_probe._certificate_details",
                        lambda der: ("Test CA", datetime.now(UTC), 0))
    observation = await net.smtp_ehlo("mx.example.org", ("mx.example.org",), verify_tls=True)
    assert observation.tls_verified is True
    assert tls_calls == ["mx.example.org"]


@pytest.mark.asyncio
@pytest.mark.parametrize("peer_certificate", [None, b"", b"not-der"])
async def test_starttls_missing_or_invalid_certificate_is_not_verified(monkeypatch, peer_certificate):
    writer = FakeWriter()

    async def start_tls(context, *, server_hostname, ssl_handshake_timeout):
        pass

    class TLS:
        def version(self):
            return "TLSv1.3"

        def getpeercert(self, binary_form=False):
            return peer_certificate

    writer.start_tls = start_tls
    writer.get_extra_info = lambda name: TLS() if name == "ssl_object" else None

    async def fake_open(ip, port):
        return reader_with("220 mx.example.org ready", "250-mx.example.org", "250 STARTTLS",
                           "220 Ready to start TLS"), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    result = await probe_smtp_ehlo(
        "mx.example.org", ("mx.example.org",), ("8.8.8.8",),
        reserve_connection=lambda: None, verify_tls=True,
    )
    assert result.tls_verified is False
    assert result.tls_error



@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    b"250 " + b"A" * 70000 + b"\r\n",
    b"250 " + b"A" * 1020 + b"\r\n",
    b"250 incomplete",
])
async def test_smtp_reply_rejects_oversized_or_incomplete_data(payload):
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    with pytest.raises(ValueError, match="incomplete or oversized"):
        await _reply(reader)



@pytest.mark.asyncio
async def test_smtp_connection_timeout_consumes_one_budget_and_never_retries(monkeypatch):
    opened = []
    net = LiveNetwork(limits=Limits(connections=1), timeout=0.01)

    async def fake_dns(name, rtype):
        return DnsAnswer(("8.8.8.8",)) if rtype == "A" else DnsAnswer(())

    async def hanging_open(ip, port):
        opened.append((ip, port))
        await asyncio.Event().wait()

    monkeypatch.setattr(net, "dns", fake_dns)
    monkeypatch.setattr(asyncio, "open_connection", hanging_open)
    with pytest.raises(TimeoutError):
        await net.smtp_ehlo("mx.example.org", ("mx.example.org",))
    assert opened == [("8.8.8.8", 25)]
    assert net._spent["connections"] == 1
    with pytest.raises(NetworkError, match="limit of 1 connections"):
        await net.smtp_ehlo("mx.example.org", ("mx.example.org",))
    assert opened == [("8.8.8.8", 25)]


@pytest.mark.asyncio
async def test_smtp_reply_timeout_closes_writer(monkeypatch):
    writer = FakeWriter()
    reader = asyncio.StreamReader()

    async def fake_open(ip, port):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    with pytest.raises(TimeoutError):
        await probe_smtp_ehlo(
            "mx.example.org", ("mx.example.org",), ("8.8.8.8",),
            reserve_connection=lambda: None, timeout=0.01,
        )
    assert writer.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout", [0, -1, 21, float("nan"), float("inf")])
async def test_smtp_rejects_invalid_timeout_without_reserving_socket(timeout, monkeypatch):
    async def must_not_connect(ip, port):
        pytest.fail("socket opened despite invalid timeout")

    monkeypatch.setattr(asyncio, "open_connection", must_not_connect)
    with pytest.raises(ValueError, match="timeout"):
        await probe_smtp_ehlo(
            "mx.example.org", ("mx.example.org",), ("8.8.8.8",),
            reserve_connection=lambda: pytest.fail("budget spent despite invalid timeout"),
            timeout=timeout,
        )



@pytest.mark.asyncio
async def test_smtp_domain_probe_refuses_undeclared_mx_before_address_dns(monkeypatch):
    net = LiveNetwork()
    queries = []

    async def fake_dns(name, rtype):
        queries.append((name, rtype))
        assert (name, rtype) == ("example.org", "MX")
        return DnsAnswer(("10 mail.example.org.",))

    monkeypatch.setattr(net, "dns", fake_dns)
    with pytest.raises(NetworkError, match="not a declared MX"):
        await net.smtp_ehlo_for_domain("example.org", "other.example.org")
    assert queries == [("example.org", "MX")]
    assert net._spent["connections"] == 0


@pytest.mark.asyncio
async def test_smtp_domain_probe_uses_dns_declared_mx(monkeypatch):
    net = LiveNetwork()
    writer = FakeWriter()
    queries = []

    async def fake_dns(name, rtype):
        queries.append((name, rtype))
        if rtype == "MX":
            return DnsAnswer(("10 mx.example.org.",))
        return DnsAnswer(("8.8.8.8",)) if rtype == "A" else DnsAnswer(())

    async def fake_open(ip, port):
        return reader_with("220 mx.example.org ready", "250 mx.example.org"), writer

    monkeypatch.setattr(net, "dns", fake_dns)
    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    result = await net.smtp_ehlo_for_domain("example.org", "mx.example.org")
    assert result.mx == "mx.example.org"
    assert queries == [("example.org", "MX"), ("mx.example.org", "A"), ("mx.example.org", "AAAA")]
    assert net._spent["connections"] == 1
