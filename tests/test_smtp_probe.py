# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""SMTP probe tests use fake streams, never real network."""

import asyncio

import pytest

from posture_cockpit.checks.smtp_probe import _reply, probe_smtp_ehlo
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
