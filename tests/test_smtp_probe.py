# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""SMTP probe tests use fake streams, never real network."""

import asyncio

import pytest

from posture_cockpit.checks.smtp_probe import _reply, probe_smtp_ehlo


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
        return reader_with("220 mail.example.org ready", "250-mail.example.org", capability), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    result = await probe_smtp_ehlo("mail.example.org", ("mail.example.org",), ("8.8.8.8",))
    assert called == [("8.8.8.8", 25)]
    assert writer.sent == [b"EHLO posture-cockpit.invalid\r\n"]
    assert writer.closed
    assert result.starttls_advertised is expected


@pytest.mark.asyncio
async def test_probe_never_connects_to_private_ip(monkeypatch):
    async def must_not_connect(*args, **kwargs):
        pytest.fail("private destination reached socket layer")

    monkeypatch.setattr(asyncio, "open_connection", must_not_connect)
    with pytest.raises(ValueError):
        await probe_smtp_ehlo("mail.example.org", ("mail.example.org",), ("192.168.1.100",))


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
        await probe_smtp_ehlo("mail.example.org", ("mail.example.org",), ("8.8.8.8",))
    assert writer.closed
