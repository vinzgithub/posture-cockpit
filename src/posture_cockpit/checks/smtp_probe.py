# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Isolated and bounded SMTP EHLO probe, not activated in live scans."""

import asyncio
import contextlib
import ssl
from collections.abc import Callable
from dataclasses import dataclass

from .smtp import parse_ehlo_reply
from .smtp_egress import allowed_smtp_mx_addresses


@dataclass(frozen=True)
class SmtpObservation:
    mx: str
    ehlo: tuple[str, ...]
    starttls_advertised: bool
    starttls_accepted: bool | None = None  # SMTP 220 readiness, not a completed TLS handshake
    tls_verified: bool | None = None  # None means TLS handshake not attempted
    tls_protocol: str = ""
    tls_error: str = ""


async def _reply(reader: asyncio.StreamReader) -> tuple[str, ...]:
    lines: list[str] = []
    for _ in range(32):
        raw = await reader.readline()
        if not raw or len(raw) > 1024 or not raw.endswith(b"\r\n"):
            raise ValueError("SMTP reply incomplete or oversized")
        line = raw[:-2].decode("ascii")
        if any(ord(char) < 32 or ord(char) == 127 for char in line):
            raise ValueError("SMTP reply contains control characters")
        if len(line) < 4 or not line[:3].isdigit() or line[3] not in "- ":
            raise ValueError("SMTP framing invalid")
        if lines and line[:3] != lines[0][:3]:
            raise ValueError("SMTP reply code changed")
        lines.append(line)
        if line[3] == " ":
            return tuple(lines)
    raise ValueError("SMTP reply exceeds 32 lines")


async def probe_smtp_ehlo(mx: str, declared_mx: tuple[str, ...],
                          addresses: tuple[str, ...], *, internal: bool = False,
                          reserve_connection: Callable[[], None],
                          timeout: float = 5.0,
                          verify_tls: bool = False) -> SmtpObservation:
    """One connection to a prevalidated, pinned MX IP, no retry or mail delivery.

    The caller must supply a per-scan connection budget reservation callback.
    """
    if not 0 < timeout <= 20:
        raise ValueError("SMTP timeout out of bounds")
    ip = allowed_smtp_mx_addresses(mx, declared_mx, addresses, internal=internal)[0]
    reserve_connection()  # Refuse the probe before any socket if the scan budget is exhausted.

    async def exchange() -> SmtpObservation:
        reader, writer = await asyncio.open_connection(ip, 25)
        try:
            banner = await _reply(reader)
            if not banner[0].startswith("220"):
                raise ValueError("SMTP greeting rejected")
            writer.write(b"EHLO posture-cockpit.invalid\r\n")
            await writer.drain()
            ehlo = await _reply(reader)
            if not ehlo[0].startswith("250"):
                raise ValueError("SMTP EHLO rejected")
            advertised = parse_ehlo_reply(ehlo).starttls_advertised
            if not advertised:
                return SmtpObservation(mx, ehlo, False)
            writer.write(b"STARTTLS\r\n")
            await writer.drain()
            reply = await _reply(reader)
            accepted = reply[0].startswith("220")
            if not accepted or not verify_tls:
                return SmtpObservation(mx, ehlo, True, accepted)
            context = ssl.create_default_context()
            try:
                await writer.start_tls(context, server_hostname=mx, ssl_handshake_timeout=timeout)
                tls = writer.get_extra_info("ssl_object")
                return SmtpObservation(mx, ehlo, True, True, True, tls.version() if tls else "")
            except (ssl.SSLError, OSError, TimeoutError) as exc:
                return SmtpObservation(mx, ehlo, True, True, False, tls_error=str(exc))
        finally:
            writer.close()
            with contextlib.suppress(OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 1)

    return await asyncio.wait_for(exchange(), timeout)
