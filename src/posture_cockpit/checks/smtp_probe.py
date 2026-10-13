# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Isolated and bounded SMTP EHLO probe, not activated in live scans."""

import asyncio
import contextlib
from dataclasses import dataclass

from .smtp import parse_ehlo_reply
from .smtp_egress import allowed_smtp_mx_addresses


@dataclass(frozen=True)
class SmtpObservation:
    mx: str
    ehlo: tuple[str, ...]
    starttls_advertised: bool


async def _reply(reader: asyncio.StreamReader) -> tuple[str, ...]:
    lines = []
    for _ in range(32):
        raw = await reader.readline()
        if not raw or len(raw) > 1024 or not raw.endswith(b"\n"):
            raise ValueError("SMTP reply incomplete or oversized")
        line = raw.decode("ascii").rstrip("\r\n")
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
                          timeout: float = 5.0) -> SmtpObservation:
    """One connection to a prevalidated, pinned MX IP, no retry or mail delivery.

    Caller must account for this probe in the per-scan connection budget.
    """
    if not 0 < timeout <= 20:
        raise ValueError("SMTP timeout out of bounds")
    ip = allowed_smtp_mx_addresses(mx, declared_mx, addresses, internal=internal)[0]

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
            return SmtpObservation(mx, ehlo, parse_ehlo_reply(ehlo).starttls_advertised)
        finally:
            writer.close()
            with contextlib.suppress(OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 1)

    return await asyncio.wait_for(exchange(), timeout)
