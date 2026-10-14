# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pure SMTP response parsing for a future bounded MX/STARTTLS probe.

No network access occurs here. Live probes must enforce the egress policy.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SmtpCapabilities:
    """Capabilities observed after EHLO, not proof that TLS succeeds."""

    starttls_advertised: bool
    extensions: tuple[str, ...]


def parse_ehlo_reply(lines: tuple[str, ...]) -> SmtpCapabilities:
    """Parse an RFC 5321 multiline 250 reply; reject incomplete replies."""
    if not lines or any(
        len(line) < 4 or not line.startswith("250") or line[3] not in "- "
        for line in lines
    ):
        return SmtpCapabilities(False, ())
    if any(line[3] != "-" for line in lines[:-1]) or lines[-1][3] != " ":
        return SmtpCapabilities(False, ())
    extensions = tuple(
        line[4:].strip().split()[0].upper()
        for line in lines[1:]
        if line[4:].strip()
    )
    return SmtpCapabilities("STARTTLS" in extensions, extensions)
