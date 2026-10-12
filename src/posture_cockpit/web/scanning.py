# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Scan a domain and keep the result: shared by the pages that start a scan."""

from __future__ import annotations

from .. import __version__
from .services import Services


async def scan_and_save(s: Services, domain: str, user_id: int | None) -> int:
    """Scans ``domain`` (already normalized), stores the result and returns the scan id."""
    result = await s.scanner.scan(domain)
    domain_id = s.scans.add_domain(domain, user_id)
    return s.scans.save(domain_id, result, __version__, user_id)
