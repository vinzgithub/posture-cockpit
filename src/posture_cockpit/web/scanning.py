# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Scan a domain and keep the result: shared by the pages and the API that start a scan.

Every scan takes a slot of the scan limiter (limits.py) and is written to the
audit log, with the perimeter it ran in.
"""

from __future__ import annotations

from .. import __version__
from ..core.model import Finding
from ..storage import Perimeter, Row
from .services import Services


def _who(user: Row | None, client: str) -> str:
    return f"user:{user['id']}" if user else f"client:{client}"


def perimeter_of(s: Services, domain: Row | None) -> Perimeter | None:
    """The perimeter a domain is scanned in; None for the Internet."""
    if domain is None or domain["perimeter_id"] is None:
        return None
    perimeter = s.perimeters.get(domain["perimeter_id"])
    assert perimeter is not None  # the foreign key keeps a used perimeter from being deleted
    return perimeter


async def scan_and_save(s: Services, domain: str, user: Row | None, *, perimeter: Perimeter | None = None,
                        client: str = "", via: str = "web") -> int:
    """Scans ``domain`` (already normalized), stores the result and returns the scan id.

    The caller has checked that ``user`` may scan this domain in this perimeter.
    Raises TooManyScans over the limits."""
    with s.scan_limiter.slot(_who(user, client)):
        result = await s.scanner.scan(domain, perimeter)
    user_id = user["id"] if user else None
    domain_id = s.scans.add_domain(domain, user_id, perimeter.id if perimeter else None)
    scan_id = s.scans.save(domain_id, result, __version__, user_id, perimeter.name if perimeter else "")
    s.audit.record("scan.internal" if perimeter else "scan", user=user, target=domain, client=client, via=via,
                   perimeter=perimeter.name if perimeter else "")
    return scan_id


async def recheck(s: Services, domain: str, check_id: str, user: Row, *, perimeter: Perimeter | None = None,
                  client: str = "") -> Finding | None:
    """Runs one check again (see Scanner.recheck). It takes a slot, not a share of the hourly quota."""
    with s.scan_limiter.slot(_who(user, client), counts=False):
        return await s.scanner.recheck(domain, check_id, perimeter)
