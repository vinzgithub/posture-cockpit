# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Scan a domain and keep the result: shared by the pages and the API that start a scan.

Every scan is written to the audit log, with the perimeter it ran in.
"""

from __future__ import annotations

from .. import __version__
from ..storage import Perimeter, Row
from .services import Services


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

    The caller has checked that ``user`` may scan this domain in this perimeter."""
    result = await s.scanner.scan(domain, perimeter)
    user_id = user["id"] if user else None
    domain_id = s.scans.add_domain(domain, user_id, perimeter.id if perimeter else None)
    scan_id = s.scans.save(domain_id, result, __version__, user_id)
    s.audit.record("scan.internal" if perimeter else "scan", user=user, target=domain, client=client, via=via,
                   perimeter=perimeter.name if perimeter else "")
    return scan_id
