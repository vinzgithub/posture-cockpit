# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pure destination eligibility checks for an eventual SMTP probe.

No socket or DNS lookup is performed here. The caller must resolve and pin
addresses before connecting, and still enforce scan budgets and timeouts.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from ipaddress import ip_address

from posture_cockpit.core.egress import Zone, classify, parse_address

_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _valid_mx_name(name: str) -> bool:
    return 0 < len(name) <= 253 and "." in name and all(
        _DNS_LABEL.fullmatch(label) for label in name.split(".")
    )


def allowed_smtp_mx_addresses(
    host: str, declared_mx: Iterable[str], addresses: Iterable[str],
    *, internal: bool = False,
) -> tuple[str, ...]:
    """Fail closed unless host is a declared MX and *every* IP is public."""
    name = host.lower().rstrip(".")
    mx_names = {mx.lower().rstrip(".") for mx in declared_mx}
    if internal or not _valid_mx_name(name) or name not in mx_names or parse_address(name) is not None:
        raise ValueError("SMTP target is not an eligible declared MX")
    candidates = tuple(addresses)
    if not candidates:
        raise ValueError("SMTP target has no addresses")
    for candidate in candidates:
        if classify(ip_address(candidate)) is not Zone.PUBLIC:
            raise ValueError("SMTP target has a non-public address")
    return candidates
