# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Runs the checks of a scan, all at once, each within its own time limit.

A check that raises or takes too long does not stop the others: it is
reported with the status ERROR ("could not be checked") and the reason in its
evidence, so the user sees it and the score simply leaves it out.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from .extension import Check, CheckContext
from .model import Finding, Outcome, Status
from .network import Network, NetworkError

log = logging.getLogger(__name__)

_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")


@dataclass(frozen=True)
class ScanResult:
    domain: str
    started_at: datetime
    duration_ms: int
    findings: list[Finding]


def normalize_domain(text: str) -> str:
    """Turns what a user typed into a domain name, or raises ValueError.

    Accepts ``Example.org``, ``https://www.example.org/contact`` (→ ``example.org``:
    the website's ``www`` is checked with its domain) and internationalised names
    (``café.fr`` → ``xn--caf-dma.fr``)."""
    name = (text or "").strip().lower()
    name = re.sub(r"^[a-z][a-z0-9+.-]*://", "", name)   # scheme
    name = re.split(r"[/?#:]", name, maxsplit=1)[0]      # path, query, port
    name = name.rstrip(".")
    if name.startswith("www.") and name.count(".") >= 2:
        name = name[4:]
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(text) from None
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or not all(_LABEL.fullmatch(label) for label in labels):
        raise ValueError(text)
    if labels[-1].isdigit():  # an IP address is not a domain
        raise ValueError(text)
    return name


async def run_check(check: Check, ctx: CheckContext, timeout: float) -> Finding:
    """Runs one check; never raises."""
    try:
        outcome = await asyncio.wait_for(check.run(ctx), timeout)
    except TimeoutError:
        outcome = Outcome(Status.ERROR, "check.error.timeout", {"seconds": int(timeout)})
    except NetworkError as e:
        outcome = Outcome(Status.ERROR, "check.error.network", evidence={"error": str(e)})
    except Exception as e:  # a bug in a check must not break the scan
        log.exception("check %s failed on %s", check.id, ctx.domain)
        outcome = Outcome(Status.ERROR, "check.error.internal", evidence={"error": f"{e.__class__.__name__}: {e}"})
    return Finding(check.id, check.category, check.weight, outcome)


async def scan(domain: str, checks: Iterable[Check], net: Network, timeout: float = 15.0,
               now: datetime | None = None) -> ScanResult:
    """Runs ``checks`` on ``domain`` concurrently. ``domain`` must already be normalized."""
    started = now or datetime.now(UTC)
    ctx = CheckContext(domain=domain, net=net, now=started)
    clock = time.monotonic()
    findings = await asyncio.gather(*(run_check(check, ctx, timeout) for check in checks))
    return ScanResult(domain, started, int((time.monotonic() - clock) * 1000), list(findings))


async def preflight(net: Network, domain: str) -> str | None:
    """Why ``domain`` cannot be scanned, or None when it can.

    ``"unknown"``: the DNS says the name does not exist (a typo).
    ``"empty"``: the name exists but has no record at all, or the resolver gives
    empty answers (a filtering resolver does that). Scanning anyway would report
    missing SPF and DMARC records that may well exist: better to say so."""
    soa = await net.dns(domain, "SOA")
    if not soa.exists:
        return "unknown"
    if soa.records:
        return None
    for rtype in ("NS", "A", "AAAA", "MX"):  # a subdomain has no SOA of its own
        if (await net.dns(domain, rtype)).records:
            return None
    return "empty"
