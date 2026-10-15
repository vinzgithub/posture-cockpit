# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Runs the checks of a scan, all at once, each within its own time limit.

A check that raises or takes too long does not stop the others: it is
reported with the status ERROR ("not evaluated") and the reason in its
evidence, so the user sees it and the score leaves it out (the coverage of the
scan shows how much could not be evaluated, see :mod:`.scoring`).
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from .egress import DestinationBlocked
from .extension import Check, CheckContext
from .model import Finding, Outcome, Status
from .network import Network, NetworkError
from .errors import ConnectionReset, ConnectionTimedOut, Refused, TLSHandshakeError

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
    the website's ``www`` is checked with its domain), bare ``www.example.org``
    (kept as a distinct DNS name), and internationalised names
    (``café.fr`` → ``xn--caf-dma.fr``)."""
    name = (text or "").strip().lower()
    # Bare hostnames are exact DNS names. Keep legacy URL / port normalization.
    website_input = bool(re.match(r"^[a-z][a-z0-9+.-]*://", name) or
                         re.search(r":\d+(?:[/?#]|$)", name))
    name = re.sub(r"^[a-z][a-z0-9+.-]*://", "", name)   # scheme
    name = re.split(r"[/?#:]", name, maxsplit=1)[0]      # path, query, port
    name = name.rstrip(".")
    if website_input and name.startswith("www.") and name.count(".") >= 2:
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
    except DestinationBlocked as e:
        # The egress policy refused a connection: say which one, and why.
        outcome = Outcome(Status.ERROR, f"check.error.blocked.{e.reason}",
                          {"host": e.host, "address": str(e.address), "port": e.port}, evidence={"error": str(e)})
    except NetworkError as e:
        reason = ("timeout" if isinstance(e, ConnectionTimedOut) else
                  "reset" if isinstance(e, ConnectionReset) else
                  "refused" if isinstance(e, Refused) else
                  "tls" if isinstance(e, TLSHandshakeError) else "network")
        outcome = Outcome(Status.ERROR, f"check.error.{reason}", evidence={"error": str(e)})
    except Exception as e:  # a bug in a check must not break the scan
        log.exception("check %s failed on %s", check.id, ctx.domain)
        outcome = Outcome(Status.ERROR, "check.error.internal", evidence={"error": f"{e.__class__.__name__}: {e}"})
    return Finding(check.id, check.category, check.weight, outcome)


async def _not_applicable(check: Check) -> Finding:
    return Finding(check.id, check.category, check.weight, Outcome(Status.NA, "check.na.internal"))


async def scan(domain: str, checks: Iterable[Check], net: Network, timeout: float = 15.0,
               now: datetime | None = None, internal: bool = False) -> ScanResult:
    """Runs ``checks`` on ``domain`` concurrently. ``domain`` must already be normalized.

    ``internal``: the scan runs in an internal perimeter; checks made for the
    Internet only are reported as not applicable without running."""
    started = now or datetime.now(UTC)
    ctx = CheckContext(domain=domain, net=net, now=started, internal=internal)
    clock = time.monotonic()
    try:
        findings = await asyncio.gather(*(
            _not_applicable(check) if internal and not check.internal else run_check(check, ctx, timeout)
            for check in checks))
    finally:
        # Work started for a check that timed out may still be running: stop it with the scan.
        ctx.close()
        close = getattr(net, "close", None)
        if callable(close):
            close()
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
