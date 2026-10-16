# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Runs the checks of a scan, all at once, each within its own time limit.

A check that raises or takes too long does not stop the others: it is
reported with the status ERROR ("not evaluated") and the reason in its
evidence, so the user sees it and the score leaves it out (the coverage of the
scan shows how much could not be evaluated, see :mod:`.scoring`).

Version 0.4: the checks of the HTTPS family (the root ``web.https_redirect`` and
the checks that need HTTPS) wait for the HTTPS probe (:mod:`.https_probe`),
which starts with the scan and stops at its deadline (9 s); then each has its
own time limit (15 s), so a scan takes 24 s at most. A dependent that cannot be
measured is not run: the engine writes its result, blocked when HTTPS is refused
on every published address, not evaluated "by dependency" otherwise. The other
checks start at once, as before.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import Awaitable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from . import https_probe
from .egress import DestinationBlocked
from .errors import ConnectionReset, ConnectionTimedOut, Refused, TLSHandshakeError
from .extension import Check, CheckContext
from .model import HTTPS_FAMILY, Finding, Outcome, Role, Status
from .network import Network, NetworkError

log = logging.getLogger(__name__)

CHECK_TIMEOUT = 15.0  # seconds a check may take; for the HTTPS family, counted from the end of the probe

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
        reason = ("network_timeout" if isinstance(e, ConnectionTimedOut) else
                  "reset" if isinstance(e, ConnectionReset) else
                  "refused" if isinstance(e, Refused) else
                  "tls" if isinstance(e, TLSHandshakeError) else "network")
        outcome = Outcome(Status.ERROR, f"check.error.{reason}", evidence={"error": str(e)})
    except Exception as e:  # a bug in a check must not break the scan
        log.exception("check %s failed on %s", check.id, ctx.domain)
        outcome = Outcome(Status.ERROR, "check.error.internal", evidence={"error": f"{e.__class__.__name__}: {e}"})
    try:
        return finding(check, outcome)
    except ValueError as e:  # e.g. a signal this check may not report: a bug, never a verdict
        log.error("check %s gave an outcome its declaration does not allow: %s", check.id, e)
        return finding(check, Outcome(Status.ERROR, "check.error.internal", evidence={"error": str(e)}))


def finding(check: Check, outcome: Outcome) -> Finding:
    """The finding of ``check``, with its place in a family of checks as declared (version 0.4)."""
    return Finding(check.id, check.category, check.weight, outcome, check.family, check.role, check.floor)


async def _not_applicable(check: Check) -> Finding:
    return finding(check, Outcome(Status.NA, "check.na.internal"))


async def _https_family(check: Check, ctx: CheckContext, timeout: float, deadline: float | None) -> Finding:
    """A check of the HTTPS family: after the probe, run, or written by the engine when it cannot be measured."""
    try:
        probe = await https_probe.result(ctx, deadline)
    except Exception as e:  # a bug in the probe must not break the scan
        log.exception("HTTPS probe failed on %s", ctx.domain)
        return finding(check, Outcome(Status.ERROR, "check.error.internal",
                                      evidence={"error": f"{e.__class__.__name__}: {e}"}))
    if check.role is Role.DEPENDENT:
        written = https_probe.dependent_outcome(probe, check.category)
        if written is not None:
            return finding(check, written)
    return await run_check(check, ctx, timeout)


async def scan(domain: str, checks: Iterable[Check], net: Network, timeout: float = CHECK_TIMEOUT,
               now: datetime | None = None, internal: bool = False,
               probe_deadline: float | None = None, history: dict | None = None) -> ScanResult:
    """Runs ``checks`` on ``domain`` concurrently. ``domain`` must already be normalized.

    ``internal``: the scan runs in an internal perimeter; checks made for the
    Internet only are reported as not applicable without running.
    ``probe_deadline``: the HTTPS probe's (default :data:`.https_probe.PROBE_DEADLINE`)."""
    started = now or datetime.now(UTC)
    ctx = CheckContext(domain=domain, net=net, now=started, internal=internal, history=history or {})
    clock = time.monotonic()

    def start(check: Check) -> Awaitable[Finding]:
        if internal and not check.internal:
            return _not_applicable(check)
        if check.family == HTTPS_FAMILY:
            return _https_family(check, ctx, timeout, probe_deadline)
        return run_check(check, ctx, timeout)

    try:
        findings = await asyncio.gather(*(start(check) for check in checks))
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
