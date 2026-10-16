# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The HTTPS probe: one look at every published address of the website, shared by the HTTPS checks (version 0.4).

The website is the domain and ``www``. For each, the probe takes every A and
AAAA address (up to :data:`PER_FAMILY` per family, sorted, so the same ones each
time) and classes it, always with the audited name as TLS SNI and HTTP ``Host``:

- *available*: TLS 1.2 or 1.3 negotiated and an HTTP status received, whatever the
  certificate (a certificate is judged by ``tls.certificate`` only);
- *TLS only*: TLS 1.2 or 1.3 negotiated, no HTTP answer: the TLS checks measure it,
  the page checks cannot, and it proves nothing about availability;
- *obsolete*: TLS 1.2 and 1.3 refused, TLS 1.0 or 1.1 negotiated; everything is
  measured there, over that old version (:mod:`.legacy_tls`);
- *refused*: a confirmed refusal. A first attempt refused (TCP refusal, reset, close
  or alert) is tried again with TLS 1.3 alone, then TLS 1.2 alone, at least
  :data:`RETRY_PAUSE` apart; after a refusal at the TLS stage, TLS 1.1 then 1.0 are
  tried, to tell an old server from a refusal. Refused only when all of them are;
- *unknown*: no answer, or a refusal then no answer. A timeout is never tried again;
- *untestable*: this machine could not test it (no route, the scan's own rule, an
  old version its TLS library cannot offer, beyond the sample, or the probe's deadline).

Port 80 is asked on every address too (the first hop of ``http://host/``), for the
redirection policy of the root check.

The whole probe stops at :data:`PROBE_DEADLINE`: attempts still running are
cancelled and their connections closed, the addresses they were testing are
untestable for that reason, never refused. :data:`CONNECTIONS` connections at
most are open at once.

From the classes come the situations the checks decide on (specification 0.4,
sections 3 and 4): a *total refusal* (every published address tested and
refused: the dependents are blocked), an *obsolete-only* HTTPS (no address in
TLS 1.2 or 1.3, at least one in TLS 1.0 or 1.1, the others refused: the protocol
cap), and an *undetermined* availability (no address in TLS 1.2 or 1.3, a refusal
or an old version observed, and an address that gave nothing conclusive: the
global grade is withheld).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any

from .egress import DestinationBlocked, parse_address
from .errors import (
    ConnectionClosed,
    ConnectionReset,
    ConnectionTimedOut,
    LegacyUnsupported,
    NetworkError,
    Refused,
    TLSAlert,
    TLSHandshakeError,
    Unreachable,
)
from .model import CAUSE_DEPENDENCY, HTTPS_ROOT_CHECK, Outcome, Status, blocked, not_evaluated
from .network import Certificate, HttpReply, Network, TlsSession

if TYPE_CHECKING:
    from .extension import CheckContext

PROBE_DEADLINE = 9.0  # seconds for the whole probe
RETRY_PAUSE = 1.0     # seconds between two confirmation attempts
PER_FAMILY = 4        # addresses tested per family (IPv4, IPv6) of each name
CONNECTIONS = 8       # connections open at once, ports 80 and 443 together
RETRIES = ("TLSv1.3", "TLSv1.2")
LEGACY = ("TLSv1.1", "TLSv1")


class Kind(StrEnum):
    """Class of one address (see the module documentation)."""

    AVAILABLE = "available"
    TLS_ONLY = "tls_only"
    OBSOLETE = "obsolete"
    REFUSED = "refused"
    UNKNOWN = "unknown"
    UNTESTABLE = "untestable"


CONCLUSIVE = frozenset({Kind.AVAILABLE, Kind.OBSOLETE, Kind.REFUSED})  # what the exhaustivity counts
NEGOTIATES = frozenset({Kind.AVAILABLE, Kind.TLS_ONLY, Kind.OBSOLETE})  # what the TLS checks measure


@dataclass
class Attempt:
    """One connection to port 443: what it offered, how it ended, where."""

    offer: str
    result: str          # "ok", "refused", "reset", "close", "alert:<name>", "tls_error", "timeout",
                         # "unreachable", "untestable", "policy", "error" or "interrupted"
    stage: str = ""      # "tcp", "tls" or "http"
    version: str = ""    # negotiated, when "ok"
    at: float = 0.0      # seconds since the probe started


@dataclass
class Port80:
    """The first hop of ``http://host/`` on one address."""

    result: str                  # "reply", "closed", "timeout", "reset", "close", "unreachable",
                                 # "policy", "error" or "interrupted"
    reply: HttpReply | None = None
    blocked: DestinationBlocked | None = None  # the scan's rule refused port 80 of this address


@dataclass
class AddressResult:
    """What the probe found on one (name, address)."""

    host: str
    address: str
    kind: Kind = Kind.UNTESTABLE
    cause: str = ""       # when not conclusive: "network", "tool", "policy" or "budget"
    reason: str = ""      # its detail: "timeout", "no_http", "no_route", "legacy", "sample", "policy", "deadline"…
    attempts: list[Attempt] = field(default_factory=list)
    version: str = ""     # the version negotiated: TLS 1.2 or 1.3, or the old one of an obsolete address
    offer: str = ""       # the offer that negotiated it: the checks read this address with it
    legacy: dict[str, bool | None] = field(default_factory=dict)  # TLS 1.1 and 1.0: accepted, refused, untestable
    certificate: Certificate | None = None
    page: HttpReply | None = None  # GET https://host/ on this address, first hop, certificate not verified
    page_error: str = ""
    port80: Port80 | None = None
    instability: bool = False      # refused, then answered
    default_refused: bool = False  # the browser offer refused, TLS 1.2 alone accepted
    launched: bool = False         # at least one connection was launched
    blocked: DestinationBlocked | None = None
    done: bool = False
    pending: str = ""              # the offer of the attempt in progress

    @property
    def family(self) -> int:
        return ip_address(self.address).version

    @property
    def label(self) -> str:
        return f"{self.host} ({self.address})"


@dataclass
class HostResult:
    """One web host: its published addresses, each with what the probe found."""

    name: str
    addresses: list[AddressResult] = field(default_factory=list)  # every address, IPv4 then IPv6, sorted
    discovery_complete: bool = False  # the A and AAAA questions were both answered
    hints: list[str] = field(default_factory=list)  # DNS HTTPS records: an indication of HTTPS, no more
    dns_errors: list[str] = field(default_factory=list)

    def of(self, *kinds: Kind) -> list[AddressResult]:
        return [a for a in self.addresses if a.kind in kinds]

    @property
    def complete(self) -> bool:
        """Every published address was tested and gave a conclusive result."""
        return self.discovery_complete and all(a.kind in CONCLUSIVE for a in self.addresses)

    @property
    def situation(self) -> str:
        """The host's situation (specification 0.4, section 3), for the texts and the expert view."""
        if not self.addresses:
            return "absent" if self.discovery_complete else "unknown"
        kinds = {a.kind for a in self.addresses}
        if Kind.AVAILABLE in kinds:
            if kinds & {Kind.REFUSED, Kind.OBSOLETE}:
                return "partial"
            return "available" if self.complete else "available_incomplete"
        if kinds & {Kind.REFUSED, Kind.OBSOLETE}:
            if self.complete:
                return "refused" if kinds == {Kind.REFUSED} else "obsolete"
            return "undetermined"
        if not self.discovery_complete or any(a.cause == "network" for a in self.addresses):
            return "unknown"
        return "untestable"


@dataclass
class ProbeResult:
    hosts: list[HostResult]
    deadline: float
    deadline_reached: bool = False
    seconds: float = 0.0

    @property
    def addresses(self) -> list[AddressResult]:
        return [a for h in self.hosts for a in h.addresses]

    def of(self, *kinds: Kind) -> list[AddressResult]:
        return [a for a in self.addresses if a.kind in kinds]

    @property
    def complete(self) -> bool:
        return all(h.complete for h in self.hosts)

    @property
    def absent(self) -> bool:
        """No web host has an address: the HTTPS checks do not apply."""
        return all(h.discovery_complete and not h.addresses for h in self.hosts)

    @property
    def total_refusal(self) -> bool:
        """Every published address of every web host tested and refused: nothing to measure."""
        return self.complete and bool(self.addresses) and all(a.kind is Kind.REFUSED for a in self.addresses)

    @property
    def obsolete_only(self) -> bool:
        """Every published address tested; none in TLS 1.2 or 1.3, one at least in TLS 1.0 or 1.1,
        the others refused."""
        kinds = {a.kind for a in self.addresses}
        return self.complete and Kind.OBSOLETE in kinds and kinds <= {Kind.OBSOLETE, Kind.REFUSED}

    @property
    def undetermined(self) -> bool:
        """No address in TLS 1.2 or 1.3, a refusal or an old version observed, something not conclusive."""
        return (not self.of(Kind.AVAILABLE) and bool(self.of(Kind.REFUSED, Kind.OBSOLETE))
                and not self.complete)

    @property
    def negotiating(self) -> list[AddressResult]:
        return self.of(*NEGOTIATES)

    @property
    def pages(self) -> list[AddressResult]:
        """Addresses whose home page was read (available, or obsolete), in host and address order."""
        return [a for a in self.of(Kind.AVAILABLE, Kind.OBSOLETE) if a.page is not None]

    def exhaustivity(self) -> dict[str, Any]:
        """The fourth indicator: (name, address) pairs discovered, attempted and conclusive."""
        return {
            "discovered": len(self.addresses),
            "attempted": sum(a.launched for a in self.addresses),
            "conclusive": sum(a.kind in CONCLUSIVE for a in self.addresses),
            "sampling_limited": any(a.reason == "sample" for a in self.addresses),
            "discovery_complete": all(h.discovery_complete for h in self.hosts),
            "deadline_reached": self.deadline_reached,
        }

    def missing(self) -> list[tuple[str, dict[str, str | int]]]:
        """Why some addresses gave nothing conclusive: (reason, its parameters), most telling first."""
        reasons: list[tuple[str, dict[str, str | int]]] = []
        if any(not h.discovery_complete for h in self.hosts):
            reasons.append(("discovery", {"hosts": ", ".join(h.name for h in self.hosts if not h.discovery_complete)}))
        for reason in ("sample", "deadline", "no_route", "legacy", "policy", "timeout", "no_http"):
            found = [a for a in self.addresses if a.kind not in CONCLUSIVE and a.reason == reason]
            if found:
                params: dict[str, str | int] = {"count": len(found), "addresses": ", ".join(a.label for a in found)}
                if reason == "deadline":
                    params["seconds"] = round(self.deadline)
                reasons.append((reason, params))
        return reasons

    def evidence(self) -> dict[str, Any]:
        """What the probe saw, for the root's expert view (JSON)."""
        return {"hosts": {h.name: {
            "situation": h.situation,
            "discovery_complete": h.discovery_complete,
            **({"dns_errors": h.dns_errors} if h.dns_errors else {}),
            **({"https_records": h.hints} if h.hints else {}),
            "addresses": {a.address: _address_evidence(a) for a in h.addresses},
        } for h in self.hosts}, "addresses": self.exhaustivity(), "seconds": round(self.seconds, 2)}


def _address_evidence(a: AddressResult) -> dict[str, Any]:
    data: dict[str, Any] = {"class": a.kind.value}
    if a.cause:
        data["cause"], data["reason"] = a.cause, a.reason
    if a.version:
        data["version"] = a.version
    data["attempts"] = [[t.offer, t.result, t.stage, t.version, round(t.at, 2)] for t in a.attempts]
    if a.legacy:
        data["legacy"] = dict(a.legacy)
    if a.page is not None:
        data["page"] = a.page.status
    elif a.page_error:
        data["page"] = a.page_error
    if a.port80 is not None:
        data["port80"] = a.port80.result if a.port80.reply is None else a.port80.reply.status
        location = a.port80.reply.header("location") if a.port80.reply is not None else ""
        if location:
            data["location"] = location
    if a.instability:
        data["instability"] = True
    if a.default_refused:
        data["default_offer_refused"] = True
    return data


# ------------------------------------------------------------------ the probe
async def run(net: Network, domain: str, *, deadline: float | None = None, pause: float | None = None) -> ProbeResult:
    """Probes the web hosts of ``domain``; never raises for a network answer, and returns by ``deadline``."""
    deadline = PROBE_DEADLINE if deadline is None else deadline
    pause = RETRY_PAUSE if pause is None else pause
    start = time.monotonic()
    probe = _Probe(net, asyncio.Semaphore(CONNECTIONS), pause, start)
    hosts = [HostResult(domain), HostResult(f"www.{domain}")]
    reached = False
    try:
        async with asyncio.timeout(deadline):
            async with asyncio.TaskGroup() as group:
                for host in hosts:
                    group.create_task(probe.host(host))
    except TimeoutError:
        reached = True
    for host in hosts:
        for address in host.addresses:
            _interrupted(address, start)
    return ProbeResult(hosts, deadline, reached, time.monotonic() - start)


async def result(ctx: CheckContext, deadline: float | None = None) -> ProbeResult:
    """The probe of this scan, run once and shared by the root and its dependents."""
    return await ctx.shared("https_probe", lambda: run(ctx.net, ctx.domain, deadline=deadline))


@dataclass
class _Probe:
    net: Network
    gate: asyncio.Semaphore
    pause: float
    start: float

    def _now(self) -> float:
        return time.monotonic() - self.start

    async def host(self, host: HostResult) -> None:
        answers = await asyncio.gather(*(self.net.dns(host.name, rtype) for rtype in ("A", "AAAA", "HTTPS")),
                                       return_exceptions=True)
        found: set[str] = set()
        complete = True
        for answer in answers[:2]:
            if isinstance(answer, BaseException):
                if not isinstance(answer, Exception):
                    raise answer
                complete = False
                host.dns_errors.append(str(answer))
                continue
            found |= {str(a) for a in map(parse_address, answer.records) if a is not None}
        if not isinstance(answers[2], BaseException):
            host.hints = list(answers[2].records)
        ordered = sorted(found, key=lambda text: (ip_address(text).version, int(ip_address(text))))
        sampled: list[AddressResult] = []
        for address in ordered:
            result_ = AddressResult(host.name, address)
            if sum(a.family == result_.family for a in sampled) < PER_FAMILY:
                sampled.append(result_)
            else:  # beyond the sample: not tested, and said so
                result_.kind, result_.cause, result_.reason, result_.done = Kind.UNTESTABLE, "tool", "sample", True
            host.addresses.append(result_)
        host.discovery_complete = complete
        async with asyncio.TaskGroup() as group:
            for address_ in sampled:
                group.create_task(self._guarded(address_, self.port443))
                group.create_task(self._guarded(address_, self.port80))

    async def _guarded(self, address: AddressResult, work: Callable[[AddressResult], Awaitable[None]]) -> None:
        """A bug in one task must not stop the others: it leaves the address untestable."""
        try:
            await work(address)
        except Exception as e:  # cancellation still goes through
            address.attempts.append(Attempt(address.pending or "?", "error", "", "", self._now()))
            if not address.done:
                address.kind, address.cause, address.reason, address.done = Kind.UNTESTABLE, "tool", f"bug: {e}", True

    @contextlib.contextmanager
    def _launching(self, address: AddressResult) -> Iterator[None]:
        before = address.launched
        address.launched = True
        try:
            yield
        except DestinationBlocked:
            address.launched = before  # refused by the scan's rule before any connection
            raise

    async def _attempt(self, address: AddressResult, offer: str) -> TlsSession | NetworkError:
        async with self.gate:
            address.pending = offer
            try:
                with self._launching(address):
                    session = await self.net.tls_at(address.host, address.address, offer)
            except NetworkError as e:
                if isinstance(e, DestinationBlocked):
                    address.blocked = e
                address.attempts.append(Attempt(offer, _code(e), e.stage, "", self._now()))
                return e
            finally:
                address.pending = ""
        address.attempts.append(Attempt(offer, "ok", "tls", session.version, self._now()))
        return session

    async def port443(self, address: AddressResult) -> None:
        first = await self._attempt(address, "default")
        if isinstance(first, TlsSession):
            return await self._negotiated(address, first, "default")
        if not _refusal(first):
            return _inconclusive(address, first)
        failures: list[NetworkError] = [first]
        for offer in RETRIES:
            await asyncio.sleep(self.pause)
            outcome = await self._attempt(address, offer)
            if isinstance(outcome, TlsSession):
                # TLS 1.2 alone after the browser offer and TLS 1.3 alone both refused at the TLS stage:
                # the server turns TLS 1.3 away, every time. Anything else is a refusal, then an answer.
                steady = offer == "TLSv1.2" and all(_tls_stage(f) for f in failures)
                address.default_refused, address.instability = steady, not steady
                return await self._negotiated(address, outcome, offer)
            if not _refusal(outcome):
                return _inconclusive(address, outcome)  # a refusal, then no answer: unknown
            failures.append(outcome)
        if not any(_tls_stage(f) for f in failures):
            address.kind, address.done = Kind.REFUSED, True  # TCP refusals only: no old version to try
            return None
        outcomes: dict[str, TlsSession | NetworkError] = {}
        for offer in LEGACY:
            outcome = await self._attempt(address, offer)
            outcomes[offer] = outcome
            if isinstance(outcome, TlsSession):
                address.legacy[offer] = True
            elif isinstance(outcome, LegacyUnsupported):
                address.legacy[offer] = None
            elif _refusal(outcome):
                address.legacy[offer] = False
            else:
                break  # no answer: no further attempt
        sessions = [(offer, o) for offer, o in outcomes.items() if isinstance(o, TlsSession)]
        if sessions:
            return await self._negotiated(address, sessions[0][1], sessions[0][0])
        silent = [o for o in outcomes.values() if isinstance(o, NetworkError)
                  and not _refusal(o) and not isinstance(o, LegacyUnsupported)]
        if silent:
            return _inconclusive(address, silent[0])
        if any(isinstance(o, LegacyUnsupported) for o in outcomes.values()):
            address.kind, address.cause, address.reason, address.done = Kind.UNTESTABLE, "tool", "legacy", True
            return None
        address.kind, address.done = Kind.REFUSED, True
        return None

    async def _negotiated(self, address: AddressResult, session: TlsSession, offer: str) -> None:
        address.version, address.certificate, address.offer = session.version, session.certificate, offer
        legacy = offer in LEGACY
        if legacy:  # an old version negotiates: the address is obsolete, page or not
            address.kind = Kind.OBSOLETE
        async with self.gate:
            try:
                address.page = await self.net.http_at(f"https://{address.host}/", address.address,
                                                      offer=offer, cache=False)
            except NetworkError as e:
                address.page_error = _code(e)
        if not legacy:
            if address.page is not None:
                address.kind = Kind.AVAILABLE
            else:
                address.kind, address.cause, address.reason = Kind.TLS_ONLY, "network", "no_http"
        address.done = True
        return None

    async def port80(self, address: AddressResult) -> None:
        async with self.gate:
            try:
                with self._launching(address):
                    reply = await self.net.http_at(f"http://{address.host}/", address.address, cache=False)
            except Refused:
                address.port80 = Port80("closed")
            except NetworkError as e:
                address.port80 = Port80(_code(e), blocked=e if isinstance(e, DestinationBlocked) else None)
            else:
                address.port80 = Port80("reply", reply)


def _interrupted(address: AddressResult, start: float) -> None:
    """At the deadline: what was still running is untestable for that reason, never a refusal."""
    if address.pending:
        address.attempts.append(Attempt(address.pending, "interrupted", "", "", time.monotonic() - start))
        address.pending = ""
    if not address.done:
        if address.version in LEGACY:
            address.kind = Kind.OBSOLETE  # the old version negotiated: conclusive, only the page is missing
        elif address.version:
            address.kind, address.cause, address.reason = Kind.TLS_ONLY, "budget", "deadline"
        else:
            address.kind, address.cause, address.reason = Kind.UNTESTABLE, "budget", "deadline"
        if address.version and address.page is None:
            address.page_error = "interrupted"
        address.done = True
    if address.port80 is None and address.reason != "sample":
        address.port80 = Port80("interrupted")


def _code(error: NetworkError) -> str:
    if isinstance(error, DestinationBlocked):
        return "policy"
    if isinstance(error, Refused):
        return "refused"
    if isinstance(error, ConnectionClosed):
        return "close"
    if isinstance(error, ConnectionReset):
        return "reset"
    if isinstance(error, TLSAlert):
        return f"alert:{error.alert}"
    if isinstance(error, TLSHandshakeError):
        return "tls_error"
    if isinstance(error, ConnectionTimedOut):
        return "timeout"
    if isinstance(error, Unreachable):
        return "unreachable"
    if isinstance(error, LegacyUnsupported):
        return "untestable"
    return "error"


def _refusal(error: NetworkError) -> bool:
    """A definite no from the server: TCP refusal, reset, close or alert."""
    return (isinstance(error, (Refused, ConnectionReset, TLSHandshakeError))
            and not isinstance(error, DestinationBlocked))


def _tls_stage(error: NetworkError) -> bool:
    return isinstance(error, (ConnectionReset, TLSHandshakeError))


def _inconclusive(address: AddressResult, error: NetworkError) -> None:
    if isinstance(error, DestinationBlocked):
        address.kind, address.cause, address.reason = Kind.UNTESTABLE, "policy", "policy"
    elif isinstance(error, Unreachable):
        address.kind, address.cause, address.reason = Kind.UNTESTABLE, "tool", "no_route"
    elif isinstance(error, LegacyUnsupported):
        address.kind, address.cause, address.reason = Kind.UNTESTABLE, "tool", "legacy"
    else:
        address.kind, address.cause, address.reason = Kind.UNKNOWN, "network", "timeout"
    address.done = True


# ---------------------------------------------------------------- decisions
def dependent_outcome(probe: ProbeResult, category: str) -> Outcome | None:
    """What the engine writes for a dependent of the HTTPS root instead of running it; None: run it.

    ``category`` tells the TLS checks (they need a TLS negotiation) from the page checks (they
    need an HTTP answer). Blocked only on a total refusal; not evaluated "by dependency" when
    what it measures may exist but nothing conclusive was obtained (specification 0.4, section 4)."""
    if probe.absent:
        return None  # the check says itself that it does not apply
    tls = category == "tls"
    if probe.negotiating if tls else probe.pages:
        return None
    if probe.total_refusal:
        return blocked("check.blocked", {"blocked_by": HTTPS_ROOT_CHECK, "reason": "https_refused"})
    if not tls and probe.negotiating:  # TLS negotiated, but no page answered: as in 0.3.2
        errors = {a.page_error for a in probe.negotiating if a.page_error}
        key = ("check.error.network_timeout" if "timeout" in errors else
               "check.error.reset" if errors & {"reset", "close"} else "check.error.network")
        return Outcome(Status.ERROR, key, evidence={"cause": "network", "depends_on": HTTPS_ROOT_CHECK,
                                                    "addresses": [a.label for a in probe.negotiating]})
    missing = probe.missing()
    notes = [{"key": f"check.dependency.{reason}", "params": params} for reason, params in missing]
    return not_evaluated("check.error.dependency", {
        "cause": CAUSE_DEPENDENCY, "depends_on": HTTPS_ROOT_CHECK,
        "reason": missing[0][0] if missing else "https", **({"notes": notes} if notes else {})})
