# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The SMTP probe of one scan: which MX to try, in which order, within which time (version 0.7).

What it does, in three steps
----------------------------
1. **Discovery.** The MX the domain publishes, read exactly as the mail checks read
   them (``mail._mx_records``): preference, name, the null MX "0 ." (RFC 7505). Each
   name is checked as a host name first; an invalid one is kept, marked
   ``invalid_mx_name``, and never resolved nor contacted (decision A of the review).
   The valid ones are sorted by preference then name, duplicates merged, and the
   first :data:`MAX_MX` are resolved: A, AAAA, and CNAME, an alias being reported
   (RFC 2181 §10.3 says an MX must not name one) and still probed under its
   published name, which stays the TLS name.
2. **Selection.** A fair pass over those MX: one address of each MX before a second
   of any, IPv4 and IPv6 in turn within an MX, up to :data:`MAX_ATTEMPTS` attempts
   (8 MX with an IPv4 and an IPv6 address each: 16). Addresses beyond are not tried,
   and said so (``sample``).
3. **Attempts.** Each selected address gets one verifying attempt, at most
   :data:`CONNECTIONS` at once. A certificate refused by verification may then be
   read once per MX, on the same address, only with an attempt left over by the
   selection (decision C): it never replaces the refusal, it is kept beside it. A
   reading the deadline cuts is said so (``reading_interrupted``), with what it
   observed, never with a certificate it did not read.

Time
----
The whole probe has ``min(12 s, CHECK_TIMEOUT − 2 s)`` (F02, T03): 12 s, 8 s and
2 s for 15, 10 and 4. The deadline is set once, when the probe starts, and covers the
DNS questions, the waits for a free connection and every attempt; a certificate
reading never extends it. Each attempt is given the deadline and returns its
observation by itself before it (core/smtp.py); a safety net
(:data:`SAFETY_SECONDS` after the deadline) stops whatever still runs, and the
addresses it stopped are marked ``deadline``. What was observed before is kept: the
observations are stored as they come, never collected at the end, so nothing is lost
to a timeout, and the probe returns before the engine stops the check (2 s later).

What it never does
------------------
No verdict: it returns a :class:`ProbeResult`, the observations of every address,
and the decision (matrix F05) reads them. No socket either: every attempt goes
through :meth:`~posture_cockpit.core.network.LiveNetwork.smtp_attempt`, which checks
again, by itself, every condition checked here. With the probe off, or in an internal
perimeter, the MX are discovered (passive DNS) and nothing is attempted.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from ipaddress import ip_address
from itertools import zip_longest
from typing import TYPE_CHECKING, Any

from ..config import SMTP_CHECK_MARGIN, check_host_name
from ..core.egress import parse_address
from ..core.errors import NetworkError
from ..core.network import SMTP_CONNECTIONS, DnsAnswer, Limits, SmtpObservation, SmtpPurpose
from ..core.smtp import Reason
from .mail import _mx_records

if TYPE_CHECKING:
    from ..core.extension import CheckContext

DEADLINE_CAP = 12.0                     # seconds: the probe's deadline is min(12 s, CHECK_TIMEOUT − 2 s) (F02)
MAX_MX = 8                              # MX tried, by preference
MAX_ATTEMPTS = Limits().smtp_attempts   # 16 attempts per scan, certificate readings included
CONNECTIONS = SMTP_CONNECTIONS          # 8 attempts at once
# After the deadline, what still runs is stopped. An attempt returns by the deadline on its own: this only
# stops one that would not (a bug), and still leaves the engine 1.5 s before its own time limit.
SAFETY_SECONDS = 0.5

__all__ = ["CONNECTIONS", "DEADLINE_CAP", "MAX_ATTEMPTS", "MAX_MX", "SAFETY_SECONDS", "AddressProbe", "MxProbe",
           "ProbeResult", "deadline_seconds", "measure", "result"]


def deadline_seconds(check_timeout: float) -> float:
    """The probe's time: min(12 s, CHECK_TIMEOUT − 2 s); the engine keeps the 2 s to stop the check."""
    return min(DEADLINE_CAP, check_timeout - SMTP_CHECK_MARGIN)


@dataclass
class AddressProbe:
    """One published address of one MX, and what was observed on it."""

    mx_name: str
    address: str
    observations: list[SmtpObservation] = field(default_factory=list)  # in order: verify, then a reading
    planned: bool = False   # selected by the fair pass
    pending: str = ""       # the purpose of the attempt launched and not observed yet (at the end: interrupted)
    interrupted: list[str] = field(default_factory=list)  # purposes of the attempts the deadline cut, unobserved
    cause: str = ""         # nothing observed: "budget" ("sample", "deadline"), "policy" ("probe_off",
    reason: str = ""        # "internal") or "tool" (a bug in the probe, said as such)

    @property
    def family(self) -> int:
        return ip_address(self.address).version

    @property
    def verification(self) -> SmtpObservation | None:
        return next((o for o in self.observations if o.purpose == SmtpPurpose.VERIFY), None)

    @property
    def reading(self) -> SmtpObservation | None:
        return next((o for o in self.observations if o.purpose == SmtpPurpose.READ_CERTIFICATE), None)

    @property
    def reading_interrupted(self) -> bool:
        """The certificate reading launched after a refused verification was cut by the deadline (R4).

        Either its own observation says so (refused before connecting or while waiting for a connection,
        or a dialogue stopped at the deadline, with what it read and no certificate), or it gave none and
        is listed in :attr:`interrupted`. The refused verification stays as observed; no certificate and no
        TLS result stand for what was not read."""
        reading = self.reading
        return SmtpPurpose.READ_CERTIFICATE in self.interrupted or (reading is not None and _cut(reading))


@dataclass
class MxProbe:
    """One published MX: its name, its addresses, and why it was not tried, when it was not."""

    name: str                    # as published: lower case, without the root's dot (made printable if invalid)
    preference: int | None
    valid: bool = True           # a host name (config.check_host_name)
    cname: tuple[str, ...] = ()  # the name is an alias of these (reported; the published name stays the TLS name)
    addresses: list[AddressProbe] = field(default_factory=list)  # IPv4 then IPv6, in address order
    dns_errors: list[str] = field(default_factory=list)
    discovery_complete: bool = False  # the A and AAAA questions were both answered
    cause: str = ""              # not tried: "invalid_mx_name" ("syntax"), "budget" ("sample": beyond MAX_MX)
    reason: str = ""


@dataclass
class ProbeResult:
    """What the SMTP probe found: every published MX, its addresses, every observation. Never a verdict."""

    enabled: bool                # the probe was on (the structured probe_enabled of the specification)
    internal: bool               # the scan ran in an internal perimeter: nothing was attempted
    deadline: float              # seconds the probe had
    mx: list[MxProbe] = field(default_factory=list)  # by preference then name, invalid names included
    null_mx: bool = False        # a "0 ." record (alone: the domain receives no mail)
    discovery_error: str = ""    # the MX question itself failed: nothing is known of the MX
    deadline_reached: bool = False
    seconds: float = 0.0
    budget_spent: int = 0        # SMTP attempts spent, as the network itself counted them

    @property
    def addresses(self) -> list[AddressProbe]:
        return [a for m in self.mx for a in m.addresses]

    @property
    def observations(self) -> list[SmtpObservation]:
        return [o for a in self.addresses for o in a.observations]

    def exhaustivity(self) -> dict[str, Any]:
        """How much of what is published was tried, for the decision.

        Three counts that are not one another (R2 of the review of PR-B2): ``budget_spent``, the attempts
        the network counted; ``consumed``, the observations that spent one; ``sockets``, those that opened
        a socket. A refusal spends nothing; a machine without IPv6 spends one and opens no socket.
        ``interrupted``: the attempts the deadline cut before they gave an observation (R4), which may or
        may not have been counted: ``consumed <= budget_spent <= consumed + interrupted``.
        ``certificate_readings``: the readings observed; ``certificate_readings_interrupted``: the readings
        the deadline cut, observed or not (:attr:`AddressProbe.reading_interrupted`)."""
        observations = self.observations
        return {
            "mx": len(self.mx),
            "mx_invalid": sum(not m.valid for m in self.mx),
            "mx_beyond_sample": sum(m.reason == "sample" for m in self.mx),
            "addresses": len(self.addresses),
            "planned": sum(a.planned for a in self.addresses),
            "budget_spent": self.budget_spent,
            "consumed": sum(o.consumed for o in observations),
            "sockets": sum(o.socket for o in observations),
            "dialogues": sum(o.dialogue is not None for o in observations),
            "interrupted": sum(len(a.interrupted) for a in self.addresses),
            "certificate_readings": sum(o.purpose == SmtpPurpose.READ_CERTIFICATE for o in observations),
            "certificate_readings_interrupted": sum(a.reading_interrupted for a in self.addresses),
            "discovery_complete": not self.discovery_error and all(m.discovery_complete for m in self.mx
                                                                   if m.valid and not m.cause),
            "deadline_reached": self.deadline_reached,
        }


# ------------------------------------------------------------------ the probe
async def measure(ctx: CheckContext) -> ProbeResult:
    """The SMTP probe of ``ctx.domain``; never raises for a network answer, and returns before the engine's limit."""
    loop = asyncio.get_running_loop()
    start = loop.time()
    seconds = deadline_seconds(ctx.check_timeout)
    deadline = start + seconds  # once, for everything below
    probe = ProbeResult(enabled=ctx.smtp.enabled, internal=ctx.internal, deadline=seconds)
    try:
        async with asyncio.timeout_at(deadline):
            await _discover(ctx, probe)
    except TimeoutError:
        probe.deadline_reached = True
    if probe.enabled and not probe.internal and not probe.deadline_reached:
        await _attempts(ctx, probe, deadline)
        probe.budget_spent = ctx.net.smtp_spent()
    _settle(probe)
    probe.seconds = loop.time() - start
    return probe


async def result(ctx: CheckContext) -> ProbeResult:
    """The SMTP probe of this scan, run once and shared."""
    return await ctx.shared("smtp_probe", lambda: measure(ctx))


async def _discover(ctx: CheckContext, probe: ProbeResult) -> None:
    try:
        records = await _mx_records(ctx)
    except (NetworkError, IndexError) as e:  # IndexError: an empty MX record, which no check can read either
        probe.discovery_error = _shown(str(e) or e.__class__.__name__)
        return
    published: dict[str, int | None] = {}
    for preference, host in records:
        if not host:
            probe.null_mx = True
            continue
        try:
            name = check_host_name(host, "MX name")
        except ValueError:
            # Kept in the evidence, never resolved nor contacted (decision A).
            probe.mx.append(MxProbe(_shown(host), preference, valid=False, cause="invalid_mx_name", reason="syntax"))
            continue
        if name not in published or _rank(preference) < _rank(published[name]):
            published[name] = preference  # a name published twice is tried once, at its best preference
    probe.mx += [MxProbe(name, preference) for name, preference in published.items()]
    probe.mx.sort(key=lambda m: (_rank(m.preference), m.name))
    tried = [m for m in probe.mx if m.valid]
    for mx in tried[MAX_MX:]:
        mx.cause, mx.reason = "budget", "sample"
    await asyncio.gather(*(_resolve(ctx, mx) for mx in tried[:MAX_MX]))


async def _resolve(ctx: CheckContext, mx: MxProbe) -> None:
    answers = await asyncio.gather(*(ctx.net.dns(mx.name, rtype) for rtype in ("A", "AAAA", "CNAME")),
                                   return_exceptions=True)
    found = set()
    complete = True
    for answer in answers[:2]:
        if not isinstance(answer, DnsAnswer):
            if not isinstance(answer, Exception):
                raise answer  # a cancellation goes through
            complete = False
            mx.dns_errors.append(_shown(str(answer)))
            continue
        found |= {a for a in map(parse_address, answer.records) if a is not None}
    alias = answers[2]
    if isinstance(alias, DnsAnswer):
        mx.cname = tuple(r.lower().rstrip(".") for r in alias.records)
    elif not isinstance(alias, Exception):
        raise alias
    mx.addresses = [AddressProbe(mx.name, str(a)) for a in sorted(found, key=lambda a: (a.version, int(a)))]
    mx.discovery_complete = complete


def _plan(probe: ProbeResult) -> list[AddressProbe]:
    """The fair pass: round by round, one address of each MX in preference order, IPv4 and IPv6 in turn."""
    queues = []
    for mx in probe.mx:
        if mx.valid and not mx.cause:
            ipv4 = [a for a in mx.addresses if a.family == 4]
            ipv6 = [a for a in mx.addresses if a.family == 6]
            queues.append([a for pair in zip_longest(ipv4, ipv6) for a in pair if a is not None])
    planned: list[AddressProbe] = []
    for turn in range(max(map(len, queues), default=0)):
        for queue in queues:
            if turn < len(queue) and len(planned) < MAX_ATTEMPTS:
                planned.append(queue[turn])
    for address in planned:
        address.planned = True
    return planned


async def _attempts(ctx: CheckContext, probe: ProbeResult, deadline: float) -> None:
    planned = _plan(probe)
    if not planned:
        return
    run = _Run(ctx, asyncio.Semaphore(CONNECTIONS), deadline, spare=MAX_ATTEMPTS - len(planned))
    try:
        async with asyncio.timeout_at(deadline + SAFETY_SECONDS):
            async with asyncio.TaskGroup() as group:
                for address in planned:
                    group.create_task(run.address(address))
    except TimeoutError:
        probe.deadline_reached = True


@dataclass
class _Run:
    ctx: CheckContext
    gate: asyncio.Semaphore
    deadline: float
    spare: int                                   # attempts the selection left: for certificate readings only
    read: set[str] = field(default_factory=set)  # MX whose certificate reading was launched

    async def address(self, address: AddressProbe) -> None:
        """The verifying attempt, then, after a refused certificate, its reading if allowed (decision C)."""
        try:
            first = await self._attempt(address, SmtpPurpose.VERIFY)
            refused = first.dialogue is not None and first.dialogue.reason is Reason.CERTIFICATE_REFUSED
            # Checked and taken with no pause in between: two refusals of one MX cannot both start a reading.
            # With no time left it is launched all the same: the network refuses it (budget, deadline), and
            # the reading is said interrupted rather than left out (R4 of the review of PR-B2).
            if refused and self.spare > 0 and address.mx_name not in self.read:
                self.read.add(address.mx_name)
                self.spare -= 1
                await self._attempt(address, SmtpPurpose.READ_CERTIFICATE)
        except Exception as e:  # a bug in one attempt must not stop the others; a cancellation goes through
            address.pending = ""
            address.cause, address.reason = "tool", _shown(f"bug: {e.__class__.__name__} {e}")[:200]

    async def _attempt(self, address: AddressProbe, purpose: str) -> SmtpObservation:
        address.pending = purpose  # from here on, an attempt the safety net stops is interrupted
        async with self.gate:
            observation = await self.ctx.net.smtp_attempt(address.mx_name, address.address, purpose,
                                                          deadline=self.deadline)
        address.observations.append(observation)  # kept at once: a later timeout cannot take it away
        address.pending = ""
        return observation


def _settle(probe: ProbeResult) -> None:
    """Why the addresses without an observation have none; an attempt still pending was interrupted.

    An attempt the safety net stopped gave no observation: its purpose goes to ``interrupted`` (a
    certificate reading among them leaves the refused verification as observed). ``deadline_reached``
    then says whether the deadline cut anything: the safety net, or an attempt that stopped at the
    deadline by itself (before connecting, while waiting for a connection, or during its dialogue)."""
    for address in probe.addresses:
        if address.pending:
            address.interrupted.append(address.pending)
            address.pending = ""
        if address.observations or address.cause:
            continue
        if not probe.enabled:
            address.cause, address.reason = "policy", "probe_off"
        elif probe.internal:
            address.cause, address.reason = "policy", "internal"
        elif address.planned or address.interrupted or probe.deadline_reached:
            address.cause, address.reason = "budget", "deadline"
        else:
            address.cause, address.reason = "budget", "sample"
    probe.deadline_reached = (probe.deadline_reached or any(a.reason == "deadline" or a.interrupted
                                                            for a in probe.addresses)
                              or any(map(_cut, probe.observations)))


def _cut(observation: SmtpObservation) -> bool:
    """The deadline stopped this attempt: before connecting or a connection, or during its dialogue."""
    return observation.reason == "deadline" or (observation.dialogue is not None
                                                and observation.dialogue.reason is Reason.DEADLINE)


def _rank(preference: int | None) -> tuple[bool, int]:
    """Lower preferences first; a record without a preference last."""
    return preference is None, preference or 0


def _shown(text: str) -> str:
    """A name or a message from the DNS, made safe to keep: printable ASCII, at most 255 characters."""
    return "".join(c if " " <= c <= "~" else "?" for c in text[:255])
