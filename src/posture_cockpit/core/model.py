# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The data model shared by the engine, the extensions, the storage and the pages.

A *check* looks at one thing (say, the DMARC record of a domain) and returns an
:class:`Outcome`: a status, a sentence describing what was found, the raw values
it saw and, when something has to change, a :class:`Remedy`.

The engine wraps each outcome into a :class:`Finding`, which also records which
check produced it and how much it weighs in the score. Findings are what the
database stores and what the pages and the PDF report display.

Texts are never stored: an outcome holds translation *keys* and their
parameters, so the same scan can be shown in French or in English.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal


class Status(StrEnum):
    """Result of one check.

    Only OK, WARN and FAIL are part of the score. NA and INFO are left out on
    purpose (the check has nothing to judge here). ERROR is left out too, but
    lowers the *coverage* of the scan: a check that should have run and could
    not is a gap in the evaluation, never a success (see :mod:`.scoring`).

    BLOCKED (version 0.4) is a check that could not be measured because what it
    measures does not exist for an observed reason: every address of the website
    refuses HTTPS, so there is no certificate or page to look at. It is left out
    of the score and of the scoring coverage (the refusal is already counted once,
    by the check that observed it), but it is shown, and counted in the
    diagnostic coverage."""

    OK = "ok"        # nothing to do
    WARN = "warn"    # could be better ("à améliorer")
    FAIL = "fail"    # needs fixing ("critique")
    NA = "na"        # does not apply (no website, no mail, check not made for internal audits)
    INFO = "info"    # worth knowing, nothing to judge
    ERROR = "error"  # not evaluated: timeout, unreachable server, destination refused, bug
    BLOCKED = "blocked"  # not measurable: the check it depends on observed a confirmed failure

    @property
    def scored(self) -> bool:
        return self in (Status.OK, Status.WARN, Status.FAIL)

    @property
    def applicable(self) -> bool:
        """Whether the check should have produced a verdict: scored, or failed to run.

        This is what the *scoring* coverage counts; a blocked check is not part of it."""
        return self.scored or self is Status.ERROR

    @property
    def diagnostic(self) -> bool:
        """Whether the check counts in the *diagnostic* coverage: applicable, or blocked."""
        return self.applicable or self is Status.BLOCKED


class Signal(StrEnum):
    """Facts a check reports for the scoring rules, beside its status (version 0.4).

    Only version 0.4 writes them, so a scan stored by an older version never
    carries one: its score, grade and coverage stay what they were."""

    # On the HTTPS root check:
    HTTPS_OBSOLETE_ONLY = "https.obsolete_only"  # every address tested, none in TLS 1.2+, one at least in TLS 1.0/1.1
    HTTPS_UNDETERMINED = "https.undetermined"    # no address in TLS 1.2+, a confirmed failure, an inconclusive address
    # On tls.certificate:
    CERTIFICATE_UNAUTHENTICATED = "tls.certificate.unauthenticated"  # a browser cannot authenticate the server


class Role(StrEnum):
    """Place of a check in a family of checks that depend on one another (version 0.4)."""

    ROOT = "root"            # observes whether the thing the others measure exists (HTTPS answers)
    DEPENDENT = "dependent"  # measures something that only exists when the root's thing does


HTTPS_FAMILY = "https"                 # the family of the checks that need HTTPS
HTTPS_ROOT_CHECK = "web.https_redirect"  # the only HTTPS root, the only check that may report its signals
CERTIFICATE_CHECK = "tls.certificate"  # the only check that may report CERTIFICATE_UNAUTHENTICATED


# Share of a check's weight earned in the score, by status.
CREDIT: Mapping[Status, float] = {Status.OK: 1.0, Status.WARN: 0.5, Status.FAIL: 0.0}

# Version 0.4: ``evidence["cause"]`` of a check that could not be evaluated because
# the check it depends on could not establish whether the thing it measures exists.
CAUSE_DEPENDENCY = "dependency"


class Effort(StrEnum):
    """Who fixes it, and how hard it is. Drives the wording of the plan."""

    EASY = "easy"          # a few clicks at the DNS host, done by the user
    MEDIUM = "medium"      # needs care, or a check beforehand
    DELEGATE = "delegate"  # done by whoever runs the website or the mail service


@dataclass(frozen=True)
class DnsChange:
    """A DNS record to add or to delete at the DNS host.

    ``name`` is relative to the domain, as DNS hosts ask for it: ``_dmarc``,
    ``www``, or ``@`` for the domain itself."""

    action: Literal["add", "delete"]
    rtype: str
    name: str
    value: str


@dataclass(frozen=True)
class Remedy:
    """How to bring a check back to OK."""

    minutes: int
    effort: Effort
    dns: tuple[DnsChange, ...] = ()
    # Translation key of a ready-to-send message, for fixes made by someone else.
    message: str = ""
    # Translation key of a short explanation of the fix, in plain words.
    how: str = ""


@dataclass(frozen=True)
class Outcome:
    """What a check returns. Build it with :func:`ok`, :func:`warn`, :func:`fail`, :func:`na` or :func:`info`."""

    status: Status
    summary: str                                            # translation key
    params: Mapping[str, str | int] = field(default_factory=dict)  # values used in the texts
    evidence: Mapping[str, Any] = field(default_factory=dict)      # raw values, for the expert view
    remedy: Remedy | None = None
    signals: frozenset[str] = frozenset()                   # facts for the scoring rules (see Signal)


def ok(summary: str, evidence: Mapping[str, Any] | None = None, **params: str | int) -> Outcome:
    return Outcome(Status.OK, summary, params, evidence or {})


def warn(summary: str, remedy: Remedy | None = None, evidence: Mapping[str, Any] | None = None,
         **params: str | int) -> Outcome:
    return Outcome(Status.WARN, summary, params, evidence or {}, remedy)


def fail(summary: str, remedy: Remedy | None = None, evidence: Mapping[str, Any] | None = None,
         **params: str | int) -> Outcome:
    return Outcome(Status.FAIL, summary, params, evidence or {}, remedy)


def info(summary: str, evidence: Mapping[str, Any] | None = None, **params: str | int) -> Outcome:
    return Outcome(Status.INFO, summary, params, evidence or {})


def na(summary: str, evidence: Mapping[str, Any] | None = None, **params: str | int) -> Outcome:
    """The check does not apply to this domain; ``summary`` says why (e.g. "no website")."""
    return Outcome(Status.NA, summary, params, evidence or {})


def not_evaluated(summary: str, evidence: Mapping[str, Any] | None = None, **params: str | int) -> Outcome:
    """The check applies but could not reach a verdict, for a reason it knows (e.g. this machine
    cannot test TLS 1.0). Like a network error, it lowers the coverage of the scan."""
    return Outcome(Status.ERROR, summary, params, evidence or {})


def blocked(summary: str, evidence: Mapping[str, Any] | None = None, **params: str | int) -> Outcome:
    """The check cannot be measured: the check it depends on observed a confirmed failure (version 0.4)."""
    return Outcome(Status.BLOCKED, summary, params, evidence or {})


def _signal_problem(signal: str, finding: Finding) -> str:
    """Why ``finding`` may not report ``signal``; "" when it may.

    The root's two signals come with its critical verdict; the certificate's with its own."""
    try:
        known = Signal(signal)
    except ValueError:
        return f"unknown signal {signal!r}"
    if known is Signal.CERTIFICATE_UNAUTHENTICATED:
        carrier = (finding.check_id == CERTIFICATE_CHECK and finding.family == HTTPS_FAMILY
                   and finding.role is Role.DEPENDENT)
        where = CERTIFICATE_CHECK
    else:
        carrier = (finding.check_id == HTTPS_ROOT_CHECK and finding.family == HTTPS_FAMILY
                   and finding.role is Role.ROOT)
        where = HTTPS_ROOT_CHECK
    if not carrier:
        return f"{known.value} may only be reported by {where}"
    if finding.status is not Status.FAIL:
        return f"{known.value} comes with a critical verdict, not {finding.status.value}"
    return ""


@dataclass(frozen=True)
class Finding:
    """An outcome together with the identity of the check that produced it.

    ``family``, ``role`` and ``floor`` (version 0.4) place the check in a family of
    checks that depend on one another, as declared when the scan ran: the HTTPS
    root and the checks that need HTTPS. ``floor`` is a dependent's lowest credit
    among the verdicts it declares that are not critical; the scoring caps use it.
    They are stored with the finding, like its weight, so that a stored scan is
    always scored with the rules of its own time."""

    check_id: str
    category: str
    weight: int
    outcome: Outcome
    family: str | None = None
    role: Role | None = None
    floor: float | None = None

    def __post_init__(self) -> None:
        """Refuses a finding the scoring rules could misread, however it was made (by the engine,
        read from storage, built by hand): a dependent without a usable floor, or a signal reported
        by a check that may not report it."""
        if (self.family is None) != (self.role is None):
            raise ValueError(f"{self.check_id}: a family needs a role, and a role needs a family")
        if self.role is Role.DEPENDENT and (self.floor is None or not 0 < self.floor <= 1):
            raise ValueError(f"{self.check_id}: a dependent needs a floor above 0 and at most 1, not {self.floor!r}")
        for signal in self.outcome.signals:
            problem = _signal_problem(signal, self)
            if problem:
                raise ValueError(f"{self.check_id}: {problem}")

    @property
    def status(self) -> Status:
        return self.outcome.status

    # The database keeps the outcome as JSON; these two functions are the only
    # place that knows its shape.
    def outcome_json(self) -> dict[str, Any]:
        o = self.outcome
        data: dict[str, Any] = {"summary": o.summary, "params": dict(o.params), "evidence": dict(o.evidence)}
        if o.remedy is not None:
            data["remedy"] = {
                "minutes": o.remedy.minutes,
                "effort": o.remedy.effort.value,
                "dns": [vars(change) for change in o.remedy.dns],
                "message": o.remedy.message,
                "how": o.remedy.how,
            }
        # Version 0.4 only: written when present, so findings without them keep their 0.3 shape.
        if o.signals:
            data["signals"] = sorted(o.signals)
        if self.family is not None and self.role is not None:
            data["family"] = {"name": self.family, "role": self.role.value, "floor": self.floor}
        return data

    @classmethod
    def from_stored(cls, check_id: str, category: str, weight: int, status: str,
                    data: Mapping[str, Any]) -> Finding:
        remedy = None
        if data.get("remedy"):
            r = data["remedy"]
            remedy = Remedy(minutes=int(r["minutes"]), effort=Effort(r["effort"]),
                            dns=tuple(DnsChange(**change) for change in r.get("dns", [])),
                            message=r.get("message", ""), how=r.get("how", ""))
        outcome = Outcome(Status(status), data["summary"], data.get("params", {}), data.get("evidence", {}), remedy,
                          frozenset(data.get("signals", ())))
        family = data.get("family") or {}
        floor = family.get("floor")
        return cls(check_id, category, weight, outcome, family.get("name"),
                   Role(family["role"]) if family.get("role") else None,
                   float(floor) if floor is not None else None)
