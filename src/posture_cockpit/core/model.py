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
    """Result of one check."""

    OK = "ok"        # nothing to do
    WARN = "warn"    # could be better ("à améliorer")
    FAIL = "fail"    # needs fixing ("critique")
    INFO = "info"    # worth knowing, not part of the score
    ERROR = "error"  # could not be checked (timeout, unreachable server): not part of the score

    @property
    def scored(self) -> bool:
        return self in (Status.OK, Status.WARN, Status.FAIL)


# Share of a check's weight earned in the score, by status.
CREDIT: Mapping[Status, float] = {Status.OK: 1.0, Status.WARN: 0.5, Status.FAIL: 0.0}


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
    """What a check returns. Build it with :func:`ok`, :func:`warn`, :func:`fail` or :func:`info`."""

    status: Status
    summary: str                                            # translation key
    params: Mapping[str, str | int] = field(default_factory=dict)  # values used in the texts
    evidence: Mapping[str, Any] = field(default_factory=dict)      # raw values, for the expert view
    remedy: Remedy | None = None


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


@dataclass(frozen=True)
class Finding:
    """An outcome together with the identity of the check that produced it."""

    check_id: str
    category: str
    weight: int
    outcome: Outcome

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
        outcome = Outcome(Status(status), data["summary"], data.get("params", {}), data.get("evidence", {}), remedy)
        return cls(check_id, category, weight, outcome)
