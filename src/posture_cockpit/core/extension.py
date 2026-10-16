# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The extension API: how checks are declared, and what they receive.

An extension is a module that creates an :class:`Extension` and decorates its
check functions with it::

    extension = Extension("mail", name="Messagerie", version="1.0",
                          messages=load_messages(Path(__file__).parent / "locales", "mail"))

    @extension.check("dmarc", category="mail", weight=10)
    async def dmarc(ctx: CheckContext) -> Outcome:
        answer = await ctx.net.dns(f"_dmarc.{ctx.domain}", "TXT")
        ...
        return ok("mail.dmarc.enforced", policy="reject")

A check function receives a :class:`CheckContext` and returns an
:class:`~.model.Outcome`. It must stay passive: everything it learns comes
from ``ctx.net`` (see :mod:`.network`). Its texts are translation keys, found in
the extension's ``messages`` (one dictionary per language).

The full guide, with a complete example package, is docs/EXTENSIONS.md.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable, Collection, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

from .model import CREDIT, HTTPS_FAMILY, HTTPS_ROOT_CHECK, Outcome, Role, Status
from .network import Network

CheckFunction = Callable[["CheckContext"], Awaitable[Outcome]]
_ID = re.compile(r"[a-z][a-z0-9_]{0,39}")
T = TypeVar("T")

# Categories known by the core. An extension may add its own: it then provides
# the texts "category.<name>" and "category.<name>.detail" in its messages.
CATEGORIES = ("mail", "web", "tls", "dns")


@dataclass(frozen=True)
class Check:
    """One check, as registered by an extension."""

    id: str          # "<extension>.<name>", stable: it is stored with every result
    category: str
    weight: int      # importance in the score, from 1 (minor) to 10 (essential)
    run: CheckFunction
    extension: str
    internal: bool = True  # whether it applies to sites audited inside an internal perimeter
    # Version 0.4: a family of checks that depend on one another (e.g. "https"), this
    # check's place in it, and the verdicts it can give (OK, WARN, FAIL).
    family: str | None = None
    role: Role | None = None
    verdicts: frozenset[Status] | None = None

    @property
    def floor(self) -> float | None:
        """Lowest credit among the declared verdicts that are not critical; None without a declaration."""
        if not self.verdicts:
            return None
        credits = [CREDIT[v] for v in self.verdicts if v is not Status.FAIL]
        return min(credits) if credits else None

    @property
    def title_key(self) -> str:
        return f"{self.id}.title"   # short name: "Politique DMARC"

    @property
    def why_key(self) -> str:
        return f"{self.id}.why"     # why it matters, in plain words


class Extension:
    """A named set of checks with their texts."""

    def __init__(self, id: str, *, name: str, version: str, description: str = "",
                 messages: Mapping[str, Mapping[str, str]] | None = None):
        if not _ID.fullmatch(id):
            raise ValueError(f"invalid extension id {id!r}: lower-case letters, digits and _")
        self.id = id
        self.name = name
        self.version = version
        self.description = description
        self.messages: dict[str, dict[str, str]] = {lang: dict(texts) for lang, texts in (messages or {}).items()}
        self.checks: list[Check] = []

    def check(self, name: str, *, category: str, weight: int, internal: bool = True,
              provides: str | None = None, requires: str | None = None,
              verdicts: Collection[Status] | None = None) -> Callable[[CheckFunction], CheckFunction]:
        """Decorator that registers ``async def f(ctx) -> Outcome`` as the check ``<extension>.<name>``.

        ``internal=False``: the check only makes sense on the Internet (SPF, DNSSEC…);
        in an internal perimeter it is reported as not applicable without running.

        ``provides="https"``: the check observes whether HTTPS answers (the root of the
        family). ``requires="https"``: the check measures something that only exists
        when HTTPS answers. Both must declare ``verdicts``, the statuses among OK, WARN
        and FAIL the check can give: the scoring caps use the lowest non-critical one."""
        if not _ID.fullmatch(name):
            raise ValueError(f"invalid check name {name!r}")
        if not 1 <= weight <= 10:
            raise ValueError(f"weight of {self.id}.{name} must be between 1 and 10")
        if provides and requires:
            raise ValueError(f"{self.id}.{name} cannot both provide and require {provides or requires!r}")
        family = provides or requires
        declared = frozenset(verdicts) if verdicts is not None else None
        if declared is not None and (not declared or not all(v.scored for v in declared)):
            raise ValueError(f"verdicts of {self.id}.{name} must be a non-empty set of OK, WARN and FAIL")
        if family and declared is None:
            raise ValueError(f"{self.id}.{name} belongs to the family {family!r}: it must declare its verdicts")
        if requires and declared is not None and declared <= {Status.FAIL}:
            raise ValueError(f"{self.id}.{name} must be able to give a verdict that is not critical")
        if provides == HTTPS_FAMILY and f"{self.id}.{name}" != HTTPS_ROOT_CHECK:
            raise ValueError(f"{self.id}.{name} cannot provide {HTTPS_FAMILY!r}: {HTTPS_ROOT_CHECK} is its only root")
        role = Role.ROOT if provides else Role.DEPENDENT if requires else None

        def register(function: CheckFunction) -> CheckFunction:
            check_id = f"{self.id}.{name}"
            if any(c.id == check_id for c in self.checks):
                raise ValueError(f"check {check_id} declared twice")
            self.checks.append(Check(check_id, category, weight, function, self.id, internal, family, role, declared))
            return function

        return register

    def __repr__(self) -> str:
        return f"<Extension {self.id} {self.version}: {len(self.checks)} checks>"


def load_messages(directory: Path, prefix: str) -> dict[str, dict[str, str]]:
    """Reads ``<prefix>.fr.json``, ``<prefix>.en.json``… from ``directory``."""
    messages = {}
    for path in sorted(directory.glob(f"{prefix}.*.json")):
        lang = path.name[len(prefix) + 1:-len(".json")]
        messages[lang] = json.loads(path.read_text(encoding="utf-8"))
    return messages


@dataclass
class CheckContext:
    """What a check function receives: the domain, the network, the time of the scan."""

    domain: str      # lower-case, ASCII (internationalised names in their xn-- form)
    net: Network
    now: datetime
    internal: bool = False  # the scan runs inside an internal perimeter
    _memo: dict[str, asyncio.Future[Any]] = field(default_factory=dict, repr=False)

    def fqdn(self, label: str) -> str:
        """``"@"`` → the domain itself; ``"_dmarc"`` → ``"_dmarc.<domain>"``."""
        return self.domain if label in ("", "@") else f"{label}.{self.domain}"

    async def txt(self, name: str) -> list[str]:
        """TXT records of ``name``, an empty list when there are none."""
        return list((await self.net.dns(name, "TXT")).records)

    async def shared(self, key: str, compute: Callable[[], Awaitable[T]]) -> T:
        """Computes something once per scan, for every check that needs it."""
        if key not in self._memo:
            self._memo[key] = asyncio.ensure_future(compute())
        # shield(): when the check that started the work times out, the work goes on
        # for the other checks waiting for it, instead of being cancelled with it.
        return await asyncio.shield(self._memo[key])

    def close(self) -> None:
        """Cancels shared work still running when the scan ends (called by the engine)."""
        for future in self._memo.values():
            future.cancel()

    async def web_hosts(self) -> list[str]:
        """Names that serve the website: the domain and ``www``, those that have an address."""

        async def find() -> list[str]:
            hosts = []
            for host in (self.domain, f"www.{self.domain}"):
                for rtype in ("A", "AAAA"):
                    if (await self.net.dns(host, rtype)).records:
                        hosts.append(host)
                        break
            return hosts

        return await self.shared("web_hosts", find)
