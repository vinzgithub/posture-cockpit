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
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

from .model import Outcome
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

    def check(self, name: str, *, category: str, weight: int) -> Callable[[CheckFunction], CheckFunction]:
        """Decorator that registers ``async def f(ctx) -> Outcome`` as the check ``<extension>.<name>``."""
        if not _ID.fullmatch(name):
            raise ValueError(f"invalid check name {name!r}")
        if not 1 <= weight <= 10:
            raise ValueError(f"weight of {self.id}.{name} must be between 1 and 10")

        def register(function: CheckFunction) -> CheckFunction:
            check_id = f"{self.id}.{name}"
            if any(c.id == check_id for c in self.checks):
                raise ValueError(f"check {check_id} declared twice")
            self.checks.append(Check(check_id, category, weight, function, self.id))
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
        return await self._memo[key]

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
