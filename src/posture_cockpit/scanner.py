# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Runs scans for the web interface and the command line.

It chooses the network to use (the real one, or recorded answers for the demo
domain), leaves out the extensions an administrator turned off, and re-runs a
single check when the user clicks "Vérifier" on the plan.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Collection
from functools import cache
from pathlib import Path

from .config import Config
from .core import engine
from .core.fixture import FixtureNetwork
from .core.model import Finding
from .core.network import LiveNetwork, Network
from .core.registry import Registry

DEMO_DIR = Path(__file__).parent / "demo"
DEMO_DOMAIN = "menuiserie-dupont.example"


@cache
def demo_data(domain: str) -> dict | None:
    """Recorded answers for a demo domain. Only names under the reserved .example TLD qualify."""
    if not domain.endswith(".example"):
        return None
    path = DEMO_DIR / f"{domain}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


class Scanner:
    def __init__(self, registry: Registry, config: Config,
                 disabled: Callable[[], Collection[str]] = lambda: (),
                 network_factory: Callable[[str], Network] | None = None):
        """``disabled`` returns the ids of the extensions turned off; ``network_factory``
        replaces the network (the tests use it)."""
        self.registry = registry
        self.config = config
        self.disabled = disabled
        self._network_factory = network_factory

    def network_for(self, domain: str) -> Network:
        """A fresh network per scan, so cached answers never outlive it."""
        if self._network_factory is not None:
            return self._network_factory(domain)
        data = demo_data(domain)
        if data is not None:
            return FixtureNetwork(data)
        return LiveNetwork(self.config.nameservers)

    async def exists(self, domain: str) -> bool:
        return await engine.domain_exists(self.network_for(domain), domain)

    async def scan(self, domain: str) -> engine.ScanResult:
        checks = self.registry.checks(disabled=self.disabled())
        return await engine.scan(domain, checks, self.network_for(domain), timeout=self.config.check_timeout)

    async def recheck(self, domain: str, check_id: str) -> Finding | None:
        """Runs one check again; None when that check no longer exists."""
        check = self.registry.get(check_id)
        if check is None:
            return None
        result = await engine.scan(domain, [check], self.network_for(domain), timeout=self.config.check_timeout)
        return result.findings[0]

