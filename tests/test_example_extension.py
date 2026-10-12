# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The example extension of docs/EXTENSIONS.md works as documented."""

import sys
from pathlib import Path

from posture_cockpit.core import registry
from posture_cockpit.core.model import Status
from posture_cockpit.core.registry import Registry
from posture_cockpit.i18n import Catalog
from worlds import DOMAIN, healthy, one

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "posture-cockpit-example"


class EntryPoint:
    """What importlib.metadata gives once the example package is installed."""

    name, value = "example", "posture_cockpit_example:extension"

    def load(self):
        sys.path.insert(0, str(EXAMPLE))
        try:
            from posture_cockpit_example import extension
        finally:
            sys.path.remove(str(EXAMPLE))
        return extension


def test_the_example_is_found_through_its_entry_point(monkeypatch):
    monkeypatch.setattr(registry, "entry_points", lambda group: [EntryPoint()])
    reg = Registry.discover()
    assert reg.errors == []
    assert reg.get("example.permissions_policy") is not None
    catalog = Catalog(reg.messages)
    assert catalog.text("fr", "example.permissions_policy.title").startswith("Fonctions du navigateur")

    data = healthy()
    assert one(data, "example.permissions_policy", registry=reg).status is Status.WARN
    data["http"][f"https://www.{DOMAIN}/"]["headers"]["Permissions-Policy"] = "camera=()"
    assert one(data, "example.permissions_policy", registry=reg).status is Status.OK
