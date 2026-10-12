# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Finds the extensions and keeps the list of checks they provide.

Extensions come from two places:

1. the built-in ones, listed in :data:`BUILTIN`;
2. installed Python packages that declare an entry point in the group
   ``posture_cockpit.extensions`` pointing to their :class:`~.extension.Extension`.

A broken third-party extension must not stop the application: its error is
recorded in :attr:`Registry.errors` and shown on the administration page.
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from importlib.metadata import entry_points

from .extension import Check, Extension

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "posture_cockpit.extensions"
BUILTIN = (
    "posture_cockpit.checks.mail",
    "posture_cockpit.checks.tls",
    "posture_cockpit.checks.web",
    "posture_cockpit.checks.dns",
)


@dataclass(frozen=True)
class LoadError:
    source: str   # module or entry point that failed
    error: str


class Registry:
    def __init__(self, extensions: Iterable[Extension] = ()):
        self._extensions: dict[str, Extension] = {}
        self._checks: dict[str, Check] = {}
        self.errors: list[LoadError] = []
        for extension in extensions:
            self.add(extension)

    @classmethod
    def discover(cls) -> Registry:
        """The built-in extensions plus every installed one."""
        registry = cls()
        for module in BUILTIN:
            registry._load(module, lambda m=module: importlib.import_module(m).extension)
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            registry._load(f"{ep.name} = {ep.value}", ep.load)
        return registry

    def _load(self, source: str, load) -> None:
        try:
            extension = load()
            if not isinstance(extension, Extension):
                raise TypeError(f"expected an Extension, got {type(extension).__name__}")
            self.add(extension)
        except Exception as e:  # any error in third-party code is reported, not raised
            log.exception("extension %s could not be loaded", source)
            self.errors.append(LoadError(source, f"{e.__class__.__name__}: {e}"))

    def add(self, extension: Extension) -> None:
        if extension.id in self._extensions:
            raise ValueError(f"two extensions are called {extension.id!r}")
        for check in extension.checks:
            if check.id in self._checks:
                raise ValueError(f"check {check.id} is declared twice")
        self._extensions[extension.id] = extension
        self._checks.update({check.id: check for check in extension.checks})

    @property
    def extensions(self) -> list[Extension]:
        return list(self._extensions.values())

    def checks(self, disabled: Collection[str] = ()) -> list[Check]:
        """Checks of every extension except the ``disabled`` ones, in declaration order."""
        return [c for c in self._checks.values() if c.extension not in disabled]

    def get(self, check_id: str) -> Check | None:
        return self._checks.get(check_id)

    def messages(self, lang: str) -> dict[str, str]:
        """Texts of every extension in one language (the core texts are in posture_cockpit/locales)."""
        merged: dict[str, str] = {}
        for extension in self._extensions.values():
            merged.update(extension.messages.get(lang, {}))
        return merged
