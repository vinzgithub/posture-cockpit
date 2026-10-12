# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Settings of the instance that administrators change from the interface."""

from __future__ import annotations

import json

from .database import Database

DISABLED_EXTENSIONS_KEY = "disabled_extensions"
REPORT_AUTHOR_KEY = "report_author"


class InstanceSettings:
    def __init__(self, db: Database):
        self.db = db

    def disabled_extensions(self) -> set[str]:
        """Ids of the extensions an administrator turned off: their checks do not run."""
        return set(json.loads(self.db.get_meta(DISABLED_EXTENSIONS_KEY) or "[]"))

    def set_extension_enabled(self, extension_id: str, enabled: bool) -> None:
        disabled = self.disabled_extensions()
        if enabled:
            disabled.discard(extension_id)
        else:
            disabled.add(extension_id)
        self.db.set_meta(DISABLED_EXTENSIONS_KEY, json.dumps(sorted(disabled)))

    def report_author(self) -> str:
        """Name printed on the PDF reports ("Dossier établi par …"), empty for none."""
        return self.db.get_meta(REPORT_AUTHOR_KEY) or ""

    def set_report_author(self, name: str) -> None:
        self.db.set_meta(REPORT_AUTHOR_KEY, name.strip()[:80])
