# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The audit log: who did what, and from where.

It records sign-ins (successful or not), changes to accounts, keys, two-factor
authentication, extensions and internal perimeters, and every scan with the
perimeter it ran in. Administrators read it on the administration page.

No secret is ever written here: no password, code or key, only the fact that
it was used or changed. The log keeps the most recent :data:`KEEP` entries.
"""

from __future__ import annotations

import json
from typing import Any

from .database import Database, Row, utcnow

KEEP = 20_000


class AuditLog:
    def __init__(self, db: Database):
        self.db = db

    def record(self, action: str, *, user: Row | None = None, target: str = "", client: str = "",
               **detail: Any) -> None:
        cur = self.db.execute(
            "INSERT INTO audit_log(at, user_id, username, action, target, detail, client) VALUES(?, ?, ?, ?, ?, ?, ?)",
            (utcnow(), user["id"] if user else None, user["username"] if user else "", action, target[:200],
             json.dumps(detail, ensure_ascii=False, default=str)[:2000], client[:64]))
        if (cur.lastrowid or 0) % 500 == 0:  # trim now and then, not on every write
            self.db.execute("DELETE FROM audit_log WHERE id <= ?", ((cur.lastrowid or 0) - KEEP,))

    def latest(self, limit: int = 200, action_prefix: str = "") -> list[dict[str, Any]]:
        """The most recent entries, newest first, with ``detail`` decoded."""
        rows = self.db.all("SELECT * FROM audit_log WHERE action LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT ?",
                           (action_prefix.replace("%", "\\%").replace("_", "\\_") + "%", limit))
        return [{**dict(r), "detail": json.loads(r["detail"] or "{}")} for r in rows]
