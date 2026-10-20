# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Transactional event ledger backed by the schema-5 events table."""
from __future__ import annotations

import json

from ..core.compare import Snapshot
from ..core.events import derive
from .database import Database


def record_state(db: Database, domain_id: int, scan_id: int) -> None:
    """Process the two latest states after inserting a state, in its existing transaction.

    The caller must already hold the write transaction. No events for the first
    state, legacy backfills, or incompatible generations.
    """
    rows = db.all(
        "SELECT st.* FROM scan_states st JOIN scans s ON s.id=st.scan_id "
        "WHERE s.domain_id=? ORDER BY st.at DESC, st.id DESC LIMIT 2", (domain_id,))
    if len(rows) != 2:
        return
    previous, current = Snapshot.from_row(dict(rows[1])), Snapshot.from_row(dict(rows[0]))
    stamp = current.at
    for item in derive(previous, current):
        opened = db.one(
            "SELECT id, severity, detail FROM events WHERE domain_id=? AND kind=? AND subject=? AND state='open'",
            (domain_id, item.kind, item.subject))
        if item.action == "open":
            if opened:
                # Preserve the original score baseline until it really recovers.
                detail = dict(item.detail)
                if item.kind == "score_drop":
                    detail["baseline_score"] = json.loads(opened["detail"])["baseline_score"]
                db.execute("UPDATE events SET severity=?, updated_at=?, detail=? WHERE id=?",
                           (item.severity, stamp, json.dumps(detail, sort_keys=True), opened["id"]))
            else:
                db.execute(
                    "INSERT INTO events(domain_id,category,kind,subject,state,severity,opened_at,"
                    "opened_scan_id,updated_at,detail) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (domain_id, item.category, item.kind, item.subject, "open", item.severity,
                     stamp, scan_id, stamp, json.dumps(item.detail, sort_keys=True)))
        elif opened and item.action == "downgrade":
            db.execute("UPDATE events SET severity='warning', updated_at=?, detail=? WHERE id=?",
                       (stamp, json.dumps(item.detail, sort_keys=True), opened["id"]))
        elif opened and item.action == "resolve":
            if item.kind == "score_drop":
                # A +1 rebound does not repair a -15 decline.
                baseline = json.loads(opened["detail"])["baseline_score"]
                if current.score is None or current.score < int(baseline):
                    continue
            db.execute("UPDATE events SET state='resolved', severity='info', updated_at=?, resolved_at=?, "
                       "resolved_scan_id=?, resolution='confirmed', detail=? WHERE id=?",
                       (stamp, stamp, scan_id, json.dumps(item.detail, sort_keys=True), opened["id"]))
