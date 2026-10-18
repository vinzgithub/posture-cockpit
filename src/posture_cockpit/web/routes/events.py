# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""In-app event center. No external notifications or changes to security scoring."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from starlette.datastructures import FormData

from ...storage import Row
from ..deps import checked_form, redirect, render, require_user
from ..services import services

router = APIRouter(prefix="/events")


@router.get("")
async def list_events(request: Request, state: str = "open", user: Row = Depends(require_user)):
    if state not in ("open", "resolved", "notice", "all"):
        state = "open"
    query = (
        "SELECT e.*, d.name AS domain_name, d.perimeter_id "
        "FROM events e LEFT JOIN domains d ON d.id=e.domain_id "
        "WHERE (e.domain_id IS NULL OR d.id IS NOT NULL) "
        "AND (? OR (e.domain_id IS NOT NULL AND d.perimeter_id IS NULL)) "
    )
    params: list[object] = [int(bool(user["is_admin"]))]
    if state != "all":
        query += "AND e.state=? "
        params.append(state)
    query += "ORDER BY e.updated_at DESC, e.id DESC LIMIT 100"
    rows = services(request).db.all(query, params)
    return render(request, "events.html", events=rows, event_state=state)


@router.post("/seen")
async def mark_seen(request: Request, user: Row = Depends(require_user),
                    form: FormData = Depends(checked_form)):
    # Reading an alert never resolves it: per-user 'seen' is independent.
    services(request).db.execute(
        "UPDATE users SET events_seen_at=strftime('%Y-%m-%dT%H:%M:%f+00:00','now') WHERE id=?",
        (user["id"],))
    return redirect("/events")
