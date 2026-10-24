# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""In-app event center. No external notifications or changes to security scoring."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from starlette.datastructures import FormData
from starlette.exceptions import HTTPException

from ...storage import Row
from ..deps import checked_form, redirect, render, require_user
from ..services import services
from .dashboard import _number

router = APIRouter(prefix="/events")


@router.get("")
async def list_events(request: Request, state: str = "open", severity: str = "all",
                      category: str = "all", domain: str = "", period: str = "all",
                      user: Row = Depends(require_user)):
    try:
        if any(len(request.query_params.getlist(k)) != 1 for k in ("page", "size") if k in request.query_params):
            raise ValueError("duplicate pagination")
        page = _number(request.query_params.get("page", "1"), 1_000_000)
        size = _number(request.query_params.get("size", "50"), 100)
    except ValueError:
        raise HTTPException(400) from None
    if state not in ("open", "resolved", "notice", "all"):
        state = "open"
    if severity not in ("critical", "warning", "info", "all"):
        severity = "all"
    if category not in ("security", "measurement", "technical", "all"):
        category = "all"
    if period not in ("all", "7", "30", "90"):
        period = "all"
    domain = domain.strip()[:253]
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
    if severity != "all":
        query += "AND e.severity=? "
        params.append(severity)
    if category != "all":
        query += "AND e.category=? "
        params.append(category)
    if domain:
        query += "AND d.name=? "
        params.append(domain.lower())
    if period != "all":
        query += "AND datetime(e.updated_at) >= datetime(?) "
        params.append((datetime.now(UTC) - timedelta(days=int(period))).isoformat())
    db = services(request).db
    with db.transaction():
        total = int(db.value(query.replace("SELECT e.*, d.name AS domain_name, d.perimeter_id ",
                                           "SELECT COUNT(*) ", 1), params) or 0)
        pages = max(1, (total + size - 1) // size)
        if page > pages:
            raise HTTPException(404)
        rows = db.all(query + "ORDER BY e.updated_at DESC, e.id DESC LIMIT ? OFFSET ?",
                      [*params, size, (page - 1) * size])

    def link(number: int) -> str:
        return "/events?" + urlencode({"state": state, "severity": severity, "category": category,
                                       "domain": domain, "period": period, "size": size, "page": number})
    return render(request, "events.html", events=rows, event_state=state,
                  event_severity=severity, event_category=category, event_domain=domain,
                  event_period=period, page=page, pages=pages, total=total, size=size,
                  previous_url=link(page - 1) if page > 1 else None,
                  next_url=link(page + 1) if page < pages else None)


@router.post("/seen")
async def mark_seen(request: Request, user: Row = Depends(require_user),
                    form: FormData = Depends(checked_form)):
    # Reading an alert never resolves it: per-user 'seen' is independent.
    services(request).db.execute(
        "UPDATE users SET events_seen_at=strftime('%Y-%m-%dT%H:%M:%f+00:00','now') WHERE id=?",
        (user["id"],))
    return redirect("/events")
