# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Read-only Mission Control. Authenticate and authorize before reading any scan."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from starlette.exceptions import HTTPException

from ...core import scoring
from ...core.compare import Snapshot
from ...storage import CorruptScan, Row
from .. import mission_control
from ..deps import lang_of, redirect, render, require_user, t, visible_domain
from ..services import services

router = APIRouter(prefix="/domains")


def _positive_id(value: str) -> int:
    if not value.isascii() or not value.isdigit() or len(value) > 9 or int(value) < 1:
        raise HTTPException(400)
    return int(value)


def _page(request: Request, name: str, user: Row, *, simulate: bool):
    s = services(request)
    # Synchronous deferred read transaction: coherent snapshot, no await or write.
    with s.db.transaction():
        domain = visible_domain(request, name, user)
        selected: list[str] = []
        query = request.query_params
        if simulate:
            if (set(query) - {"scan_id", "state_id", "check"}
                    or len(query.getlist("scan_id")) != 1 or len(query.getlist("state_id")) != 1):
                raise HTTPException(400)
            submitted_scan = _positive_id(query["scan_id"])
            submitted_state = _positive_id(query["state_id"])
            selected = query.getlist("check")
            if len(selected) > 20 or any(len(check) > 81 for check in selected):
                raise HTTPException(400)
        scan = s.scans.latest(domain["id"])
        if scan is None:
            return redirect("/domains")
        state = s.scans.current_state(scan.id)
        if state is None:
            return render(request, "mission_control_stale.html", status=409, domain=domain)
        if simulate and (submitted_scan != scan.id or submitted_state != state["id"]):
            return render(request, "mission_control_stale.html", status=409, domain=domain)
        try:
            states = [Snapshot.from_row(dict(row)) for row in s.scans.state_history(domain["id"], state["id"])]
        except (ValueError, TypeError, KeyError):
            raise CorruptScan(scan.id) from None
        events = s.db.all("SELECT * FROM events WHERE domain_id=? ORDER BY updated_at DESC,id DESC LIMIT 5",
                          (domain["id"],))
    result = None
    if simulate:
        try:
            result = scoring.simulate(scan.current(), selected, s.registry)
        except ValueError:
            raise HTTPException(400) from None
    view = mission_control.context(s.catalog, lang_of(request), domain, scan, states, s.registry)
    # Detect a newer measurement committed by another process during calculation.
    with s.db.transaction():
        domain = visible_domain(request, name, user)
        latest_id = s.scans.latest_id(domain["id"])
        latest_state = s.scans.current_state(scan.id)
        if latest_id != scan.id or latest_state is None or latest_state["id"] != state["id"]:
            return render(request, "mission_control_stale.html", status=409, domain=domain)
    response = render(request, "mission_control.html", simulation=result, selected=set(selected),
                      state_id=state["id"], recent_events=events, **view)
    response.headers["Cache-Control"] = "private, no-store"
    return response


def _authorized_page(request: Request, name: str, user: Row, *, simulate: bool):
    try:
        return _page(request, name, user, simulate=simulate)
    except HTTPException as error:
        if error.status_code != 404:
            raise
        # Same response for unknown and hidden names; even the language form's
        # return URL must not echo the requested internal path.
        return render(request, "error.html", status=404, message=t(request, "error.not_found"), back="/domains")


@router.get("/{name}/mission-control")
async def mission_page(request: Request, name: str, user: Row = Depends(require_user)):
    return _authorized_page(request, name, user, simulate=False)


@router.get("/{name}/mission-control/simulate")
async def simulation_page(request: Request, name: str, user: Row = Depends(require_user)):
    return _authorized_page(request, name, user, simulate=True)
