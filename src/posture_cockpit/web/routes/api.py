# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""JSON API, for Home Assistant, cron or any monitoring tool.

- ``GET /api/v1/domains``: the latest score of every domain;
- ``POST /api/v1/domains/<name>/scan``: scan a followed domain again.

Authentication: ``Authorization: Bearer <key>``, with a key created on the
settings page. See docs/user/HOME_ASSISTANT.md.
"""

from __future__ import annotations

from collections.abc import Iterable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ...core import scoring
from ...core.model import Finding, Status
from ...security import token_hash
from ...storage import Scan
from ..scanning import scan_and_save
from ..services import services

router = APIRouter(prefix="/api/v1")


def _user_id(request: Request) -> int | None:
    """The user the bearer key belongs to, or None."""
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return services(request).accounts.check_token(token_hash(token.strip()))


def _unauthorized() -> JSONResponse:
    return JSONResponse({"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})


def _certificate_days(findings: Iterable[Finding]) -> int | None:
    """Days left before the website certificate expires, when the scan saw it."""
    cert = next((f for f in findings if f.check_id == "tls.certificate"), None)
    if cert is None or "days" not in cert.outcome.params:
        return None
    return int(cert.outcome.params["days"])


def _summary(scan: Scan) -> dict:
    current = scan.current()
    counts = scoring.counts(current)
    return {
        "domain": scan.domain,
        "score": scan.score,
        "grade": scan.grade,
        "scanned_at": scan.started_at,
        "critical": counts.get(Status.FAIL, 0),
        "to_improve": counts.get(Status.WARN, 0),
        "certificate_days_left": _certificate_days(current),
    }


@router.get("/domains")
async def domains(request: Request):
    """The latest result of every domain."""
    if _user_id(request) is None:
        return _unauthorized()
    s = services(request)
    scans = (s.scans.get(row["scan_id"]) for row in s.scans.domains() if row["scan_id"])
    return {"domains": [_summary(scan) for scan in scans if scan is not None]}


@router.post("/domains/{name}/scan")
async def scan(request: Request, name: str):
    """Scans a domain already followed, e.g. once a month from a Home Assistant automation or cron."""
    user_id = _user_id(request)
    if user_id is None:
        return _unauthorized()
    s = services(request)
    if s.scans.domain(name) is None:
        return JSONResponse({"error": "unknown domain"}, status_code=404)
    scan = s.scans.get(await scan_and_save(s, name, user_id))
    assert scan is not None
    return _summary(scan)
