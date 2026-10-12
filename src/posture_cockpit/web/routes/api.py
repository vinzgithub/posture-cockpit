# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Read-only JSON API, for Home Assistant or any monitoring tool.

Authentication: ``Authorization: Bearer <key>``, with a key created on the
settings page. See docs/HOME_ASSISTANT.md.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ...core import scoring
from ...core.model import Status
from ...security import token_hash
from ..services import services

router = APIRouter(prefix="/api/v1")


def _authorized(request: Request) -> bool:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return False
    return services(request).accounts.check_token(token_hash(token.strip())) is not None


def _certificate_days(findings) -> int | None:
    cert = next((f for f in findings if f.check_id == "tls.certificate"), None)
    if cert is None or "days" not in cert.outcome.params:
        return None
    return int(cert.outcome.params["days"])


@router.get("/domains")
async def domains(request: Request):
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
    s = services(request)
    result = []
    for row in s.scans.domains():
        scan = s.scans.get(row["scan_id"]) if row["scan_id"] else None
        if scan is None:
            continue
        current = scan.current()
        counts = scoring.counts(current)
        result.append({
            "domain": scan.domain,
            "score": scan.score,
            "grade": scan.grade,
            "scanned_at": scan.started_at,
            "critical": counts.get(Status.FAIL, 0),
            "to_improve": counts.get(Status.WARN, 0),
            "certificate_days_left": _certificate_days(current),
        })
    return {"domains": result}
