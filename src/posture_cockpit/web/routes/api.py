# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""JSON API, for Home Assistant, cron or any monitoring tool.

- ``GET /api/v1/domains``: the latest score of every domain the key's owner sees;
- ``POST /api/v1/domains/<name>/scan``: scan a followed domain again.

Authentication: ``Authorization: Bearer <key>``, with a key created on the
settings page. A key has the rights of its owner: the domains of internal
perimeters are only listed and scanned with an administrator's key.
See docs/user/HOME_ASSISTANT.md.
"""

from __future__ import annotations

from collections.abc import Iterable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ...core import scoring
from ...core.model import Finding, Status
from ...scanner import InternalScansDisabled
from ...security import token_hash
from ...storage import CorruptScan, Row, Scan
from ..deps import client_key
from ..limits import TooManyScans
from ..scanning import perimeter_of, scan_and_save
from ..services import services

router = APIRouter(prefix="/api/v1")


def _user(request: Request) -> Row | None:
    """The user the bearer key belongs to, or None."""
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    accounts = services(request).accounts
    user_id = accounts.check_token(token_hash(token.strip()))
    return accounts.get(user_id) if user_id is not None else None


def _unauthorized() -> JSONResponse:
    return JSONResponse({"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})


def _certificate_days(findings: Iterable[Finding]) -> int | None:
    """Days left before the website certificate expires, when the scan saw it."""
    cert = next((f for f in findings if f.check_id == "tls.certificate"), None)
    if cert is None or "days" not in cert.outcome.params:
        return None
    return int(cert.outcome.params["days"])


def _summary(scan: Scan) -> dict:
    """What a monitoring tool needs. ``score`` and ``grade`` are null when the scan is not evaluated
    (too little could be checked); ``evaluation`` says which case applies."""
    current = scan.current()
    counts = scoring.counts(current)
    result = scan.assessment()
    evaluation = result.evaluation
    modern = any(f.family is not None for f in current)
    return {
        "domain": scan.domain,
        "score": result.score,
        "grade": result.grade,
        "evaluation": evaluation,
        "coverage": round(result.coverage, 3),
        "diagnostic_coverage": result.diagnostic_coverage if modern else round(scan.coverage, 3),
        "checks_blocked": result.blocked if modern else 0,
        "score_raw": result.score_raw if modern else (scan.score / 100 if scan.score is not None else None),
        "score_cap": result.score_cap if modern else None,
        "score_final": result.score_final if modern else (scan.score / 100 if scan.score is not None else None),
        "cap_reasons": list(result.cap_reasons),
        "grade_withheld_reason": result.grade_withheld_reason,
        "addresses": scan.addresses(),
        "addresses_discovered": scan.addresses().get("discovered"),
        "addresses_attempted": scan.addresses().get("attempted"),
        "addresses_conclusive": scan.addresses().get("conclusive"),
        "address_sampling_limited": scan.addresses().get("sampling_limited"),
        "address_discovery_complete": scan.addresses().get("discovery_complete"),
        "checks_evaluated": result.evaluated,
        "checks_applicable": result.applicable,
        "scanned_at": scan.started_at,
        "perimeter": scan.perimeter or None,
        "critical": counts.get(Status.FAIL, 0),
        "to_improve": counts.get(Status.WARN, 0),
        "not_evaluated": counts.get(Status.ERROR, 0),
        "certificate_days_left": _certificate_days(current),
    }


@router.get("/domains")
async def domains(request: Request):
    """The latest result of every domain the key's owner may see."""
    user = _user(request)
    if user is None:
        return _unauthorized()
    s = services(request)
    rows = s.scans.domains(internal=bool(user["is_admin"]))
    results = []
    for row in rows:
        if row["scan_id"]:
            try:
                scan = s.scans.get(row["scan_id"])
                if scan is not None:
                    results.append(_summary(scan))
            except CorruptScan as error:
                results.append({"domain": row["name"], "error": "scan_unreadable", "scan_id": error.scan_id})
    return {"domains": results}


@router.post("/domains/{name}/scan")
async def scan(request: Request, name: str):
    """Scans a domain already followed, e.g. once a month from a Home Assistant automation or cron."""
    user = _user(request)
    if user is None:
        return _unauthorized()
    s = services(request)
    domain = s.scans.domain(name)
    if domain is None or (domain["perimeter_id"] is not None and not user["is_admin"]):
        return JSONResponse({"error": "unknown domain"}, status_code=404)
    try:
        scan_id = await scan_and_save(s, name, user, perimeter=perimeter_of(s, domain), client=client_key(request),
                                      via="api")
    except InternalScansDisabled:
        return JSONResponse({"error": "internal scans are disabled on this instance"}, status_code=403)
    except TooManyScans as e:
        message = "too many scans running, try again shortly" if e.reason == "busy" else "hourly scan quota reached"
        return JSONResponse({"error": message}, status_code=429, headers={"Retry-After": str(e.retry_after)})
    result = s.scans.get(scan_id)
    assert result is not None
    return _summary(result)
