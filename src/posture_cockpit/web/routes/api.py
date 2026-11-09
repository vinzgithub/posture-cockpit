# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""JSON API, for Home Assistant, cron or any monitoring tool.

- ``GET /api/v1/domains``: the latest score of every domain the key's owner sees;
- ``POST /api/v1/domains/<name>/scan``: scan a followed domain again.

Authentication: ``Authorization: Bearer <key>``, with a key created on the
settings page. A key has the rights of its owner: the domains of internal
perimeters are only listed and scanned with an administrator's key.
See docs/user/HOME_ASSISTANT.md.

Version 0.7.0 adds two fields to each domain, and changes no other (P4 of PR-D). Both are read from the
stored result of mail.smtp_starttls, never recomputed, never taken from the current configuration:

``smtp_probe``, always an object::

    {"scope": "on" | "off" | "internal" | "absent" | "unknown",
     "status": "ok" | "warn" | "fail" | "na" | "error" | null,
     "rule": "F05.01" … "F05.12" | null,
     "mx": int | null, "addresses": int | null, "verified": int | null}

``scope`` is the measurement scope of the history: "off" the probe was off (status "na", rule F05.01),
"on" it measured, "internal" a scan of an internal perimeter (the check is not run there), "absent" a
scan without the check (made before 0.7.0), "unknown" a result without its scope (an error of the
engine, status "error", rule null). ``status`` is null only when the check is absent. ``mx``,
``addresses`` and ``verified`` (addresses whose certificate was verified) are null unless the probe
measured. ``mx`` counts every MX published, ``addresses`` every address of the MX measured; ``verified``
is the count the measure recorded (``counts.addresses.verified`` of the evidence, correction 2 of
0.7.0), whatever the bounded evidence left out; for a scan stored before it, the addresses of the
evidence, which kept every MX measured with all its addresses (R1 of the review of PR-D). The three are
those of the measure.

``mail_enforce_readiness``, always an object, the indicator F06 as the check stored it::

    {"state": "ready" | "compatible" | "to_fix" | "unconfirmed" | "not_applicable" | null,
     "causes": [str, ...],
     "policy": "enforce" | "testing" | "none" | "missing" | "invalid" | "unavailable" | "unreadable" | null}

``state`` is null when the scan holds no readiness (check absent, internal perimeter, engine error);
"unconfirmed" with the cause "probe_off" when the probe was off. ``policy`` is null when no policy
was read (probe off, no MX). A readiness is measured from this instance: no guarantee of delivery
from the Internet.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ...core import scoring
from ...core.compare import SMTP_CHECK, measurement_scope
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


def _smtp(scan: Scan, current: list[Finding]) -> tuple[dict, dict]:
    """``smtp_probe`` and ``mail_enforce_readiness`` (0.7.0, documented above), from the stored outcome."""
    finding = next((f for f in current if f.check_id == SMTP_CHECK), None)
    evidence: Mapping[str, Any] | None = finding.outcome.evidence if finding is not None else None
    stored: Mapping[str, Any] = evidence or {}
    rule = stored.get("rule")
    counts = stored.get("exhaustivity") if isinstance(stored.get("exhaustivity"), Mapping) else None
    probe = {"scope": measurement_scope(evidence, internal=bool(scan.perimeter)),
             "status": finding.status.value if finding is not None else None,
             "rule": rule if isinstance(rule, str) else None,
             "mx": counts.get("mx") if counts else None, "addresses": counts.get("addresses") if counts else None,
             "verified": _verified(stored) if counts else None}
    found = stored.get("readiness")
    readiness: Mapping[str, Any] = found if isinstance(found, Mapping) else {}
    policy = readiness.get("policy")
    ready = {"state": readiness.get("state"), "causes": list(readiness.get("causes", [])),
             "policy": policy.get("state") if isinstance(policy, Mapping) else None}
    return probe, ready


def _verified(evidence: Mapping[str, Any]) -> int:
    """The addresses whose certificate was verified: as the measure counted them (correction 2 of 0.7.0),
    else, for an evidence stored before, its addresses (every address of every MX measured)."""
    recorded = (evidence.get("counts") or {}).get("addresses")
    if isinstance(recorded, Mapping) and isinstance(recorded.get("verified"), int):
        return int(recorded["verified"])
    return sum(a.get("seen") == "verified" for mx in evidence.get("mx", []) for a in mx.get("addresses", []))


def _ratio(value: float | None) -> float | None:
    return None if value is None else round(value, 3)


def _summary(scan: Scan) -> dict:
    """What a monitoring tool needs. ``score`` and ``grade`` are null when the scan is not evaluated
    (too little could be checked); ``evaluation`` says which case applies."""
    current = scan.current()
    counts = scoring.counts(current)
    result = scan.assessment()
    evaluation = result.evaluation
    modern = any(f.family is not None for f in current)
    smtp_probe, readiness = _smtp(scan, current)
    return {
        "domain": scan.domain,
        "score": result.score,
        "grade": result.grade,
        "evaluation": evaluation,
        "coverage": round(result.coverage, 3),
        # Ratios rounded to 3 decimals, like coverage (0.4.1: diagnostic_coverage was not rounded).
        "diagnostic_coverage": (_ratio(result.diagnostic_coverage) if modern else round(scan.coverage, 3)),
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
        # 0.5.0, added: how the scan was started (web, api, schedule; null before 0.5.0) and the
        # generation of the rules that judged it (null: unknown); only scans of the same
        # generation are compared.
        "via": scan.via,
        "engine": scan.engine,
        # 0.7.0, added: the SMTP probe and the readiness for MTA-STS enforce (see the module).
        "smtp_probe": smtp_probe,
        "mail_enforce_readiness": readiness,
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
