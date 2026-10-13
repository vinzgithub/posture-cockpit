# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The PDF report of the latest scan of a domain."""

from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from ...report import ReportUnavailable, build_pdf
from ...storage import Row
from ..deps import audit, flash, lang_of, redirect, require_user, visible_domain
from ..services import services

router = APIRouter()


@router.get("/domains/{name}/report.pdf")
async def report(request: Request, name: str, user: Row = Depends(require_user)):
    s = services(request)
    domain = visible_domain(request, name, user)
    scan = s.scans.latest(domain["id"])
    if scan is None:
        return redirect("/domains")
    try:
        pdf = build_pdf(s.catalog, lang_of(request), scan, author=s.settings.report_author())
    except ReportUnavailable:
        flash(request, "error", "error.pdf_unavailable")
        return redirect(f"/domains/{name}")
    if domain["perimeter_id"] is not None:
        audit(request, "report.internal", user=user, target=name, perimeter=domain["perimeter"])
    filename = f"posture-{name}-{date.today().isoformat()}.pdf"
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
