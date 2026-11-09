# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The PDF report of a domain: of its latest scan, or of one scan of its history.

Version 0.7.0, corrective 3: the report is laid out in a process of its own (report/jobs.py), never in the
event loop that serves every page, the API, /healthz and the scans in progress. The HTML is rendered here
(report.render_html, a few milliseconds); report/worker.py makes the PDF. A few reports at once on the
instance, one at a time for an account (web/limits.py): a report over the limit is refused at once, with a
message on the page it came from. The process is killed at its deadline, on a failure, or when the person
goes away before it is ready, and the place is given back once the process is gone.

The rest is as before: the domain and the scan are checked before anything is taken; the report of an
internal perimeter is audited once the PDF is made, before it is sent (which does not prove the browser
received all of it); the names of the files and the headers are unchanged. The PDF of an unreadable scan
(409) is made the same way, within the same limits, or replaced by the page of the error.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from ...report import ReportUnavailable, jobs, render_html, unreadable_html
from ...storage import CorruptScan, Row
from ...timezones import local_date
from ..deps import audit, flash, lang_of, redirect, render, require_user, stored_scan, t, visible_domain
from ..limits import TooManyReports
from ..services import services

router = APIRouter()
log = logging.getLogger("uvicorn.error")

# The status of the answer to a person who went away before the PDF was ready: nobody reads it, the log
# does (the convention of nginx, "client closed request").
CLIENT_GONE = 499


class ClientGone(Exception):
    """The person went away before the PDF was ready; its process was killed."""


@router.get("/domains/{name}/history/{scan_id}/report.pdf")
async def historical_report(request: Request, name: str, scan_id: str,
                            user: Row = Depends(require_user)):
    """Read-only PDF for exactly one stored analysis, with domain ownership enforced."""
    s = services(request)
    domain = visible_domain(request, name, user)
    try:
        scan = stored_scan(request, domain, scan_id)
    except CorruptScan:
        return await _unreadable(request, user)
    made = await _made(request, user, f"/domains/{name}/history/{scan.id}", lambda: render_html(
        s.catalog, lang_of(request), scan, s.settings.report_author(), s.config.timezone, historical=True))
    if isinstance(made, Response):
        return made
    if domain["perimeter_id"] is not None:
        audit(request, "report.internal", user=user, target=name, perimeter=domain["perimeter"], scan=scan.id)
    # The day of the scan as the pages show it, in the time zone of the instance.
    filename = f"posture-{name}-{local_date(scan.started_at, s.config.timezone).isoformat()}-scan-{scan.id}.pdf"
    return Response(made, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/domains/{name}/report.pdf")
async def report(request: Request, name: str, user: Row = Depends(require_user)):
    s = services(request)
    domain = visible_domain(request, name, user)
    try:
        scan = s.scans.latest(domain["id"])
    except CorruptScan:
        return await _unreadable(request, user)
    if scan is None:
        return redirect("/domains")
    made = await _made(request, user, f"/domains/{name}", lambda: render_html(
        s.catalog, lang_of(request), scan, s.settings.report_author(), s.config.timezone))
    if isinstance(made, Response):
        return made
    if domain["perimeter_id"] is not None:
        audit(request, "report.internal", user=user, target=name, perimeter=domain["perimeter"])
    filename = f"posture-{name}-{datetime.now(s.config.timezone).date().isoformat()}.pdf"
    return Response(made, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _who(user: Row) -> str:
    return f"user:{user['id']}"


async def _made(request: Request, user: Row, back: str, html: Callable[[], str]) -> bytes | Response:
    """The PDF of ``html()``, or the answer that replaces it: back to ``back`` with the reason (the limits,
    the deadline, a failure, WeasyPrint missing), or nothing for a person who went away."""
    s = services(request)
    try:
        release = s.report_limiter.take(_who(user))
    except TooManyReports as refusal:
        log.info("PDF report refused for %s: %s", _who(user), refusal.reason)
        flash(request, "error", "error.pdf_busy_account" if refusal.reason == "account" else "error.pdf_busy")
        return redirect(back)
    try:
        return await _unless_gone(request, jobs.make_pdf(html(), timeout=s.config.report_timeout,
                                                         memory_mb=s.config.report_memory_mb))
    except ReportUnavailable:
        flash(request, "error", "error.pdf_unavailable")
    except jobs.ReportTimeout:
        log.warning("PDF report of %s stopped at its deadline of %d s", back, s.config.report_timeout)
        flash(request, "error", "error.pdf_timeout", seconds=s.config.report_timeout)
    except jobs.ReportFailed as failure:
        log.warning("PDF report of %s failed (%s): %s", back, failure.reason, failure.detail[-1000:])
        flash(request, "error", "error.pdf_failed")
    except ClientGone:
        log.info("PDF report of %s stopped: the client went away", back)
        return Response(status_code=CLIENT_GONE)
    finally:
        release()  # the process is gone: make_pdf returns or raises only then
    return redirect(back)


async def _unreadable(request: Request, user: Row) -> Response:
    """The PDF of an unreadable scan (409), within the limits of the reports, or the page of the error."""
    s = services(request)

    def page() -> Response:
        return render(request, "error.html", status=409, message=t(request, "error.scan_unreadable"))

    try:
        release = s.report_limiter.take(_who(user))
    except TooManyReports:
        return page()
    try:
        pdf = await _unless_gone(request, jobs.make_pdf(unreadable_html(s.catalog, lang_of(request)),
                                                        timeout=s.config.report_timeout,
                                                        memory_mb=s.config.report_memory_mb))
    except (ReportUnavailable, jobs.ReportTimeout, jobs.ReportFailed):
        return page()
    except ClientGone:
        return Response(status_code=CLIENT_GONE)
    finally:
        release()
    return Response(pdf, status_code=409, media_type="application/pdf")


async def _unless_gone(request: Request, work: Coroutine[Any, Any, bytes]) -> bytes:
    """The outcome of ``work``, unless the person goes away first: ``work`` is then cancelled (report/jobs.py
    kills its process) and ClientGone raised. Returns or raises only once ``work`` is over, even when this
    task is cancelled meanwhile."""
    job = asyncio.ensure_future(work)
    watch = asyncio.ensure_future(_gone(request))
    watch.add_done_callback(lambda task: task.cancelled() or task.exception())  # read, never reported unread
    try:
        await asyncio.wait({job, watch}, return_when=asyncio.FIRST_COMPLETED)
        if job.done():
            return job.result()
        raise ClientGone()
    finally:
        watch.cancel()
        job.cancel()
        await jobs.wait_out(job)


async def _gone(request: Request) -> None:
    """Returns when the person went away: the server reports ``http.disconnect``. The body of the request,
    if it was not read, comes first; nothing else does."""
    while (await request.receive())["type"] != "http.disconnect":
        pass
