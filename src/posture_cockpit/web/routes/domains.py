# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The domains: list, new scan, plan of fixes, recheck of one fix, expert view.

Every page works without JavaScript; app.js only makes them quicker (switching
tasks and DNS hosts without reloading, copy buttons, spinner while scanning).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from starlette.datastructures import FormData
from starlette.exceptions import HTTPException

from ...core import providers
from ...core.engine import normalize_domain
from ...core.network import NetworkError
from ...scanner import DEMO_DOMAIN
from ...storage import Row
from ..deps import checked_form, field, flash, lang_of, redirect, render, require_user, t
from ..scanning import scan_and_save
from ..services import services
from ..views import plan_view

router = APIRouter(prefix="/domains")


def domain_or_404(request: Request, name: str) -> Row:
    row = services(request).scans.domain(name)
    if row is None:
        raise HTTPException(404)
    return row


@router.get("")
async def domain_list(request: Request, user: Row = Depends(require_user)):
    return render(request, "domains.html", domains=services(request).scans.domains(), demo_domain=DEMO_DOMAIN)


@router.post("")
async def add_domain(request: Request, user: Row = Depends(require_user), form: FormData = Depends(checked_form)):
    s = services(request)
    typed = field(form, "domain", 300)
    try:
        name = normalize_domain(typed)
    except ValueError:
        return render(request, "domains.html", status=400, domains=s.scans.domains(), demo_domain=DEMO_DOMAIN,
                      typed=typed, error=t(request, "error.domain_invalid"))
    try:
        exists = await s.scanner.exists(name)
    except NetworkError:
        return render(request, "domains.html", status=502, domains=s.scans.domains(), demo_domain=DEMO_DOMAIN,
                      typed=typed, error=t(request, "error.dns_unreachable"))
    if not exists:
        return render(request, "domains.html", status=400, domains=s.scans.domains(), demo_domain=DEMO_DOMAIN,
                      typed=typed, error=t(request, "error.domain_unknown", domain=name))
    await scan_and_save(s, name, user["id"])
    return redirect(f"/domains/{name}")


@router.get("/{name}")
async def plan(request: Request, name: str, task: str = "", user: Row = Depends(require_user)):
    s = services(request)
    domain = domain_or_404(request, name)
    scan = s.scans.latest(domain["id"])
    if scan is None:
        return redirect("/domains")
    view = plan_view(s.catalog, lang_of(request), scan, domain)
    # The task shown first: the one asked for, else the first priority not done yet.
    selected = next((x for x in view.tasks if x.check_id == task), None)
    selected = selected or next((x for x in view.priorities if not x.done), None) or next(iter(view.tasks), None)
    return render(request, "plan.html", plan=view, selected=selected, history=s.scans.history(domain["id"]))


@router.post("/{name}/scan")
async def rescan(request: Request, name: str, user: Row = Depends(require_user),
                 form: FormData = Depends(checked_form)):
    domain_or_404(request, name)
    await scan_and_save(services(request), name, user["id"])
    flash(request, "ok", "flash.scanned")
    return redirect(f"/domains/{name}")


@router.post("/{name}/verify/{check_id}")
async def verify(request: Request, name: str, check_id: str, user: Row = Depends(require_user),
                 form: FormData = Depends(checked_form)):
    """Runs one check again and records the result on the latest scan."""
    s = services(request)
    domain = domain_or_404(request, name)
    scan = s.scans.latest(domain["id"])
    if scan is None or all(f.check_id != check_id for f in scan.findings):
        raise HTTPException(404)
    finding = await s.scanner.recheck(name, check_id)
    if finding is None:
        raise HTTPException(404)
    before = scan.score
    after = s.scans.save_recheck(scan.id, finding)
    if finding.status.value == "ok":
        flash(request, "ok", "flash.verified", points=max(after - before, 0), score=after)
    else:
        flash(request, "warn", "flash.not_yet")
    return redirect(f"/domains/{name}?task={check_id}#task")


@router.post("/{name}/dns-host")
async def choose_dns_host(request: Request, name: str, user: Row = Depends(require_user),
                          form: FormData = Depends(checked_form)):
    s = services(request)
    domain = domain_or_404(request, name)
    host_id = field(form, "dns_host", 20)
    if host_id not in {h.id for h in providers.DNS_HOSTS} | {providers.OTHER.id}:
        raise HTTPException(400)
    s.scans.set_dns_host(domain["id"], host_id)
    if request.headers.get("x-csrf-token"):  # sent by app.js: no page to return
        return Response(status_code=204)
    task = field(form, "task", 60)
    return redirect(f"/domains/{name}?task={task}#task" if task else f"/domains/{name}")


@router.get("/{name}/details")
async def details(request: Request, name: str, user: Row = Depends(require_user)):
    """Every check with its raw values: the page for the technician."""
    s = services(request)
    domain = domain_or_404(request, name)
    scan = s.scans.latest(domain["id"])
    if scan is None:
        return redirect("/domains")
    current = scan.current()
    categories: dict[str, list] = {}
    for finding in current:
        categories.setdefault(finding.category, []).append(finding)
    return render(request, "details.html", scan=scan, categories=categories,
                  registry=s.registry, rechecks=scan.rechecks)


@router.post("/{name}/delete")
async def delete(request: Request, name: str, user: Row = Depends(require_user),
                 form: FormData = Depends(checked_form)):
    domain = domain_or_404(request, name)
    services(request).scans.delete_domain(domain["id"])
    flash(request, "ok", "flash.domain_deleted", name=name)
    return redirect("/domains")
