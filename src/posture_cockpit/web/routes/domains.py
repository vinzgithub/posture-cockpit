# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The domains: list, new scan, plan of fixes, recheck of one fix, expert view.

Domains added here are scanned from the Internet. Domains of internal
perimeters are added from the administration (routes/perimeters.py) and only
administrators see them: every route below goes through ``visible_domain``.

Every page works without JavaScript; app.js only makes them quicker (switching
tasks and DNS hosts without reloading, copy buttons, spinner while scanning).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from starlette.datastructures import FormData
from starlette.exceptions import HTTPException

from ...core import providers, scoring
from ...core.engine import normalize_domain
from ...core.model import Status
from ...core.network import NetworkError
from ...scanner import DEMO_DOMAIN, InternalScansDisabled
from ...storage import Row
from ..deps import (
    audit,
    checked_form,
    client_key,
    field,
    flash,
    lang_of,
    redirect,
    render,
    require_user,
    t,
    visible_domain,
)
from ..limits import TooManyScans
from ..scanning import perimeter_of, recheck, scan_and_save
from ..services import services
from ..views import plan_view

router = APIRouter(prefix="/domains")


def list_page(request: Request, user: Row, status: int = 200, **context):
    domains = services(request).scans.domains(internal=bool(user["is_admin"]))
    return render(request, "domains.html", status=status, domains=domains, demo_domain=DEMO_DOMAIN,
                  full_coverage=scoring.FULL_COVERAGE, **context)


@router.get("")
async def domain_list(request: Request, user: Row = Depends(require_user)):
    return list_page(request, user)


@router.post("")
async def add_domain(request: Request, user: Row = Depends(require_user), form: FormData = Depends(checked_form)):
    """Adds and scans a domain from the Internet."""
    s = services(request)
    typed = field(form, "domain", 300)
    try:
        name = normalize_domain(typed)
    except ValueError:
        return list_page(request, user, status=400, typed=typed, error=t(request, "error.domain_invalid"))
    existing = s.scans.domain(name)
    if existing is not None and existing["perimeter_id"] is not None:
        # Followed inside an internal perimeter: it is not scanned from the Internet under the same name.
        return list_page(request, user, status=400, typed=typed, error=t(request, "error.domain_internal", domain=name))
    try:
        problem = await s.scanner.preflight(name)
    except NetworkError:
        problem = "unreachable"
    if problem:
        key = {"unknown": "error.domain_unknown", "empty": "error.domain_empty"}.get(problem, "error.dns_unreachable")
        return list_page(request, user, status=400, typed=typed, error=t(request, key, domain=name))
    try:
        await scan_and_save(s, name, user, client=client_key(request))
    except TooManyScans as e:
        return list_page(request, user, status=429, typed=typed, error=t(request, f"error.scan_{e.reason}"))
    return redirect(f"/domains/{name}")


@router.get("/{name}")
async def plan(request: Request, name: str, task: str = "", user: Row = Depends(require_user)):
    s = services(request)
    domain = visible_domain(request, name, user)
    scan = s.scans.latest(domain["id"])
    if scan is None:
        return redirect("/domains")
    view = plan_view(s.catalog, lang_of(request), scan, domain)
    # The task shown first: the one asked for, else the first priority not done yet.
    selected = next((x for x in view.tasks if x.check_id == task), None)
    selected = selected or next((x for x in view.priorities if not x.done), None) or next(iter(view.tasks), None)
    return render(request, "plan.html", plan=view, selected=selected, history=s.scans.history(domain["id"]),
                  domain=domain)


@router.post("/{name}/scan")
async def rescan(request: Request, name: str, user: Row = Depends(require_user),
                 form: FormData = Depends(checked_form)):
    s = services(request)
    domain = visible_domain(request, name, user)
    try:
        await scan_and_save(s, name, user, perimeter=perimeter_of(s, domain), client=client_key(request))
    except InternalScansDisabled:
        flash(request, "error", "error.internal_disabled")
        return redirect(f"/domains/{name}")
    except TooManyScans as e:
        flash(request, "error", f"error.scan_{e.reason}")
        return redirect(f"/domains/{name}")
    flash(request, "ok", "flash.scanned")
    return redirect(f"/domains/{name}")


@router.post("/{name}/verify/{check_id}")
async def verify(request: Request, name: str, check_id: str, user: Row = Depends(require_user),
                 form: FormData = Depends(checked_form)):
    """Runs one check again and records the result on the latest scan."""
    s = services(request)
    domain = visible_domain(request, name, user)
    scan = s.scans.latest(domain["id"])
    if scan is None or all(f.check_id != check_id for f in scan.findings):
        raise HTTPException(404)
    perimeter = perimeter_of(s, domain)
    try:
        finding = await recheck(s, name, check_id, user, perimeter=perimeter, client=client_key(request))
    except InternalScansDisabled:
        flash(request, "error", "error.internal_disabled")
        return redirect(f"/domains/{name}?task={check_id}#task")
    except TooManyScans as e:
        flash(request, "error", f"error.scan_{e.reason}")
        return redirect(f"/domains/{name}?task={check_id}#task")
    if finding is None:
        raise HTTPException(404)
    audit(request, "scan.internal.recheck" if perimeter else "scan.recheck", user=user, target=name, check=check_id)
    before = scan.assessment()
    after = s.scans.save_recheck(scan.id, finding)
    if finding.status is Status.OK and before.score is not None and after.score is not None:
        flash(request, "ok", "flash.verified", points=max(after.score - before.score, 0), score=after.score)
    elif finding.status is Status.OK:
        flash(request, "ok", "flash.verified_unscored")
    else:
        flash(request, "warn", "flash.not_yet")
    return redirect(f"/domains/{name}?task={check_id}#task")


@router.post("/{name}/dns-host")
async def choose_dns_host(request: Request, name: str, user: Row = Depends(require_user),
                          form: FormData = Depends(checked_form)):
    s = services(request)
    domain = visible_domain(request, name, user)
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
    domain = visible_domain(request, name, user)
    scan = s.scans.latest(domain["id"])
    if scan is None:
        return redirect("/domains")
    current = scan.current()
    categories: dict[str, list] = {}
    for finding in current:
        categories.setdefault(finding.category, []).append(finding)
    return render(request, "details.html", scan=scan, categories=categories,
                  registry=s.registry, rechecks=scan.rechecks, domain=domain)


@router.post("/{name}/delete")
async def delete(request: Request, name: str, user: Row = Depends(require_user),
                 form: FormData = Depends(checked_form)):
    domain = visible_domain(request, name, user)
    services(request).scans.delete_domain(domain["id"])
    audit(request, "domain.deleted", user=user, target=name, perimeter=domain["perimeter"] or "")
    flash(request, "ok", "flash.domain_deleted", name=name)
    return redirect("/domains")
