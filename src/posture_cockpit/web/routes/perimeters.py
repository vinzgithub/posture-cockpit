# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Internal perimeters, in the administration: create, change, delete, add a domain.

Two keys are needed to scan a private network:

1. whoever runs the instance starts it with ``POSTURE_COCKPIT_INTERNAL_SCANS=1``;
2. an administrator (who typed their password again in the last ten minutes)
   describes the perimeter: networks, DNS servers, ports, certificate authority.

Only administrators add domains to a perimeter, see them and scan them. Every
change and every internal scan is written to the audit log. While the variable
is off, perimeters can still be read and deleted, not created, changed or scanned.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from starlette.datastructures import FormData
from starlette.exceptions import HTTPException

from ...core.engine import normalize_domain
from ...core.network import NetworkError
from ...storage import Perimeter, PerimeterError, Row
from ...storage.perimeters import DEFAULT_PORTS, PerimeterForm, parse_form
from ..deps import audit, checked_form, client_key, field, flash, redirect, render, require_admin, t
from ..scanning import scan_and_save
from ..services import services

router = APIRouter(prefix="/admin/perimeters")


def _enabled(request: Request) -> bool:
    return services(request).config.internal_scans


def _perimeter_or_404(request: Request, perimeter_id: int) -> Perimeter:
    perimeter = services(request).perimeters.get(perimeter_id)
    if perimeter is None:
        raise HTTPException(404)
    return perimeter


def _draft(perimeter: Perimeter | None) -> dict[str, str]:
    """The form's fields, filled with a perimeter's values (or the defaults)."""
    if perimeter is None:
        return {"name": "", "networks": "", "nameservers": "", "ports": DEFAULT_PORTS, "ca_pem": ""}
    return {"name": perimeter.name, "networks": "\n".join(str(n) for n in perimeter.networks),
            "nameservers": "\n".join(perimeter.nameservers), "ports": " ".join(map(str, sorted(perimeter.ports))),
            "ca_pem": perimeter.ca_pem}


def _page(request: Request, perimeter: Perimeter | None, status: int = 200, **context):
    s = services(request)
    return render(request, "admin_perimeter.html", status=status, perimeter=perimeter, enabled=_enabled(request),
                  draft=context.pop("draft", None) or _draft(perimeter),
                  domains=s.perimeters.domains(perimeter.id) if perimeter else [], **context)


def _read_form(request: Request, form: FormData, perimeter_id: int | None) -> PerimeterForm:
    """The perimeter typed in the form, checked. Raises PerimeterError."""
    values = parse_form(field(form, "name", 80), field(form, "networks", 4000), field(form, "nameservers", 400),
                        field(form, "ports", 100), str(form.get("ca_pem", ""))[:200_000])
    if services(request).perimeters.name_taken(values.name, except_id=perimeter_id):
        raise PerimeterError("name", "error.perimeter_name_taken")
    return values


def _error(request: Request, error: PerimeterError) -> str:
    return t(request, error.key, value=error.value)


@router.get("/new")
async def new_page(request: Request, me: Row = Depends(require_admin)):
    return _page(request, None)


@router.post("")
async def create(request: Request, me: Row = Depends(require_admin), form: FormData = Depends(checked_form)):
    if not _enabled(request):
        raise HTTPException(403)
    try:
        values = _read_form(request, form, None)
    except PerimeterError as e:
        return _page(request, None, status=400, error=_error(request, e), draft=dict(form))
    perimeter_id = services(request).perimeters.create(values, me["id"])
    audit(request, "perimeter.created", user=me, target=values.name, networks=values.networks.split("\n"),
          nameservers=values.nameservers.split("\n") if values.nameservers else [], ports=values.ports,
          custom_ca=bool(values.ca_pem))
    flash(request, "ok", "flash.perimeter_created", name=values.name)
    return redirect(f"/admin/perimeters/{perimeter_id}")


@router.get("/{perimeter_id}")
async def show(request: Request, perimeter_id: int, me: Row = Depends(require_admin)):
    return _page(request, _perimeter_or_404(request, perimeter_id))


@router.post("/{perimeter_id}")
async def update(request: Request, perimeter_id: int, me: Row = Depends(require_admin),
                 form: FormData = Depends(checked_form)):
    perimeter = _perimeter_or_404(request, perimeter_id)
    if not _enabled(request):
        raise HTTPException(403)
    try:
        values = _read_form(request, form, perimeter_id)
    except PerimeterError as e:
        return _page(request, perimeter, status=400, error=_error(request, e), draft=dict(form))
    services(request).perimeters.update(perimeter_id, values)
    audit(request, "perimeter.changed", user=me, target=values.name, previous_name=perimeter.name,
          networks=values.networks.split("\n"), nameservers=values.nameservers.split("\n") if values.nameservers
          else [], ports=values.ports, custom_ca=bool(values.ca_pem))
    flash(request, "ok", "flash.saved")
    return redirect(f"/admin/perimeters/{perimeter_id}")


@router.post("/{perimeter_id}/delete")
async def delete(request: Request, perimeter_id: int, me: Row = Depends(require_admin),
                 form: FormData = Depends(checked_form)):
    perimeter = _perimeter_or_404(request, perimeter_id)
    if not services(request).perimeters.delete(perimeter_id):
        return _page(request, perimeter, status=400, error=t(request, "error.perimeter_in_use"))
    audit(request, "perimeter.deleted", user=me, target=perimeter.name)
    flash(request, "ok", "flash.perimeter_deleted", name=perimeter.name)
    return redirect("/admin#perimeters")


@router.post("/{perimeter_id}/domains")
async def add_domain(request: Request, perimeter_id: int, me: Row = Depends(require_admin),
                     form: FormData = Depends(checked_form)):
    """Adds a domain to the perimeter and scans it there."""
    s = services(request)
    perimeter = _perimeter_or_404(request, perimeter_id)
    if not _enabled(request):
        raise HTTPException(403)
    typed = field(form, "domain", 300)

    def refuse(key: str, **params):
        return _page(request, perimeter, status=400, typed=typed, domain_error=t(request, key, **params))

    try:
        name = normalize_domain(typed)
    except ValueError:
        return refuse("error.domain_invalid")
    if s.scans.domain(name) is not None:
        return refuse("error.domain_followed", domain=name)
    try:
        problem = await s.scanner.preflight(name, perimeter)
    except NetworkError:
        problem = "unreachable"
    if problem:
        key = {"unknown": "error.domain_unknown", "empty": "error.domain_empty_internal"}.get(
            problem, "error.dns_unreachable")
        return refuse(key, domain=name)
    audit(request, "domain.added", user=me, target=name, perimeter=perimeter.name)
    await scan_and_save(s, name, me, perimeter=perimeter, client=client_key(request))
    return redirect(f"/domains/{name}")
