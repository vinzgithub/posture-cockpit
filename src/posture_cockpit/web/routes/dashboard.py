# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Server-rendered portfolio; permission filtering precedes all aggregation."""
from datetime import UTC, datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from starlette.exceptions import HTTPException

from ...storage import Row
from ...storage.portfolio import EVALUATIONS, FRESHNESS, SEVERITIES, SORTS, DomainFilter
from .. import portfolio
from ..deps import lang_of, render, require_user
from ..services import services

router = APIRouter()


def _number(value: str, maximum: int) -> int:
    if not value.isascii() or not value.isdigit() or len(value) > 7 or not 1 <= int(value) <= maximum:
        raise ValueError("invalid pagination")
    return int(value)


@router.get("/dashboard")
async def dashboard(request: Request, user: Row = Depends(require_user)):
    query = request.query_params
    if set(query) - {"q", "evaluation", "severity", "freshness", "sort", "page", "size"}:
        raise HTTPException(400)
    if any(len(query.getlist(key)) != 1 for key in query):
        raise HTTPException(400)
    try:
        filters = DomainFilter(query.get("q", "").strip(), query.get("evaluation", "all"),
                               query.get("severity", "all"), query.get("freshness", "all"),
                               query.get("sort", "attention"), _number(query.get("page", "1"), 1_000_000),
                               _number(query.get("size", "50"), 100))
    except ValueError:
        raise HTTPException(400) from None
    s = services(request)
    now = datetime.now(UTC)
    with s.db.transaction():
        state = portfolio.scheduler_state(s, getattr(request.app.state, "scheduler", None), now)
        page, domains = portfolio.load(s, filters, internal=bool(user["is_admin"]), scheduler=state,
                                       now=now, lang=lang_of(request))
    pages = max(1, (page.total + filters.size - 1) // filters.size)
    if filters.page > pages:
        raise HTTPException(404)

    def link(number: int) -> str:
        return "/dashboard?" + urlencode({"q": filters.name, "evaluation": filters.evaluation,
                                         "severity": filters.severity, "freshness": filters.freshness,
                                         "sort": filters.sort, "page": number, "size": filters.size})

    return render(request, "dashboard.html", filters=filters, facts=page.facts, domains=domains,
                  total=page.total, pages=pages, scheduler_state=state,
                  previous_url=link(filters.page - 1) if filters.page > 1 else None,
                  next_url=link(filters.page + 1) if filters.page < pages else None,
                  evaluations=EVALUATIONS, severities=SEVERITIES, freshness_choices=FRESHNESS, sorts=tuple(SORTS))
