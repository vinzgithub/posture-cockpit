# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The PDF report, laid out like an expert's file ("dossier").

Page 1 is for the decision-maker: grade, diagnosis in plain words and the
"prescription" (the priority fixes, who does them, how long they take).
Page 2 sums up each area, lists the improvements and what could not be
evaluated, and states the method. The annex is for the technician: every
check, what was found and the references.

The report shows the same result as the pages and the API (Scan.assessment):
the score with its coverage, or "not evaluated". It names its perimeter; the
report of an internal perimeter is marked for restricted distribution.

The HTML is rendered with Jinja (report.html, report.css) and turned into PDF
by WeasyPrint. WeasyPrint needs the Pango library; when it is missing the rest
of the application keeps working and only this report is unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, tzinfo
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__
from ..core import scoring
from ..core.model import Effort, Finding, Status
from ..i18n import Catalog, finding_summary, finding_verdict, fmt_date
from ..storage import Scan
from ..timezones import UTC, local, offset_label

REPORT_DIR = Path(__file__).parent
_env = Environment(loader=FileSystemLoader(REPORT_DIR), autoescape=select_autoescape(["html"]))


class ReportUnavailable(Exception):
    """WeasyPrint or one of its system libraries is missing."""


@dataclass(frozen=True)
class Prescription:
    number: int
    title: str
    summary: str
    who: str
    minutes: int
    gain: int
    gain_max: int | None
    deadline: str   # "Avant le 21 octobre 2026", or ""


def _who(catalog: Catalog, lang: str, finding: Finding) -> str:
    remedy = finding.outcome.remedy
    if remedy is None or remedy.effort is Effort.DELEGATE:
        return catalog.text(lang, "report.who.provider")
    return catalog.text(lang, "report.who.you_dns" if remedy.dns else "report.who.you")


def _text(catalog: Catalog, lang: str, key: str, finding: Finding, domain: str) -> str:
    return finding_summary(catalog, lang, finding, domain)


def report_context(catalog: Catalog, lang: str, scan: Scan, author: str = "", tz: tzinfo = UTC, *,
                   historical: bool = False, now: datetime | None = None) -> dict[str, Any]:
    """Everything the report template shows, already worded. ``now``: when the PDF is made (tests)."""
    findings = scan.current()
    plan = scoring.plan(findings)
    result = scan.assessment()
    counts = scoring.counts(findings)

    def t(key: str, /, **params: Any) -> str:
        return catalog.text(lang, key, params)

    prescriptions = []
    for i, item in enumerate(plan.priorities, start=1):
        f = item.finding
        expires = f.outcome.params.get("expires_on")
        prescriptions.append(Prescription(
            number=i,
            title=catalog.first(lang, [f"{f.outcome.summary}.action", f"{f.check_id}.action"],
                                {"domain": scan.domain, **f.outcome.params}),
            summary=_text(catalog, lang, f.outcome.summary, f, scan.domain),
            who=_who(catalog, lang, f), minutes=f.outcome.remedy.minutes if f.outcome.remedy else 0,
            gain=item.gain, gain_max=item.gain_max,
            deadline=t("report.deadline", date=fmt_date(str(expires), lang)) if expires else "",
        ))
    improvements = [
        {"title": catalog.first(lang, [f"{i.finding.outcome.summary}.action", f"{i.finding.check_id}.action"],
                                {"domain": scan.domain, **i.finding.outcome.params}),
         "summary": _text(catalog, lang, i.finding.outcome.summary, i.finding, scan.domain), "gain": i.gain}
        for i in plan.improvements
    ]

    # The diagnosis: the numbers, then the critical findings in plain words.
    minutes = sum(p.minutes for p in prescriptions)
    numbers = {"total": result.evaluated, "ok": counts.get(Status.OK, 0), "fail": counts.get(Status.FAIL, 0),
               "warn": counts.get(Status.WARN, 0)}
    if not result.evaluated_ok:
        diagnosis = t("report.diagnosis.not_evaluated", evaluated=result.evaluated, applicable=result.applicable)
        conclusion = t("report.diagnosis.plan_unscored", n=len(prescriptions)) if prescriptions else ""
    elif prescriptions:
        # A count of zero is left out of the sentence rather than written as "0 can be improved".
        diagnosis = t("report.diagnosis.issues" if numbers["fail"] and numbers["warn"]
                      else "report.diagnosis.issues_no_warn" if numbers["fail"] else "report.diagnosis.issues_no_fail",
                      **numbers)
        conclusion = t("report.diagnosis.plan_partial" if result.partial else "report.diagnosis.plan",
                       n=len(prescriptions), minutes=minutes, grade=plan.target.grade,
                       coverage=result.coverage_percent)
    else:
        diagnosis = t("report.diagnosis.clean" if numbers["warn"] else "report.diagnosis.all_ok", **numbers)
        conclusion = ""

    categories = []
    for category, assessment in scoring.by_category(findings).items():
        items = [f for f in findings if f.category == category and f.status.scored]
        worst = next((f for status in (Status.FAIL, Status.WARN) for f in items if f.status is status), None)
        if assessment.score is None:
            # The category may have reliable FAIL/WARN findings despite insufficient coverage.
            comment = (t("report.area_unscored_with_finding",
                         finding=finding_verdict(catalog, lang, worst, scan.domain))
                       if worst else t("report.area_not_evaluated"))
        elif worst:
            # The verdict only: its details are in the prescription and the annex.
            comment = finding_verdict(catalog, lang, worst, scan.domain)
        else:
            comment = t("report.all_ok")
        categories.append({"label": t(f"category.{category}"), "score": assessment.score,
                           "partial": assessment.partial, "comment": comment})

    # What could not be measured, by cause. Checks with the same reason share one line (the ten
    # dependents of a refused HTTPS say the same thing); an address needs no reason: its heading
    # is the cause.
    def gap_reason(f: Finding) -> str:
        if f.status is Status.BLOCKED:
            return t("v04.gap.blocked")
        if f.outcome.evidence.get("cause") == scoring.CAUSE_DEPENDENCY:
            return t("v04.gap.dependency")
        return finding_verdict(catalog, lang, f, scan.domain)

    gaps = [{"cause": f.outcome.evidence.get("cause", "dependency" if f.status is Status.BLOCKED else "network"),
             "title": t(f"{f.check_id}.title"), "reason": gap_reason(f)}
            for f in findings if f.status in {Status.ERROR, Status.BLOCKED}]

    root = next((f for f in findings if f.check_id == "web.https_redirect"), None)
    if root is not None:
        for host, observation in root.outcome.evidence.get("observation", {}).get("hosts", {}).items():
            for address, observed in observation.get("addresses", {}).items():
                if observed["class"] in {"unknown", "untestable", "tls_only"}:
                    cause = observed.get("cause", "network")
                    gaps.append({"cause": cause, "title": f"{host} ({address})", "reason": ""})

    annex = []
    for f in findings:
        annex.append({
            "id": f.check_id, "status": f.status.value, "status_label": t(f"status.{f.status.value}"),
            "title": t(f"{f.check_id}.title"),
            "summary": _text(catalog, lang, f.outcome.summary, f, scan.domain),
            "ref": catalog.text(lang, f"{f.check_id}.ref") if catalog.has(lang, f"{f.check_id}.ref") else "",
        })

    started = local(scan.started_at, tz)
    generated = (now or datetime.now(UTC)).astimezone(tz)
    return {
        "lang": lang, "t": t, "domain": scan.domain, "scan": scan, "author": author,
        "historical": historical, "generator_version": __version__,
        # A historical report is made long after the scan: it says when, in the time zone of the instance.
        "generated": {"date": fmt_date(generated.date(), lang), "time": generated.strftime("%H:%M"),
                      "zone": offset_label(generated)},
        # The file number keeps the UTC day: it must not change with the time zone of the instance.
        "file_number": f"{scan.started_at[:10].replace('-', '')}-{scan.id:04d}",
        "date": fmt_date(started.date(), lang), "time": started.strftime("%H:%M"), "zone": offset_label(started),
        "result": result, "grade_label": t(scoring.grade_label(result.grade)) if result.grade else "",
        "coverage": t("score.coverage", evaluated=result.evaluated, applicable=result.applicable,
                      percent=result.coverage_percent),
        "perimeter": scan.perimeter,
        "diagnosis": diagnosis, "conclusion": conclusion, "prescriptions": prescriptions,
        "improvements": improvements, "categories": categories, "annex": annex, "gaps": gaps,
        "checks_count": len(findings), "addresses": scan.addresses(), "plan": plan,
        "gap_groups": {cause: _same_reason([g for g in gaps if g["cause"] == cause])
                       for cause in ("network", "dependency", "tool", "policy", "budget")},
    }


def _same_reason(gaps: list[dict]) -> list[dict]:
    """One line per reason, in the order of first appearance: titles joined, reason once."""
    lines: dict[str, list[str]] = {}
    for gap in gaps:
        lines.setdefault(gap["reason"], []).append(gap["title"])
    return [{"titles": titles, "reason": reason} for reason, titles in lines.items()]


def render_html(catalog: Catalog, lang: str, scan: Scan, author: str = "", tz: tzinfo = UTC, *,
                historical: bool = False) -> str:
    context = report_context(catalog, lang, scan, author, tz, historical=historical)
    return _env.get_template("report.html").render(**context)


def build_pdf(catalog: Catalog, lang: str, scan: Scan, author: str = "", tz: tzinfo = UTC, *,
              historical: bool = False) -> bytes:
    """The report as PDF bytes, times in the time zone ``tz``.

    Raises ReportUnavailable when WeasyPrint cannot run here."""
    try:
        from weasyprint import HTML  # imported here: it loads system libraries
    except (ImportError, OSError) as e:
        raise ReportUnavailable(str(e)) from e
    html = render_html(catalog, lang, scan, author, tz, historical=historical)
    return HTML(string=html, base_url=str(REPORT_DIR)).write_pdf()


def build_unreadable_pdf(catalog: Catalog, lang: str) -> bytes:
    """A localized error document; never render untrusted stored outcomes as a report."""
    from html import escape

    try:
        from weasyprint import HTML
    except (ImportError, OSError) as error:
        raise ReportUnavailable(str(error)) from error
    message = escape(catalog.text(lang, "error.scan_unreadable"))
    html = f'<html lang="{escape(lang)}"><meta charset="utf-8"><body><p>{message}</p></body></html>'
    return HTML(string=html).write_pdf()
