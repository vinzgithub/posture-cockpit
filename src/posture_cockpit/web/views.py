# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""What the plan page shows, computed from a scan.

These functions turn findings into ready-to-display texts and numbers, so the
template (plan.html) stays simple, with no logic beyond loops and conditions.
The page is tested in tests/test_domains.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote

from ..core import providers, scoring
from ..core.model import DnsChange, Finding, Status
from ..i18n import Catalog
from ..storage import Row, Scan

EFFORT_KEYS = {"easy": "effort.easy", "medium": "effort.medium", "delegate": "effort.delegate"}


@dataclass(frozen=True)
class Step:
    """One numbered instruction; ``path`` is a menu path shown as a chip."""

    text: str
    path: str = ""


@dataclass(frozen=True)
class RecordView:
    change: DnsChange
    fqdn: str


@dataclass(frozen=True)
class DnsHostView:
    id: str
    name: str
    detected: bool
    selected: bool


@dataclass
class TaskView:
    check_id: str
    number: int
    title: str          # what to do: "Publier une politique DMARC"
    summary: str        # what was found (or, once verified, what is found now)
    why: str
    category: str
    minutes: int
    effort: str         # "easy", "medium" or "delegate"
    effort_label: str
    gain: int           # points this fix brings to the score
    records: list[RecordView] = field(default_factory=list)
    steps: dict[str, list[Step]] = field(default_factory=dict)  # by DNS host id
    message: str = ""
    mailto: str = ""
    how: str = ""
    done: bool = False          # checked again and now OK
    checked_at: str = ""        # when it was checked again, if it was
    still_failing: bool = False  # checked again and still not OK


@dataclass(frozen=True)
class StepperStep:
    label: str
    detail: str
    state: str  # "done", "active" or "todo"


@dataclass
class PlanView:
    domain: str
    scan: Scan
    score: int
    grade: str
    grade_label: str
    start_score: int
    target: int
    target_grade: str
    priorities: list[TaskView]
    improvements: list[TaskView]
    counts: dict[str, int]
    categories: list[tuple[str, str, int]]   # (id, label, score)
    dns_hosts: list[DnsHostView]
    dns_host: str                            # id of the selected host
    detected_host: str                       # name of the detected host, "" if unknown
    nameservers: list[str]
    headline: str = ""
    subline: str = ""
    score_note: str = ""
    steps: list[StepperStep] = field(default_factory=list)

    @property
    def tasks(self) -> list[TaskView]:
        return self.priorities + self.improvements

    @property
    def done_count(self) -> int:
        return sum(t.done for t in self.priorities)


def _nameservers(findings: list[Finding]) -> list[str]:
    ns = next((f for f in findings if f.check_id == "dns.nameservers"), None)
    return list(ns.outcome.evidence.get("nameservers", [])) if ns else []


def dns_host_steps(catalog: Catalog, lang: str, host_id: str, change: DnsChange, domain: str) -> list[Step]:
    """Instructions to add or delete ``change`` at this DNS host."""
    params = {"domain": domain, "rtype": change.rtype, "name": change.name}

    def text(part: str) -> str:
        return catalog.text(lang, f"dnshost.{host_id}.{part}", params)

    steps = [Step(text("open"), text("path"))]
    if change.action == "add":
        steps.append(Step(text("add")))
        steps.append(Step(text("fill")))
        if change.name == "@":
            steps.append(Step(text("apex")))
    else:
        steps.append(Step(text("delete")))
    return steps


def task_view(catalog: Catalog, lang: str, scan: Scan, finding: Finding, number: int, gain: int,
              host_ids: list[str]) -> TaskView:
    """One item of the plan, in the reader's language."""
    remedy = finding.outcome.remedy
    assert remedy is not None
    params = {"domain": scan.domain, **finding.outcome.params}

    def text(key: str) -> str:
        return catalog.text(lang, key, params)

    # After "Vérifier", the latest result describes the domain as it is now.
    recheck = scan.rechecks.get(finding.check_id)
    current = recheck.finding if recheck else finding
    summary_key = current.outcome.summary
    current_params = {"domain": scan.domain, **current.outcome.params}
    view = TaskView(
        check_id=finding.check_id, number=number,
        title=catalog.first(lang, [f"{finding.outcome.summary}.action", f"{finding.check_id}.action"], params),
        summary=catalog.text(lang, summary_key, current_params),
        why=text(f"{finding.check_id}.why"),
        category=text(f"category.{finding.category}"),
        minutes=remedy.minutes, effort=remedy.effort.value, effort_label=text(EFFORT_KEYS[remedy.effort.value]),
        gain=gain,
        records=[RecordView(c, scan.domain if c.name == "@" else f"{c.name}.{scan.domain}") for c in remedy.dns],
        how=text(remedy.how) if remedy.how else "",
        done=recheck is not None and current.status is Status.OK,
        checked_at=recheck.checked_at if recheck else "",
    )
    view.still_failing = recheck is not None and not view.done
    if remedy.message:
        view.message = text(remedy.message)
        subject = catalog.text(lang, "plan.mail_subject", {"domain": scan.domain, "title": view.title})
        view.mailto = f"mailto:?subject={quote(subject)}&body={quote(view.message)}"
    for host_id in host_ids:
        view.steps[host_id] = [step for c in remedy.dns
                               for step in dns_host_steps(catalog, lang, host_id, c, scan.domain)]
    return view


def plan_view(catalog: Catalog, lang: str, scan: Scan, domain_row: Row) -> PlanView:
    findings = scan.findings
    current = scan.current()
    plan = scoring.plan(findings)
    nameservers = _nameservers(findings)
    detected = providers.detect(nameservers)
    host_ids = [h.id for h in providers.DNS_HOSTS] + [providers.OTHER.id]
    selected = domain_row["dns_host"] or (detected.id if detected else providers.OTHER.id)
    hosts = [DnsHostView(h.id, h.name or catalog.text(lang, "dnshost.other.name"), detected is not None
                         and h.id == detected.id, h.id == selected)
             for h in (*providers.DNS_HOSTS, providers.OTHER)]

    def views(items: list[scoring.PlanItem], first: int) -> list[TaskView]:
        return [task_view(catalog, lang, scan, item.finding, first + i, item.gain, host_ids)
                for i, item in enumerate(items)]

    priorities = views(plan.priorities, 1)
    improvements = views(plan.improvements, len(priorities) + 1)
    value = scoring.score(current)
    counts = scoring.counts(current)
    view = PlanView(
        domain=scan.domain, scan=scan, score=value, grade=scoring.grade(value),
        grade_label=catalog.text(lang, scoring.grade_label(value)),
        start_score=plan.score, target=max(plan.target, value), target_grade=scoring.grade(max(plan.target, value)),
        priorities=priorities, improvements=improvements,
        counts={status.value: counts.get(status, 0) for status in Status},
        categories=[(cat, catalog.text(lang, f"category.{cat}"), s) for cat, s in scoring.by_category(current).items()],
        dns_hosts=hosts, dns_host=selected, detected_host=detected.name if detected else "", nameservers=nameservers,
    )
    _tell_the_story(catalog, lang, view)
    return view


def _tell_the_story(catalog: Catalog, lang: str, view: PlanView) -> None:
    """Headline, subline, stepper and the note under the score bar, from where the user stands."""
    def text(key: str, /, **params: object) -> str:
        return catalog.text(lang, key, params)

    total = len(view.priorities)
    done = view.done_count
    remaining = total - done
    minutes = sum(t.minutes for t in view.priorities if not t.done)
    start_grade = scoring.grade(view.start_score)
    if total == 0:
        view.headline = text("plan.headline.clean")
        view.subline = (text("plan.subline.clean_improvements", n=len(view.improvements)) if view.improvements
                        else text("plan.subline.clean"))
    elif done == 0:
        view.headline = (text("plan.headline.start", n=total, start=start_grade, end=view.target_grade)
                         if start_grade != view.target_grade else text("plan.headline.start_points", n=total,
                                                                        points=view.target - view.start_score))
        view.subline = text("plan.subline.start", minutes=minutes)
    elif remaining:
        view.headline = text("plan.headline.progress", n=remaining, grade=view.target_grade)
        view.subline = text("plan.subline.progress", start=view.start_score, score=view.score)
    else:
        view.headline = text("plan.headline.done")
        view.subline = text("plan.subline.done")

    all_done = remaining == 0
    view.steps = [
        StepperStep(text("plan.step.scan"), text("plan.step.scan_detail", n=len(view.scan.findings)), "done"),
        StepperStep(text("plan.step.fix"), text("plan.step.fix_detail", done=done, total=total),
                    "done" if all_done else "active"),
        StepperStep(text("plan.step.check"), text("plan.step.check_detail"), "active" if all_done else "todo"),
        StepperStep(text("plan.step.share"), text("plan.step.share_detail"), "todo"),
    ]
    view.score_note = (text("plan.score_note.remaining", n=remaining) if remaining
                       else text("plan.score_note.reached"))
