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
from ..i18n import Catalog, finding_summary
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
    gain: int | None    # points this fix brings to the score
    records: list[RecordView] = field(default_factory=list)
    steps: dict[str, list[Step]] = field(default_factory=dict)  # by DNS host id
    message: str = ""
    mailto: str = ""
    how: str = ""
    done: bool = False          # checked again and now OK
    checked_at: str = ""        # when it was checked again, if it was
    gain_max: int | None = None
    still_failing: bool = False  # checked again and still not OK


@dataclass(frozen=True)
class StepperStep:
    label: str
    detail: str
    state: str  # "done", "active" or "todo"


@dataclass(frozen=True)
class GapView:
    """A check that should have run and could not: why, in the reader's words."""

    check_id: str
    title: str
    reason: str


@dataclass
class PlanView:
    domain: str
    scan: Scan
    now: scoring.Assessment      # the domain as it is now (rechecks included)
    start: scoring.Assessment    # as the scan found it
    target: scoring.Assessment   # once every priority is fixed
    grade_label: str             # "" when not evaluated
    priorities: list[TaskView]
    improvements: list[TaskView]
    counts: dict[str, int]
    categories: list[tuple[str, str, scoring.Assessment]]   # (id, label, assessment)
    gaps: list[GapView]          # checks not evaluated
    dns_hosts: list[DnsHostView]
    dns_host: str                            # id of the selected host
    detected_host: str                       # name of the detected host, "" if unknown
    nameservers: list[str]
    completed: list[TaskView] = field(default_factory=list)
    target_max_score: int | None = None
    provisional: bool = False
    headline: str = ""
    subline: str = ""
    score_note: str = ""
    steps: list[StepperStep] = field(default_factory=list)

    @property
    def tasks(self) -> list[TaskView]:
        return self.priorities + self.improvements + self.completed

    @property
    def score(self) -> int | None:
        return self.now.score

    @property
    def grade(self) -> str | None:
        return self.now.grade

    @property
    def target_score(self) -> int | None:
        """Conditional score after the current priority steps; it may be lower or absent."""
        return self.target.score

    @property
    def target_grade(self) -> str | None:
        return self.target.grade

    @property
    def target_kind(self) -> str:
        return scoring.target_kind(self.now, self.target, self.provisional)

    @property
    def done_count(self) -> int:
        return len(self.completed)


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


def task_view(catalog: Catalog, lang: str, scan: Scan, finding: Finding, number: int, gain: int | None,
              host_ids: list[str], gain_max: int | None = None) -> TaskView:
    """One item of the plan, in the reader's language."""
    remedy = finding.outcome.remedy
    assert remedy is not None
    params = {"domain": scan.domain, **finding.outcome.params}

    def text(key: str) -> str:
        return catalog.text(lang, key, params)

    # After "Vérifier", the latest result describes the domain as it is now.
    recheck = scan.rechecks.get(finding.check_id)
    current = recheck.finding if recheck else finding
    view = TaskView(
        check_id=finding.check_id, number=number,
        title=catalog.first(lang, [f"{finding.outcome.summary}.action", f"{finding.check_id}.action"], params),
        summary=finding_summary(catalog, lang, current, scan.domain),
        why=catalog.first(lang, [f"{finding.outcome.summary}.why", f"{finding.check_id}.why"], params),
        category=text(f"category.{finding.category}"),
        minutes=remedy.minutes, effort=remedy.effort.value, effort_label=text(EFFORT_KEYS[remedy.effort.value]),
        gain=gain, gain_max=gain_max,
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


def gaps(catalog: Catalog, lang: str, domain: str, findings: list[Finding]) -> list[GapView]:
    """The checks that could not be evaluated, with the reason (timeout, unreachable, destination refused)."""
    return [GapView(f.check_id, catalog.text(lang, f"{f.check_id}.title"), finding_summary(catalog, lang, f, domain))
            for f in findings if f.status is Status.ERROR]


def plan_view(catalog: Catalog, lang: str, scan: Scan, domain_row: Row,
              registry: scoring.VerdictRegistry | None = None) -> PlanView:
    findings = scan.findings
    current = scan.current()
    plan = scoring.plan(current, registry)
    original = scoring.plan(findings, registry)
    nameservers = _nameservers(findings)
    detected = providers.detect(nameservers)
    host_ids = [h.id for h in providers.DNS_HOSTS] + [providers.OTHER.id]
    selected = domain_row["dns_host"] or (detected.id if detected else providers.OTHER.id)
    hosts = [DnsHostView(h.id, h.name or catalog.text(lang, "dnshost.other.name"), detected is not None
                         and h.id == detected.id, h.id == selected)
             for h in (*providers.DNS_HOSTS, providers.OTHER)]

    def views(items: list[scoring.PlanItem], first: int) -> list[TaskView]:
        return [task_view(catalog, lang, scan, item.finding, first + i, item.gain, host_ids, item.gain_max)
                for i, item in enumerate(items)]

    priorities = views(plan.priorities, 1)
    improvements = views(plan.improvements, len(priorities) + 1)
    completed = views([item for item in original.items
                       if item.finding.check_id in scan.rechecks
                       and scan.rechecks[item.finding.check_id].finding.status is Status.OK],
                      len(priorities) + len(improvements) + 1)
    for task in completed:
        # Original hypothetical gains are not proof of points actually earned.
        task.gain = task.gain_max = None
    now = scan.assessment()
    counts = scoring.counts(current)
    view = PlanView(
        domain=scan.domain, scan=scan, now=now, start=original.now, target=plan.target, provisional=plan.provisional,
        target_max_score=plan.target_max.score if plan.target_max is not None else None,
        grade_label=catalog.text(lang, scoring.grade_label(now.grade)) if now.grade else "",
        priorities=priorities, improvements=improvements, completed=completed,
        counts={status.value: counts.get(status, 0) for status in Status},
        categories=[(cat, catalog.text(lang, f"category.{cat}"), a) for cat, a in scoring.by_category(current).items()],
        gaps=gaps(catalog, lang, scan.domain, current),
        dns_hosts=hosts, dns_host=selected, detected_host=detected.name if detected else "", nameservers=nameservers,
    )
    _tell_the_story(catalog, lang, view)
    return view


def _tell_the_story(catalog: Catalog, lang: str, view: PlanView) -> None:
    """Headline, subline, stepper and the note under the score, from where the user stands."""
    def text(key: str, /, **params: object) -> str:
        return catalog.text(lang, key, params)

    total = len(view.priorities) + view.done_count
    done = view.done_count
    remaining = total - done
    minutes = sum(t.minutes for t in view.priorities if not t.done)
    now = view.now
    if not now.evaluated_ok:
        # Too little could be checked to grade the domain: say so first, then list what was found anyway.
        view.headline = text("plan.headline.not_evaluated")
        view.subline = text("plan.subline.not_evaluated", evaluated=now.evaluated, applicable=now.applicable,
                            percent=now.coverage_percent)
    elif total == 0:
        view.headline = text("plan.headline.clean")
        view.subline = (text("plan.subline.clean_improvements", n=len(view.improvements)) if view.improvements
                        else text("plan.subline.clean"))
    elif done == 0:
        # The scan itself may have had no score (too little evaluated) and gained one through
        # rechecks: then there is no starting point to quote, and no projection either.
        start_grade, end_grade = view.now.grade, view.target_grade
        target, start = view.target_score, view.now.score
        if view.target_kind == "estimated" and start_grade and end_grade and start_grade != end_grade:
            view.headline = text("plan.headline.start", n=total, start=start_grade, end=end_grade)
        elif view.target_kind == "estimated" and start is not None and target is not None and target > start:
            view.headline = text("plan.headline.start_points", n=total, points=target - start)
        else:
            view.headline = text("plan.headline.start_plain", n=total)
        view.subline = text("plan.subline.start", minutes=minutes)
    elif remaining:
        view.headline = (text("plan.headline.progress", n=remaining, grade=view.target_grade)
                         if view.target_grade and view.target_kind == "estimated"
                         else text("plan.headline.progress_plain", n=remaining))
        view.subline = (text("plan.subline.progress", start=view.start.score, score=now.score)
                        if view.start.score is not None else text("plan.subline.progress_plain", score=now.score))
    else:
        view.headline = text("plan.headline.done")
        view.subline = text("plan.subline.done")

    all_done = remaining == 0
    if not now.evaluated_ok:
        # The first step is not done: the scan has to run again once the servers answer.
        scan_step = StepperStep(text("plan.step.scan"), text("plan.step.scan_incomplete", evaluated=now.evaluated,
                                                             applicable=now.applicable), "active")
        fix_state = check_state = "todo"
    else:
        scan_step = StepperStep(text("plan.step.scan"), text("plan.step.scan_detail", n=now.evaluated),
                                "done")
        fix_state, check_state = ("done", "active") if all_done else ("active", "todo")
    view.steps = [
        scan_step,
        StepperStep(text("plan.step.fix"), text("plan.step.fix_detail", done=done, total=total), fix_state),
        StepperStep(text("plan.step.check"), text("plan.step.check_detail"), check_state),
        StepperStep(text("plan.step.share"), text("plan.step.share_detail"), "todo"),
    ]
    if not now.evaluated_ok:
        view.score_note = text("plan.score_note.not_evaluated")
    elif now.partial:
        view.score_note = text("plan.score_note.partial", percent=now.coverage_percent)
    else:
        view.score_note = (text("plan.score_note.remaining", n=remaining) if remaining
                           else text("plan.score_note.reached"))
