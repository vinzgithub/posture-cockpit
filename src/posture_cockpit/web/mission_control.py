# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Presentation of authorized current observations; no network or storage writes."""
from __future__ import annotations

from dataclasses import dataclass

from ..core import scoring
from ..core.compare import CheckChange, LastConclusive, Snapshot, check_changes, compare, last_conclusive
from ..core.model import CAUSE_DEPENDENCY, HTTPS_FAMILY, Role, Status
from ..core.remediation import expected_status
from ..i18n import Catalog
from ..storage import Row, Scan
from .views import plan_view


@dataclass(frozen=True)
class Transition:
    change: CheckChange
    previous: Snapshot
    current: Snapshot
    last: LastConclusive


def context(catalog: Catalog, lang: str, domain: Row, scan: Scan, states: list[Snapshot],
            registry: scoring.VerdictRegistry) -> dict:
    """Prepare status-only history and a plan from one coherent current observation."""
    current = states[0]
    previous = states[1] if len(states) > 1 else None
    changes = check_changes(previous, current)
    order = {"regressed": 0, "new_issue": 0, "unmeasured": 1, "improved": 2, "not_applicable": 3}
    transitions = [Transition(change, previous, current, last_conclusive(states, change.check_id))
                   for change in sorted(changes.changes, key=lambda c: (order.get(c.kind, 4), c.check_id))
                   if previous is not None]
    findings = scan.current()
    view = plan_view(catalog, lang, scan, domain, registry)
    candidates = []
    by_id = {f.check_id: f for f in findings}
    for task in view.priorities + view.improvements:
        finding = by_id[task.check_id]
        candidates.append({"task": task, "observed": finding.status,
                           "expected": expected_status(finding)})
    dependencies = [f for f in findings if f.family == HTTPS_FAMILY and f.role is Role.DEPENDENT
                    and (f.status is Status.BLOCKED
                         or (f.status is Status.ERROR and f.outcome.evidence.get("cause") == CAUSE_DEPENDENCY))]
    return {"domain": domain, "scan": scan, "current_state": current, "plan": view,
            "candidates": candidates, "transitions": transitions, "changes": changes,
            "comparison": compare(previous, current), "dependencies": dependencies}
