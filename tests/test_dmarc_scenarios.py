# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Synthetic DMARC scenarios: the healthy test world (100/100, A) with only its DMARC record
changed, computed by the engine. The table in docs/user/SCORING.md §7 comes from here.

These are test worlds, not measurements of any real domain."""

import pytest

from posture_cockpit.core import scoring
from posture_cockpit.core.model import Status
from worlds import DOMAIN, changed, healthy, run

RECORD = f"_dmarc.{DOMAIN} TXT"
OK, WARN = Status.OK, Status.WARN


@pytest.mark.parametrize(("dns", "status", "verdict", "notes", "score"), [
    # 0.3.1 in the comment: what the same world gave before.
    ({}, OK, "enforced", [], 100),                                                           # same
    ({RECORD: None, "_dmarc.org TXT": ["v=DMARC1; p=none; psd=y"]},
     WARN, "monitoring_inherited", [], 94),                                                  # same verdict
    ({RECORD: ["v=DMARC1; p=reject; pct=50"]}, WARN, "partial_reject", [], 94),              # OK, 100
    ({RECORD: ["v=DMARC1; p=reject; pct=0"]}, WARN, "partial_reject", [], 94),               # OK, 100
    ({RECORD: ["v=DMARC1; p=quarantine; pct=0"]}, WARN, "partial", [], 94),                  # OK, 100
    ({RECORD: ["v=DMARC1; p=reject; pct=abc"]}, WARN, "syntax", [], 94),                     # OK, 100
    ({RECORD: ["v=DMARC1; p=none; pct=abc"]}, WARN, "monitoring_no_reports", ["syntax"], 94),  # monitoring
    ({RECORD: ["v=DMARC1; p=reject; t=y; pct=101"]}, WARN, "testing", ["syntax"], 94),       # testing, no note
    ({RECORD: ["v=DMARC1; p=reject; t=y; pct=50"]}, WARN, "testing", ["partial_reject"], 94),  # testing, no note
    ({RECORD: ["v=DMARC1; p=quarantine; t=y; pct=50"]}, WARN, "testing", ["partial"], 94),   # testing, no note
    ({RECORD: ["v=DMARC1; p=reject; pct=50; sp=none"]},
     WARN, "partial_reject", ["subdomains_open"], 94),                                       # subdomains_open
    ({RECORD: ["v=DMARC1; p=none"]}, WARN, "monitoring_no_reports", [], 94),                 # monitoring
])
def test_synthetic_dmarc_scenarios(dns, status, verdict, notes, score):
    findings = list(run(changed(healthy(), dns=dns)).values())
    dmarc = next(f for f in findings if f.check_id == "mail.dmarc")
    assert (dmarc.status, dmarc.outcome.summary) == (status, f"mail.dmarc.{verdict}")
    assert [n["key"] for n in dmarc.outcome.evidence.get("notes", [])] == [f"mail.dmarc.note.{n}" for n in notes]
    result = scoring.assess(findings)
    assert (result.score, result.grade, result.coverage) == (score, "A", 1.0)
