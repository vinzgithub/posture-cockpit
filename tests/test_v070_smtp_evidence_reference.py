# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The verdicts of mail.smtp_starttls on the reference corpus are those recorded before the bounding.

tests/data/smtp-evidence-reference.json was written by tests/smtp_reference.py on integration/v0.7.0 at
0042c80, before the evidence was bounded (correction 2). For every world, field by field: the status,
the rule of F05, the key of the summary, its parameters, the remedy, the signals; F06, its causes and the
state of the policy; the real counts of MX and addresses (exhaustivity) and of what each address showed;
every attempt with what it showed; the totals of silent MX and of the lists of the policy; the notes and
their counts. And for every fixed world, the whole scan: the score, the grade, the status of each of the
21 checks and the measurement scope. The bounding changes what the evidence keeps, never any of these.
"""

import json

import pytest

from smtp_reference import DATA, corpus, observed, outcome_of, scored

REFERENCE = json.loads(DATA.read_text())
WORLDS = {name: (world, probe) for name, world, probe in corpus()}


def test_the_reference_was_recorded_before_the_bounding_and_covers_f05_and_f06():
    """The corpus was recorded on 0042c80 and holds every line of F05 that has a branch and every state of F06."""
    assert REFERENCE["recorded_on"] == "0042c801e0e093683067c94ad9990a3cbd9c7024"
    assert sorted(REFERENCE["worlds"]) == sorted(WORLDS)
    rules = {v["rule"] for v in REFERENCE["worlds"].values()}
    assert rules == {"F05.01", "F05.02", "F05.03", "F05.04", "F05.06", "F05.07", "F05.08", "F05.09", "F05.10"}
    states = {v["readiness"]["state"] for v in REFERENCE["worlds"].values()}
    assert states == {"ready", "compatible", "to_fix", "unconfirmed", "not_applicable"}


@pytest.mark.parametrize("name", sorted(REFERENCE["worlds"]))
def test_the_check_decides_as_recorded(name):
    """F05, F06, A5: the same verdict, the same readiness, the same real counts and attempts as recorded."""
    world, probe = WORLDS[name]
    assert observed(outcome_of(world, probe)) == REFERENCE["worlds"][name]


@pytest.mark.parametrize("name", sorted(REFERENCE["scans"]))
def test_the_score_the_statuses_and_the_scope_are_as_recorded(name):
    """F05, F06 downstream: the scoring, the 21 checks and measurement_scope, the same as recorded for every
    fixed world."""
    world, probe = WORLDS[name]
    assert scored(world, probe) == REFERENCE["scans"][name]
