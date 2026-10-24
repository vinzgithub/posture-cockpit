# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Calculable plan contributions do not imply a calculable complete target."""
from dataclasses import replace

import pytest

from posture_cockpit.core import scoring
from posture_cockpit.core.model import Effort, Outcome, Remedy, Status
from test_v060_simulation import REGISTRY
from worlds import DOMAIN, changed, healthy, run


@pytest.mark.parametrize('weight', [1, 6, 30])
def test_unknown_anywhere_keeps_known_gains_without_promising_full_target(weight):
    fs = list(run(changed(healthy(), dns={f'_dmarc.{DOMAIN} TXT': [], f'{DOMAIN} CAA': []})).values())
    f = next(f for f in fs if f.check_id == 'dns.dnssec')
    unknown = replace(f, weight=weight, outcome=Outcome(Status.FAIL, 'dns.dnssec.broken',
                                                       remedy=Remedy(10, Effort.MEDIUM)))
    fs = [unknown if item.check_id == unknown.check_id else item for item in fs]
    plan = scoring.plan(fs, REGISTRY)
    items = {i.finding.check_id: i for i in plan.items}
    assert items['dns.dnssec'].gain is None
    assert items['mail.dmarc'].gain is not None
    assert items['dns.caa'].gain is not None
    assert plan.target.score is None
    assert plan.unknown == ('dns.dnssec',)
    assert scoring.simulate(fs, ['mail.dmarc', 'dns.dnssec', 'dns.caa'], REGISTRY).worst.score is None
    assert scoring.plan(fs, REGISTRY) == plan
