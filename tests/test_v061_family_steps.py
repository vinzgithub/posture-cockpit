# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""F04: compare first-step expectations with real check outcomes on recorded answers."""
import copy

import pytest

from posture_cockpit.core.model import Finding
from posture_cockpit.core.remediation import expected_status
from worlds import DOMAIN, changed, healthy, run


def worlds(kind):
    base = healthy()
    if kind == 'spf':
        return 'mail.spf', changed(base, dns={f'{DOMAIN} TXT': ['v=spf1 mx +all']}), base
    if kind == 'dnssec':
        return 'dns.dnssec', changed(base, dns={f'{DOMAIN} DS': []}), base
    if kind == 'mx':
        before = changed(base, dns={f'{DOMAIN} MX': ['0 .', '10 mx.example.net.']})
        return 'mail.mx', before, changed(base, dns={f'{DOMAIN} MX': ['0 .']})
    if kind == 'mta':
        before = changed(base, dns={f'_mta-sts.{DOMAIN} TXT': []})
        after = copy.deepcopy(base)
        url = f'https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt'
        after['http'][url]['body'] = after['http'][url]['body'].replace('mode: enforce', 'mode: testing')
        return 'mail.mta_sts', before, after
    before = copy.deepcopy(base)
    headers = before['http'][f'https://www.{DOMAIN}/']['headers']
    policy = headers.pop('Content-Security-Policy')
    after = copy.deepcopy(before)
    after['http'][f'https://www.{DOMAIN}/']['headers']['Content-Security-Policy-Report-Only'] = policy
    return 'web.csp', before, after


@pytest.mark.parametrize('kind', ['spf', 'dnssec', 'mx', 'mta', 'csp'])
def test_actual_first_step_matches_projection_before_and_after_storage(kind):
    check, before, after = worlds(kind)
    f = run(before, check)[check]
    actual = run(after, check)[check]
    assert f.outcome.remedy is not None
    assert expected_status(f) is actual.status
    for historical in (False, True):
        payload = f.outcome_json()
        if historical:
            payload['remedy'].pop('expect')
        read = Finding.from_stored(f.check_id, f.category, f.weight, f.status, payload)
        assert expected_status(read) is actual.status
