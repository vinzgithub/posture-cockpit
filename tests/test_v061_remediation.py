# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Actions are compared with the next actual check, using recorded network answers."""
import re
from dataclasses import replace

import pytest

import https_worlds as H
from posture_cockpit.core.model import Effort, Outcome, Remedy, Status
from posture_cockpit.core.remediation import expected_status
from worlds import DOMAIN, changed, healthy, run


@pytest.mark.parametrize('age', [3600, 86399, 86400, 604800])
def test_testing_to_enforce_retains_short_age(age):
    url = f'https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt'
    # Keep the fixture's actual MX pattern rather than inventing a mismatch.
    body = healthy()['http'][url]['body']
    def state(mode):
        new = re.sub(r'mode: \w+', f'mode: {mode}', body)
        new = re.sub(r'max_age: \d+', f'max_age: {age}', new)
        return changed(healthy(), http={url: {'status': 200, 'body': new}})
    before = run(state('testing'), 'mail.mta_sts')['mail.mta_sts']
    after = run(state('enforce'), 'mail.mta_sts')['mail.mta_sts']
    assert before.outcome.summary == 'mail.mta_sts.testing'
    assert expected_status(before) is after.status
    assert after.status is (Status.WARN if age < 86400 else Status.OK)


@pytest.mark.parametrize('age', [None, True, '86400'])
def test_testing_missing_or_malformed_age_is_unknown(age):
    f = run(healthy(), 'mail.mta_sts')['mail.mta_sts']
    outcome = Outcome(Status.WARN, 'mail.mta_sts.testing', evidence={'max_age': age},
                      remedy=Remedy(10, Effort.DELEGATE))
    assert expected_status(replace(f, outcome=outcome)) is None


@pytest.mark.parametrize('tls13', [True, False])
def test_disable_obsolete_does_not_enable_tls13(tls13):
    old = {'versions': {'TLSv1': True, 'TLSv1.1': True, 'TLSv1.2': True, 'TLSv1.3': tls13}}
    fixed = {'versions': {**old['versions'], 'TLSv1': False, 'TLSv1.1': False}}
    before = run(H.site({H.V4A: old}))['tls.protocols']
    after = run(H.site({H.V4A: fixed}))['tls.protocols']
    assert before.status is Status.FAIL
    assert expected_status(before) is after.status
    assert after.status is (Status.OK if tls13 else Status.WARN)


def test_only_obsolete_https_cannot_be_projected_as_warn():
    before = run(H.site({H.V4A: H.OBSOLETE}))['tls.protocols']
    after = run(H.site({H.V4A: H.REFUSED}))
    assert expected_status(before) is None
    assert after['web.https_redirect'].status is Status.FAIL
    assert after['tls.protocols'].status is Status.BLOCKED


@pytest.mark.parametrize('accepted', [{}, None, [], {'one': {}}, {'one': {'TLSv1.3': None}},
                                      {'one': {'TLSv1.3': True}, 'two': {'TLSv1.3': None}}])
def test_tls_missing_proof_is_not_ok(accepted):
    f = run(H.site({H.V4A: {'versions': {'TLSv1': True}}}))['tls.protocols']
    assert expected_status(replace(f, outcome=replace(f.outcome, evidence={'accepted': accepted}))) is None


def test_mixed_modern_and_obsolete_only_addresses_still_have_unknown_effect():
    f = run(H.site({H.V4A: {}, H.V4B: H.OBSOLETE}))['tls.protocols']
    assert f.status is Status.FAIL
    assert expected_status(f) is None
