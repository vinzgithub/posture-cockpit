# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Explicit new expectations, conservative old extensions, current built-in adapter."""
import copy
from dataclasses import replace

import pytest

from posture_cockpit.core import engine, scoring
from posture_cockpit.core.model import Effort, Finding, Outcome, Remedy, Status
from posture_cockpit.core.remediation import expected_status, with_expectation
from posture_cockpit.storage import Database, Scans
from worlds import DOMAIN, NOW, healthy, run


@pytest.mark.parametrize('expect', [Status.OK, Status.WARN, Status.INFO, None])
def test_extension_real_storage_roundtrip(tmp_path, expect):
    f = Finding('extra.custom', 'dns', 2, Outcome(Status.FAIL, 'extra.problem',
                remedy=Remedy(2, Effort.EASY, expect=expect)))
    assert 'expect' in f.outcome_json()['remedy']
    db = Database(tmp_path / 'test.db')
    try:
        scans = Scans(db)
        did = scans.add_domain(DOMAIN, None)
        sid = scans.save(did, engine.ScanResult(DOMAIN, NOW, 1, [f]), '0.6.1', None)
        read = scans.get(sid).findings[0]
        assert read == f
        assert expected_status(read) is expect
        assert scoring.plan([read]) == scoring.plan([f])
    finally:
        db.close()


@pytest.mark.parametrize('expect', [Status.OK, Status.WARN, Status.INFO, None])
def test_f05_bis_builtin_current_table_precedes_stored_value(expect):
    f = run(healthy())['dns.caa']
    f = replace(f, outcome=Outcome(Status.WARN, 'dns.caa.missing', remedy=Remedy(2, Effort.EASY, expect=expect)))
    original = copy.deepcopy(f.outcome_json())
    read = Finding.from_stored(f.check_id, f.category, f.weight, f.status, original)
    assert expected_status(read) is Status.OK
    assert with_expectation(read).outcome.remedy.expect is Status.OK
    assert original == f.outcome_json()
    extension = replace(f, check_id='extra.custom')
    assert expected_status(extension) is expect
    assert with_expectation(extension).outcome.remedy.expect is expect


def test_old_extension_is_unknown_and_old_builtin_is_adapted():
    payload = {'summary': 'extra.problem', 'remedy': {'minutes': 2, 'effort': 'easy'}}
    f = Finding.from_stored('extra.custom', 'dns', 2, 'fail', payload)
    assert expected_status(f) is None
    payload['summary'] = 'dns.caa.missing'
    f = Finding.from_stored('dns.caa', 'dns', 2, 'warn', payload)
    assert expected_status(f) is Status.OK


def test_current_builtin_unknown_overrides_explicit_ok():
    f = run(healthy())['dns.dnssec']
    f = replace(f, outcome=Outcome(Status.FAIL, 'dns.dnssec.broken', remedy=Remedy(2, Effort.EASY)))
    read = Finding.from_stored(f.check_id, f.category, f.weight, f.status, f.outcome_json())
    assert read.outcome.remedy.expect is Status.OK
    assert expected_status(read) is None
    assert with_expectation(read).outcome.remedy.expect is None
