# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Four storage-path scenarios reconstructed from the review (attachment unavailable)."""
import asyncio
import json
from datetime import timedelta

import pytest

from https_worlds import HEADERS, OK, V4A, site
from posture_cockpit.core import engine
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.registry import Registry
from posture_cockpit.storage import Database, Scans
from worlds import DOMAIN, NOW

REGISTRY = Registry.discover()


@pytest.fixture
def scans(tmp_path):
    db = Database(tmp_path / 'hsts.db')
    yield Scans(db)
    db.close()


def scan_result(at, header):
    data = site({V4A: OK})
    headers = {k: v for k, v in HEADERS.items() if k.lower() != 'strict-transport-security'}
    if header is not None:
        headers['strict-transport-security'] = header
    data['http'][f'https://{DOMAIN}/']['headers'] = headers
    return asyncio.run(engine.scan(DOMAIN, REGISTRY.checks(), FixtureNetwork(data, NOW), now=at))


def save(scans, at, header):
    return scans.save(scans.add_domain(DOMAIN, None), scan_result(at, header), '0.4.0', None)


def recheck(scans, monkeypatch, scan_id, at, header):
    monkeypatch.setattr('posture_cockpit.storage.scans.utcnow', lambda: at.isoformat())
    findings = [f for f in scan_result(at, header).findings if f.family == 'https']
    scans.save_rechecks(scan_id, findings)
    assert len(scans.get(scan_id).rechecks) == 11


def test_zero_then_missing_on_same_scan(scans, monkeypatch):
    scan_id = save(scans, NOW, 'max-age=86400; preload')
    recheck(scans, monkeypatch, scan_id, NOW + timedelta(minutes=1), 'max-age=0')
    recheck(scans, monkeypatch, scan_id, NOW + timedelta(minutes=2), None)
    state = scans.https_history(DOMAIN, now=NOW + timedelta(minutes=3))[DOMAIN]
    assert 'hsts' not in state and 'preload' not in state
    assert state['last_available'] == (NOW + timedelta(minutes=2)).isoformat()


def test_zero_survives_new_scans_without_header(scans):
    save(scans, NOW, 'max-age=86400; preload')
    save(scans, NOW + timedelta(minutes=1), 'max-age=0')
    save(scans, NOW + timedelta(minutes=2), None)
    state = scans.https_history(DOMAIN, now=NOW + timedelta(minutes=3))[DOMAIN]
    assert 'hsts' not in state and 'preload' not in state


def test_rechecking_older_scan_does_not_resurrect_erased_header(scans, monkeypatch):
    older = save(scans, NOW, 'max-age=86400; includeSubDomains; preload')
    save(scans, NOW + timedelta(minutes=1), 'max-age=0')
    recheck(scans, monkeypatch, older, NOW + timedelta(minutes=2), None)
    recheck(scans, monkeypatch, older, NOW + timedelta(minutes=3), None)
    state = scans.https_history(DOMAIN, now=NOW + timedelta(minutes=4))[DOMAIN]
    assert 'hsts' not in state and 'preload' not in state


def test_compaction_is_bounded_retains_dates_and_zero(scans, monkeypatch):
    scan_id = save(scans, NOW, 'max-age=86400; preload')
    policy_at = NOW + timedelta(minutes=1)
    recheck(scans, monkeypatch, scan_id, policy_at, 'max-age=3600; preload')
    for minute in range(2, 42):
        recheck(scans, monkeypatch, scan_id, NOW + timedelta(minutes=minute), None)
    now = NOW + timedelta(minutes=42)
    state = scans.https_history(DOMAIN, now=now)[DOMAIN]
    assert state['hsts']['at'] == policy_at.isoformat()
    assert state['hsts']['expires_at'] == (policy_at + timedelta(hours=1)).isoformat()
    raw = scans.db.value('SELECT outcome FROM rechecks WHERE scan_id=? AND check_id=?',
                         (scan_id, 'web.https_redirect'))
    trail = json.loads(raw)['evidence']['https_history_previous']
    assert len(trail) <= 2
    recheck(scans, monkeypatch, scan_id, now, 'max-age=0')
    for minute in range(43, 83):
        recheck(scans, monkeypatch, scan_id, NOW + timedelta(minutes=minute), None)
    state = scans.https_history(DOMAIN, now=NOW + timedelta(minutes=83))[DOMAIN]
    assert 'hsts' not in state and 'preload' not in state
    raw = scans.db.value('SELECT outcome FROM rechecks WHERE scan_id=? AND check_id=?',
                         (scan_id, 'web.https_redirect'))
    trail = json.loads(raw)['evidence']['https_history_previous']
    assert len(trail) <= 2
    headers = [header for event in trail for observation in event['observation'].values()
               for header in observation.get('hsts', [])]
    assert headers == ['max-age=0']


def test_compaction_replays_the_same_state_for_multiple_hosts():
    from random import Random

    from posture_cockpit.core.https_history import compact, summarize

    random = Random(404)  # noqa: S311 — deterministic fixture generation, not cryptography
    hosts = (DOMAIN, 'www.' + DOMAIN, 'other.' + DOMAIN)
    events = [(NOW.isoformat(), {h: {'available': True} for h in hosts})]
    choices = [None, 'invalid', 'max-age=0', 'max-age=10',
               'max-age=5000; includeSubDomains', 'max-age=999999999999; preload']
    for second in range(1, 301):
        observations = {}
        for host in hosts:
            header = random.choice(choices)
            observations[host] = {'available': random.choice([True, False]),
                                  'hsts': [] if header is None else [header]}
        events.append(((NOW + timedelta(seconds=second)).isoformat(), observations))
    reduced = compact(events)
    assert sum(len(event['observation']) for event in reduced) <= 2 * len(hosts)
    for now in (NOW + timedelta(minutes=10), NOW + timedelta(days=366)):
        assert summarize(events, now) == summarize([(e['at'], e['observation']) for e in reduced], now)
