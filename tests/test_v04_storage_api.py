# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Step 4: persistence, HTTPS group rechecks, announcements and all consumers."""
import asyncio
import json
import sqlite3
from dataclasses import replace
from datetime import timedelta

import pytest

from helpers import post, setup_account
from https_worlds import ELSEWHERE, OBSOLETE, OK, REFUSED, TIMEOUT, V4A, V4B, V6A, site
from posture_cockpit.config import Config
from posture_cockpit.core import engine, scoring
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.https_history import announced, summarize
from posture_cockpit.core.model import HTTPS_FAMILY
from posture_cockpit.core.registry import Registry
from posture_cockpit.i18n import Catalog
from posture_cockpit.report import build_pdf, render_html
from posture_cockpit.scanner import Scanner
from posture_cockpit.storage import Database, Scans
from posture_cockpit.storage.schema import MIGRATIONS
from posture_cockpit.web.routes.api import _summary
from worlds import DOMAIN, NOW

REGISTRY = Registry.discover()


def result(data):
    return asyncio.run(engine.scan(DOMAIN, REGISTRY.checks(), FixtureNetwork(data, NOW), now=NOW))


def store(tmp_path, data):
    scans = Scans(Database(tmp_path / 'test.db'))
    scan_id = scans.save(scans.add_domain(DOMAIN, None), result(data), '0.4.0', None)
    return scans, scan_id


def test_migration4_preserves_every_legacy_value_and_backup(tmp_path):
    path = tmp_path / 'old.db'
    db = Database(path, MIGRATIONS[:3])
    db.execute("INSERT INTO domains(name,created_at) VALUES(?,?)", (DOMAIN, NOW.isoformat()))
    db.execute("INSERT INTO scans(domain_id,started_at,duration_ms,score,grade,coverage,version) "
               "VALUES(1,?,123,67,'C',0.54,'0.3.2')", (NOW.isoformat(),))
    db.execute("INSERT INTO findings VALUES(1,'mail.spf','mail',8,'ok',?)", ('{"summary":"mail.spf.ok"}',))
    before = [tuple(row) for row in db.all('SELECT * FROM scans')]
    findings = [tuple(row) for row in db.all('SELECT * FROM findings')]
    db.close()
    db = Database(path)
    row = db.one('SELECT * FROM scans')
    assert tuple(row)[:len(before[0])] == before[0]
    assert all(row[k] is None for k in dict(row) if k not in
               {'id','domain_id','started_at','duration_ms','score','grade','coverage','version','started_by','perimeter'})
    assert [tuple(row) for row in db.all('SELECT * FROM findings')] == findings
    assert db.schema_version == 4 and not db.all('PRAGMA foreign_key_check')
    backups = list((tmp_path / 'backups').glob('old-schema3-*.db'))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as copied:
        assert copied.execute('SELECT * FROM scans').fetchall() == before
    db.close()
    db = Database(path)
    assert db.schema_version == 4 and len(list((tmp_path / 'backups').glob('*.db'))) == 1
    db.close()


@pytest.mark.parametrize('data,evaluation', [
    (site({V4A: OK}), 'complete'),
    (site({V4A: REFUSED}, **{f'http://{DOMAIN}/': ELSEWHERE}), 'complete'),
    (site({V4A: REFUSED, V6A: TIMEOUT}), 'undetermined'),
    (site({V4A: OBSOLETE, V6A: TIMEOUT}), 'undetermined'),
])
def test_metrics_roundtrip_api_and_pdf(tmp_path, data, evaluation):
    scans, scan_id = store(tmp_path, data)
    scan = scans.get(scan_id)
    a = scan.assessment()
    row = scans.db.one('SELECT * FROM scans WHERE id=?', (scan_id,))
    for key in ('score_raw','score_cap','score_final','diagnostic_coverage','grade_withheld_reason'):
        assert row[key] == getattr(a, key)
    assert row['checks_blocked'] == a.blocked
    assert json.loads(row['cap_reasons']) == list(a.cap_reasons)
    assert row['addresses_discovered'] == scan.addresses()['discovered']
    api = _summary(scan)
    assert api['evaluation'] == evaluation
    assert api['not_evaluated'] == sum(f.status.value == 'error' for f in scan.current())
    assert api['checks_blocked'] == a.blocked
    assert api['grade'] == a.grade and api['score'] == a.score
    for lang in ('fr','en'):
        catalog = Catalog(REGISTRY.messages)
        html = render_html(catalog, lang, scan)
        assert 'None' not in html and 'v04.' not in html
        assert str(a.score) in html
        if a.undetermined:
            assert catalog.text(lang, 'v04.undetermined') in html
        pdf = build_pdf(catalog, lang, scan)
        assert pdf.startswith(b'%PDF-') and len(pdf) > 10000
    scans.db.close()


@pytest.mark.parametrize('check_id', ['web.https_redirect', 'tls.certificate','web.hsts'])
def test_family_recheck_updates_all_eleven_atomically(tmp_path, check_id):
    scans, scan_id = store(tmp_path, site({V4A: REFUSED}))
    original = scans.get(scan_id).findings
    scanner = Scanner(REGISTRY, Config(data_dir=tmp_path),
                      network_factory=lambda _: FixtureNetwork(site({V4A: OK}), NOW))
    findings = asyncio.run(scanner.recheck_group(DOMAIN, check_id))
    assert len(findings) == 11 and all(f.family == HTTPS_FAMILY for f in findings)
    a = scans.save_rechecks(scan_id, findings)
    scan = scans.get(scan_id)
    assert len(scan.rechecks) == 11 and scan.findings == original
    assert len({r.checked_at for r in scan.rechecks.values()}) == 1
    assert not a.blocked and not a.cap_reasons and a.grade == 'A'
    assert scans.db.value('SELECT checks_blocked FROM scans') == 0
    scans.db.execute("CREATE TRIGGER fail_batch BEFORE INSERT ON rechecks "
                     "WHEN NEW.check_id='tls.key' BEGIN SELECT RAISE(ABORT,'simulated disk failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        scans.save_rechecks(scan_id, list(reversed(original)))
    assert scans.get(scan_id).current() == scan.current()
    assert scans.get(scan_id).score == scan.score
    scans.db.close()


def test_non_https_recheck_and_disabled_extensions(tmp_path):
    scanner = Scanner(REGISTRY, Config(data_dir=tmp_path),
                      network_factory=lambda _: FixtureNetwork(site({V4A: OK}), NOW))
    assert len(asyncio.run(scanner.recheck_group(DOMAIN, 'mail.dmarc'))) == 1
    assert asyncio.run(scanner.recheck_group(DOMAIN, 'missing.check')) == []
    scanner.disabled = lambda: ['tls']
    assert asyncio.run(scanner.recheck_group(DOMAIN, 'tls.key')) == []
    assert len(asyncio.run(scanner.recheck_group(DOMAIN, 'web.hsts'))) == 8


def event(header=None, available=True):
    return {DOMAIN: {'available': available, 'hsts': [] if header is None else [header]}}


def test_hsts_history_lifetime_removal_and_subdomain_scope():
    at = NOW.isoformat()
    old = (NOW - timedelta(days=1)).isoformat()
    header = 'max-age=999999999; includeSubDomains; preload'
    state = summarize([(old, event(header)), (at, event())], NOW)
    policy = state[DOMAIN]['hsts']
    assert policy['header'] == header and policy['expires_at'] == (NOW + timedelta(days=364)).isoformat()
    assert announced('www.' + DOMAIN, state, NOW)['hsts']['source'] == DOMAIN
    assert 'hsts' not in announced('other.example', state, NOW)
    assert not summarize([(old, event('max-age=10'))], NOW)[DOMAIN].get('hsts')
    assert not summarize([(old, event(header)), (at, event('max-age=0'))], NOW)[DOMAIN].get('hsts')
    state = summarize([(old, event('max-age=864000')), (at, event('max-age=oops'))], NOW)
    assert state[DOMAIN]['hsts']['at'] == old
    assert 'hsts' not in announced('www.' + DOMAIN, state, NOW)


def test_hsts_observations_authenticated_only_and_history_has_no_scoring_effect(tmp_path):
    scans, _scan_id = store(tmp_path, site({V4A: OK}))
    history = scans.https_history(DOMAIN, now=NOW)
    assert history[DOMAIN]['hsts'] and history[DOMAIN]['last_available']
    refused = site({V4A: REFUSED})
    plain = result(refused)
    with_history = asyncio.run(engine.scan(DOMAIN, REGISTRY.checks(), FixtureNetwork(refused, NOW), now=NOW,
                                           history=history))
    assert scoring.assess(plain.findings) == scoring.assess(with_history.findings)
    root = next(f for f in with_history.findings if f.check_id == 'web.https_redirect')
    assert 'hsts_history' in root.outcome.evidence['announced']['signals']
    assert history == scans.https_history(DOMAIN, now=NOW)  # checking does not mutate persisted history
    invalid = site({V4A: {'certificate': {'trusted': False}}})
    findings = result(invalid).findings
    root = next(f for f in findings if f.check_id == 'web.https_redirect')
    assert root.outcome.evidence['https_history'][DOMAIN]['hsts'] == []
    scans.db.close()


@pytest.mark.parametrize('data', [site({V4A: REFUSED}), site({V4A: REFUSED,V6A: TIMEOUT}), site({V4A: OK,V4B: OK})])
def test_pages_show_four_indicators_and_recheck_group(client, world, data):
    setup_account(client)
    world[DOMAIN] = data
    response = post(client, '/domains', domain=DOMAIN)
    assert response.status_code == 303
    for path in ('', '/details', '/history', '/history/1'):
        html = client.get('/domains/' + DOMAIN + path).text
        assert 'Couverture diagnostique' in html and 'Bloqués' in html and 'Adresses' in html
        assert 'None' not in html
    world[DOMAIN] = site({V4A: OK})
    assert post(client, f'/domains/{DOMAIN}/verify/web.https_redirect').status_code == 303
    scans = client.app.state.services.scans
    assert len(scans.latest(scans.domain(DOMAIN)['id']).rechecks) == 11


def test_legacy_api_does_not_invent_new_measurements(tmp_path):
    scans, scan_id = store(tmp_path, site({V4A: OK}))
    scan = scans.get(scan_id)
    legacy = replace(scan, findings=[replace(f, family=None, role=None, floor=None,
                                             outcome=replace(f.outcome, signals=frozenset())) for f in scan.findings])
    api = _summary(legacy)
    assert api['score'] == 100 and api['grade'] == 'A'
    assert api['score_raw'] == api['score_final'] == 1.0 and api['checks_blocked'] == 0
    assert api['diagnostic_coverage'] == legacy.coverage and api['score_cap'] is None
    scans.db.close()


def test_hsts_zero_survives_later_rechecks_without_header(tmp_path, monkeypatch):
    scans, scan_id = store(tmp_path, site({V4A: OK}))
    def root_with(header):
        root = next(f for f in result(site({V4A: OK})).findings if f.check_id == 'web.https_redirect')
        return replace(root, outcome=replace(root.outcome, evidence={**root.outcome.evidence,
                               'https_history': event(header)}))
    monkeypatch.setattr('posture_cockpit.storage.scans.utcnow', lambda: (NOW + timedelta(seconds=1)).isoformat())
    scans.save_recheck(scan_id, root_with('max-age=0'))
    monkeypatch.setattr('posture_cockpit.storage.scans.utcnow', lambda: (NOW + timedelta(seconds=2)).isoformat())
    scans.save_recheck(scan_id, root_with(None))
    # Query the persisted trail at a deterministic instant as well as through the live repository.
    row = scans.db.one('SELECT outcome FROM rechecks WHERE scan_id=?', (scan_id,))
    evidence = json.loads(row['outcome'])['evidence']
    assert len(evidence['https_history_previous']) == 1
    old = scans.get(scan_id).findings
    initial = next(f for f in old if f.check_id == 'web.https_redirect').outcome.evidence['https_history']
    events = [(NOW.isoformat(), initial)]
    events += [(e['at'], e['observation']) for e in evidence['https_history_previous']]
    events += [((NOW + timedelta(seconds=2)).isoformat(), evidence['https_history'])]
    assert 'hsts' not in summarize(events, NOW + timedelta(seconds=3))[DOMAIN]
    scans.db.close()


def test_history_provisional_point_is_hollow_without_delta(client, world):
    setup_account(client)
    world[DOMAIN] = site({V4A: OK})
    post(client, '/domains', domain=DOMAIN)
    world[DOMAIN] = site({V4A: REFUSED, V6A: TIMEOUT})
    post(client, f'/domains/{DOMAIN}/scan')
    html = client.get(f'/domains/{DOMAIN}/history').text
    assert 'trend-provisional' in html and 'trend-graded' in html
    assert 'None' not in html and 'Score provisoire, non comparable' in html
