# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Counter-review: hints, corrupt storage, legacy API and inconclusive wording."""
import asyncio
import json
from dataclasses import replace
from datetime import timedelta

import pytest

from helpers import DEMO, post, setup_account
from https_worlds import OK, POLICY, REFUSED, TIMEOUT, V4A, V4B, V6A, site
from posture_cockpit.checks.web import _announced, _Redirection, _refusal_remedy
from posture_cockpit.core import engine, scoring
from posture_cockpit.core.extension import CheckContext
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.https_history import summarize
from posture_cockpit.core.https_probe import HostResult
from posture_cockpit.core.registry import Registry
from posture_cockpit.i18n import Catalog
from posture_cockpit.report import build_pdf, render_html
from posture_cockpit.security import new_token, token_hash
from posture_cockpit.storage import CorruptScan
from posture_cockpit.web.routes.api import _summary
from test_v04_storage_api import result, store
from worlds import DOMAIN, NOW

REGISTRY = Registry.discover()


def test_s4_alone_is_only_a_hint_and_does_not_change_the_score():
    # Closed HTTP port: no S1. Another successful negotiation localizes attribution.
    data = site({V4A: {**REFUSED, '80': 'refused'}})
    ctx = CheckContext(DOMAIN, FixtureNetwork(data, NOW), NOW,
                       history={DOMAIN: {'last_available': (NOW - timedelta(days=1)).isoformat()}})
    announcement = _announced(HostResult(DOMAIN), _Redirection(), ctx)
    assert announcement['level'] == 'hints'
    assert announcement['signals'] == [] and announcement['hints'] == ['https_history']
    remedy = _refusal_remedy('web.https_redirect.refused', {'level': 'destination'}, announcement)
    assert remedy == _refusal_remedy('web.https_redirect.refused', {'level': 'destination'},
                                     {'level': 'not_announced'})
    assert remedy.message.endswith('refused.message')
    plain = result(data)
    historical = asyncio.run(engine.scan(DOMAIN, REGISTRY.checks(), FixtureNetwork(data, NOW), now=NOW,
                                          history=ctx.history))
    assert scoring.assess(plain.findings) == scoring.assess(historical.findings)
    before = next(f for f in plain.findings if f.check_id == 'web.https_redirect')
    after = next(f for f in historical.findings if f.check_id == 'web.https_redirect')
    assert before.status == after.status and before.outcome.summary == after.outcome.summary
    assert before.outcome.remedy == after.outcome.remedy
    assert any(n['key'].endswith('announced.https_history') for n in after.outcome.evidence['notes'])


def test_t8_preload_is_a_hint_never_a_browser_list_claim():
    for age, expected in [('86400', True), ('0', False)]:
        events = [((NOW - timedelta(hours=1)).isoformat(),
                   {DOMAIN: {'hsts': ['max-age=86400; preload']}})]
        events.append((NOW.isoformat(), {DOMAIN: {'hsts': ['max-age=' + age + '; preload']}}))
        history = summarize(events, NOW)
        ctx = CheckContext(DOMAIN, FixtureNetwork({}), NOW, history=history)
        a = _announced(HostResult(DOMAIN), _Redirection(), ctx)
        assert ('preload' in a['hints']) == expected
        assert 'preload' not in a['signals']
    # An expired HSTS policy cannot announce HTTPS; its preload request remains only a hint.
    history = summarize([((NOW - timedelta(days=2)).isoformat(),
                           {DOMAIN: {'hsts': ['max-age=10; preload']}})], NOW)
    a = _announced(HostResult(DOMAIN), _Redirection(), CheckContext(DOMAIN, FixtureNetwork({}), NOW, history=history))
    assert a['level'] == 'hints' and a['hints'] == ['preload']
    # A stale snapshot must not turn an already expired policy into an announcement.
    history[DOMAIN]['hsts'] = {'expires_at': (NOW - timedelta(seconds=1)).isoformat(),
                                'include_subdomains': False}
    a = _announced(HostResult(DOMAIN), _Redirection(), CheckContext(DOMAIN, FixtureNetwork({}), NOW, history=history))
    assert a['level'] == 'hints' and a['signals'] == []
    catalog = Catalog(REGISTRY.messages)
    assert 'l’en-tête demande le préchargement' in catalog.text('fr', 'web.https_redirect.announced.preload',
                                                               {'host': DOMAIN})
    assert 'the header requests preloading' in catalog.text(
        'en', 'web.https_redirect.announced.preload', {'host': DOMAIN})


@pytest.mark.parametrize('damage', ['nan', 'inf', 'negative_inf', 'root_nan', 'false_root', 'json'])
@pytest.mark.parametrize('table', ['findings', 'rechecks'])
def test_corrupt_scan_is_isolated_and_localized(client, world, damage, table):
    setup_account(client, demo=True)
    world[DOMAIN] = site({V4A: OK})
    assert post(client, '/domains', domain=DOMAIN).status_code == 303
    s = client.app.state.services
    scan = s.scans.latest(s.scans.domain(DOMAIN)['id'])
    check_id = 'web.https_redirect' if damage == 'root_nan' else 'tls.key'
    original = next(f for f in scan.findings if f.check_id == check_id)
    if table == 'rechecks':
        s.scans.save_recheck(scan.id, original)
    payload = original.outcome_json()
    if damage == 'false_root':
        payload['family']['role'] = 'root'
    elif damage != 'json':
        payload['family']['floor'] = {'nan': float('nan'), 'inf': float('inf'),
                                       'negative_inf': -float('inf'), 'root_nan': float('nan')}[damage]
    value = '{broken JSON' if damage == 'json' else json.dumps(payload)
    # table is one of the two literal values parametrized above, never user input.
    sql = ('UPDATE findings SET outcome=? WHERE scan_id=? AND check_id=?' if table == 'findings' else
           'UPDATE rechecks SET outcome=? WHERE scan_id=? AND check_id=?')
    s.db.execute(sql, (value, scan.id, original.check_id))
    with pytest.raises(CorruptScan):
        s.scans.get(scan.id)
    token = new_token()
    s.accounts.add_token(1, 'test', token_hash(token))
    auth = {'Authorization': 'Bearer ' + token}
    response = client.get('/api/v1/domains', headers=auth)
    assert response.status_code == 200
    by_domain = {d['domain']: d for d in response.json()['domains']}
    assert by_domain[DOMAIN] == {'domain': DOMAIN, 'error': 'scan_unreadable', 'scan_id': scan.id}
    assert isinstance(by_domain[DEMO]['score'], int)
    single = client.get(f'/domains/{DOMAIN}/details', headers={'Accept': 'application/json'})
    assert single.status_code == 409 and single.json()['error'] == 'scan_unreadable'
    for lang in ('fr', 'en'):
        post(client, '/lang', lang=lang, back='/domains')
        message = s.catalog.text(lang, 'error.scan_unreadable')
        for path in ('', '/details', f'/history/{scan.id}'):
            response = client.get('/domains/' + DOMAIN + path)
            assert response.status_code == 409 and message in response.text
        assert client.get('/domains').status_code == 200 and message in client.get('/domains').text
        history = client.get(f'/domains/{DOMAIN}/history')
        assert history.status_code == 200 and message in history.text
        assert client.get(f'/domains/{DEMO}').status_code == 200
        for path in ('/report.pdf', f'/history/{scan.id}/report.pdf'):
            response = client.get('/domains/' + DOMAIN + path)
            assert response.status_code == 409 and response.headers['content-type'] == 'application/pdf'
            assert response.content.startswith(b'%PDF-')


def test_legacy_api_uses_stored_values_without_backfill(tmp_path):
    scans, scan_id = store(tmp_path, site({V4A: OK}))
    scan = scans.get(scan_id)
    old = replace(scan, score=67, coverage=0.5432,
                  findings=[replace(f, family=None, role=None, floor=None,
                                    outcome=replace(f.outcome, signals=frozenset())) for f in scan.findings])
    data = _summary(old)
    assert data['score_raw'] == data['score_final'] == 0.67
    assert data['diagnostic_coverage'] == 0.543 and data['checks_blocked'] == 0 and data['score_cap'] is None
    scans.db.close()


@pytest.mark.parametrize('language', ['fr', 'en'])
@pytest.mark.parametrize('extra', [False, True])
def test_inconclusive_count_on_pages_and_pdf(client, world, language, extra):
    setup_account(client, lang=language)
    addresses = {V4A: REFUSED, V6A: TIMEOUT}
    if extra:
        addresses[V4B] = TIMEOUT
    world[DOMAIN] = site(addresses)
    post(client, '/domains', domain=DOMAIN)
    s = client.app.state.services
    scan = s.scans.latest(s.scans.domain(DOMAIN)['id'])
    n = 2 if extra else 1
    assert scan.nonconclusive() == n
    expected = s.catalog.text(language, 'v04.undetermined_count', {'n': n})
    for suffix in ('', '/details', '/history', f'/history/{scan.id}'):
        page = client.get('/domains/' + DOMAIN + suffix)
        assert page.status_code == 200 and expected in page.text
    assert expected in render_html(s.catalog, language, scan)


def test_legacy_history_rows_keep_their_original_presentation(client, world):
    setup_account(client)
    world[DOMAIN] = site({V4A: OK})
    post(client, '/domains', domain=DOMAIN)
    s = client.app.state.services
    scan = s.scans.latest(s.scans.domain(DOMAIN)['id'])
    for f in scan.findings:
        data = f.outcome_json()
        data.pop('family', None)
        data.pop('signals', None)
        # A genuine 0.3.x root has no per-address probe evidence.
        if f.check_id == 'web.https_redirect':
            data['evidence'].pop('addresses', None)
        s.db.execute('UPDATE findings SET outcome=? WHERE scan_id=? AND check_id=?',
                     (json.dumps(data), scan.id, f.check_id))
    s.db.execute("UPDATE scans SET version='0.3.2', diagnostic_coverage=NULL, checks_blocked=NULL, "
                 "score_raw=NULL, score_cap=NULL, score_final=NULL, addresses_discovered=NULL, "
                 "addresses_attempted=NULL, addresses_conclusive=NULL, cap_reasons=NULL, "
                 "grade_withheld_reason=NULL WHERE id=?", (scan.id,))
    before = tuple(s.db.one('SELECT * FROM scans WHERE id=?', (scan.id,)))
    html = client.get(f'/domains/{DOMAIN}/history').text
    assert 'Adresses : —' in html
    assert 'v04-indicators' not in html and '100/100' in html
    assert tuple(s.db.one('SELECT * FROM scans WHERE id=?', (scan.id,))) == before

    # The placeholder must not imply readable results when the old analysis is corrupt.
    api = _summary(s.scans.get(scan.id))
    assert all(api[k] is None for k in ('addresses_discovered', 'addresses_attempted', 'addresses_conclusive'))
    s.db.execute("UPDATE findings SET outcome='invalid JSON' WHERE scan_id=? AND check_id='tls.key'", (scan.id,))
    unreadable = client.get(f'/domains/{DOMAIN}/history')
    assert unreadable.status_code == 200
    assert s.catalog.text('fr', 'error.scan_unreadable') in unreadable.text
    assert 'Adresses : —' not in unreadable.text


@pytest.mark.parametrize('language', ['fr', 'en'])
def test_inconclusive_count_excludes_policy_blocked_addresses(client, world, language):
    setup_account(client, lang=language)
    world[DOMAIN] = site({V4A: REFUSED, V6A: TIMEOUT, V4B: POLICY})
    assert post(client, '/domains', domain=DOMAIN).status_code == 303
    s = client.app.state.services
    scan = s.scans.latest(s.scans.domain(DOMAIN)['id'])
    addresses = scan.addresses()
    assert (addresses['discovered'], addresses['attempted'], addresses['conclusive']) == (3, 2, 1)
    assert scan.assessment().undetermined and scan.nonconclusive() == 1
    expected = s.catalog.text(language, 'v04.undetermined_count', {'n': 1})
    incorrect = s.catalog.text(language, 'v04.undetermined_count', {'n': 2})
    for suffix in ('', '/details', '/history', f'/history/{scan.id}'):
        page = client.get('/domains/' + DOMAIN + suffix)
        assert page.status_code == 200 and expected in page.text and incorrect not in page.text
    html = render_html(s.catalog, language, scan)
    assert expected in html and incorrect not in html
    assert build_pdf(s.catalog, language, scan).startswith(b'%PDF-')
    api = _summary(scan)
    assert (api['addresses_discovered'], api['addresses_attempted'], api['addresses_conclusive']) == (3, 2, 1)
