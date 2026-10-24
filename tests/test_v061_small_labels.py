# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Small render corrections preserve conditional bounds and observed progress."""
from dataclasses import replace

import pytest

from helpers import post
from posture_cockpit.core.model import Outcome, Status
from posture_cockpit.web.views import plan_view
from test_v060_mission_routes import URL, seed, selection
from worlds import DOMAIN, changed, healthy


@pytest.mark.parametrize('lang', ['fr', 'en'])
def test_exact_gain_uses_one_number_and_empty_events_match_filters(client, lang):
    s, _, sid, _ = seed(client, changed(healthy(), dns={f'_dmarc.{DOMAIN} TXT': []}))
    post(client, '/lang', '/', lang=lang, back='/')
    text = client.get(URL + '/simulate', params=selection(s, sid, ['mail.dmarc'])).text
    assert '+6 points' in text
    assert '+6 à +6' not in text and '+6 to +6' not in text
    assert s.catalog.text(lang, 'events.empty') in client.get('/events?state=all&category=all').text


def test_completed_improvement_is_not_a_completed_priority(client):
    s, _did, sid, fs = seed(client, changed(healthy(), dns={f'_dmarc.{DOMAIN} TXT': [], f'{DOMAIN} CAA': []}))
    f = next(f for f in fs if f.check_id == 'dns.caa')
    s.scans.save_recheck(sid, replace(f, outcome=Outcome(Status.OK, 'dns.caa.ok')))
    view = plan_view(s.catalog, 'fr', s.scans.get(sid), s.scans.domain(DOMAIN), s.registry)
    assert len(view.completed) == 1
    assert view.done_count == 0
    assert len(view.priorities) == 1
    f = next(f for f in fs if f.check_id == 'mail.dmarc')
    s.scans.save_recheck(sid, replace(f, outcome=Outcome(Status.OK, 'mail.dmarc.ok')))
    view = plan_view(s.catalog, 'fr', s.scans.get(sid), s.scans.domain(DOMAIN), s.registry)
    assert len(view.completed) == 2
    assert view.done_count == 1
    assert not view.priorities


@pytest.mark.parametrize('delta', [-3, 0, 7])
def test_exact_deltas_keep_the_sign_without_a_duplicate_range(client, monkeypatch, delta):
    from posture_cockpit.core import scoring
    s, _, sid, _ = seed(client, changed(healthy(), dns={f'_dmarc.{DOMAIN} TXT': []}))
    simulate = scoring.simulate

    def chosen(*args, **kwargs):
        result = simulate(*args, **kwargs)
        if args[1]:
            projected = replace(result.worst, score=result.now.score + delta)
            return replace(result, worst=projected, best=projected)
        return result

    monkeypatch.setattr(scoring, 'simulate', chosen)
    text = client.get(URL + '/simulate', params=selection(s, sid, ['mail.dmarc'])).text
    assert f'{delta:+d} points' in text
    assert f'{delta:+d} à {delta:+d}' not in text


def test_f12_recent_then_expired_heartbeat_is_read_only(client):
    import json
    from datetime import timedelta

    from posture_cockpit.web.portfolio import scheduler_state
    from worlds import NOW

    s, _, _, _ = seed(client)
    s.config.scheduler = False
    s.db.set_meta('scheduler_heartbeat', json.dumps({'at': NOW.isoformat()}))
    frozen = list(s.db._conn.iterdump())
    assert scheduler_state(s, None, NOW) == 'elsewhere'
    assert scheduler_state(s, None, NOW + timedelta(minutes=4)) == 'off'
    assert list(s.db._conn.iterdump()) == frozen
