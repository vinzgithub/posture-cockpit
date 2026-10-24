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
