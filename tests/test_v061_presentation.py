# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Corrective projections: real stored scans, bilingual server and PDF renders."""
from dataclasses import replace

import pytest

import https_worlds as H
from helpers import post
from posture_cockpit.core.model import Effort, Outcome, Remedy, Status
from posture_cockpit.report import render_html, report_context
from test_v060_mission_routes import seed
from worlds import DOMAIN


@pytest.mark.parametrize('lang', ['fr', 'en'])
@pytest.mark.parametrize('unknown', [False, True])
def test_target_is_not_a_promise_or_none(client, lang, unknown):
    s, _, sid, fs = seed(client, H.site({H.V4A: H.REFUSED}))
    if unknown:
        f = next(f for f in fs if f.check_id == 'dns.dnssec')
        s.scans.save_recheck(sid, replace(f, outcome=Outcome(
            Status.FAIL, 'dns.dnssec.broken', remedy=Remedy(5, Effort.MEDIUM))))
    post(client, '/lang', '/', lang=lang, back='/')
    scan = s.scans.get(sid)
    context = report_context(s.catalog, lang, scan)
    html = render_html(s.catalog, lang, scan)
    page = client.get(f'/domains/{DOMAIN}').text
    assert 'None' not in html + page
    assert 'suffisent pour atteindre' not in html
    assert 'are enough to reach' not in html
    assert 'pour passer de B à C' not in page
    assert 'from B to C' not in page
    if unknown:
        assert context['plan'].target.score is None
        assert ('non concluante' if lang == 'fr' else 'inconclusive') in context['conclusion']
    else:
        assert context['plan'].now.score == 79
        assert context['plan'].target.score == 66
        assert context['plan'].target_max.score == 100
        assert '66' in context['conclusion'] and '100' in context['conclusion']
        assert ('mesurables' if lang == 'fr' else 'measurable') in context['conclusion']
