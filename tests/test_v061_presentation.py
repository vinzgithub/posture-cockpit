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


@pytest.mark.parametrize('lang', ['fr', 'en'])
def test_excluded_actions_are_named_in_web_and_pdf(client, lang):
    s, _, sid, fs = seed(client)
    f = next(f for f in fs if f.check_id == 'dns.dnssec')
    s.scans.save_recheck(sid, replace(f, outcome=Outcome(
        Status.FAIL, 'dns.dnssec.broken', remedy=Remedy(5, Effort.MEDIUM))))
    post(client, '/lang', '/', lang=lang, back='/')
    warning = s.catalog.text(lang, 'projection.excluded')
    for page in [client.get(f'/domains/{DOMAIN}').text,
                 client.get(f'/domains/{DOMAIN}/mission-control').text,
                 render_html(s.catalog, lang, s.scans.get(sid))]:
        assert warning in page
        assert 'DNSSEC' in page


@pytest.mark.parametrize('lang', ['fr', 'en'])
@pytest.mark.parametrize('unknown', [False, True])
def test_real_pdf_edge_cases_keep_the_diagnosis_on_page_one(client, lang, unknown):
    from test_report_layout import _boxes, _layout

    s, _, sid, fs = seed(client, H.site({H.V4A: H.REFUSED}))
    if unknown:
        f = next(f for f in fs if f.check_id == 'dns.dnssec')
        s.scans.save_recheck(sid, replace(f, outcome=Outcome(
            Status.FAIL, 'dns.dnssec.broken', remedy=Remedy(5, Effort.MEDIUM))))
    context = report_context(s.catalog, lang, s.scans.get(sid))
    document = _layout(context)
    text = ' '.join(getattr(b, 'text', '') for page in document.pages for b in _boxes(page._page_box))
    assert 'None' not in text
    first = list(_boxes(document.pages[0]._page_box))
    assert any(b.element is not None and 'diagnosis' in (b.element.get('class') or '').split() for b in first)
    first_text = ' '.join(getattr(b, 'text', '') for b in first)
    assert ('non concluante' if lang == 'fr' else 'inconclusive') in first_text
    assert document.write_pdf().startswith(b'%PDF-')
