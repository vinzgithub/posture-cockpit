# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Integrated safety boundaries: real second connection and escaped filter links."""
from datetime import timedelta

from posture_cockpit.core import engine, scoring
from posture_cockpit.storage import Database, Scans
from test_v060_mission_routes import URL, seed, selection
from worlds import DOMAIN, NOW, changed, healthy


def test_t28_independent_sqlite_writer_during_projection_requires_refresh(client, monkeypatch):
    s, did, sid, fs = seed(client, changed(healthy(), dns={f'_dmarc.{DOMAIN} TXT': []}))
    submitted = selection(s, sid, ['mail.dmarc'])
    original = scoring.simulate
    written = False

    def simulate(*args, **kwargs):
        nonlocal written
        result = original(*args, **kwargs)
        if not written:
            written = True
            writer = Database(s.config.data_dir / 'posture_cockpit.db')
            try:
                Scans(writer).save(did, engine.ScanResult(DOMAIN, NOW + timedelta(days=1), 1, fs),
                                   '0.5.0', None, via='schedule')
            finally:
                writer.close()
        return result

    monkeypatch.setattr(scoring, 'simulate', simulate)
    response = client.get(URL + '/simulate', params=submitted)
    assert response.status_code == 409
    assert 'Rafraîchir la fiche' in response.text
    assert '94/100' not in response.text
    assert s.db.value('SELECT COUNT(*) FROM scans') == 2


def test_t20_filters_cannot_inject_markup_or_broaden_visible_scope(client):
    s, _, _, _ = seed(client)
    before = list(s.db._conn.iterdump())
    payload = '\"><script>alert(1)</script>'
    for path, key in [('/dashboard', 'q'), ('/events', 'domain')]:
        response = client.get(path, params={key: payload})
        assert response.status_code == 200
        assert '<script>alert(1)</script>' not in response.text
        assert '&lt;script&gt;' in response.text
    response = client.get('/dashboard', params={'q': "' OR 1=1 --"})
    assert response.status_code == 200 and 'data-domain=' not in response.text
    assert list(s.db._conn.iterdump()) == before
