# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""T18: stable complete pages, visible scope and independent seen state."""
import re
from html import unescape
from urllib.parse import parse_qs, urlsplit

import pytest

from helpers import PASSWORD, log_in, post, setup_account
from posture_cockpit.security import hash_password


def fill(client):
    setup_account(client)
    s = client.app.state.services
    public = s.scans.add_domain("shared.example", None)
    stamp = "2026-10-24T00:00:00+00:00"
    for n in range(137):
        s.db.execute("INSERT INTO events(domain_id,category,kind,subject,state,severity,opened_at,updated_at) "
                     "VALUES(?,'security','check',?,'open','critical',?,?)",
                     (public, f"public-{n}", stamp, stamp))
    return s


def test_t18_all_filtered_events_once_with_tied_dates_and_preserved_filters(client):
    s = fill(client)
    expected = [r['id'] for r in s.db.all('SELECT id FROM events ORDER BY updated_at DESC,id DESC')]
    # Every existing filter must exclude distractors, including ties at the page boundary.
    other = s.scans.add_domain('other.example', None)
    shared = s.scans.domain('shared.example')['id']
    for domain, state, severity, category in [(other, 'open', 'critical', 'security'),
                                              (shared, 'resolved', 'critical', 'security'),
                                              (shared, 'open', 'warning', 'security'),
                                              (shared, 'open', 'critical', 'measurement')]:
        s.db.execute("INSERT INTO events(domain_id,category,kind,subject,state,severity,opened_at,updated_at) "
                     "VALUES(?,?,'check',?,?,?, ?,?)",
                     (domain, category, category + severity, state, severity, '2026-10-24', '2026-10-24'))
    before = list(s.db._conn.iterdump())
    url = '/events?state=open&severity=critical&category=security&domain=shared.example&period=all&size=50'
    found = []
    while url:
        response = client.get(url)
        assert response.status_code == 200
        found.extend(int(value) for value in re.findall(r'data-event-id="(\d+)"', response.text))
        links = re.findall(r'<a class="btn btn-secondary" href="([^"]+)">([^<]+)</a>', response.text)
        url = next((unescape(href) for href, label in links if 'suivant' in label.lower()), None)
        if url:
            query = parse_qs(urlsplit(url).query)
            assert query['domain'] == ['shared.example'] and query['severity'] == ['critical']
            assert query['category'] == ['security'] and query['size'] == ['50']
    assert found == expected and len(found) == 137
    assert list(s.db._conn.iterdump()) == before


@pytest.mark.parametrize('query', ['page=0', 'page=-1', 'page=1000001', 'size=101', 'size=0',
                                   'page=x', 'page=1&page=2', 'size=50&size=100'])
def test_bounds(client, query):
    setup_account(client)
    assert client.get('/events?' + query).status_code == 400


def test_empty_and_out_of_range(client):
    setup_account(client)
    assert client.get('/events').status_code == 200
    assert client.get('/events?page=2').status_code == 404


def test_acl_seen_and_bilingual_labels(client):
    s = fill(client)
    perimeter = s.db.execute(
        "INSERT INTO perimeters(name,networks,created_at) VALUES('secret-perimeter','[]','2026-10-24')").lastrowid
    private = s.scans.add_domain('secret.example', None, perimeter)
    for domain, subject in [(private, 'private-proof'), (None, 'global-proof')]:
        s.db.execute("INSERT INTO events(domain_id,category,kind,subject,state,severity,opened_at,updated_at) "
                     "VALUES(?,'technical','scheduler_stalled',?,'open','warning','2026-10-24','2026-10-24')",
                     (domain, subject))
    s.accounts.create('reader', hash_password(PASSWORD))
    post(client, '/logout', '/events')
    log_in(client, 'reader', PASSWORD)
    page = client.get('/events?state=all&size=100')
    assert 'private-proof' not in page.text and 'global-proof' not in page.text
    assert 'secret.example' not in page.text and '137 événement(s)' in page.text
    post(client, '/events/seen', '/events')
    page = client.get('/events')
    assert 'Consulté' in page.text and 'Ouverts' in page.text
    assert s.db.value("SELECT COUNT(*) FROM events WHERE state='resolved'") == 0
    post(client, '/lang', '/events', lang='en', back='/events')
    page = client.get('/events')
    assert 'Seen' in page.text and 'Open' in page.text
    assert not re.search(r'events\.(seen|pagination|total)', page.text)
