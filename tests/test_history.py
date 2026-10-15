# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Historic scans: read-only access, pagination, PDFs, authorization and i18n."""

from datetime import UTC, datetime
from html import unescape
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient

from helpers import DEMO, post, setup_account
from posture_cockpit.config import Config
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import Finding, Outcome, Status
from posture_cockpit.i18n import Catalog, finding_summary
from posture_cockpit.report import render_html, report_context
from posture_cockpit.web.app import create_app


@pytest.fixture
def signed_in(client):
    setup_account(client)
    return client


def create_demo_scan(client):
    return post(client, "/domains", "/domains", domain=DEMO)


def test_history_is_paginated_and_reads_all_pages(signed_in):
    create_demo_scan(signed_in)
    for _ in range(24):
        post(signed_in, f"/domains/{DEMO}/scan", f"/domains/{DEMO}")
    s = signed_in.app.state.services
    domain = s.scans.domain(DEMO)
    rows, total = s.scans.history_page(domain["id"])
    assert total == 25 and len(rows) == 20
    more, more_total = s.scans.history_page(domain["id"], page=2)
    assert more_total == 25 and len(more) == 5
    assert rows[-1]["id"] != more[0]["id"]
    html = signed_in.get(f"/domains/{DEMO}/history").text
    assert "Historique des analyses" in html
    assert 'page=2' in html
    assert str(rows[0]["id"]) in html
    assert signed_in.get(f"/domains/{DEMO}/history?page=2").status_code == 200
    assert signed_in.get(f"/domains/{DEMO}/history?page=0").status_code == 404
    assert signed_in.get(f"/domains/{DEMO}/history?page=3").status_code == 404


def test_historical_details_pdf_are_read_only(signed_in):
    create_demo_scan(signed_in)
    s = signed_in.app.state.services
    domain = s.scans.domain(DEMO)
    old_id = s.scans.latest(domain["id"]).id
    post(signed_in, f"/domains/{DEMO}/scan", f"/domains/{DEMO}")
    newer_id = s.scans.latest(domain["id"]).id
    assert old_id != newer_id
    before = s.db.value("SELECT COUNT(*) FROM scans")
    page = signed_in.get(f"/domains/{DEMO}/history/{old_id}")
    assert page.status_code == 200
    assert "lecture seule" in page.text
    assert "/verify/" not in page.text
    assert "/delete" not in page.text
    assert s.db.value("SELECT COUNT(*) FROM scans") == before
    pdf = signed_in.get(f"/domains/{DEMO}/history/{old_id}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert f"scan-{old_id}.pdf" in pdf.headers["content-disposition"]
    html = render_html(s.catalog, "fr", s.scans.get(old_id), historical=True)
    assert "Rapport historique" in html
    assert "PDF généré le" in html


def test_scans_cannot_be_cross_read_between_domains(signed_in, world):
    create_demo_scan(signed_in)
    scan_id = signed_in.app.state.services.scans.latest(
        signed_in.app.state.services.scans.domain(DEMO)["id"]).id
    world["other.example"] = world[DEMO]
    post(signed_in, "/domains", "/domains", domain="other.example")
    for suffix in (f"/history/{scan_id}", f"/history/{scan_id}/report.pdf"):
        assert signed_in.get("/domains/other.example" + suffix).status_code == 404
        assert signed_in.get("/domains/missing.example" + suffix).status_code == 404
        invalid_path = f"/domains/{DEMO}/history/-1" + ("/report.pdf" if suffix.endswith("pdf") else "")
        assert signed_in.get(invalid_path).status_code == 404


def test_history_requires_authentication(client):
    assert client.get(f"/domains/{DEMO}/history", follow_redirects=False).status_code in (303, 307)


def test_legacy_dns_zone_placeholder_never_leaks(signed_in):
    s = signed_in.app.state.services
    legacy = Finding("dns.dnssec", "dns", 4, Outcome(Status.OK, "dns.dnssec.on"))
    assert "{zone}" not in finding_summary(s.catalog, "fr", legacy, DEMO)
    assert "{zone}" not in finding_summary(s.catalog, "en", legacy, DEMO)
    with_zone = Finding("dns.dnssec", "dns", 4,
                        Outcome(Status.OK, "dns.dnssec.on", evidence={"zone": "other.example"}))
    assert "other.example" in finding_summary(s.catalog, "fr", with_zone, DEMO)


def test_history_has_mobile_card_structure(signed_in):
    create_demo_scan(signed_in)
    html = signed_in.get(f"/domains/{DEMO}/history").text
    assert 'class="panel history-panel"' in html
    assert 'class="history-actions"' in html
    assert 'class="history-date"' in html
    assert 'data-label="Couverture"' in html
    assert 'data-label="Version"' in html
    assert f"/domains/{DEMO}/history/" in html
    assert "report.pdf" in html


# ------------------------------------------------------------ addresses that name nothing
@pytest.mark.parametrize("number", ["abc", "0", "-1", "00", "1e3", "1.0", "²", "١", "%201",
                                    "9" * 10, "99999999999999999999999999"])
def test_a_scan_number_that_is_not_one_is_a_404_page(signed_in, number):
    """0.3.1: a huge number crashed (500, OverflowError in SQLite) and text gave a JSON 422."""
    create_demo_scan(signed_in)
    for suffix in ("", "/report.pdf"):
        r = signed_in.get(f"/domains/{DEMO}/history/{number}{suffix}")
        assert r.status_code == 404, (number, suffix)
        assert r.headers["content-type"].startswith("text/html")
        assert "Cette page n'existe pas." in unescape(r.text)


@pytest.mark.parametrize("page", ["abc", "", "0", "-1", "2", "1e3", "²", "99999999999999999999999999"])
def test_a_page_number_that_is_not_one_is_a_404_page(signed_in, page):
    create_demo_scan(signed_in)
    r = signed_in.get(f"/domains/{DEMO}/history?page={page}")
    assert r.status_code == 404 and r.headers["content-type"].startswith("text/html")


def test_scripts_get_a_json_404_not_a_validation_error(signed_in):
    create_demo_scan(signed_in)
    r = signed_in.get(f"/domains/{DEMO}/history/abc", headers={"Accept": "application/json"})
    assert r.status_code == 404 and r.json() == {"error": "Not Found"}


def test_a_leading_zero_still_names_the_scan(signed_in):
    create_demo_scan(signed_in)
    s = signed_in.app.state.services
    scan_id = s.scans.latest(s.scans.domain(DEMO)["id"]).id
    assert signed_in.get(f"/domains/{DEMO}/history/0{scan_id}").status_code == 200
    assert signed_in.get(f"/domains/{DEMO}/history?page=01").status_code == 200


# -------------------------------------------------------------------- the list
def test_the_count_agrees_with_the_number(signed_in):
    """0.3.1: "1 analyses conservées"."""
    create_demo_scan(signed_in)
    assert "1 analyse conservée" in signed_in.get(f"/domains/{DEMO}/history").text
    post(signed_in, f"/domains/{DEMO}/scan", f"/domains/{DEMO}")
    assert "2 analyses conservées" in signed_in.get(f"/domains/{DEMO}/history").text
    post(signed_in, "/lang", "/domains", lang="en")
    assert "2 saved scans" in signed_in.get(f"/domains/{DEMO}/history").text


def test_each_row_says_its_number_coverage_origin_and_which_is_the_latest(signed_in):
    create_demo_scan(signed_in)
    post(signed_in, f"/domains/{DEMO}/scan", f"/domains/{DEMO}")
    s = signed_in.app.state.services
    domain = s.scans.domain(DEMO)
    rows, _total = s.scans.history_page(domain["id"])
    newest, older = rows[0]["id"], rows[1]["id"]
    html = signed_in.get(f"/domains/{DEMO}/history").text
    assert f"n° {newest}" in html and f"n° {older}" in html
    assert html.count('class="badge badge-latest"') == 1
    assert html.index('class="badge badge-latest"') < html.index(f"n° {older}")   # on the newest row
    assert html.count('aria-current="true"') == 1
    result = s.scans.get(newest).assessment()
    assert f"{result.evaluated} contrôles évalués sur\u00a0{result.applicable}" in html
    assert 'data-label="Point de mesure"' in html and ">Internet</td>" in html


# ------------------------------------------------------------------ the detail
def test_the_detail_says_whether_it_is_the_latest_scan(signed_in):
    create_demo_scan(signed_in)
    s = signed_in.app.state.services
    domain = s.scans.domain(DEMO)
    first = s.scans.latest(domain["id"]).id
    page = unescape(signed_in.get(f"/domains/{DEMO}/history/{first}").text)
    assert f"Analyse n° {first}" in page
    assert "C'est la dernière analyse du domaine" in page and f'href="/domains/{DEMO}"' in page
    post(signed_in, f"/domains/{DEMO}/scan", f"/domains/{DEMO}")
    page = unescape(signed_in.get(f"/domains/{DEMO}/history/{first}").text)
    assert "Une analyse plus récente existe" in page and "Voir le plan d'action actuel" in page
    assert "C'est la dernière analyse" not in page


def test_details_and_history_share_the_same_findings_markup(signed_in):
    create_demo_scan(signed_in)
    s = signed_in.app.state.services
    scan_id = s.scans.latest(s.scans.domain(DEMO)["id"]).id
    current = signed_in.get(f"/domains/{DEMO}/details").text
    stored = signed_in.get(f"/domains/{DEMO}/history/{scan_id}").text

    def checks(html):
        return html[html.index('<section class="panel details"'):html.rindex("</section>")]

    assert checks(stored) in current


# --------------------------------------------------------------- historical PDF
PARIS = ZoneInfo("Europe/Paris")


def test_the_historical_pdf_says_when_it_was_made(signed_in):
    create_demo_scan(signed_in)
    s = signed_in.app.state.services
    scan = s.scans.latest(s.scans.domain(DEMO)["id"])
    made = datetime(2026, 10, 15, 6, 5, tzinfo=UTC)
    context = report_context(Catalog(), "fr", scan, tz=PARIS, historical=True, now=made)
    assert context["generated"] == {"date": "15 octobre 2026", "time": "08:05", "zone": "UTC+2"}
    html = render_html(s.catalog, "fr", scan, tz=PARIS, historical=True)
    assert "PDF généré le " in html and " avec la version " in html
    assert "PDF généré le" not in render_html(s.catalog, "fr", scan, tz=PARIS)   # only on historical reports


def test_the_historical_pdf_is_named_after_the_local_day(tmp_path, world):
    """Scanned at 22:30 UTC on 12 October: the 13th in Paris, as every page of the instance shows it."""
    def network(domain):
        return FixtureNetwork(world.get(domain, {"dns": {f"{domain} SOA": None}}))

    app = create_app(Config(data_dir=tmp_path, timezone=PARIS), network_factory=network)
    with TestClient(app) as client:
        setup_account(client)
        create_demo_scan(client)
        s = client.app.state.services
        s.db.execute("UPDATE scans SET started_at = '2026-10-12T22:30:00+00:00'")
        scan_id = s.scans.latest(s.scans.domain(DEMO)["id"]).id
        r = client.get(f"/domains/{DEMO}/history/{scan_id}/report.pdf")
        assert r.status_code == 200
        assert f'filename="posture-{DEMO}-2026-10-13-scan-{scan_id}.pdf"' in r.headers["content-disposition"]
