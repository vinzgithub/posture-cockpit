# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Historic scans: read-only access, pagination, PDFs, authorization and i18n."""

import pytest

from helpers import DEMO, post, setup_account
from posture_cockpit.report import render_html
from posture_cockpit.i18n import finding_summary
from posture_cockpit.core.model import Finding, Outcome, Status


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
    assert "PDF généré avec" in html


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
