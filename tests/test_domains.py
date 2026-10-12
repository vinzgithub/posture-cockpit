# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Domains in the web interface: scan, plan, recheck, expert view, report, API."""

import re

import pytest

from helpers import DEMO, post, setup_account
from posture_cockpit.security import new_token, token_hash
from worlds import DOMAIN, healthy


@pytest.fixture
def signed_in(client):
    setup_account(client)
    return client


def scan(client, domain):
    return post(client, "/domains", "/domains", domain=domain)


def test_add_a_domain_by_pasting_an_address(signed_in, world):
    world[DOMAIN] = healthy()
    r = scan(signed_in, f"https://www.{DOMAIN}/contact")
    assert r.headers["location"] == f"/domains/{DOMAIN}"
    page = signed_in.get(r.headers["location"]).text
    assert "Aucune correction urgente" in page and "100" in page
    assert DOMAIN in signed_in.get("/domains").text


def test_unknown_and_invalid_domains_are_refused(signed_in):
    r = scan(signed_in, "nope.example")
    assert r.status_code == 400 and "n&#39;existe pas" in r.text
    r = scan(signed_in, "not a domain")
    assert r.status_code == 400 and "Ce n&#39;est pas un nom de domaine" in r.text
    assert signed_in.app.state.services.scans.domains() == []


def test_plan_of_the_demo_domain(signed_in):
    scan(signed_in, DEMO)
    page = signed_in.get(f"/domains/{DEMO}").text
    assert "3 corrections pour passer de C à A" in page
    # the priorities, in order, with their gains
    titles = re.findall(r'<span class="task-title">([^<]+)</span>', page)
    assert titles[:3] == ["Renouveler le certificat du site", "Publier une politique DMARC",
                          "Désactiver les anciennes versions de TLS"]
    # DNS instructions for the detected host, and the record to copy
    assert "Détecté : OVHcloud" in page
    assert 'data-copy="v=DMARC1; p=none; rua=mailto:dmarc@menuiserie-dupont.example"' in page
    # the first task is shown, the others are hidden until chosen
    assert re.search(r'data-panel="tls.certificate"[^>]*>', page).group(0).find("hidden") == -1
    assert "hidden" in re.search(r'data-panel="mail.dmarc"[^>]*>', page).group(0)
    page = signed_in.get(f"/domains/{DEMO}?task=mail.dmarc").text
    assert "hidden" not in re.search(r'data-panel="mail.dmarc"[^>]*>', page).group(0)


def test_verify_after_a_fix(signed_in, world):
    scan(signed_in, DEMO)
    # Not fixed yet: the check runs again and says so.
    r = post(signed_in, f"/domains/{DEMO}/verify/mail.dmarc", f"/domains/{DEMO}")
    assert r.headers["location"] == f"/domains/{DEMO}?task=mail.dmarc#task"
    assert "Pas encore visible" in signed_in.get(r.headers["location"]).text
    # The user publishes the record.
    world[DEMO]["dns"][f"_dmarc.{DEMO} TXT"] = [f"v=DMARC1; p=none; rua=mailto:dmarc@{DEMO}"]
    post(signed_in, f"/domains/{DEMO}/verify/mail.dmarc", f"/domains/{DEMO}")
    page = signed_in.get(f"/domains/{DEMO}?task=mail.dmarc").text
    # p=none is a warning, not a full fix: the task is still open, but the score went up.
    scans = signed_in.app.state.services.scans
    latest = scans.latest(scans.domain(DEMO)["id"])
    assert latest.score > 57 and "mail.dmarc" in latest.rechecks
    world[DEMO]["dns"][f"_dmarc.{DEMO} TXT"] = [f"v=DMARC1; p=reject; rua=mailto:dmarc@{DEMO}"]
    post(signed_in, f"/domains/{DEMO}/verify/mail.dmarc", f"/domains/{DEMO}")
    page = signed_in.get(f"/domains/{DEMO}").text
    assert "C&#39;est corrigé : +" in page
    assert "Plus que 2 corrections avant la note A" in page
    assert re.search(r'class="task-card is-done"[^>]*data-task="mail.dmarc"', page)


def test_verify_an_unknown_check(signed_in):
    scan(signed_in, DEMO)
    assert post(signed_in, f"/domains/{DEMO}/verify/nope.nope", f"/domains/{DEMO}").status_code == 404


def test_the_dns_host_choice_is_remembered(signed_in):
    scan(signed_in, DEMO)
    r = post(signed_in, f"/domains/{DEMO}/dns-host", f"/domains/{DEMO}", dns_host="cloudflare", task="mail.dmarc")
    assert r.headers["location"] == f"/domains/{DEMO}?task=mail.dmarc#task"
    page = signed_in.get(f"/domains/{DEMO}").text
    assert re.search(r'value="cloudflare" aria-pressed="true"', page)
    assert post(signed_in, f"/domains/{DEMO}/dns-host", f"/domains/{DEMO}", dns_host="evil").status_code == 400


def test_details_show_every_check_and_its_values(signed_in):
    scan(signed_in, DEMO)
    page = signed_in.get(f"/domains/{DEMO}/details").text
    assert page.count('class="check status-') == 20
    assert "Apache/2.4.41" in page


def test_rescan_and_delete(signed_in):
    scan(signed_in, DEMO)
    post(signed_in, f"/domains/{DEMO}/scan", f"/domains/{DEMO}")
    scans = signed_in.app.state.services.scans
    assert len(scans.history(scans.domain(DEMO)["id"])) == 2
    post(signed_in, f"/domains/{DEMO}/delete", f"/domains/{DEMO}/details")
    assert scans.domain(DEMO) is None
    assert signed_in.get(f"/domains/{DEMO}").status_code == 404


def test_pdf_report(signed_in):
    scan(signed_in, DEMO)
    r = signed_in.get(f"/domains/{DEMO}/report.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert f'filename="posture-{DEMO}-' in r.headers["content-disposition"]


def test_api_lists_scores_with_a_key(signed_in):
    scan(signed_in, DEMO)
    assert signed_in.get("/api/v1/domains").status_code == 401
    token = new_token()
    signed_in.app.state.services.accounts.add_token(1, "Home Assistant", token_hash(token))
    r = signed_in.get("/api/v1/domains", headers={"Authorization": f"Bearer {token}"})
    data = r.json()["domains"][0]
    assert data["domain"] == DEMO and data["score"] == 57 and data["grade"] == "C"
    assert data["critical"] == 3 and data["certificate_days_left"] == 9


def test_pages_carry_a_strict_security_policy(signed_in):
    r = signed_in.get("/domains")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert "unsafe-inline" not in r.headers["content-security-policy"]
    assert ' style="' not in r.text  # inline styles would be blocked by the policy
