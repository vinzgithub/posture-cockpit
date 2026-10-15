# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Domains in the web interface: scan, plan, recheck, expert view, report, API."""

import re

import pytest

from helpers import DEMO, post, setup_account
from posture_cockpit.core import scoring
from posture_cockpit.report import report_context
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
    assert signed_in.app.state.services.scans.domains(internal=True) == []


def test_a_resolver_giving_empty_answers_is_not_mistaken_for_missing_records(signed_in, world):
    world["quiet.example"] = {"dns": {}}
    r = scan(signed_in, "quiet.example")
    assert r.status_code == 400 and "Le DNS ne renvoie aucune information" in r.text


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
    auth = {"Authorization": f"Bearer {token}"}
    assert signed_in.post(f"/api/v1/domains/{DEMO}/scan").status_code == 401
    assert signed_in.post("/api/v1/domains/unknown.example/scan", headers=auth).status_code == 404
    r = signed_in.post(f"/api/v1/domains/{DEMO}/scan", headers=auth)
    assert r.status_code == 200 and r.json()["score"] == 57
    scans = signed_in.app.state.services.scans
    assert len(scans.history(scans.domain(DEMO)["id"])) == 2


def test_pages_carry_a_strict_security_policy(signed_in):
    r = signed_in.get("/domains")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert "unsafe-inline" not in r.headers["content-security-policy"]
    assert ' style="' not in r.text  # inline styles would be blocked by the policy


def unreachable(domain="down.example"):
    """A domain whose name answers, and nothing else: DNS timeouts for mail, no web server."""
    data = {"dns": {f"{domain} SOA": ["ns1.example.net. hostmaster.example.org. 1 7200 3600 1209600 300"],
                    f"{domain} NS": ["ns1.example.net.", "ns2.example.net."],
                    f"{domain} A": ["192.0.2.20"], f"www.{domain} A": ["192.0.2.20"]}}
    for name in (domain, f"_dmarc.{domain}", f"_mta-sts.{domain}", f"_smtp._tls.{domain}"):
        data["dns"][f"{name} TXT"] = "timeout"
    data["dns"][f"{domain} MX"] = "timeout"
    return data


def test_a_domain_that_could_not_be_checked_is_not_evaluated_everywhere(signed_in, world):
    """The same verdict on the plan, the list, the API, the PDF and in the database: never 100/A."""
    world["down.example"] = unreachable()
    assert scan(signed_in, "down.example").headers["location"] == "/domains/down.example"
    s = signed_in.app.state.services
    stored = s.scans.latest(s.scans.domain("down.example")["id"])
    assert (stored.score, stored.grade) == (None, None) and stored.coverage < scoring.MIN_COVERAGE

    plan = signed_in.get("/domains/down.example").text
    assert "Non évalué" in plan and "Note impossible" in plan and "100</strong>" not in plan
    assert re.search(r"Couverture \d+\xa0% : \d+ contrôles évalués sur \d+", plan)
    # The recorded timeouts are reported as LiveNetwork reports real ones (0.3.1: a plain network error).
    assert "contrôles non évalués" in plan and "Délai dépassé lors de la connexion au serveur" in plan
    listing = signed_in.get("/domains").text
    assert "Non évalué" in listing

    token = new_token()
    s.accounts.add_token(1, "cron", token_hash(token))
    data = next(d for d in signed_in.get("/api/v1/domains", headers={"Authorization": f"Bearer {token}"})
                .json()["domains"] if d["domain"] == "down.example")
    assert data["score"] is None and data["grade"] is None and data["evaluation"] == "not_evaluated"
    assert data["not_evaluated"] > 0 and data["coverage"] == round(stored.coverage, 3)

    context = report_context(s.catalog, "fr", stored)
    assert context["result"].score is None and "trop peu pour donner une note" in context["diagnosis"]
    assert context["gaps"] and context["perimeter"] == ""
    pdf = signed_in.get("/domains/down.example/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")


def test_score_is_the_same_on_every_surface(signed_in):
    scan(signed_in, DEMO)
    s = signed_in.app.state.services
    stored = s.scans.latest(s.scans.domain(DEMO)["id"])
    computed = scoring.assess(stored.current())
    assert (stored.score, stored.grade) == (computed.score, computed.grade) == (57, "C")
    page = signed_in.get(f"/domains/{DEMO}").text
    assert '<strong>57</strong><span>/100</span>' in page and "Couverture 100" in page
    context = report_context(s.catalog, "fr", stored)
    assert (context["result"].score, context["result"].grade) == (57, "C")
