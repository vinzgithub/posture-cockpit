# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Numbers in sentences: agreement, gains below one point, scores that do not exist."""

import re
from types import SimpleNamespace

import pytest

from helpers import post, setup_account
from posture_cockpit.core import scoring
from posture_cockpit.i18n import Catalog
from posture_cockpit.report import render_html
from posture_cockpit.web import views
from worlds import DOMAIN, changed, healthy

CATALOG = Catalog()


def text(lang, key, **params):
    return CATALOG.text(lang, key, params)


# ---------------------------------------------------------------- agreement
@pytest.mark.parametrize(("lang", "counts", "expected"), [
    ("fr", {"total": 3, "ok": 1, "fail": 1, "warn": 1},
     "Sur 3 contrôles évalués, 1 est conforme, 1 demande une correction rapide et 1 peut être amélioré."),
    ("fr", {"total": 9, "ok": 4, "fail": 3, "warn": 2},
     "Sur 9 contrôles évalués, 4 sont conformes, 3 demandent une correction rapide et 2 peuvent être améliorés."),
    ("en", {"total": 3, "ok": 1, "fail": 1, "warn": 1},
     "Out of 3 checks evaluated, 1 is compliant, 1 needs a quick fix and 1 can be improved."),
    ("en", {"total": 9, "ok": 4, "fail": 3, "warn": 2},
     "Out of 9 checks evaluated, 4 are compliant, 3 need a quick fix and 2 can be improved."),
])
def test_the_report_diagnosis_agrees_with_its_numbers(lang, counts, expected):
    assert text(lang, "report.diagnosis.issues", **counts) == expected


def test_other_counted_sentences_agree(client):
    assert text("fr", "report.diagnosis.clean", total=2, ok=1, warn=1) == (
        "Sur 2 contrôles évalués, 1 est conforme et aucun ne demande de correction urgente. "
        "1 point peut encore être amélioré.")
    assert text("fr", "report.diagnosis.clean", total=5, ok=3, warn=2).endswith(
        "3 sont conformes et aucun ne demande de correction urgente. 2 points peuvent encore être améliorés.")
    assert "1 point can still be improved" in text("en", "report.diagnosis.clean", total=2, ok=1, warn=1)
    assert text("fr", "report.points", n=1) == "+1 pt" and text("fr", "report.points", n=12) == "+12 pts"
    assert text("fr", "report.minutes", n=1) == "1 minute" and text("en", "report.minutes", n=30) == "30 minutes"
    assert text("fr", "flash.verified", points=1, score=100) == "C'est corrigé : +1 point, votre note passe à 100."
    assert text("en", "flash.verified", points=6, score=93) == "Fixed: +6 points, your score is now 93."
    assert text("fr", "plan.subline.not_evaluated", evaluated=1, applicable=19, percent=5).startswith(
        "1 contrôle réalisé sur 19 seulement (5 %).")
    assert text("en", "plan.subline.not_evaluated", evaluated=1, applicable=19, percent=5).startswith(
        "Only 1 check out of 19 could run (5%).")
    assert text("fr", "report.diagnosis.not_evaluated", evaluated=8, applicable=19).startswith(
        "8 contrôles réalisés sur 19 seulement")
    checks = client.app.state.services.catalog  # with the texts of the built-in checks
    assert "que 1 seconde :" in checks.text("fr", "mail.mta_sts.short_max_age", {"seconds": 1})
    assert "for 1 second:" in checks.text("en", "mail.mta_sts.short_max_age", {"seconds": 1})


# --------------------------------------------------------- gains below a point
def _two_small_improvements():
    """TLS-RPT and security.txt missing: each weighs about 0.6 point. Fixed in turn, the first
    one leaves the rounded score where it was (99 → 99), the second one adds a point (→ 100)."""
    return changed(healthy(), dns={f"_smtp._tls.{DOMAIN} TXT": []},
                   http={f"https://{DOMAIN}/.well-known/security.txt": {"status": 404}})


def test_a_gain_below_one_point_is_said_so(client, world):
    world[DOMAIN] = _two_small_improvements()
    setup_account(client)
    post(client, "/domains", "/domains", domain=DOMAIN)
    page = client.get(f"/domains/{DOMAIN}?task=mail.tls_rpt").text
    assert "<strong>+</strong>" not in page
    card = re.search(r'data-task="mail\.tls_rpt".*?</a>', page, re.S).group(0)
    assert "<strong>&lt; 1</strong>" in card and "<small>point</small>" in card
    assert "moins d&#39;1 point" in page  # the panel of the selected task
    card = re.search(r'data-task="web\.security_txt".*?</a>', page, re.S).group(0)
    assert "<strong>+1</strong>" in card and "<small>point</small>" in card  # +1 point, not "+1 points"


def test_the_report_never_prints_plus_zero(client, world):
    world[DOMAIN] = _two_small_improvements()
    setup_account(client)
    post(client, "/domains", "/domains", domain=DOMAIN)
    services = client.app.state.services
    scan = services.scans.latest(services.scans.domain(DOMAIN)["id"])
    html = render_html(services.catalog, "fr", scan)
    assert "(&lt; 1 pt)" in html and "(+1 pt)" in html
    assert "+0 pt" not in html and "(+1 pts)" not in html


def test_a_fix_worth_less_than_a_point_does_not_announce_plus_zero(client, world):
    world[DOMAIN] = _two_small_improvements()
    setup_account(client)
    post(client, "/domains", "/domains", domain=DOMAIN)
    world[DOMAIN] = changed(world[DOMAIN], dns={f"_smtp._tls.{DOMAIN} TXT": [f"v=TLSRPTv1; rua=mailto:tls@{DOMAIN}"]})
    r = post(client, f"/domains/{DOMAIN}/verify/mail.tls_rpt", f"/domains/{DOMAIN}")
    page = client.get(r.headers["location"]).text
    assert "Votre note reste à 99 : ce contrôle pèse moins d&#39;1 point." in page
    assert "+0" not in page


def test_a_one_point_fix_is_singular(client, world):
    world[DOMAIN] = changed(healthy(), dns={f"_smtp._tls.{DOMAIN} TXT": []})
    setup_account(client)
    post(client, "/domains", "/domains", domain=DOMAIN)
    world[DOMAIN] = healthy()
    r = post(client, f"/domains/{DOMAIN}/verify/mail.tls_rpt", f"/domains/{DOMAIN}")
    assert "C&#39;est corrigé : +1 point, votre note passe à 100." in client.get(r.headers["location"]).text


# --------------------------------------------- a scan that had no score at first
def _story(start, now, target, priorities):
    view = views.PlanView(
        domain=DOMAIN, scan=SimpleNamespace(findings=[]), now=now, start=start, target=target, grade_label="",
        priorities=priorities, improvements=[], counts={}, categories=[], gaps=[], dns_hosts=[], dns_host="",
        detected_host="", nameservers=[])
    views._tell_the_story(CATALOG, "fr", view)
    return view


def _task(done=False):
    return views.TaskView(check_id="x", number=1, title="", summary="", why="", category="", minutes=10,
                          effort="easy", effort_label="", gain=0, done=done)


@pytest.fixture
def no_score():
    return scoring.Assessment(None, None, 0.4, 4, 10)


def test_no_score_at_first_is_never_quoted_as_zero(no_score):
    now = scoring.Assessment(70, "C", 0.6, 6, 10)  # rechecks made it gradable
    view = _story(no_score, now, no_score, [_task(), _task()])
    assert view.headline == "2 corrections prioritaires à faire"
    assert "0" not in view.headline
    view = _story(no_score, now, no_score, [_task(done=True), _task()])
    assert view.headline == "Plus que 1 correction prioritaire"
    assert view.subline == "Votre note est maintenant de 70. Continuez sur votre lancée."
    assert "de 0 à" not in view.subline


def test_a_known_start_keeps_the_usual_sentences():
    start = scoring.Assessment(57, "C", 1.0, 19, 19)
    target = scoring.Assessment(83, "B", 1.0, 19, 19)
    assert _story(start, start, target, [_task(), _task()]).headline == "2 corrections pour passer de C à B"
    view = _story(start, scoring.Assessment(70, "C", 1.0, 19, 19), target, [_task(done=True), _task()])
    assert view.headline == "Plus que 1 correction avant la note B"
    assert view.subline == "Votre note est passée de 57 à 70. Continuez sur votre lancée."
