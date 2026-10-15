# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""DMARC: one verdict, and the other anomalies of the record as notes that every page shows.

Also the remedies under p=none: never a faulty value copied into a record to publish, never a
stricter policy without reports to check first, never a made-up report address."""

from html import unescape

import pytest

from helpers import DEMO, post, setup_account
from posture_cockpit.checks.mail import stricter_dmarc
from posture_cockpit.checks.records import parse_dmarc
from posture_cockpit.core import scoring
from posture_cockpit.core.model import Finding, Outcome, Status
from posture_cockpit.core.registry import Registry
from posture_cockpit.i18n import Catalog, finding_summary
from posture_cockpit.report import render_html
from worlds import DOMAIN, changed, healthy, run

SHOP = f"shop.{DOMAIN}"


def texts() -> Catalog:
    """Interface and check texts, as the application has them."""
    return Catalog(Registry.discover().messages)


def dmarc(record: str | None, domain: str = DOMAIN, parent: str | None = None):
    dns = {f"_dmarc.{domain} TXT": [record] if record else None}
    if parent is not None:
        dns[f"_dmarc.{DOMAIN} TXT"] = [parent]
    return run(changed(healthy(), dns=dns), "mail.dmarc", domain=domain)["mail.dmarc"]


def notes(finding) -> list[str]:
    return [n["key"] for n in finding.outcome.evidence.get("notes", [])]


def proposed(finding) -> list[str]:
    remedy = finding.outcome.remedy
    return [c.value for c in remedy.dns if c.action == "add"] if remedy else []


# ------------------------------------------------------------------ verdict and notes
@pytest.mark.parametrize(("record", "summary", "expected_notes"), [
    # p=none and t=y stay the verdict; the faulty value is a note (0.3.2 audit: it vanished).
    ("v=DMARC1; p=none; pct=abc", "mail.dmarc.monitoring_no_reports", ["mail.dmarc.note.syntax"]),
    (f"v=DMARC1; p=none; pct=abc; rua=mailto:d@{DOMAIN}", "mail.dmarc.monitoring", ["mail.dmarc.note.syntax"]),
    ("v=DMARC1; p=reject; t=y; pct=101", "mail.dmarc.testing", ["mail.dmarc.note.syntax"]),
    # t=y with pct: receivers that follow RFC 7489 ignore t=y and apply pct, whatever the RFC 9989 level.
    ("v=DMARC1; p=reject; t=y; pct=50", "mail.dmarc.testing", ["mail.dmarc.note.partial_reject"]),
    ("v=DMARC1; p=quarantine; t=y; pct=50", "mail.dmarc.testing", ["mail.dmarc.note.partial"]),
    # Two anomalies at once: one verdict, the other one kept.
    ("v=DMARC1; p=reject; pct=50; sp=none", "mail.dmarc.partial_reject", ["mail.dmarc.note.subdomains_open"]),
    ("v=DMARC1; p=reject; pct=50; rua=x@y", "mail.dmarc.syntax", ["mail.dmarc.note.partial_reject"]),
    ("v=DMARC1; p=quarantine; pct=abc; sp=none", "mail.dmarc.syntax", ["mail.dmarc.note.subdomains_open"]),
    # pct means nothing under p=none: no note about it.
    (f"v=DMARC1; p=none; pct=50; rua=mailto:d@{DOMAIN}", "mail.dmarc.monitoring", []),
    (f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}", "mail.dmarc.enforced", []),
])
def test_one_verdict_and_the_other_anomalies_as_notes(record, summary, expected_notes):
    f = dmarc(record)
    assert (f.status, f.outcome.summary) == (Status.OK if summary.endswith("enforced") else Status.WARN, summary)
    assert notes(f) == expected_notes
    if parse_dmarc(record).errors:
        assert f.outcome.evidence["errors"]


def test_t_y_with_pct_keeps_the_rfc_9989_level_and_the_pct_note():
    f = dmarc("v=DMARC1; p=quarantine; t=y; pct=50")
    assert f.outcome.params["effective"] == "none"
    assert f.outcome.evidence["notes"] == [{"key": "mail.dmarc.note.partial", "params": {"pct": 50}}]
    assert f.outcome.remedy.how == "mail.dmarc.testing.how"


def test_an_inherited_policy_shows_the_faulty_value_of_the_parent():
    f = dmarc(None, domain=SHOP, parent="v=DMARC1; p=none; pct=abc")
    assert f.outcome.summary == "mail.dmarc.monitoring_inherited"
    assert f.outcome.evidence["notes"] == [
        {"key": "mail.dmarc.note.syntax", "params": {"name": f"_dmarc.{DOMAIN}", "tags": "pct=abc"}}]
    # The recommendation is still a policy of the subdomain's own.
    assert proposed(f) == [f"v=DMARC1; p=none; rua=mailto:dmarc@{SHOP}"]
    shown = finding_summary(texts(), "fr", f, SHOP)
    assert shown.startswith(f"Le domaine suit la politique DMARC de {DOMAIN}")
    assert f"L'enregistrement _dmarc.{DOMAIN} contient aussi des valeurs non conformes" in shown
    assert shown.endswith("pct=abc.")


def test_notes_are_translation_keys_not_sentences():
    f = dmarc("v=DMARC1; p=reject; pct=50; sp=none")
    for note in f.outcome.evidence["notes"]:
        assert set(note) == {"key", "params"} and note["key"].startswith("mail.dmarc.note.")
        assert all(isinstance(v, (str, int)) for v in note["params"].values())
    catalog = texts()
    assert "sous-domaines sont aussi exclus" in finding_summary(catalog, "fr", f, DOMAIN)
    assert "subdomains are also left out" in finding_summary(catalog, "en", f, DOMAIN)


def test_the_score_does_not_depend_on_notes():
    with_note = scoring.assess(list(run(changed(healthy(), dns={
        f"_dmarc.{DOMAIN} TXT": ["v=DMARC1; p=reject; pct=50; sp=none"]})).values()))
    without = scoring.assess(list(run(changed(healthy(), dns={
        f"_dmarc.{DOMAIN} TXT": ["v=DMARC1; p=reject; pct=50"]})).values()))
    assert (with_note.score, with_note.grade) == (without.score, without.grade)


# ------------------------------------------------------------------ remedies under p=none
def test_the_record_to_publish_never_copies_a_faulty_value():
    f = dmarc(f"v=DMARC1; p=none; pct=abc; rua=mailto:d@{DOMAIN}; adkim=s")
    assert f.outcome.summary == "mail.dmarc.monitoring"
    assert proposed(f) == [f"v=DMARC1; p=quarantine; rua=mailto:d@{DOMAIN}; adkim=s"]


def test_valid_report_addresses_are_kept_and_faulty_ones_left_out():
    f = dmarc(f"v=DMARC1; p=none; rua=mailto:a@{DOMAIN},b@y; ruf=bad, mailto:f@{DOMAIN}")
    assert proposed(f) == [f"v=DMARC1; p=quarantine; rua=mailto:a@{DOMAIN}; ruf=mailto:f@{DOMAIN}"]
    assert notes(f) == ["mail.dmarc.note.syntax"]


@pytest.mark.parametrize("record", ["v=DMARC1; p=none", "v=DMARC1; p=none; rua=d@x.org", "v=DMARC1",
                                    "v=DMARC1; p=none; rua=mailto:"])
def test_without_a_valid_report_address_nothing_stricter_and_no_address_made_up(record):
    f = dmarc(record)
    assert (f.status, f.outcome.summary) == (Status.WARN, "mail.dmarc.monitoring_no_reports")
    assert f.outcome.remedy.dns == ()
    assert f.outcome.remedy.how == "mail.dmarc.monitoring_no_reports.how"
    assert f.outcome.params["name"] == f"_dmarc.{DOMAIN}"


def test_the_stricter_record_puts_p_second_and_drops_repeated_tags():
    text = "v=DMARC1; rua=mailto:a@x.org; p=none; fo=1; fo=0"
    assert stricter_dmarc(text, parse_dmarc(text)) == "v=DMARC1; p=quarantine; rua=mailto:a@x.org"


@pytest.mark.parametrize("lang", ["fr", "en"])
def test_the_advice_asks_to_check_the_reports_before_quarantine(lang):
    catalog = texts()
    finding = dmarc(f"v=DMARC1; p=none; rua=mailto:d@{DOMAIN}")
    how = catalog.text(lang, finding.outcome.remedy.how)
    assert "_report._dmarc" in how
    assert ("quelqu'un les lit" in how) if lang == "fr" else ("someone reads them" in how)
    first_step = catalog.text(lang, "mail.dmarc.how")
    assert ("exister, fonctionner et être consultée" in first_step) if lang == "fr" else \
        ("exist, work and be read" in first_step)


# ------------------------------------------------------------------ texts
def test_pct_wording_follows_rfc_7489_by_policy():
    catalog = texts()
    reject = catalog.text("fr", "mail.dmarc.partial_reject", {"pct": 0, "policy": "reject"})
    assert "sélectionnés pour le rejet" in reject and "devraient être mis en quarantaine" in reject
    quarantine = catalog.text("fr", "mail.dmarc.partial", {"pct": 50, "policy": "quarantine"})
    assert "filtrage habituel" in quarantine
    for lang in ("fr", "en"):
        assert "9989" in catalog.text(lang, "mail.dmarc.partial.how")
        assert "7489" in catalog.text(lang, "mail.dmarc.testing.how")
        assert catalog.has(lang, "mail.dmarc.partial_reject.action")
        assert catalog.has(lang, "mail.dmarc.testing.action")
        assert catalog.has(lang, "mail.dmarc.monitoring_no_reports.action")


def test_a_note_this_version_does_not_know_is_not_shown_raw():
    catalog = texts()
    finding = Finding("mail.dmarc", "mail", 10, Outcome(
        Status.WARN, "mail.dmarc.monitoring", evidence={"notes": [{"key": "mail.dmarc.note.future", "params": {}},
                                                                  "not a note"]}))
    text = finding_summary(catalog, "fr", finding, DOMAIN)
    assert text == catalog.text("fr", "mail.dmarc.monitoring", {"domain": DOMAIN})


# ------------------------------------------------------------------ every page, both languages
@pytest.fixture
def signed_in(client):
    setup_account(client)
    return client


SECOND_RECORD = "v=DMARC1; p=reject; pct=50; sp=none"
NOTE_FR = "Les sous-domaines sont aussi exclus de la politique (sp=none)"
NOTE_EN = "The subdomains are also left out of the policy (sp=none)"


def _pages(client, scan_id):
    return {
        "plan": client.get(f"/domains/{DEMO}?task=mail.dmarc").text,
        "details": client.get(f"/domains/{DEMO}/details").text,
        "history": client.get(f"/domains/{DEMO}/history/{scan_id}").text,
    }


def test_notes_show_on_the_plan_the_technical_page_the_history_and_the_pdfs(signed_in, world):
    world[DEMO]["dns"][f"_dmarc.{DEMO} TXT"] = [SECOND_RECORD]
    post(signed_in, "/domains", "/domains", domain=DEMO)
    s = signed_in.app.state.services
    scan = s.scans.latest(s.scans.domain(DEMO)["id"])
    for name, page in _pages(signed_in, scan.id).items():
        assert NOTE_FR in unescape(page), name
    for historical in (False, True):
        assert NOTE_FR in unescape(render_html(s.catalog, "fr", scan, historical=historical))
        assert NOTE_EN in unescape(render_html(s.catalog, "en", scan, historical=historical))
    post(signed_in, "/lang", "/domains", lang="en")
    for name, page in _pages(signed_in, scan.id).items():
        assert NOTE_EN in unescape(page), name


def test_after_a_recheck_the_plan_shows_the_notes_of_the_new_result(signed_in, world):
    world[DEMO]["dns"][f"_dmarc.{DEMO} TXT"] = ["v=DMARC1; p=none; pct=abc"]
    post(signed_in, "/domains", "/domains", domain=DEMO)
    page = unescape(signed_in.get(f"/domains/{DEMO}?task=mail.dmarc").text)
    assert "sans adresse de rapports valide" in page and "pct=abc" in page
    world[DEMO]["dns"][f"_dmarc.{DEMO} TXT"] = [SECOND_RECORD]
    post(signed_in, f"/domains/{DEMO}/verify/mail.dmarc", f"/domains/{DEMO}?task=mail.dmarc")
    page = unescape(signed_in.get(f"/domains/{DEMO}?task=mail.dmarc").text)
    assert "sélectionnés pour le rejet" in page and NOTE_FR in page
    assert "pct=abc" not in page
