# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""DMARC remedies: a record the plan asks to publish must be valid, give the protection it
announces, and keep the reports the next step relies on. And an invalid policy hides nothing."""

from html import unescape

import pytest

from helpers import DEMO, post, setup_account
from posture_cockpit.checks.records import parse_dmarc, tags
from posture_cockpit.core.model import Status
from posture_cockpit.core.registry import Registry
from posture_cockpit.i18n import Catalog, finding_summary
from posture_cockpit.report import render_html
from worlds import DOMAIN, changed, healthy, run

REPORTS = "rua=mailto:reports@example.org"


def dmarc(record: str):
    return run(changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": [record]}), "mail.dmarc")["mail.dmarc"]


def proposed(finding) -> list[str]:
    remedy = finding.outcome.remedy
    return [c.value for c in remedy.dns if c.action == "add"] if remedy else []


# ----------------------------------------------- the record offered for p=quarantine
@pytest.mark.parametrize("record", [
    f"v=DMARC1; p=none; t=y; {REPORTS}",      # RFC 9989 §4.7: quarantine with t=y is none
    f"v=DMARC1; p=none; pct=0; {REPORTS}",    # RFC 7489 §6.6.4: no failing mail selected for quarantine
    f"v=DMARC1; p=none; pct=50; t=n; {REPORTS}",
])
def test_the_quarantine_offered_is_a_full_quarantine(record):
    f = dmarc(record)
    assert f.outcome.summary == "mail.dmarc.monitoring"
    assert proposed(f) == [f"v=DMARC1; p=quarantine; {REPORTS}"]


@pytest.mark.parametrize(("record", "note"), [
    # 860b627: "v=DMARC1; p=quarantine", without any report address.
    ("v=DMARC1; p=none; rua=mailto:a@example.org; rua=mailto:b@example.org", "repeated"),  # which one? not chosen
    ("v=DMARC1; p=none; rua=mailto:a@example.org; rua=mailto:a@example.org", "repeated"),  # repeated all the same
    ("v=DMARC1; p=none; rua=d@x.org", "syntax"),                                             # no valid address left
])
def test_no_quarantine_offered_when_the_reports_are_not_established(record, note):
    f = dmarc(record)
    assert (f.status, f.outcome.summary) == (Status.WARN, "mail.dmarc.monitoring_no_reports")
    assert f.outcome.remedy.dns == ()
    assert f.outcome.remedy.how == "mail.dmarc.monitoring_no_reports.how"   # reports first
    assert [n["key"] for n in f.outcome.evidence["notes"]] == [f"mail.dmarc.note.{note}"]


def test_a_valid_address_next_to_a_faulty_one_is_kept():
    f = dmarc("v=DMARC1; p=none; rua=mailto:a@example.org,b@y")
    assert proposed(f) == ["v=DMARC1; p=quarantine; rua=mailto:a@example.org"]


@pytest.mark.parametrize("record", [
    f"v=DMARC1; p=none; t=y; pct=0; {REPORTS}",
    f"v=DMARC1; p=none; pct=abc; adkim=x; fo=1; fo=0; {REPORTS}",
    "v=DMARC1; rua=mailto:a@example.org,bad; sp=none; aspf=s; p=none; ruf=mailto:f@example.org",
    "v=DMARC1; p=none; rua=mailto:a@example.org; ruf=x; ruf=mailto:f@example.org; t=y",
])
def test_every_record_offered_is_valid_and_gives_what_it_announces(record):
    """Checked on the result, not on the input: no faulty or repeated tag, no t=y, pct 100, a report address."""
    for value in proposed(dmarc(record)):
        offered = parse_dmarc(value)
        names = [name for name, _ in tags(value)]
        assert offered.starts_right and offered.errors == () and len(names) == len(set(names))
        assert offered.policy == "quarantine" and not offered.testing and offered.pct == 100
        assert offered.rua


def test_t_n_and_pct_100_are_left_out_too():
    """A normalisation, not a defect of 860b627: they are the defaults, leaving them out changes nothing."""
    assert proposed(dmarc(f"v=DMARC1; p=none; t=n; pct=100; {REPORTS}")) == [f"v=DMARC1; p=quarantine; {REPORTS}"]


def test_sp_and_np_are_kept_as_written_and_the_advice_names_the_subdomains():
    f = dmarc(f"v=DMARC1; p=none; sp=none; np=reject; {REPORTS}")
    assert proposed(f) == [f"v=DMARC1; p=quarantine; sp=none; np=reject; {REPORTS}"]
    catalog = texts()
    how = {lang: catalog.text(lang, f.outcome.remedy.how) for lang in ("fr", "en")}
    assert "Sans valeur sp, la quarantaine s'applique aussi aux sous-domaines" in how["fr"]
    assert "reprise telle quelle" in how["fr"] and "ne reprend ni t=y ni pct" in how["fr"]
    assert "Without an sp value, the quarantine also applies to the subdomains" in how["en"]
    assert "kept as written" in how["en"] and "keeps neither t=y nor pct" in how["en"]


# ----------------------------------------------- repeated tags: said, not scored differently (0.4)
def test_a_repeated_tag_is_said_to_risk_the_whole_record():
    f = dmarc(f"v=DMARC1; p=reject; {REPORTS}; rua=mailto:b@example.org")
    assert (f.status, f.outcome.summary) == (Status.WARN, "mail.dmarc.syntax")   # as in 860b627
    assert f.outcome.evidence["notes"] == [
        {"key": "mail.dmarc.note.repeated", "params": {"name": f"_dmarc.{DOMAIN}", "tags": "rua"}}]
    fr = finding_summary(texts(), "fr", f, DOMAIN)
    en = finding_summary(texts(), "en", f, DOMAIN)
    assert "certaines messageries peuvent ignorer l'enregistrement entier" in fr and "RFC 6376" in fr
    assert "some receivers may ignore the whole record" in en
    # The verdict no longer claims that every faulty value is replaced by its default (40cee65 did).
    assert fr.startswith("La politique DMARC (p=reject) contient des valeurs non conformes : rua=mailto:b@example.org. "
                         "Leur traitement peut varier selon l'anomalie et la messagerie destinataire ; "
                         "l'enregistrement doit être corrigé.")
    assert en.startswith("The DMARC policy (p=reject) contains invalid values: rua=mailto:b@example.org. "
                         "How they are handled may depend on the error and the receiving mail service; "
                         "the record should be corrected.")
    assert "remplacent par les valeurs par défaut" not in fr and "replace them by the defaults" not in en


# ----------------------------------------------- an invalid policy hides nothing
def texts() -> Catalog:
    return Catalog(Registry.discover().messages)


@pytest.mark.parametrize(("record", "status", "summary", "policy_value"), [
    (f"v=DMARC1; p=incorrect; pct=abc; {REPORTS}", Status.WARN, "mail.dmarc.invalid_monitoring", "p=incorrect"),
    ("v=DMARC1; p=reject; sp=bad; pct=abc", Status.FAIL, "mail.dmarc.invalid", "sp=bad"),   # 860b627 said « p »
])
def test_an_invalid_policy_names_its_value_and_keeps_the_other_faulty_ones(record, status, summary, policy_value):
    f = dmarc(record)
    assert (f.status, f.outcome.summary) == (status, summary)   # statuses unchanged
    assert f.outcome.params["tags"] == policy_value
    assert f.outcome.evidence["notes"] == [
        {"key": "mail.dmarc.note.syntax", "params": {"name": f"_dmarc.{DOMAIN}", "tags": "pct=abc"}}]
    for lang in ("fr", "en"):
        shown = finding_summary(texts(), lang, f, DOMAIN)
        assert policy_value in shown and "pct=abc" in shown
        assert shown.count(policy_value) == 1   # the verdict names it, the note does not repeat it


@pytest.fixture
def signed_in(client):
    setup_account(client)
    return client


def test_an_invalid_policy_shows_both_values_on_every_page(signed_in, world):
    world[DEMO]["dns"][f"_dmarc.{DEMO} TXT"] = [f"v=DMARC1; p=incorrect; pct=abc; {REPORTS}"]
    post(signed_in, "/domains", "/domains", domain=DEMO)
    s = signed_in.app.state.services
    scan = s.scans.latest(s.scans.domain(DEMO)["id"])
    for lang in ("fr", "en"):
        post(signed_in, "/lang", "/domains", lang=lang)
        for url in (f"/domains/{DEMO}?task=mail.dmarc", f"/domains/{DEMO}/details"):
            page = unescape(signed_in.get(url).text)
            assert "p=incorrect" in page and "pct=abc" in page, (lang, url)
        pdf_html = unescape(render_html(s.catalog, lang, scan))
        assert "p=incorrect" in pdf_html and "pct=abc" in pdf_html
