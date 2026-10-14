# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every text exists in French and in English, and is written out correctly."""

import re
from pathlib import Path

import pytest

from posture_cockpit.core import providers
from posture_cockpit.core.registry import Registry
from posture_cockpit.i18n import LOCALES, Catalog, fmt_date, interface_texts
from worlds import DOMAIN, changed, dkim_key, healthy, run, with_certificate

ROOT = Path(__file__).resolve().parents[1] / "src" / "posture_cockpit"


@pytest.fixture(scope="module")
def catalog():
    return Catalog(Registry.discover().messages)


def scenarios():
    """Answers that make every check produce each of its outcomes, more or less."""
    h = healthy()
    no_mail = changed(h, dns={f"{DOMAIN} MX": [], f"{DOMAIN} TXT": [], f"_dmarc.{DOMAIN} TXT": None})
    yield h
    yield no_mail
    yield changed(h, dns={f"{DOMAIN} TXT": ["v=spf1 +all"], f"_dmarc.{DOMAIN} TXT": ["v=DMARC1; p=none"],
                          f"selector1._domainkey.{DOMAIN} TXT": [f"p={dkim_key(1024)}"], f"{DOMAIN} DS": [],
                          f"{DOMAIN} CAA": [], f"{DOMAIN} NS": ["ns1.example.net."], f"_mta-sts.{DOMAIN} TXT": [],
                          f"_smtp._tls.{DOMAIN} TXT": []},
                  http={f"http://www.{DOMAIN}/": {"status": 200}})
    yield with_certificate(expires_in_days=5, key_type="RSA", key_bits=1024)
    yield with_certificate(trusted=False, problem="unable to get local issuer certificate")
    yield changed(h, dns={f"{DOMAIN} A": [], f"www.{DOMAIN} A": []})


def test_every_check_has_a_title_and_an_explanation(catalog):
    for check in Registry.discover().checks():
        for lang in LOCALES:
            for key in (check.title_key, check.why_key):
                assert catalog.has(lang, key), f"{lang}: {key}"


def test_every_outcome_text_exists_in_both_languages(catalog):
    keys = set()
    for data in scenarios():
        for f in run(data).values():
            keys.add(f.outcome.summary)
            if f.outcome.remedy:
                keys |= {k for k in (f.outcome.remedy.how, f.outcome.remedy.message) if k}
                if f.status.scored:
                    action = [f"{f.outcome.summary}.action", f"{f.check_id}.action"]
                    assert any(catalog.has("fr", k) for k in action), action
    missing = [(lang, k) for k in sorted(keys) for lang in LOCALES if not catalog.has(lang, k)]
    assert missing == []


def test_every_dns_host_has_its_texts():
    for host in (*providers.DNS_HOSTS, providers.OTHER):
        for lang in LOCALES:
            for part in ("open", "path", "add", "fill", "apex", "delete"):
                assert f"dnshost.{host.id}.{part}" in interface_texts(lang)


def test_interface_keys_used_in_templates_exist():
    used = set()
    for path in (ROOT / "web" / "templates").glob("*.html"):
        used |= set(re.findall(r"""\bt\(\s*'([a-z_]+(?:\.[a-z0-9_]+)+)'\s*[,)]""", path.read_text(encoding="utf-8")))
    for path in (ROOT / "web").rglob("*.py"):
        used |= {key for key in re.findall(r'"((?:flash|error|plan|mfa|admin|api|domains|details)\.[a-z0-9_.]+)"',
                                           path.read_text(encoding="utf-8")) if not key.endswith(".html")}
    assert len(used) > 100
    for lang in LOCALES:
        missing = sorted(k for k in used if k not in interface_texts(lang))
        assert missing == [], lang


def test_both_languages_have_the_same_keys():
    assert set(interface_texts("fr")) == set(interface_texts("en"))
    for ext in Registry.discover().extensions:
        assert set(ext.messages["fr"]) == set(ext.messages["en"]), ext.id


def test_plural_and_dates(catalog):
    assert catalog.text("fr", "plan.headline.start", {"n": 1, "start": "C", "end": "B"}) == \
        "1 correction pour passer de C à B"
    assert catalog.text("en", "plan.headline.start", {"n": 3, "start": "C", "end": "A"}) == "3 fixes to go from C to A"
    assert catalog.text("fr", "tls.certificate.expires", {"host": "x", "days": 1, "expires_on": "2026-11-01"}) == \
        "Le certificat de x expire dans 1 jour (1er novembre 2026)."
    assert fmt_date("2026-10-21", "en") == "21 October 2026"


def test_missing_texts_and_parameters_do_not_break_pages(catalog):
    assert catalog.text("fr", "no.such.key") == "no.such.key"
    assert catalog.text("fr", "flash.user_created", {}) == "Compte {name} créé."
    assert catalog.text("de", "nav.domains") == "Domains"


def test_external_https_redirect_uses_evidence_specific_explanation(catalog):
    from types import SimpleNamespace

    from posture_cockpit.core.model import Effort, Finding, Outcome, Remedy, Status
    from posture_cockpit.web.views import task_view

    finding = Finding("web.https_redirect", "web", 8,
                      Outcome(Status.FAIL, "web.https_redirect.external", {"host": DOMAIN},
                              remedy=Remedy(15, Effort.DELEGATE, message="web.https_redirect.external.message")))
    scan = SimpleNamespace(domain=DOMAIN, rechecks={})
    for language in ("fr", "en"):
        view = task_view(catalog, language, scan, finding, 1, 18, [])
        assert view.why == catalog.text(language, "web.https_redirect.external.why", {"host": DOMAIN})
        assert view.message == catalog.text(language, "web.https_redirect.external.message", {"host": DOMAIN})


def test_dkim_dns_evidence_does_not_claim_messages_were_signed(catalog):
    for language in ("fr", "en"):
        message = catalog.text(language, "mail.dkim.found", {"selectors": "dkim"})
        assert "dkim" in message
        if language == "fr":
            assert "signature effective" in message
            assert "n'a pas été vérifiée" in message
        else:
            assert "signatures were not verified" in message
