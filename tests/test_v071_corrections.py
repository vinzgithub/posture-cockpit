# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Version 0.7.1: the three corrections found by the recette of 0.7.0, and the results of a newer version (D7).

1. The limit of the SMTP measure ("port 25 reached from this instance is no guarantee of delivery from the
   Internet") is said only when port 25 was reached: at least one SMTP dialogue in the stored evidence. Never
   with the probe off, never when no address could be reached, never for an evidence that does not say.
2. The counts of the limits of the measure agree with their number, in French (0 and 1 singular) and in English
   (1 singular), on the page and in the PDF.
3. The page of the history carries no ``style`` attribute (the policy of the application, unchanged, refused
   them): the chart is drawn by the style sheet, as it was shown since 0.6.

D7. A scan recorded by a newer version may hold results this version cannot explain (an observation of a later
TLS audit, a check added later). They are shown apart, bounded and escaped, never worded from a missing key;
never proposed (plan, simulations), never among the checks not evaluated nor the transitions; the score, the
coverage and the API stay those of 0.7.0, so an informative result changes none of them. Scans that hold none
are shown as before (the rest of the suite).
"""

import asyncio
import html as markup
import re
from dataclasses import replace
from pathlib import Path

import pytest

from posture_cockpit import unknown
from posture_cockpit.core import engine, scoring
from posture_cockpit.core.extension import SmtpSettings
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import HTTPS_FAMILY, Effort, Finding, Outcome, Remedy, Role, Status
from posture_cockpit.core.registry import Registry
from posture_cockpit.i18n import Catalog
from posture_cockpit.report import render_html
from posture_cockpit.report.smtp import _limits, view
from posture_cockpit.web.app import CSP
from posture_cockpit.web.routes.api import _summary
from test_v070_smtp_display import MX1, V4, Instance, past_margin, world
from worlds import DOMAIN

TEMPLATES = Path(__file__).parent.parent / "src" / "posture_cockpit" / "web" / "templates"
SCOPE = {"fr": "garantie de livraison depuis Internet", "en": "no guarantee of delivery from the Internet"}


@pytest.fixture
def instance(tmp_path):
    made = []

    def make(probe: bool = True, lang: str = "fr") -> Instance:
        made.append(Instance(tmp_path / f"i{len(made)}", probe, lang))
        return made[-1]

    yield make
    for i in made:
        i.close()


def latest(i: Instance):
    return i.scans.get(i.scans.latest_id(i.scans.domain(DOMAIN)["id"]))


def catalog(i: Instance) -> Catalog:
    return i.app.state.services.catalog


# ------------------------------------------------------------------ correction 1: the limit of port 25
@pytest.mark.parametrize("lang", ["fr", "en"])
@pytest.mark.parametrize(("probe", "outcome", "said"), [
    (True, "tls_verified", True),   # a dialogue: port 25 was reached
    (True, "timeout", False),       # the probe on, no address reached
    (False, "tls_verified", False),  # the probe off
])
def test_the_limit_of_port_25_is_said_only_when_port_25_was_reached(instance, lang, probe, outcome, said):
    """Correction 1: read from the stored evidence (``exhaustivity.dialogues``), on the page and in the PDF."""
    i = instance(probe=probe, lang=lang)
    page = i.scan(world({MX1: {V4: outcome}}))
    scan = latest(i)
    evidence = next(f for f in scan.current() if f.check_id == "mail.smtp_starttls").outcome.evidence
    assert ((evidence.get("exhaustivity") or {}).get("dialogues", 0) > 0) is said
    assert (SCOPE[lang] in page) is said
    assert (SCOPE[lang] in render_html(catalog(i), lang, scan)) is said
    if not said:
        assert 'class="small muted smtp-scope"' not in page  # no empty paragraph either


@pytest.mark.parametrize("evidence", [
    {"rule": "F05.10", "readiness": {"state": "ready"}},                                  # does not say
    {"rule": "F05.10", "readiness": {"state": "ready"}, "exhaustivity": {"dialogues": "2"}},  # not a number
    {"rule": "F05.10", "readiness": {"state": "ready"}, "exhaustivity": {"dialogues": True}},
    {"rule": "F05.10", "readiness": {"state": "ready"}, "exhaustivity": []},
])
def test_an_evidence_that_does_not_say_how_many_dialogues_never_gets_the_limit(evidence):
    shown = view(evidence, lambda key, **params: key)
    assert shown is not None and shown["readiness"]["scope"] == ""


# ------------------------------------------------------------------ correction 2: singular and plural
@pytest.mark.parametrize(("lang", "n", "expected"), [
    ("fr", 0, "0 MX, 0 adresse publiée, 0 connexion ouverte, 0 dialogue SMTP, 0 tentative sur les 16 permises"),
    ("fr", 1, "1 MX, 1 adresse publiée, 1 connexion ouverte, 1 dialogue SMTP, 1 tentative sur les 16 permises"),
    ("fr", 2, "2 MX, 2 adresses publiées, 2 connexions ouvertes, 2 dialogues SMTP, 2 tentatives sur les 16 permises"),
    ("en", 0, "0 MX, 0 published addresses, 0 connections opened, 0 SMTP dialogues, 0 attempts of the 16 allowed"),
    ("en", 1, "1 MX, 1 published address, 1 connection opened, 1 SMTP dialogue, 1 attempt of the 16 allowed"),
    ("en", 2, "2 MX, 2 published addresses, 2 connections opened, 2 SMTP dialogues, 2 attempts of the 16 allowed"),
])
def test_the_counts_of_the_limits_agree_with_their_number(lang, n, expected):
    texts = Catalog()
    counts = {"mx": n, "addresses": n, "sockets": n, "dialogues": n, "budget_spent": n}
    line = _limits({"exhaustivity": counts, "deadline": 20}, lambda key, **params: texts.text(lang, key, params))
    assert expected in line and line.endswith("20 s.")


@pytest.mark.parametrize("lang", ["fr", "en"])
def test_one_address_reads_in_the_singular_on_the_page_and_in_the_pdf(instance, lang):
    """The recette of 0.7.0 read "1 adresses publiées": one MX at one address, verified."""
    i = instance(lang=lang)
    page = i.scan(world({MX1: {V4: "tls_verified"}}))
    report = render_html(catalog(i), lang, latest(i))
    singular = {"fr": "1 adresse publiée", "en": "1 published address,"}[lang]
    wrong = {"fr": r"\b1 (adresses|connexions|dialogues|tentatives)\b",
             "en": r"\b1 (published addresses|connections|SMTP dialogues|attempts)\b"}[lang]
    for text in (page, report):
        assert singular in text and not re.search(wrong, text)


# ------------------------------------------------------------------ correction 3: no style attribute
def test_no_template_of_the_pages_carries_a_style_attribute():
    """The policy of the application refuses inline styles (style-src 'self'): none is left to refuse."""
    found = [(p.name, m.group(0)) for p in sorted(TEMPLATES.glob("*.html"))
             for m in re.finditer(r"\sstyle\s*=|<style\b", p.read_text(encoding="utf-8"))]
    assert found == []


def test_the_policy_of_the_application_is_that_of_070(instance):
    """No 'unsafe-inline', hash or nonce was added to make the styles pass: the policy sent is unchanged."""
    assert CSP == ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; "
                   "form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors {frame_ancestors}")
    i = instance(probe=False)
    i.scan(world({MX1: {V4: "tls_verified"}}))
    i.scan(world({MX1: {V4: "tls_verified"}}))
    response = i.client.get(f"/domains/{DOMAIN}/history")
    assert response.status_code == 200 and 'class="history-trend"' in response.text
    ancestors = i.app.state.services.config.frame_ancestors
    assert response.headers["content-security-policy"] == CSP.format(frame_ancestors=ancestors)


# ------------------------------------------------------------------ D7: results of a newer version
HOSTILE = "<script>alert(1)</script>" + "x" * 300


def observation(check_id: str = "tls.audit.site", **evidence) -> Finding:
    """An informative result of a later version, as 0.8 is planned to store one (status info)."""
    return Finding(check_id, "tls", 0, Outcome(Status.INFO, f"{check_id}.summary", {"n": 3},
                                               evidence or {"level": "standard", "addresses": ["192.0.2.80"]}))


def future_check() -> Finding:
    """A scored check added by a later version, failing, with a remedy."""
    remedy = Remedy(5, Effort.EASY, message="future.check.message", how="future.check.how")
    return Finding("future.check", "web", 7, Outcome(Status.FAIL, "future.check.bad", {}, {"seen": 1}, remedy))


def future_dependent() -> Finding:
    """A later dependent of HTTPS, kept from being measured by its root."""
    return Finding("future.https", "web", 4, Outcome(Status.BLOCKED, "future.https.blocked", {},
                                                     {"cause": "dependency"}), HTTPS_FAMILY, Role.DEPENDENT, 0.5)


def scan_result(data: dict):
    net = FixtureNetwork(data, domain=DOMAIN)
    return asyncio.run(engine.scan(DOMAIN, Registry.discover().checks(), net, timeout=5,
                                   smtp=SmtpSettings(False, None)))


def recorded_by_a_newer_version(i: Instance, *extra: Finding, data: dict | None = None) -> tuple[int, int]:
    """Two scans of the same observation, stored as by this version and as by a newer one (``extra`` added,
    version 0.8.0, same generation): their ids."""
    base = scan_result(data or world({MX1: {V4: "tls_verified"}}))
    domain_id = i.scans.domain(DOMAIN)["id"]
    plain = i.scans.save(domain_id, base, "0.7.1", None)
    newer = i.scans.save(domain_id, replace(base, findings=[*base.findings, *extra]), "0.8.0", None)
    return plain, newer


RAW = re.compile(r"(tls\.audit\.site|future\.check|future\.https)"
                 r"\.(title|summary|bad|blocked|action|why|message|how|ok)")


def no_raw_key(text: str) -> None:
    assert not RAW.search(text), RAW.search(text)


@pytest.mark.parametrize("lang", ["fr", "en"])
def test_an_informative_result_of_a_newer_version_is_shown_apart_and_changes_nothing(instance, lang):
    """The case of the TLS audit of 0.8 (informative, D3): shown apart, in words of this version; the score, the
    grade, the coverage, the plan, the gaps, the API and the annex of the PDF are those of the same observation
    without it."""
    i = instance(probe=False, lang=lang)
    i.scan(world({MX1: {V4: "tls_verified"}}))
    plain_id, newer_id = recorded_by_a_newer_version(i, observation())
    plain, newer = i.scans.get(plain_id), i.scans.get(newer_id)
    assert newer.assessment() == plain.assessment()
    assert (newer.score, newer.grade, newer.coverage) == (plain.score, plain.grade, plain.coverage)
    assert _summary(newer) == _summary(plain)
    texts = catalog(i)
    frozen = unknown.unknown_ids(texts, newer.findings)
    assert [p.finding.check_id for p in scoring.plan(newer.current(), frozen=frozen).items] \
        == [p.finding.check_id for p in scoring.plan(plain.current()).items]

    details = i.client.get(f"/domains/{DOMAIN}/details")
    assert details.status_code == 200
    heading = {"fr": "Résultats d&#39;une version plus récente", "en": "Results from a newer version"}[lang]
    assert heading in details.text and "<code class=\"check-id muted small\">tls.audit.site</code>" in details.text
    assert "0.8.0" in details.text
    assert {"fr": "Sans effet sur la note et la couverture.", "en": "No effect on the score or the coverage."}[lang] \
        in details.text
    no_raw_key(details.text)
    # Not in its category with the checks of this version: in the section apart only.
    section = details.text[details.text.index('id="unknown-results"'):]
    assert details.text.count("tls.audit.site") == section.count("tls.audit.site")

    for path in ("", "/history", f"/history/{newer_id}", "/mission-control"):
        response = i.client.get(f"/domains/{DOMAIN}{path}")
        assert response.status_code == 200, path
        no_raw_key(response.text)
    for path in ("/dashboard", "/events", "/domains"):
        assert i.client.get(path).status_code == 200
        no_raw_key(i.client.get(path).text)

    report = render_html(texts, lang, newer)
    no_raw_key(report)
    annex = {"fr": "les 21 contrôles", "en": "the 21 checks"}[lang]
    assert annex in report and annex in render_html(texts, lang, plain)
    line = {"fr": "1 résultat enregistré par une version plus récente de Posture Cockpit n&#39;est pas détaillé "
                  "dans ce rapport : tls.audit.site.",
            "en": "1 result recorded by a newer version of Posture Cockpit is not detailed in this report: "
                  "tls.audit.site."}[lang]
    assert line in report and "annex-unknown" not in render_html(texts, lang, plain)


def test_what_is_shown_of_an_unknown_result_is_bounded_and_escaped(instance):
    """A hostile or very long identifier, category and evidence: escaped, bounded; the evidence cut for the eye,
    the database keeping it whole; at most 30 results listed, then how many more."""
    i = instance(probe=False)
    i.scan(world({MX1: {V4: "tls_verified"}}))
    many = [observation(f"later.observation{n}") for n in range(40)]
    hostile = Finding(HOSTILE, "<b>" + "c" * 100 + "</b>", 0,
                      Outcome(Status.INFO, "<i>key</i>", {}, {"html": "<img src=x onerror=alert(1)>",
                                                               "ballast": "y" * 70_000}))
    _, newer_id = recorded_by_a_newer_version(i, hostile, *many)
    i.scans.db.execute("UPDATE scans SET version=? WHERE id=?", ("<svg onload=alert(1)>" + "9" * 100, newer_id))
    page = i.client.get(f"/domains/{DOMAIN}/details").text
    assert "<script>alert(1)</script>" not in page and "<img src=x" not in page and "<svg onload" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page and "&lt;svg onload=alert(1)&gt;" in page
    assert HOSTILE not in markup.unescape(page) and HOSTILE[:unknown.SHOWN_ID] + "…" in markup.unescape(page)
    assert "y" * 70_000 not in page and "y" * 1000 in page
    assert "Valeurs affichées tronquées à 4 Kio sur 68 Kio." in page
    assert page.count('<li class="check status-info">') == unknown.SHOWN_ITEMS
    assert "11 autres résultats non reconnus ne sont pas affichés." in page
    assert "c" * 100 not in page and "Autre catégorie (&lt;b&gt;" in page
    stored = i.scans.db.value("SELECT outcome FROM findings WHERE scan_id=? AND check_id=?", (newer_id, HOSTILE))
    assert "y" * 70_000 in stored  # never rewritten

    report = render_html(catalog(i), "fr", i.scans.get(newer_id))
    assert "<script>alert(1)" not in report and "41 résultats enregistrés" in report and "et 33 autres" in report
    assert HOSTILE not in markup.unescape(report)
    weasyprint = pytest.importorskip("weasyprint")
    from posture_cockpit.report import REPORT_DIR
    document = weasyprint.HTML(string=report, base_url=str(REPORT_DIR)).render()
    assert past_margin(document) <= 1  # the line of identifiers never runs past the page


def test_a_scored_result_of_a_newer_version_is_never_proposed(instance):
    """A failing check of a later version, with a remedy: shown apart with its weight, counted in the score as 0.7.0
    counts it, never a task of the plan, never a candidate of a simulation, never a recheck."""
    i = instance(probe=False)
    i.scan(world({MX1: {V4: "tls_verified"}}))
    _, newer_id = recorded_by_a_newer_version(i, future_check())
    newer = i.scans.get(newer_id)
    assert newer.assessment().score == newer.score == scoring.assess(newer.current()).score
    plan = i.client.get(f"/domains/{DOMAIN}").text
    assert 'data-task="future.check"' not in plan and "future.check" not in plan
    details = i.client.get(f"/domains/{DOMAIN}/details").text
    assert "Pris en compte dans la note et la couverture avec le poids que lui a donné la version plus récente (7)." \
        in details
    no_raw_key(details)
    mission = i.client.get(f"/domains/{DOMAIN}/mission-control").text
    assert 'value="future.check"' not in mission
    no_raw_key(mission)
    state_id = i.scans.current_state(newer_id)["id"]
    refused = i.client.get(f"/domains/{DOMAIN}/mission-control/simulate",
                           params={"scan_id": newer_id, "state_id": state_id, "check": "future.check"})
    assert refused.status_code == 400
    from helpers import post
    assert post(i.client, f"/domains/{DOMAIN}/verify/future.check", f"/domains/{DOMAIN}").status_code == 404
    report = render_html(catalog(i), "fr", newer)
    no_raw_key(report)
    assert "future.check" in report.split('class="annex-unknown"')[1] and "future.check" not in \
        report.split('class="annex-unknown"')[0]


def test_simulations_hold_an_unknown_result_as_recorded():
    """core/scoring.py: a frozen result is never a candidate and never hypothesized, even when fixing the root of
    HTTPS would let it be measured; without ``frozen`` (0.7.0), the fallback of the registry hypothesizes it."""
    from worlds import healthy, run

    findings = list(run(healthy()).values())
    root = next(f for f in findings if f.check_id == "web.https_redirect")
    remedy = Remedy(10, Effort.MEDIUM)
    findings = [replace(f, outcome=replace(f.outcome, status=Status.FAIL, remedy=remedy)) if f is root else f
                for f in findings] + [future_dependent(), future_check()]
    registry = Registry.discover()
    frozen = frozenset({"future.https", "future.check"})
    held = scoring.simulate(findings, ["web.https_redirect"], registry, frozen=frozen)
    assert "future.https" not in held.unmeasured
    assert not any(a.check_id.startswith("future.") for a in held.assumptions)
    guessed = scoring.simulate(findings, ["web.https_redirect"], registry)
    assert "future.https" in guessed.unmeasured  # what 0.7.0 did
    with pytest.raises(ValueError):
        scoring.simulate(findings, ["future.check"], registry, frozen=frozen)
    plan = scoring.plan(findings, registry, frozen=frozen)
    assert [i.finding.check_id for i in plan.items] == ["web.https_redirect"]
    assert plan.now == scoring.assess(findings)  # the score counts them as recorded, as 0.7.0 does


def test_a_recheck_keeps_unknown_results_as_recorded_and_derives_no_event_from_them(instance):
    """Comparisons and events read the stored statuses: a recheck by this version holds the unknown results as
    they were recorded, so none of them changes, opens or resolves anything."""
    i = instance(probe=False)
    i.scan(world({MX1: {V4: "tls_verified"}}))
    _, newer_id = recorded_by_a_newer_version(i, observation(), future_check())
    from helpers import post
    assert post(i.client, f"/domains/{DOMAIN}/verify/mail.dmarc", f"/domains/{DOMAIN}").status_code == 303
    states = i.scans.states(newer_id)
    assert len(states) == 2 and states[-1]["origin"] == "recheck"
    import json
    checks = json.loads(states[-1]["checks"])
    assert checks["tls.audit.site"] == "info" and checks["future.check"] == "fail"
    subjects = {row["subject"] for row in i.scans.db.all("SELECT subject FROM events")}
    assert not subjects & {"tls.audit.site", "future.check"}
    history = i.client.get(f"/domains/{DOMAIN}/history")
    assert history.status_code == 200
    no_raw_key(history.text)
