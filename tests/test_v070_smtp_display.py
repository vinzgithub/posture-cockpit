# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""What the pages, the PDF and the API show of mail.smtp_starttls (version 0.7, PR-D).

An instance with the probe on scans recorded worlds (core/fixture.py) through the web application; the
details page, the history, Mission Control, the PDF (its HTML, and WeasyPrint's layout) and the API
are read as a user or a monitoring tool reads them. What they show is the stored evidence in the words
of the catalogues: the five statuses and the five states of readiness (F05, F06), one row per MX and
address with the cause proper to each (``silent_mx``, never the global one of F05.08 on every server),
the certificate verified, refused or read for the diagnosis only, the limits of the measure. Then the
reasons "engine", "scope" and an unknown scope; the additive API fields for every kind of scan; and
hostile or very long contents from the network, shown as text.
"""

import asyncio
import html as markup
import json
import re

import pytest
from fastapi.testclient import TestClient

from helpers import post, setup_account
from posture_cockpit.config import Config
from posture_cockpit.core import engine
from posture_cockpit.core.extension import SmtpSettings
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.registry import Registry
from posture_cockpit.report import render_html
from posture_cockpit.report.smtp import view
from posture_cockpit.web.app import create_app
from posture_cockpit.web.routes.api import _summary
from worlds import DOMAIN, EHLO, changed, healthy

CHECK = "mail.smtp_starttls"
MX1, MX2 = "mx.example.net", "mx2.example.net"
V4, V4B, V6 = "192.0.2.25", "192.0.2.26", "2001:db8:ffff:ffff:ffff:ffff:ffff:25"
URL = f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt"


def world(mx: dict[str, dict], policy: str | None = "enforce", **dns) -> dict:
    """The healthy domain with these MX (name → {address: outcome}) and an MTA-STS policy covering them."""
    records = {f"{DOMAIN} MX": [f"{10 * (i + 1)} {name}." for i, name in enumerate(mx)]}
    for name, by_address in mx.items():
        records[f"{name} A"] = [a for a in by_address if ":" not in a]
        records[f"{name} AAAA"] = [a for a in by_address if ":" in a]
    data = changed(healthy(), dns={**records, **dns})
    data["smtp"] = {name: dict(v) for name, v in mx.items()}
    if policy is None:
        data["dns"].pop(f"_mta-sts.{DOMAIN} TXT")
    else:
        lines = "".join(f"mx: {m}\n" for m in mx)
        data["http"][URL] = {"status": 200, "body": f"version: STSv1\nmode: {policy}\n{lines}max_age: 604800\n"}
    return data


class Instance:
    """An instance with the SMTP probe on (or off), its first account, scanning recorded worlds."""

    def __init__(self, tmp_path, probe: bool = True, lang: str = "fr"):
        self.data: dict = {}
        self.app = create_app(Config(data_dir=tmp_path, smtp_probe=probe, smtp_ehlo_name=EHLO if probe else None),
                              network_factory=lambda d: FixtureNetwork(self.data, domain=d,
                                                                       ehlo_name=EHLO if probe else None))
        self.client = TestClient(self.app).__enter__()
        setup_account(self.client, lang=lang)

    def scan(self, data: dict) -> str:
        self.data.clear()
        self.data.update(data)
        post(self.client, "/domains", "/domains", domain=DOMAIN)
        return self.client.get(f"/domains/{DOMAIN}/details").text

    @property
    def scans(self):
        return self.app.state.services.scans

    def close(self):
        self.client.__exit__(None, None, None)


@pytest.fixture
def instance(tmp_path):
    made = []

    def make(probe: bool = True, lang: str = "fr") -> Instance:
        made.append(Instance(tmp_path / f"i{len(made)}", probe, lang))
        return made[-1]

    yield make
    for i in made:
        i.close()


def smtp_part(page: str) -> str:
    """The SMTP block of the details page (empty when there is none)."""
    found = re.search(r'<div class="smtp" data-rule="[^"]*">.*?\n</div>', page, re.S)
    return found.group(0) if found else ""


def rows(page: str) -> list[str]:
    """The rows of the SMTP table as text, as a reader sees them."""
    found = re.findall(r'<tr class="smtp-[a-z_]+">(.*?)</tr>', smtp_part(page), re.S)
    return [markup.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", r))).strip() for r in found]


# ------------------------------------------------------------------ the five statuses (F05)
@pytest.mark.parametrize(("outcome", "status", "rule"), [
    ("tls_verified", "ok", "F05.10"), ("certificate_refused", "fail", "F05.04"),
    ("starttls_absent", "fail", "F05.03"), ("timeout", "error", "F05.08")])
def test_the_statuses_of_the_check_and_their_table(instance, outcome, status, rule):
    """F05.03, F05.04, F05.08, F05.10, T05: each status of the check shows its badge, its line of the matrix and
    one row for the MX with the result in words; the JSON of the evidence stays after it (progressive reading)."""
    page = instance().scan(world({MX1: {V4: outcome}}))
    part = smtp_part(page)
    assert f'data-rule="{rule}"' in part and f'id="{CHECK}"' in page
    assert re.search(rf'id="{CHECK}".*?badge-{status}', page, re.S)
    assert len(rows(page)) == 1 and rows(page)[0].startswith(f"{MX1} priorité 10 {V4} IPv4")
    assert page.index('class="smtp"') < page.index('class="evidence"', page.index(f'id="{CHECK}"'))


def test_warn_and_its_readiness(instance):
    """F05.06, F06: a refused certificate without enforce in force: WARN, readiness to fix with its cause."""
    page = instance().scan(world({MX1: {V4: "certificate_refused"}}, policy="testing"))
    part = smtp_part(page)
    assert 'data-rule="F05.06"' in part and "À corriger" in part
    assert "Un certificat SMTP est refusé (chaîne, nom ou dates)." in part


def test_probe_off_shows_na_and_no_table(instance):
    """F05.01, A1a, F06: the probe off: NA, readiness "cannot be confirmed" with the probe off as its cause, the
    limit of the measure, and no table (nothing was measured)."""
    page = instance(probe=False).scan(world({MX1: {V4: "tls_verified"}}))
    part = smtp_part(page)
    assert 'data-rule="F05.01"' in part and "Impossible à confirmer" in part
    assert "Sonde SMTP désactivée sur cette instance." in part and "<table" not in part
    assert "ne prouve pas que d&#39;autres expéditeurs le joignent" in part


# ------------------------------------------------------------------ the five states of readiness (F06)
@pytest.mark.parametrize(("data", "state", "label"), [
    (world({MX1: {V4: "tls_verified"}}, policy="testing"), "ready",
     "Prêt selon les mesures réalisées depuis cette instance"),
    (world({MX1: {V4: "tls_verified"}}), "compatible", "Compatible avec la politique enforce en vigueur"),
    (world({MX1: {V4: "starttls_absent"}}), "to_fix", "À corriger"),
    (world({MX1: {V4: "tls_verified"}}, policy=None), "unconfirmed", "Impossible à confirmer"),
    (changed(healthy(), dns={f"{DOMAIN} MX": ["0 ."]}), "not_applicable", "Sans objet")])
def test_the_five_states_of_readiness(instance, data, state, label):
    """F06: the five states, in the words of the catalogue of PR-C, apart from the verdict; an OK never shows
    "ready" by itself (the unconfirmed case is OK); the scope sentence is always there."""
    part = smtp_part(instance().scan(data))
    assert f'smtp-ready-{state}">{label}</span>' in part
    assert "garantie de livraison depuis Internet" in part


# ------------------------------------------------------------------ rows, causes and certificates (P1)
def test_partial_ok_shows_the_untested_address_and_its_cause(instance):
    """F05.09, A2b, T03: the IPv4 address verified, the IPv6 one without route: two rows, the IPv6 address whole,
    its own cause, the coverage note; readiness unconfirmed."""
    page = instance().scan(world({MX1: {V4: "tls_verified", V6: "no_ipv6"}}))
    assert [r.split(" ")[3] for r in rows(page)] == [V4, V6]
    assert "Non joignable depuis ce réseau (aucune route)" in rows(page)[1]
    assert "Impossible à confirmer" in smtp_part(page)
    summary = page[page.index(f'id="{CHECK}"'):page.index('class="smtp"')]
    assert "Mesure partielle" in summary and "1 adresse non testée" in summary  # the notes, once, in the text


def test_a_refused_certificate_and_its_diagnostic_reading(instance):
    """F03, F05.04, R4: the refusal in the words of the verification, then the diagnostic reading said "not
    verified", with the names and the issuer it read."""
    page = instance().scan(world({MX1: {V4: {"verify": {"reason": "certificate_refused", "verify_code": 62,
                                                         "verify_message": "Hostname mismatch"},
                                              "read_certificate": "tls_unverified"}}}))
    row = rows(page)[0]
    assert "Refusé : Hostname mismatch (code 62)" in row and "Lecture diagnostique, non vérifiée :" in row
    assert "Vérifié" not in row.split("Lecture diagnostique")[0].replace("certificat refusé", "")


def test_each_mx_shows_its_own_cause_from_silent_mx(instance):
    """F05.08, F01 (P1 of PR-D): an invalid MX name and a valid MX that times out: each row gives the cause of
    its own MX, never the global cause of F05.08 on every server."""
    data = changed(world({MX2: {V4B: "timeout"}}), dns={f"{DOMAIN} MX": ["10 bad_name!.example.", f"20 {MX2}."]})
    page = instance().scan(data)
    invalid, timed_out = rows(page)
    assert invalid.startswith("bad_name!.example priorité 10") and "Nom de MX invalide : non testé" in invalid
    assert timed_out.startswith(f"{MX2} priorité 20 {V4B}") and "Port 25 inaccessible ou délai dépassé" in timed_out
    assert "Nom de MX invalide" not in timed_out and "Port 25" not in invalid


@pytest.mark.parametrize(("data", "expected"), [
    (world({MX1: {V4: "tls_verified"}}, **{f"{MX1} CNAME": ["mail.provider.example."]}),
     "alias de mail.provider.example"),
    (world({MX1: {V4: "esmtp_altered"}}), "Capacités SMTP altérées sur le trajet (XXXXXXXA)"),
    (world({MX1: {V4: "deadline@banner"}}), "Échéance de la mesure atteinte"),
    (world({f"mx{i}.example.net": {f"192.0.2.{30 + i}": "tls_verified"} for i in range(10)}),
     "Hors de l'échantillon testé")])
def test_cname_inspection_deadline_and_sample(instance, data, expected):
    """F05.12, F05.08, F05.11, F04, T03: an MX that is an alias, keywords masked on the path, the deadline, MX beyond
    the sample of 8: each shown in the row of its MX, the limits of the measure under the table."""
    page = instance().scan(data)
    assert any(expected in r for r in rows(page)), rows(page)
    assert "Limites de la mesure" in smtp_part(page)


def test_english_texts(instance):
    """Q03, F06: the same page in English."""
    part = smtp_part(instance(lang="en").scan(world({MX1: {V4: "tls_verified", V6: "no_ipv6"}})))
    assert "Results by server and address" in part and "Not reachable from this network (no route)" in part
    assert "Cannot be confirmed" in part and "no guarantee of delivery from the Internet" in part


def test_a_recheck_shows_the_new_measure(instance):
    """R6, F05.03, F05.10: a recheck of the SMTP check (after a fix) shows the new measure in the details, said
    rechecked; the scan keeps its first measure in its history."""
    i = instance()
    i.scan(world({MX1: {V4: "starttls_absent"}}))
    i.data.update(world({MX1: {V4: "tls_verified"}}))
    post(i.client, f"/domains/{DOMAIN}/verify/{CHECK}", f"/domains/{DOMAIN}?task={CHECK}")
    page = i.client.get(f"/domains/{DOMAIN}/details").text
    title = page[page.index(f'id="{CHECK}"'):page.index('class="smtp"')]
    assert 'data-rule="F05.10"' in smtp_part(page) and "revérifié le" in title
    scan_id = i.scans.latest_id(i.scans.domain(DOMAIN)["id"])
    stored = i.scans.db.one("SELECT outcome FROM findings WHERE scan_id=? AND check_id=?", (scan_id, CHECK))
    assert json.loads(stored["outcome"])["evidence"]["rule"] == "F05.03"


# ------------------------------------------------------------------ history: rechecks, engine, scope, unknown (P3)
def result(data: dict, probe: bool, internal: bool = False):
    net = FixtureNetwork(data, domain=DOMAIN, ehlo_name=EHLO if probe else None)
    return asyncio.run(engine.scan(DOMAIN, Registry.discover().checks(), net, timeout=5, internal=internal,
                                   smtp=SmtpSettings(probe, EHLO if probe else None)))


def test_history_and_mission_control_say_scope_and_unknown(instance, monkeypatch):
    """R5, T08 (P3 of PR-D): probe off then on: the history and Mission Control say the scope changed; after an
    error of the engine on the SMTP check, they say the scope is unknown: no regression nor resolution shown;
    an earlier scan's details are shown as stored, whatever the configuration now."""
    i = instance()
    i.scan(world({MX1: {V4: "tls_verified"}}))
    domain_id = i.scans.domain(DOMAIN)["id"]
    i.scans.save(domain_id, result(world({MX1: {V4: "tls_verified"}}), probe=False), "0.7.0", None)
    history = i.client.get(f"/domains/{DOMAIN}/history").text
    assert "portée de mesure différente (sonde SMTP activée ou désactivée)" in history
    assert "La portée de mesure a changé" in i.client.get(f"/domains/{DOMAIN}/mission-control").text
    from posture_cockpit.checks import smtp_verdict

    def broken(*args, **kwargs):
        raise RuntimeError("broken verdict")

    monkeypatch.setattr(smtp_verdict, "decide", broken)
    i.scans.save(domain_id, result(world({MX1: {V4: "tls_verified"}}), probe=True), "0.7.0", None)
    history = i.client.get(f"/domains/{DOMAIN}/history").text
    assert "portée de mesure inconnue (erreur du moteur sur le contrôle SMTP)" in history
    mc = i.client.get(f"/domains/{DOMAIN}/mission-control").text
    assert "erreur du moteur" in mc and "les événements ouverts restent ouverts" in mc
    first = min(r["id"] for r in i.scans.history(domain_id))
    assert 'data-rule="F05.10"' in i.client.get(f"/domains/{DOMAIN}/history/{first}").text  # as stored


def test_an_engine_error_shows_the_finding_without_an_smtp_block(instance, monkeypatch):
    """F05.08, R5: an error of the engine on the check: the finding shows its error as any check does, no SMTP
    block is made up from nothing."""
    from posture_cockpit.checks import smtp_verdict

    monkeypatch.setattr(smtp_verdict, "decide", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    page = instance().scan(world({MX1: {V4: "tls_verified"}}))
    assert smtp_part(page) == "" and re.search(rf'id="{CHECK}".*?badge-error', page, re.S)


# ------------------------------------------------------------------ hostile and very long contents
HOSTILE = '<script>alert("smtp")</script><img src=x onerror=alert(1)>'


def test_hostile_and_long_contents_are_text_in_the_page_and_the_pdf(instance):
    """F07, S05 (rendering): a banner, certificate names and a verification message from the network that hold
    HTML, or are very long, are shown as escaped text, bounded, in the details and in the PDF; nothing of them
    becomes markup."""
    i = instance()
    i.scan(world({MX1: {V4: "certificate_refused"}}))
    scan_id = i.scans.latest_id(i.scans.domain(DOMAIN)["id"])
    row = i.scans.db.one("SELECT outcome FROM findings WHERE scan_id=? AND check_id=?", (scan_id, CHECK))
    outcome = json.loads(row["outcome"])
    dialogue = outcome["evidence"]["mx"][0]["addresses"][0]["observations"][0]["dialogue"]
    dialogue["banner"]["text"] = [HOSTILE + "A" * 5000]
    dialogue["verify_message"] = HOSTILE
    i.scans.db.execute("UPDATE findings SET outcome=? WHERE scan_id=? AND check_id=?",
                       (json.dumps(outcome), scan_id, CHECK))
    page = i.client.get(f"/domains/{DOMAIN}/details").text
    part = smtp_part(page)
    assert "<script>alert" not in page and "<img src=x" not in part
    assert "&lt;script&gt;alert(&#34;smtp&#34;)&lt;/script&gt;" in part
    assert max(len(m) for m in re.findall(r'<code class="smtp-banner">(.*?)</code>', part, re.S)) < 400
    html = render_html(i.app.state.services.catalog, "fr", i.scans.get(scan_id))
    assert "<script>alert" not in html and "&lt;script&gt;" in html


# ------------------------------------------------------------------ the PDF (annex)
def test_the_pdf_annex_shows_the_rows_and_whole_ipv6_addresses(instance):
    """F06, Q03, T05: the annex of the PDF has the SMTP table, the readiness and its limit; the IPv6 address is
    whole, in a cell that never wraps it, and no row of the table is split across two pages."""
    weasyprint = pytest.importorskip("weasyprint")
    i = instance()
    i.scan(world({MX1: {V4: "tls_verified", V6: "no_ipv6"}, MX2: {V4B: "tls_verified"}}))
    scan = i.scans.get(i.scans.latest_id(i.scans.domain(DOMAIN)["id"]))
    html = render_html(i.app.state.services.catalog, "fr", scan)
    annex = html[html.index('class="smtp-annex"'):]
    assert "Messagerie : STARTTLS des serveurs de réception" in annex and V6 in annex
    assert "Préparation au mode enforce" in annex and "garantie de livraison" in annex
    from posture_cockpit.report import REPORT_DIR

    document = weasyprint.HTML(string=html, base_url=str(REPORT_DIR)).render()
    text = [box.text for page in document.pages for box in _texts(page._page_box)]
    assert V6 in text  # the cell of the table: the address in one line, never cut


def _texts(box):
    if getattr(box, "text", None):
        yield box
    for child in getattr(box, "children", []):
        yield from _texts(child)


def test_old_scans_and_the_probe_off_have_no_smtp_annex(instance):
    """T05, F05.01: a scan without the SMTP check (before 0.7) and a scan with the probe off: no SMTP annex."""
    i = instance(probe=False)
    i.scan(world({MX1: {V4: "tls_verified"}}))
    scan_id = i.scans.latest_id(i.scans.domain(DOMAIN)["id"])
    assert 'class="smtp-annex"' not in render_html(i.app.state.services.catalog, "fr", i.scans.get(scan_id))
    i.scans.db.execute("DELETE FROM findings WHERE scan_id=? AND check_id=?", (scan_id, CHECK))
    assert 'class="smtp-annex"' not in render_html(i.app.state.services.catalog, "fr", i.scans.get(scan_id))


# ------------------------------------------------------------------ the API (P4)
def api(i: Instance) -> dict:
    return _summary(i.scans.get(i.scans.latest_id(i.scans.domain(DOMAIN)["id"])))


def test_api_probe_on_off_and_engine_error(instance, monkeypatch):
    """P4 of PR-D, R5, F06: the two objects added to the API, read from the stored result: probe on (scope "on",
    the rule, the counts, the readiness), probe off ("off", F05.01, readiness unconfirmed probe_off, no policy),
    an error of the engine ("unknown", status error, rule and readiness null); no other field changes."""
    on = instance()
    on.scan(world({MX1: {V4: "tls_verified", V6: "no_ipv6"}}))
    assert api(on)["smtp_probe"] == {"scope": "on", "status": "ok", "rule": "F05.09", "mx": 1, "addresses": 2,
                                     "verified": 1}
    assert api(on)["mail_enforce_readiness"] == {"state": "unconfirmed", "causes": ["incomplete"], "policy": "enforce"}
    off = instance(probe=False)
    off.scan(world({MX1: {V4: "tls_verified"}}))
    assert api(off)["smtp_probe"] == {"scope": "off", "status": "na", "rule": "F05.01", "mx": None, "addresses": None,
                                      "verified": None}
    assert api(off)["mail_enforce_readiness"] == {"state": "unconfirmed", "causes": ["probe_off"], "policy": None}
    from posture_cockpit.checks import smtp_verdict

    monkeypatch.setattr(smtp_verdict, "decide", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    broken = instance()
    broken.scan(world({MX1: {V4: "tls_verified"}}))
    assert api(broken)["smtp_probe"] == {"scope": "unknown", "status": "error", "rule": None, "mx": None,
                                         "addresses": None, "verified": None}
    assert api(broken)["mail_enforce_readiness"] == {"state": None, "causes": [], "policy": None}
    assert set(api(on)) == set(api(off)) == set(api(broken))


def test_api_internal_scan_is_internal_never_off(instance):
    """P4 of PR-D, S05, R5: a scan of an internal perimeter: scope "internal", the check NA from the engine,
    no readiness; never confused with "off" or "absent"."""
    i = instance()
    i.scan(world({MX1: {V4: "tls_verified"}}))
    domain_id = i.scans.domain(DOMAIN)["id"]
    scan_id = i.scans.save(domain_id, result(world({MX1: {V4: "tls_verified"}}), probe=True, internal=True),
                           "0.7.0", None, perimeter="lab")
    summary = _summary(i.scans.get(scan_id))
    assert summary["smtp_probe"] == {"scope": "internal", "status": "na", "rule": None, "mx": None,
                                     "addresses": None, "verified": None}
    assert summary["mail_enforce_readiness"] == {"state": None, "causes": [], "policy": None}


def test_the_view_is_none_without_a_structured_result():
    """F05.08, R5 (P1): an evidence without the structured result (an engine error, or nothing) gives no view."""
    assert view(None, lambda k, **p: k) is None and view({"error": "boom"}, lambda k, **p: k) is None
