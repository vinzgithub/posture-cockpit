# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.4.1, counter-review point 6: the HTTPS wordings on representative results, in both languages,
on the pages and in the PDF report, as the 0.4 arbitrations wrote them."""

import html
import json
import re

import pytest

from helpers import post, setup_account
from https_worlds import OBSOLETE, OK, REFUSED, TIMEOUT, V4A, V4B, V6A, site
from posture_cockpit.report import render_html
from worlds import DOMAIN, http_only_with_redirect_elsewhere

WORLDS = {
    "blocked": site({V4A: REFUSED}),
    "undetermined": site({V4A: REFUSED, V6A: TIMEOUT}),
    "partial": site({V4A: REFUSED, V4B: OK}),
    "obsolete": site({V4A: OBSOLETE}),
    "elsewhere": http_only_with_redirect_elsewhere(),
    "healthy": site({V4A: OK}),
}
ARBITRATED = {
    "blocked": {"fr": "Bloqué — dépend de : Redirection HTTPS (refus observé)",
                "en": "Blocked — depends on: HTTPS redirection (observed refusal)"},
    "undetermined": {"fr": "l’accessibilité HTTPS n’est pas établie (1 adresse non concluante)",
                     "en": "HTTPS availability is undetermined (1 inconclusive address)"},
}
RAW_KEY = re.compile(r"\b(?:web|tls|mail|dns|check|v04|report|score|plan|details)\.[a-z_]+\.[a-z0-9_.]+\b")


def visible(page: str) -> str:
    """The text a reader sees, without the raw values a technician unfolds (<pre> blocks)."""
    page = re.sub(r"<(script|style|svg|pre)[^>]*>.*?</\1>", " ", page, flags=re.S)
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


@pytest.mark.parametrize("lang", ["fr", "en"])
@pytest.mark.parametrize("case", list(WORLDS))
def test_https_wordings_on_representative_results(client, world, case, lang):
    setup_account(client, lang=lang)
    domain = f"{case}.example"
    world[domain] = json.loads(json.dumps(WORLDS[case]).replace(DOMAIN, domain))
    assert post(client, "/domains", domain=domain).status_code == 303
    services = client.app.state.services
    scan = services.scans.latest(services.scans.domain(domain)["id"])
    texts = {
        "plan": visible(client.get(f"/domains/{domain}").text),
        "details": visible(client.get(f"/domains/{domain}/details").text),
        "pdf": visible(render_html(services.catalog, lang, scan)),
    }
    scoring_coverage = "Couverture de notation" if lang == "fr" else "Scoring coverage"
    for where, text in texts.items():
        assert not RAW_KEY.findall(text), (where, RAW_KEY.findall(text)[:3])
        assert "None" not in text, where
        # the status is said once: no "Not evaluated: ..." repeated in the reason of a dependent
        assert not re.search(r"Non évalué\s*:\s*ce point|Not evaluated:\s*this depends", text), where
        if where != "pdf":
            assert text.count(scoring_coverage) == 1, where
        if case in ARBITRATED and (where != "pdf" or case == "undetermined"):
            assert ARBITRATED[case][lang] in text, (where, case)
    root = next(f for f in scan.current() if f.check_id == "web.https_redirect")
    for note in root.outcome.evidence.get("notes", []):
        if note["key"].startswith("web.https_redirect.attribution."):
            # spec 0.4 section 7: the text always starts with the observation
            start = "Depuis l'analyseur, HTTPS de" if lang == "fr" else "From the scanner, HTTPS on"
            assert services.catalog.text(lang, note["key"], {"host": domain, "address": "x", "other": "y"}).startswith(
                start)
