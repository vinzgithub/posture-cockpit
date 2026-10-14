# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Page layout of the PDF report: no heading left alone at the bottom of a page.

The checks read WeasyPrint's layout (pages and their boxes), which is what ends up in the PDF.
"""

import pytest
from fastapi.testclient import TestClient

from posture_cockpit.config import Config
from posture_cockpit.core import scoring
from posture_cockpit.report import REPORT_DIR, _env, report_context
from posture_cockpit.storage import Scan
from posture_cockpit.web.app import create_app
from worlds import DOMAIN, healthy, http_only_with_redirect_elsewhere, run

weasyprint = pytest.importorskip("weasyprint")
HEADINGS = {"section-label", "annex-title"}


@pytest.fixture(scope="module")
def catalog(tmp_path_factory):
    """Interface and check texts, as the application has them."""
    with TestClient(create_app(Config(data_dir=tmp_path_factory.mktemp("data")))) as client:
        return client.app.state.services.catalog


def _scan(world) -> Scan:
    findings = list(run(world).values())
    a = scoring.assess(findings)
    return Scan(20, 1, DOMAIN, "2026-10-13T07:19:05+00:00", 3000, a.score, a.grade, a.coverage, "0.2.0", "",
                findings, {})


def _layout(context):
    html = _env.get_template("report.html").render(**context)
    return weasyprint.HTML(string=html, base_url=str(REPORT_DIR)).render()


def _boxes(box):
    yield box
    for child in getattr(box, "children", []):
        yield from _boxes(child)


def _classes(box) -> set[str]:
    element = getattr(box, "element", None)
    return set((element.get("class") or "").split()) if element is not None else set()


def lonely_headings(document) -> list[tuple[int, str]]:
    """(page, heading text) for each page whose content ends with a heading."""
    found = []
    for number, page in enumerate(document.pages, 1):
        for box in _boxes(page._page_box):
            element = getattr(box, "element", None)
            if element is None or element.tag != "section" or not box.children:
                continue
            last = box.children[-1]
            if _classes(last) & HEADINGS or getattr(last, "element_tag", "") == "h2":
                found.append((number, "".join(last.element.itertext()).strip()))
    return found


def _pages_of(document, css_class: str) -> list[int]:
    return [n for n, page in enumerate(document.pages, 1)
            for box in _boxes(page._page_box) if css_class in _classes(box) and box.children]


def test_the_method_is_no_longer_cut_from_its_heading(catalog):
    """The report of fournet.one on 13 October 2026 ended page 2 with the heading "MÉTHODE",
    its text alone on an almost empty page 3."""
    document = _layout(report_context(catalog, "fr", _scan(http_only_with_redirect_elsewhere())))
    assert lonely_headings(document) == []
    method_heading = [n for n, page in enumerate(document.pages, 1) for box in _boxes(page._page_box)
                      if "section-label" in _classes(box)
                      and "".join(box.element.itertext()).strip() == catalog.text("fr", "report.method")]
    assert method_heading and set(method_heading) == set(_pages_of(document, "method"))
    # The annex follows on the same page instead of leaving most of it blank.
    assert _pages_of(document, "annex-title")[0] == method_heading[0]


def test_no_page_ends_with_a_heading_whatever_the_length(catalog):
    """Reports of several lengths: the headings must always open their section."""
    base = report_context(catalog, "fr", _scan(http_only_with_redirect_elsewhere()))
    gaps = base["gaps"] * 3
    contexts = [report_context(catalog, "en", _scan(healthy()))]                  # all compliant, short
    contexts += [{**base, "gaps": gaps[:n]} for n in (0, 6, 16, 24)]              # more or fewer open points
    contexts.append({**base, "gaps": gaps, "improvements": base["improvements"] * 6,
                     "annex": base["annex"] * 6})                                  # a long file
    lengths = []
    for context in contexts:
        document = _layout(context)
        assert lonely_headings(document) == [], len(document.pages)
        lengths.append(len(document.pages))
    assert min(lengths) <= 3 and max(lengths) >= 10  # from a short file to a long one


@pytest.mark.parametrize("language", ["fr", "en"])
def test_partial_pdf_projection_is_conditional(catalog, language):
    context = report_context(catalog, language, _scan(http_only_with_redirect_elsewhere()))
    assert context["result"].partial
    assert context["result"].coverage_percent < 90
    assert context["conclusion"]
    assert ("confirmer" in context["conclusion"] if language == "fr"
            else "confirmed" in context["conclusion"])
    assert str(context["result"].coverage_percent) in context["conclusion"]


@pytest.mark.parametrize("language", ["fr", "en"])
def test_unscored_web_area_preserves_critical_finding(catalog, language):
    context = report_context(catalog, language, _scan(http_only_with_redirect_elsewhere()))
    web_findings = [f for f in context["scan"].current() if f.category == "web"]
    assert any(f.status.value == "fail" for f in web_findings)
    web_area = next(c for c in context["categories"] if c["label"] == catalog.text(language, "category.web"))
    assert web_area["score"] is None
    assert ("Défaut détecté" in web_area["comment"] if language == "fr"
            else "Detected issue" in web_area["comment"])
    assert ("renvoie vers un site HTTPS extérieur" in web_area["comment"] if language == "fr"
            else "redirect" in web_area["comment"].lower())


@pytest.mark.parametrize(("n", "expected"), [(1, "Après 1 correction"), (2, "Après 2 corrections")])
def test_partial_projection_french_agreement(catalog, n, expected):
    sentence = catalog.text("fr", "report.diagnosis.plan_partial",
                            {"n": n, "minutes": 15 * n, "grade": "B", "coverage": 54})
    assert expected in sentence
    assert "la note B pourrait être atteinte" in sentence
    assert "1 pourrait" not in sentence and "2 pourraient" not in sentence
