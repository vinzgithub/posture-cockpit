# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The PDF report keeps its time and its layout whatever the length of a list from the DNS (v0.7.0).

After the merge of PR-D, a domain publishing hundreds of MX made the report take minutes: the text of
a finding that lists them sat in a table cell that could break anywhere, and WeasyPrint measured it
character by character, again and again, to size its column (R2 had let these cells break anywhere).
The tables of the report now take the widths of their columns from their first row (table-layout:
fixed), their cells break only a word too long for its line, and the body of a recommendation is never
measured to size itself: the text laid out is measured once, line by line.

What is checked here, without depending on the speed of a machine: the text WeasyPrint measures to
size boxes stays of the order of the text the report shows (it grew with the square of a list); the
time of a report of 300 MX stays of the order of an ordinary one, measured in the same run; the
columns keep the widths the automatic layout gave them; every status pill fits its column; no text
runs past the page or out of its cell; a row is split only when it cannot fit on one page.
"""

import json
import time
from pathlib import Path

import pytest

from test_v070_smtp_display import (
    DOMAIN,
    MX1,
    V4,
    Instance,
    _texts,
    changed,
    long_names,
    past_margin,
    split_rows,
    world,
)

weasyprint = pytest.importorskip("weasyprint")

from posture_cockpit.report import REPORT_DIR, render_html  # noqa: E402

LOCALES = Path(__file__).parent.parent / "src" / "posture_cockpit" / "locales"


def invalid_mx(n: int) -> dict:
    """The healthy world, with ``n`` invalid MX names before its MX: lists of ``n`` names in the texts."""
    return changed(world({MX1: {V4: "tls_verified"}}),
                   dns={f"{DOMAIN} MX": [f"{i} x{i}_.example." for i in range(1, n + 1)] + [f"60000 {MX1}."]})


def addresses(n: int) -> dict:
    """The healthy world, its MX with ``n`` IPv4 addresses: a row each in the SMTP annex, a list in a note."""
    more = [f"198.{18 + i // 65536}.{i // 256 % 256}.{i % 256}" for i in range(n - 1)]
    return changed(world({MX1: {V4: "tls_verified"}}), dns={f"{MX1} A": [V4, *more]})


@pytest.fixture
def report(tmp_path):
    """The HTML of the report of a world, scanned by an instance with the probe on (or off), in a language."""
    made = []

    def make(data: dict, probe: bool = True, lang: str = "fr") -> str:
        directory = tmp_path / f"instance-{len(made)}"
        directory.mkdir()
        instance = Instance(directory, probe=probe, lang=lang)
        made.append(instance)
        instance.scan(data)
        scan = instance.scans.get(instance.scans.latest_id(instance.scans.domain(DOMAIN)["id"]))
        return render_html(instance.app.state.services.catalog, lang, scan)

    yield make
    for instance in made:
        instance.close()


def layout(html: str):
    return weasyprint.HTML(string=html, base_url=str(REPORT_DIR)).render()


def measured_while(html: str, monkeypatch) -> int:
    """The characters WeasyPrint measures to size boxes (their preferred widths) while laying out ``html``."""
    from weasyprint.layout import preferred

    if not hasattr(preferred, "split_first_line"):
        pytest.skip("this WeasyPrint measures preferred widths elsewhere: the probe of this test is to move")
    split, counted = preferred.split_first_line, [0]

    def counting(text, *args, **kwargs):
        counted[0] += len(text)
        return split(text, *args, **kwargs)

    monkeypatch.setattr(preferred, "split_first_line", counting)
    layout(html)
    monkeypatch.setattr(preferred, "split_first_line", split)
    return counted[0]


def shown(document) -> int:
    return sum(len(box.text) for page in document.pages for box in _texts(page._page_box))


@pytest.mark.parametrize("data", [invalid_mx(160), addresses(200)], ids=["160 MX", "200 addresses"])
def test_the_layout_measures_about_the_text_it_shows(report, monkeypatch, data):
    """T05, review of the merge of PR-D: the text measured to size boxes stays of the order of the text shown
    (at most three times; it was 469 times for 160 MX after R2, 55 times before it, and grew with the square of
    the list), so that the time of a report follows its length. Counted, not timed: the same on every machine."""
    html = report(data)
    document = layout(html)
    assert measured_while(html, monkeypatch) <= 3 * shown(document)


def test_a_report_of_300_mx_takes_about_the_time_of_an_ordinary_one(report):
    """T05, review of the merge of PR-D: the same comparison in time, both reports made in this run on this
    machine, the best of two each: 300 MX cost about twice an ordinary report (they cost a hundred times)."""
    ordinary, large = report(world({MX1: {V4: "tls_verified"}})), report(invalid_mx(300))
    layout(ordinary)  # the fonts, loaded once

    def best(html: str) -> float:
        times = []
        for _ in range(2):
            start = time.perf_counter()
            layout(html)
            times.append(time.perf_counter() - start)
        return min(times)

    assert best(large) <= 12 * best(ordinary)


def columns(document, name: str) -> list[float]:
    """The widths of the cells of the first body row of the table of class ``name`` (border boxes)."""
    for page in document.pages:
        found = _find(page._page_box, name)
        if found is not None:
            body = next(g for g in found.children if not getattr(g, "is_header", False))
            return [cell.border_width() for cell in body.children[0].children]
    raise AssertionError(f"no table {name}")


def _find(box, name: str):
    element = getattr(box, "element", None)
    if type(box).__name__ == "TableBox" and element is not None and element.get("class") == name:
        return box
    for child in getattr(box, "children", []):
        found = _find(child, name)
        if found is not None:
            return found
    return None


@pytest.mark.parametrize(("probe", "lang"), [(False, "fr"), (True, "fr"), (False, "en"), (True, "en")])
def test_the_tables_keep_their_columns(report, probe, lang):
    """The columns of the summary by area (28 %, the score, the bar, the comment) and of the annex of the
    checks (34 %, the result, the finding) are those the automatic layout gave the report of a domain whose
    probe is off: the result column, 15.81 %, is the width it took for its longest pill, "Non applicable"."""
    document = layout(report(world({MX1: {V4: "tls_verified"}}), probe=probe, lang=lang))
    areas, checks = columns(document, "areas"), columns(document, "checks")
    width = sum(checks)
    assert checks == pytest.approx([0.34 * width, 0.1581 * width, (1 - 0.34 - 0.1581) * width], abs=0.05)
    assert checks == pytest.approx([218.46, 101.58, 322.48], abs=0.05)  # as the automatic layout gave them
    assert areas == pytest.approx([179.91, 50.67, 176.0, 235.95], abs=0.05)


def test_every_status_pill_fits_its_column():
    """No pill of a status, in French or English, runs past the content of the result column, now fixed."""
    css = (REPORT_DIR / "report.css").read_text()
    labels = sorted({value for lang in ("fr", "en")
                     for key, value in json.loads((LOCALES / f"{lang}.json").read_text()).items()
                     if key.startswith("status.") and key.count(".") == 1})
    rows = "".join(f'<tr><td>x</td><td><span class="pill pill-na">{label}</span></td><td>y</td></tr>'
                   for label in labels)
    document = layout(f'<style>{css}</style><section class="sheet"><table class="checks"><thead><tr><th>a</th>'
                      f'<th>b</th><th>c</th></tr></thead><tbody>{rows}</tbody></table></section>')
    pills = []

    def walk(box, cell=None):
        cell = box if type(box).__name__ == "TableCellBox" else cell
        if cell is not None and type(box).__name__ == "InlineBlockBox":
            pills.append(box.position_x + box.margin_width() - (cell.content_box_x() + cell.width))
        for child in getattr(box, "children", []):
            walk(child, cell)

    for page in document.pages:
        walk(page._page_box)
    assert len(pills) == len(labels) >= 12 and max(pills) <= 0.01


def out_of_cells(document) -> float:
    """How far a box inside a cell of a table of the report runs past the content of its cell, at worst."""
    worst = 0.0

    def inside(box, right):
        nonlocal worst
        for child in getattr(box, "children", []):
            if type(child).__name__ != "LineBox":
                worst = max(worst, child.position_x + child.margin_width() - right)
            inside(child, right)

    def walk(box):
        if type(box).__name__ == "TableCellBox":
            inside(box, box.content_box_x() + box.width)
            return
        for child in getattr(box, "children", []):
            walk(child)

    for page in document.pages:
        walk(page._page_box)
    return worst


def rows_split_without_need(document) -> list[float]:
    """The heights of the rows laid out on several pages although a page could hold them (a row longer than a
    page has to be split; any other must keep to one page)."""
    fragments: dict[int, list[float]] = {}
    room = 0.0

    def walk(box):
        if getattr(box, "is_header", False):
            return
        if type(box).__name__ == "TableRowBox":
            fragments.setdefault(id(box.element), []).append(box.margin_height())
        for child in getattr(box, "children", []):
            walk(child)

    for page in document.pages:
        room = max(room, page._page_box.height)
        walk(page._page_box)
    return [sum(parts) for parts in fragments.values() if len(parts) > 1 and sum(parts) < room]


@pytest.mark.parametrize("data", [invalid_mx(300), long_names()], ids=["300 MX", "long names"])
def test_long_lists_keep_to_the_page_and_to_their_cells(report, data):
    """T05, R2 kept: with 300 MX or names of 200 characters, nothing runs past the page nor out of its cell; a
    row of a table is split only when it is longer than a page; no row of the SMTP annex is ever split."""
    document = layout(report(data))
    assert past_margin(document) <= 0.5
    assert out_of_cells(document) <= 0.5
    assert rows_split_without_need(document) == []
    assert split_rows(document) == []


def test_the_tls_line_stays_whole_beside_long_certificate_names(report):
    """R2 kept, T05: only the lines of a certificate with a long name may break anywhere; the line of the TLS
    version and cipher beside them never does."""
    document = layout(report(long_names()))
    text = [box.text for page in document.pages for box in _texts(page._page_box)]
    assert any("TLS_AES_256_GCM_SHA384" in line for line in text)
