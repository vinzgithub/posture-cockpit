# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The bounded evidence of mail.smtp_starttls on the details page, in Chromium (version 0.7.0, correction 2).

Two instances of their own, with the probe on, scan an MX that publishes 4,000 addresses: the first stores
the evidence bounded, as the check does now; the second stores it as 0042c80 did, before the bounding (631
KiB). On a desktop and on a phone: the page never scrolls sideways; the table lists the twenty addresses kept
and says the others in one row; the JSON panel holds what the page was given, within 64 KiB; for the older
evidence, the page says it is shown bounded, and its link gives the original, byte for byte, as a file.
"""

import json
from pathlib import Path

import pytest
from test_smtp_details import serve

from helpers import PASSWORD
from posture_cockpit.checks import smtp_evidence
from smtp_reference import large
from test_v070_smtp_evidence_bounds import older
from worlds import DOMAIN

FOUR_THOUSAND = {name: world for name, world, _ in large()}["4,000 addresses on one MX"]
CHECK = "mail.smtp_starttls"


@pytest.fixture(scope="module")
def bounded_port(tmp_path_factory):
    number, server = serve(tmp_path_factory.mktemp("bounded"), FOUR_THOUSAND)
    yield number
    server.should_exit = True


@pytest.fixture(scope="module")
def older_port(tmp_path_factory):
    with pytest.MonkeyPatch.context() as patch:  # the evidence as 0042c80 stored it
        patch.setattr(smtp_evidence, "bound", older)
        patch.setattr(smtp_evidence, "listed", lambda items, most=8: (", ".join(items), 0))
        number, server = serve(tmp_path_factory.mktemp("older"), FOUR_THOUSAND)
    yield number
    server.should_exit = True


@pytest.fixture
def details(browser, playwright, bounded_port, older_port):
    contexts = []

    def open_page(port, device=None):
        options = dict(playwright.devices[device]) if device else {}
        context = browser.new_context(base_url=f"http://127.0.0.1:{port}", accept_downloads=True, **options)
        contexts.append(context)
        page = context.new_page()
        page.goto("/login")
        page.fill("input[name=username]", "vincent")
        page.fill("input[name=password]", PASSWORD)
        page.click("form[action='/login'] button[type=submit]")
        page.wait_for_url("**/domains")
        page.goto(f"/domains/{DOMAIN}/details")
        return page

    yield open_page
    for context in contexts:
        context.close()


@pytest.mark.parametrize("device", [None, "iPhone 13"])
@pytest.mark.parametrize("which", ["bounded", "older"])
def test_four_thousand_addresses_on_a_page(details, bounded_port, older_port, which, device):
    """F05.09, T05, S05 (correction 2, A3 A5 A7): the twenty addresses kept, then one row for the 3,980 others,
    never as measured; the counts of the measure; the page never wider than the screen; the JSON panel within
    64 KiB; an older evidence says it is shown bounded."""
    page = details(bounded_port if which == "bounded" else older_port, device)
    assert page.evaluate("document.scrollingElement.scrollWidth <= window.innerWidth + 1")
    block = page.locator(".smtp")
    rows = block.locator("tbody tr")
    assert rows.count() == 21 and block.locator("tbody tr.smtp-left_out").count() == 1
    assert "3980 adresses publiées, non tentées, ne sont pas reprises dans ce tableau." in rows.nth(20).inner_text()
    counts = block.locator(".smtp-counts").inner_text()
    assert "4000 découvertes, 16 tentées dont 1 avec un résultat concluant" in counts
    if device is None:
        assert block.locator(".table-scroll").evaluate("e => e.scrollWidth <= e.clientWidth")
    smtp = page.locator("li#mail\\.smtp_starttls")
    smtp.locator("details summary").click()
    panel = json.loads(smtp.locator("pre.evidence").inner_text())
    assert smtp_evidence.size(panel) <= smtp_evidence.LIMIT_BYTES
    assert (panel["bounds"].get("source") == "display") is (which == "older")
    assert (block.locator(".smtp-display").count() == 1) is (which == "older")


def test_the_original_of_an_older_evidence_is_a_file(details, older_port):
    """S05, R5 (correction 2, A7): the link of an older evidence downloads its original, as the database keeps
    it, byte for byte: a JSON file, never a page."""
    page = details(older_port)
    smtp = page.locator("li#mail\\.smtp_starttls")
    smtp.locator("details summary").click()
    with page.expect_download() as download:
        smtp.locator(".evidence-original a").click()
    file = download.value
    assert file.suggested_filename.startswith(f"posture-{DOMAIN}-scan-") and file.suggested_filename.endswith(
        f"-{CHECK}.json")
    original = json.loads(Path(file.path()).read_bytes())
    assert smtp_evidence.size(original) > 600_000 and "counts" not in original and len(
        original["mx"][0]["addresses"]) == 4000
