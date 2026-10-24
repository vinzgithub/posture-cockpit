# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A portfolio can be filtered and paginated with native controls and no JS."""
import pytest
from playwright.sync_api import expect

from helpers import DEMO, PASSWORD


@pytest.mark.parametrize(("width", "language", "scheme"), [(1280, "fr", "light"), (390, "fr", "dark"),
                                                         (1280, "en", "dark"), (390, "en", "light")])
def test_portfolio_filters_pagination_and_domain_link_without_js(browser, port, width, language, scheme):
    context = browser.new_context(base_url=f"http://127.0.0.1:{port}", java_script_enabled=False,
                                  viewport={"width": width, "height": 900}, color_scheme=scheme)
    page = context.new_page()
    page.goto("/login")
    page.fill("input[name=username]", "vincent")
    page.fill("input[name=password]", PASSWORD)
    page.locator("form[action='/login'] button[type=submit]").click()
    page.wait_for_url("**/domains")
    page.goto("/dashboard?size=1&sort=name")
    if page.locator("html").get_attribute("lang") != language:
        page.locator(f"form.lang-switch button[value={language}]").click()
    expect(page.get_by_role("heading", name="Portefeuille" if language == "fr" else "Portfolio",
                            exact=True)).to_be_visible()
    rows = page.locator("tr[data-domain]")
    expect(rows).to_have_count(1)
    first = rows.first.get_attribute("data-domain")
    page.locator('nav.pf-pagination a[href*="page=2"]').click()
    assert rows.first.get_attribute("data-domain") != first
    assert "size=1" in page.url
    page.get_by_label("Domaine" if language == "fr" else "Domain", exact=True).fill("menuiserie")
    page.locator("form[action='/dashboard'] button[type=submit]").click()
    expect(rows).to_have_count(1)
    expect(rows.first).to_have_attribute("data-domain", DEMO)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    rows.first.locator('a[href*="/mission-control"]').first.click()
    expect(page.get_by_role("heading", name=DEMO, exact=True)).to_be_visible()
    if page.locator("html").get_attribute("lang") != "fr":
        page.locator("form.lang-switch button[value=fr]").click()
    context.close()
