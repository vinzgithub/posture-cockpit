# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Mission Control is usable without JavaScript, on desktop and mobile."""
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect

from helpers import DEMO, PASSWORD


@pytest.mark.parametrize(("width", "language", "scheme"), [(1280, "fr", "light"), (390, "fr", "dark"),
                                                         (1280, "en", "dark"), (390, "en", "light")])
def test_select_two_first_steps_without_javascript(browser, port, width, language, scheme):
    base = f"http://127.0.0.1:{port}"
    context = browser.new_context(base_url=base, java_script_enabled=False, viewport={"width": width, "height": 900},
                                  color_scheme=scheme, reduced_motion="reduce")
    # Browser traffic is loopback only, including fonts and scripts.
    context.route("**/*", lambda route: route.continue_() if urlsplit(route.request.url).hostname == "127.0.0.1"
                  else route.abort())
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto("/login")
    page.fill("input[name=username]", "vincent")
    page.fill("input[name=password]", PASSWORD)
    page.locator("form[action='/login'] button[type=submit]").click()
    page.wait_for_url("**/domains")
    page.goto(f"/domains/{DEMO}/mission-control")
    if page.locator("html").get_attribute("lang") != language:
        page.locator(f"form[action='/lang'] button[value={language}]").click()
    select = page.locator("input[name=check][value='mail.dmarc']")
    select.focus()
    select.press("Space")
    expect(select).to_be_checked()
    page.locator("input[name=check][value='tls.certificate']").check()
    button = page.get_by_role("button", name="Simuler ces hypothèses" if language == "fr"
                             else "Simulate these assumptions", exact=True)
    expect(button).to_have_class("btn btn-secondary mc-simulate")
    button.click()
    expect(page.get_by_role("heading", name="Projection conditionnelle" if language == "fr"
                            else "Conditional projection", exact=True)).to_be_visible()
    expect(page.locator("input[name=check]:checked")).to_have_count(2)
    expect(page.locator("#simulation-result")).to_contain_text("Statut supposé après cette étape" if language == "fr"
                                                            else "Assumed status after this step")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert not errors
    context.close()


def test_form_rejects_scan_created_after_page_was_loaded(browser, port):
    context = browser.new_context(base_url=f"http://127.0.0.1:{port}", java_script_enabled=False)
    page = context.new_page()
    page.goto("/login")
    page.fill("input[name=username]", "vincent")
    page.fill("input[name=password]", PASSWORD)
    page.locator("form[action='/login'] button[type=submit]").click()
    page.wait_for_url("**/domains")
    # Do not mutate the shared demo scan used by the older history tests.
    page.goto("/domains/blocked.example/mission-control")
    if page.locator("html").get_attribute("lang") != "fr":
        page.locator("form[action='/lang'] button[value=fr]").click()
    token = page.locator('meta[name=csrf]').get_attribute("content")
    response = context.request.post("/domains/blocked.example/scan", form={"csrf": token})
    assert response.status == 200
    page.locator("input[name=check][value='web.https_redirect']").check()
    with page.expect_response(lambda r: "/mission-control/simulate?" in r.url) as submitted:
        page.get_by_role("button", name="Simuler ces hypothèses", exact=True).click()
    assert submitted.value.status == 409
    expect(page.get_by_role("heading", name="L’état a changé", exact=True)).to_be_visible()
    expect(page.get_by_role("link", name="Rafraîchir la fiche", exact=True)).to_be_visible()
    context.close()


@pytest.mark.parametrize(("language", "label", "width"), [
    ("fr", "Aller au contenu principal", 390),
    ("en", "Skip to main content", 1280),
])
def test_skip_navigation_keyboard_accessible_without_javascript(browser, port, language, label, width):
    """The first keyboard shortcut is visible when focused and bypasses the navigation."""
    context = browser.new_context(base_url=f"http://127.0.0.1:{port}", java_script_enabled=False,
                                  viewport={"width": width, "height": 900})
    page = context.new_page()
    page.goto("/login")
    if page.locator("html").get_attribute("lang") != language:
        page.locator(f"form.lang-switch button[value={language}]").click()
    skip = page.get_by_role("link", name=label, exact=True)
    expect(skip).to_have_attribute("href", "#main")
    skip.focus()
    expect(skip).to_be_focused()
    expect(skip).to_have_css("top", "8px")
    skip.press("Enter")
    assert page.evaluate("location.hash") == "#main"
    expect(page.locator("main#main")).to_be_focused()
    context.close()
