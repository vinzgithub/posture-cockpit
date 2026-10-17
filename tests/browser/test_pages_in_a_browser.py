# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""What only a browser shows: copy buttons, the language switch after a task change, the steps.

The 0.3.2 recette found the "Copier" buttons dead at http://192.168.2.15:8086: there,
navigator.clipboard does not exist. Pages opened with visit() are in that situation."""

import re

import pytest
from playwright.sync_api import expect

from posture_cockpit.scanner import DEMO_DOMAIN

DMARC = "v=DMARC1; p=none; rua=mailto:dmarc@menuiserie-dupont.example"
PLAN = f"/domains/{DEMO_DOMAIN}?task=mail.dmarc"
COPY_DMARC = f'[data-panel="mail.dmarc"] button[data-copy="{DMARC}"]'


@pytest.mark.parametrize("device", [None, "Pixel 7"])
def test_copy_on_a_page_in_plain_http(visit, device):
    page, clipboard = visit(device=device)
    page.goto(PLAN)
    assert page.evaluate("[window.isSecureContext, typeof navigator.clipboard]") == [False, "undefined"]
    clipboard.write("before")
    button = page.locator(COPY_DMARC)
    if device:
        button.tap()
    else:
        button.click()
    expect(button).to_have_text("Copié ✓")
    assert clipboard.read() == DMARC


def test_copying_an_api_key_leaves_no_trace(visit):
    page, clipboard = visit()
    page.goto("/settings")
    page.fill("form[action='/settings/token'] input[name=name]", "browser test")
    page.click("form[action='/settings/token'] button[type=submit]")
    token = page.text_content("code.secret")
    assert token
    console, requests = [], []
    page.on("console", lambda message: console.append(message.text))
    page.on("request", lambda request: requests.append(request.url))
    clipboard.write("before")
    button = page.locator(".token-box button.btn-copy")
    button.click()
    expect(button).to_have_text("Copié ✓")
    assert clipboard.read() == token
    assert page.locator(".copy-buffer").count() == 0  # the text area is gone
    assert requests == []  # nothing leaves the page
    assert not any(token in text for text in console)  # nothing is logged
    assert page.content().count(token) == 2  # still only the value shown and its button


def test_copy_with_the_clipboard_api_in_a_secure_context(visit):
    page, clipboard = visit(secure=True, init="document.execCommand = () => { throw new Error('not used'); };")
    page.goto(PLAN)
    assert page.evaluate("window.isSecureContext") is True
    clipboard.write("before")
    button = page.locator(COPY_DMARC)
    button.click()
    expect(button).to_have_text("Copié ✓")
    assert clipboard.read() == DMARC


def test_a_refused_clipboard_falls_back_to_the_copy_command(visit):
    refused = "navigator.clipboard.writeText = () => Promise.reject(new DOMException('refused', 'NotAllowedError'));"
    page, clipboard = visit(secure=True, init=refused)
    page.goto(PLAN)
    clipboard.write("before")
    button = page.locator(COPY_DMARC)
    button.click()
    expect(button).to_have_text("Copié ✓")
    assert clipboard.read() == DMARC


def test_when_no_copy_works_the_value_is_selected_with_a_message(visit):
    page, clipboard = visit(init="document.execCommand = () => false;")
    page.goto(PLAN)
    clipboard.write("before")
    button = page.locator(COPY_DMARC)
    button.click()
    status = page.locator('[data-panel="mail.dmarc"] .copy-status')
    expect(status).to_have_text(re.compile(r"^Copie automatique impossible ici .*Ctrl\+C.*appui long"))
    expect(status).to_have_attribute("role", "status")
    expect(button).to_have_text("Copier")
    assert page.evaluate("String(getSelection())") == DMARC
    assert clipboard.read() == "before"
    button.click()
    expect(page.locator('[data-panel="mail.dmarc"] .copy-status')).to_have_count(1)  # one message, not two


def test_two_quick_clicks_bring_the_label_back(visit):
    page, _ = visit()
    page.goto(PLAN)
    button = page.locator(COPY_DMARC)
    button.click()
    page.wait_for_timeout(300)
    button.click()
    expect(button).to_have_text("Copié ✓")
    expect(button).to_have_text("Copier", timeout=5000)  # until 0.3.2: stayed on "Copié ✓"


def test_the_language_switch_keeps_the_task_chosen_on_the_page(visit):
    page, _ = visit()
    page.goto(f"/domains/{DEMO_DOMAIN}")
    expect(page.locator('[data-panel="mail.dmarc"]')).to_be_hidden()
    page.click('.task-card[data-task="mail.dmarc"]')  # shown without reloading the page
    expect(page.locator('[data-panel="mail.dmarc"]')).to_be_visible()
    try:
        page.click("form.lang-switch button")
        page.wait_for_url(re.compile(r"\?task=mail\.dmarc$"))
        expect(page.locator("html")).to_have_attribute("lang", "en")
        expect(page.locator('[data-panel="mail.dmarc"]')).to_be_visible()
    finally:
        page.click("form.lang-switch button")  # the language is the account's: back to French
        expect(page.locator("html")).to_have_attribute("lang", "fr")


STEPS = """() => {
  const steps = [...document.querySelectorAll('.stepper .step')];
  const stepper = document.querySelector('.stepper');
  return {
    rows: new Set(steps.map((s) => Math.round(s.getBoundingClientRect().top))).size,
    lines: steps.slice(0, -1).filter((s) => getComputedStyle(s, '::after').display !== 'none').length,
    overflow: stepper.scrollWidth > stepper.clientWidth + 1,
  };
}"""


def test_the_steps_never_leave_a_line_hanging(visit):
    """On a phone the four steps went over two lines, the line after "Corriger" leading nowhere;
    the same on a desktop window between 1090 and 1190 px, the steps beside the score card."""
    page, _ = visit()
    page.goto(f"/domains/{DEMO_DOMAIN}")
    wrong = []
    try:
        for language in ("fr", "en"):
            if language == "en":
                page.click("form.lang-switch button")
                expect(page.locator("html")).to_have_attribute("lang", "en")
            for width in range(320, 1301, 10):
                page.set_viewport_size({"width": width, "height": 900})
                steps = page.evaluate(STEPS)
                if steps["overflow"] or (steps["rows"] > 1 and steps["lines"]):
                    wrong.append((language, width, steps))
    finally:
        if page.locator("html").get_attribute("lang") == "en":
            page.click("form.lang-switch button")  # the language is the account's: back to French
    assert wrong == []


@pytest.mark.parametrize('device', [None, 'Pixel 7'])
def test_https_indicators_on_plan_details_history_and_read_only_scan(visit, device):
    page, _ = visit(secure=True, device=device)
    for path in ('', '/details', '/history', '/history/1'):
        page.goto(f'/domains/{DEMO_DOMAIN}{path}')
        indicators = page.locator('.v04-indicators')
        expect(indicators).to_be_visible()
        expect(indicators).to_contain_text('Couverture diagnostique')
        expect(indicators).to_contain_text('Bloqués : 0')
        expect(indicators).to_contain_text('Adresses :')
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')


def test_provisional_score_and_blocked_links_in_browser(visit):
    from worlds import DOMAIN

    page, _ = visit(secure=True)
    page.goto(f'/domains/{DOMAIN}')
    expect(page.locator('.v04-indicators + .coverage-partial')).to_contain_text('sans lettre')
    expect(page.locator('.scorecard-score')).not_to_contain_text('Non évalué')
    expect(page.locator('.scorecard')).not_to_contain_text('None')
    page.goto('/domains/blocked.example')
    blocked = page.locator('li.status-blocked')
    expect(blocked).to_have_count(10)
    blocked.first.locator('a').click()
    expect(page.locator('#web\\.https_redirect')).to_be_in_viewport()


@pytest.mark.parametrize('device', [None, 'Pixel 7', 'iPhone SE'])
def test_every_result_page_fits_the_screen_and_states_its_coverage_once(visit, device):
    """0.4.1: one sentence for the scoring coverage per page, the help when blocked checks make
    the two coverages differ, and no page wider than the screen, on a desktop and on phones."""
    from worlds import DOMAIN

    page, _ = visit(secure=True, device=device)
    for domain in (DEMO_DOMAIN, DOMAIN, 'blocked.example'):
        for path in ('', '/details', '/history', '/history/1' if domain == DEMO_DOMAIN else ''):
            page.goto(f'/domains/{domain}{path}')
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), (domain, path)
            if path in ('', '/details'):
                assert page.get_by_text('Couverture de notation').count() == 1, (domain, path)
                help_line = page.locator('.coverage-help')
                expect(help_line).to_have_count(1 if domain == 'blocked.example' else 0)
    page.goto('/domains')
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.goto('/domains/blocked.example')
    blocked_line = 'Bloqué — dépend de : Redirection HTTPS (refus observé)'  # the wording of the 0.4 arbitration
    expect(page.locator('li.status-blocked').first).to_contain_text(blocked_line)


@pytest.mark.parametrize('device', [None, 'Pixel 7', 'iPhone SE'])
def test_the_history_shows_how_each_scan_was_started(visit, device):
    """0.5.0: the column "Origine" (Manuelle, API, Planifiée, or a dash before 0.5.0), in French and
    in English, in the table on a desktop and in the cards on phones, never as a raw key."""
    page, _ = visit(secure=True, device=device)
    page.goto(f'/domains/{DEMO_DOMAIN}/history')
    try:
        for language, header, value in (('fr', 'Origine', 'Manuelle'), ('en', 'Started', 'Manually')):
            if language == 'en':
                page.click('form.lang-switch button')
                expect(page.locator('html')).to_have_attribute('lang', 'en')
            cell = page.locator('td.history-via').first
            expect(cell).to_be_visible()
            expect(cell).to_have_text(value)
            if device:  # the cards: the label comes from data-label, shown above the value
                assert page.evaluate("getComputedStyle(document.querySelector('td.history-via'), '::before')"
                                     ".content") == f'"{header}"'
            else:
                expect(page.locator('table.history thead')).to_contain_text(header)
            assert 'history.via' not in page.content()
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    finally:
        if page.locator('html').get_attribute('lang') == 'en':
            page.click('form.lang-switch button')  # the language is the account's: back to French
