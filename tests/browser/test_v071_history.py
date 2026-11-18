# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Version 0.7.1, correction 3: no page breaks the policy of the application (style-src 'self').

The recette of 0.7.0 found the console of the browser reporting the two ``style`` attributes of the history
page, refused by the policy since 0.6. They are gone, and the policy is unchanged: no page reports a violation
any more, and the chart keeps the size the browser has shown since 0.6, that of the style sheet
(``.history-trend``: as wide as its column up to 34rem, 10rem high)."""

from playwright.sync_api import expect

from posture_cockpit.scanner import DEMO_DOMAIN

# Records what the policy refuses, before any script or style of the page is read.
WATCH = """
window.__violations = [];
document.addEventListener('securitypolicyviolation',
  (e) => window.__violations.push(`${e.violatedDirective} ${e.blockedURI} ${e.sample}`));
"""

PAGES = ["/domains", "/dashboard", "/events", "/settings",
         f"/domains/{DEMO_DOMAIN}", f"/domains/{DEMO_DOMAIN}/details", f"/domains/{DEMO_DOMAIN}/history",
         f"/domains/{DEMO_DOMAIN}/history/1", f"/domains/{DEMO_DOMAIN}/mission-control",
         "/domains/blocked.example", "/domains/blocked.example/details", "/domains/blocked.example/history"]


def test_no_page_breaks_the_policy_and_the_chart_keeps_its_size(visit):
    page, _ = visit(secure=True, init=WATCH)
    console = []
    page.on("console", lambda message: console.append(message.text))
    # A second scan of a domain the older history tests do not read: its history then draws the chart.
    page.goto("/domains/blocked.example")
    token = page.locator("meta[name=csrf]").get_attribute("content")
    assert page.context.request.post("/domains/blocked.example/scan", form={"csrf": token}).ok

    for path in PAGES:
        response = page.goto(path)
        assert response is not None and response.status == 200, path
        assert page.evaluate("window.__violations") == [], path

    page.goto("/domains/blocked.example/history")
    chart = page.locator("svg.history-trend")
    expect(chart).to_be_visible()
    assert chart.get_attribute("style") is None
    size = page.evaluate("""() => {
        const svg = document.querySelector('svg.history-trend');
        const rem = parseFloat(getComputedStyle(document.documentElement).fontSize);
        const column = svg.parentElement.getBoundingClientRect().width;
        const box = svg.getBoundingClientRect();
        return {width: box.width, height: box.height, expected: Math.min(column, 34 * rem), rem};
    }""")
    assert abs(size["width"] - size["expected"]) < 1 and abs(size["height"] - 10 * size["rem"]) < 1, size
    assert not [text for text in console if "Content Security Policy" in text]
