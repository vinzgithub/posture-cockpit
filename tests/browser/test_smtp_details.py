# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The SMTP measure on the details page, in Chromium (version 0.7, PR-D).

An instance of its own, with the probe on, scans a recorded domain whose MX has an IPv4 address that
verifies, an IPv6 address without route and a backup MX that times out. The page is read in French
and in English, on a desktop and on a phone, with the keyboard: the readiness, the table by MX and
address (caption, headers, a scrollable region reachable by the keyboard), no horizontal scroll of the
page on a phone, the IPv6 address on one line, and the JSON of the evidence still there after it.
"""

import re
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from helpers import PASSWORD
from posture_cockpit.config import Config
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.web.app import create_app
from worlds import DOMAIN, EHLO, changed, healthy

V6 = "2001:db8:ffff:ffff:ffff:ffff:ffff:25"
WORLD = changed(healthy(), dns={f"{DOMAIN} MX": ["10 mx.example.net.", "20 mx2.example.net."],
                                "mx.example.net AAAA": [V6], "mx2.example.net A": ["192.0.2.26"]})
WORLD["smtp"] = {"mx.example.net": {"192.0.2.25": "tls_verified", V6: "no_ipv6"},
                 "mx2.example.net": {"192.0.2.26": "timeout"}}


@pytest.fixture(scope="module")
def smtp_port(tmp_path_factory):
    app = create_app(Config(data_dir=tmp_path_factory.mktemp("smtp"), smtp_probe=True, smtp_ehlo_name=EHLO),
                     network_factory=lambda d: FixtureNetwork(WORLD, domain=d, ehlo_name=EHLO))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True).start()
    deadline = time.monotonic() + 15
    while not server.started:
        assert time.monotonic() < deadline, "the application did not start"
        time.sleep(0.05)
    number = sock.getsockname()[1]
    with httpx.Client(base_url=f"http://127.0.0.1:{number}", trust_env=False) as client:
        csrf = re.search(r'name="csrf" content="([^"]+)"', client.get("/setup").text).group(1)
        client.post("/setup", data={"csrf": csrf, "setup_code": app.state.setup_code, "username": "vincent",
                                    "password": PASSWORD, "password2": PASSWORD, "lang": "fr"})
        csrf = re.search(r'name="csrf" content="([^"]+)"', client.get("/domains").text).group(1)
        assert client.post("/domains", data={"csrf": csrf, "domain": DOMAIN}).status_code == 303
    yield number
    server.should_exit = True


@pytest.fixture
def details(browser, playwright, smtp_port):
    contexts = []

    def open_page(device=None, lang="fr"):
        options = dict(playwright.devices[device]) if device else {}
        context = browser.new_context(base_url=f"http://127.0.0.1:{smtp_port}", **options)
        contexts.append(context)
        page = context.new_page()
        page.goto("/login")
        page.fill("input[name=username]", "vincent")
        page.fill("input[name=password]", PASSWORD)
        page.click("form[action='/login'] button[type=submit]")
        page.wait_for_url(re.compile(r"/domains"))
        if lang == "en":
            page.click("button[name=lang][value=en]")
            page.wait_for_load_state()
        page.goto(f"/domains/{DOMAIN}/details")
        return page

    yield open_page
    for context in contexts:
        context.close()


def test_the_smtp_table_on_a_desktop_in_french(details):
    """F06, F05.08, Q03 (PR-D, P1): the readiness, then one row per MX and address with the cause proper to each
    server, the caption and the column headers of the table, the IPv6 address on one line, the JSON after."""
    page = details()
    block = page.locator(".smtp")
    # The policy of the healthy domain covers mx.example.net only: the backup MX makes it "to fix".
    assert block.locator(".smtp-readiness .badge").inner_text() == "À corriger"
    assert "La politique MTA-STS ne couvre pas tous les serveurs de messagerie." in block.inner_text()
    rows = block.locator("tbody tr")
    assert rows.count() == 3
    assert "Non joignable depuis ce réseau (aucune route)" in rows.nth(1).inner_text()
    assert "Port 25 inaccessible ou délai dépassé" in rows.nth(2).inner_text()
    assert "Port 25" not in rows.nth(0).inner_text()
    assert block.locator("caption").count() == 1 and block.locator("thead th[scope=col]").count() == 7
    assert block.locator("tbody th[scope=row]").count() == 3
    address = block.locator("code.smtp-address", has_text=V6)
    assert address.evaluate("e => e.getClientRects().length") == 1  # one line box: never cut
    smtp = page.locator("li#mail\\.smtp_starttls")
    assert smtp.locator("details summary").count() == 1  # the technical JSON, after the readable part


def test_the_table_is_reached_and_scrolled_with_the_keyboard_on_a_phone(details):
    """F06, Q03 (PR-D, accessibility): on a phone, the page itself never scrolls sideways; the table scrolls in
    its own region, which the keyboard reaches (tabindex, a name, a visible focus) and scrolls with the arrows."""
    page = details(device="iPhone 13")
    assert page.evaluate("document.scrollingElement.scrollWidth <= window.innerWidth + 1")
    region = page.locator(".smtp .table-scroll")
    assert region.get_attribute("role") == "region" and region.get_attribute("aria-label")
    assert region.evaluate("e => e.scrollWidth > e.clientWidth")  # the table is wider than the phone
    for _ in range(80):
        page.keyboard.press("Tab")
        if page.evaluate("document.activeElement.classList.contains('table-scroll')"):
            break
    assert page.evaluate("document.activeElement.classList.contains('table-scroll')")
    assert region.evaluate("e => getComputedStyle(e).outlineStyle") != "none"
    for _ in range(20):
        page.keyboard.press("ArrowRight")
        page.wait_for_timeout(50)
        if region.evaluate("e => e.scrollLeft") > 0:
            break
    assert region.evaluate("e => e.scrollLeft") > 0


def test_the_smtp_table_in_english(details):
    """Q03, F06 (PR-D): the same block in English, in the words of the catalogues."""
    page = details(lang="en")
    block = page.locator(".smtp")
    assert block.locator(".smtp-readiness .badge").inner_text() == "To fix"
    assert "Results by server and address" in block.inner_text()
    assert "no guarantee of delivery from the Internet" in block.inner_text()
