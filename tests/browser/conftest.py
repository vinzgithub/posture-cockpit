# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Browser tests: the real pages in Chromium, served by uvicorn on 127.0.0.1.

They run in their own CI job, where Playwright and Chromium are installed:

    python -m pip install -e ".[dev,browser]"
    python -m playwright install --with-deps chromium
    python -m pytest tests/browser

The main job does not collect this folder (norecursedirs in pyproject.toml). Here a
missing Playwright is an error, never a skipped test.
"""

import json
import os
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import httpx
import pytest
import uvicorn
from playwright.sync_api import sync_playwright

from helpers import PASSWORD
from https_worlds import REFUSED, TIMEOUT, V4A, V6A, site
from posture_cockpit.config import Config
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.scanner import DEMO_DOMAIN, demo_data
from posture_cockpit.web.app import create_app
from worlds import DOMAIN

# Chromium sends this name to 127.0.0.1. A name that is not "localhost" is not a secure
# context: the page sees what it sees at http://192.168.x.x on a local network.
LAN = "posture-cockpit.test"
SECURE = "127.0.0.1"


@pytest.fixture(scope="session")
def port(tmp_path_factory):
    """The application with its first account, the demo domain scanned."""
    def network(domain):
        if domain in {DOMAIN, "blocked.example"}:
            data = site({V4A: REFUSED, V6A: TIMEOUT}) if domain == DOMAIN else site({V4A: REFUSED})
            return FixtureNetwork(json.loads(json.dumps(data).replace(DOMAIN, domain)))
        return FixtureNetwork(demo_data(domain) if domain == DEMO_DOMAIN else {"dns": {f"{domain} SOA": None}})

    app = create_app(Config(data_dir=tmp_path_factory.mktemp("data")), network_factory=network)
    sock = socket.socket()
    sock.bind((SECURE, 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        assert time.monotonic() < deadline, "the application did not start"
        time.sleep(0.05)
    number = sock.getsockname()[1]
    with httpx.Client(base_url=f"http://{SECURE}:{number}", trust_env=False) as client:
        csrf = re.search(r'name="csrf" content="([^"]+)"', client.get("/setup").text).group(1)
        r = client.post("/setup", data={"csrf": csrf, "setup_code": app.state.setup_code, "username": "vincent",
                                        "password": PASSWORD,
                                        "password2": PASSWORD, "lang": "fr", "demo": "on"})
        assert r.status_code == 303 and r.headers["location"] == f"/domains/{DEMO_DOMAIN}"
        for domain in (DOMAIN, "blocked.example"):
            csrf = re.search(r'name="csrf" content="([^"]+)"', client.get("/domains").text).group(1)
            assert client.post("/domains", data={"csrf": csrf, "domain": domain}).status_code == 303
    yield number
    server.should_exit = True
    thread.join(10)


@pytest.fixture(scope="session")
def playwright():
    with sync_playwright() as p:
        yield p


@pytest.fixture(scope="session")
def browser(playwright, port):
    # Some execution environments intercept names even with Chromium's DNS override.
    # A loopback-only proxy forwards real HTTP requests without changing the document origin.
    proxy = None
    args = [f"--host-resolver-rules=MAP {LAN} {SECURE}", "--no-proxy-server"]
    if os.environ.get("POSTURE_TEST_LOOPBACK_TRANSPORT"):
        class LoopbackProxy(BaseHTTPRequestHandler):
            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def log_message(self, *args):
                pass

            def forward(self):
                url = urlsplit(self.path)
                if url.hostname != LAN or url.port != port:
                    self.send_error(403)
                    return
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                with httpx.Client(trust_env=False) as transport:
                    reply = transport.request(self.command, f"http://{SECURE}:{port}{url.path}"
                                              + ("?" + url.query if url.query else ""),
                                              headers=dict(self.headers), content=body)
                self.send_response(reply.status_code)
                for name, value in reply.headers.multi_items():
                    if name.lower() not in {"transfer-encoding", "connection", "content-length"}:
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(reply.content)))
                self.end_headers()
                self.wfile.write(reply.content)

        proxy = ThreadingHTTPServer((SECURE, 0), LoopbackProxy)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        args = [f"--proxy-server=http://{SECURE}:{proxy.server_port}"]
    browser = playwright.chromium.launch(args=args)
    yield browser
    browser.close()
    if proxy:
        proxy.shutdown()
        proxy.server_close()


class Clipboard:
    """The system clipboard, read and written from a page of a secure origin."""

    def __init__(self, page):
        self.page = page

    def read(self) -> str:
        return self.page.evaluate("navigator.clipboard.readText()")

    def write(self, text: str) -> None:
        self.page.evaluate("(text) => navigator.clipboard.writeText(text)", text)


@pytest.fixture
def visit(port, playwright, browser):
    """visit(secure=False, device=None, init=None) -> (page signed in, clipboard).

    secure=False: a page at a local network name, without navigator.clipboard;
    secure=True: the same page at 127.0.0.1, a secure context like HTTPS."""
    contexts = []

    def open_page(secure=False, device=None, init=None):
        host = SECURE if secure else LAN
        options = dict(playwright.devices[device]) if device else {}
        context = browser.new_context(base_url=f"http://{host}:{port}", **options)
        contexts.append(context)
        context.grant_permissions(["clipboard-read", "clipboard-write"], origin=f"http://{SECURE}:{port}")
        reader = context.new_page()
        reader.goto(f"http://{SECURE}:{port}/healthz")
        page = context.new_page()
        if init:
            page.add_init_script(init)  # this page only: the clipboard reader stays as it is
        page.goto("/login")
        page.fill("input[name=username]", "vincent")
        page.fill("input[name=password]", PASSWORD)
        page.click("form[action='/login'] button[type=submit]")
        page.wait_for_url(re.compile(r"/domains"))
        return page, Clipboard(reader)

    yield open_page
    for context in contexts:
        context.close()
