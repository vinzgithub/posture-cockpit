# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Helpers shared by the web tests: forms, CSRF tokens, accounts."""

import re

PASSWORD = "correct horse 42"
DEMO = "menuiserie-dupont.example"


def csrf_of(html: str) -> str:
    return re.search(r'name="csrf" content="([^"]+)"', html).group(1)


def page_csrf(client, path: str = "/settings") -> str:
    return csrf_of(client.get(path).text)


def setup_account(client, demo: bool = False, lang: str = "fr"):
    data = {"csrf": page_csrf(client, "/setup"), "username": "vincent", "password": PASSWORD,
            "password2": PASSWORD, "lang": lang}
    if demo:
        data["demo"] = "on"
    return client.post("/setup", data=data, follow_redirects=False)


def log_in(client, username: str = "vincent", password: str = PASSWORD):
    token = page_csrf(client, "/login")
    return client.post("/login", data={"csrf": token, "username": username, "password": password},
                       follow_redirects=False)


def log_out(client):
    client.post("/logout", data={"csrf": page_csrf(client, "/domains")})


def post(client, url: str, page: str = "/domains", **data):
    """A form submission with the CSRF token of ``page``."""
    return client.post(url, data={"csrf": page_csrf(client, page), **data}, follow_redirects=False)
