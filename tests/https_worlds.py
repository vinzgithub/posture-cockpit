# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Version 0.4: recorded worlds described address by address, and a scan that shows what the HTTPS
family decided (the matrix of the specification, section 5)."""

from __future__ import annotations

import asyncio
import copy
from dataclasses import dataclass

from posture_cockpit.core import engine, scoring
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import CAUSE_DEPENDENCY, Finding, Status
from posture_cockpit.core.registry import Registry
from worlds import DOMAIN, NOW, changed, healthy, http_only_with_redirect_elsewhere

WWW = f"www.{DOMAIN}"
REGISTRY = Registry.discover()
HEADERS = healthy()["http"][f"https://www.{DOMAIN}/"]["headers"]
SECURITY_TXT = healthy()["http"][f"https://{DOMAIN}/.well-known/security.txt"]

V4A, V4B, V4C, V4D, V4E, V4F = (f"192.0.2.{n}" for n in (10, 11, 12, 13, 14, 15))
V6A, V6B = "2001:db8::10", "2001:db8::11"

# What one address does (see core/fixture.py); {} answers normally.
OK: dict = {}
REFUSED = {"443": "refused"}                 # TCP refusal, every attempt
RESET = {"443": "reset"}                     # reset after the Client Hello, every attempt, old versions included
CLOSE = {"443": "close"}
ALERT = {"443": "alert:sslv3_alert_handshake_failure"}
TIMEOUT = {"443": "timeout", "80": "timeout"}
NO_ROUTE = {"443": "unreachable", "80": "unreachable"}
POLICY = {"443": "policy", "80": "policy"}
OBSOLETE = {"versions": {"TLSv1.3": False, "TLSv1.2": False, "TLSv1.1": False, "TLSv1": True}}
NO_OLD_TLS_HERE = {"versions": {"TLSv1.3": False, "TLSv1.2": False, "TLSv1.1": None, "TLSv1": None}}
HANG = {"443": "hang"}
ELSEWHERE = {"status": 301, "headers": {"Location": "https://github.com/vinzgithub"}}


def site(domain: dict[str, dict] | None, www: dict[str, dict] | None = None, *, mail=healthy,
         dns: dict | None = None, **http) -> dict:
    """The healthy domain's mail and DNS, with these web hosts: address -> what it does.

    None: the host has no address. Each host serves its own page (HSTS and the other headers),
    ``http://`` redirects to its own HTTPS, and both publish a security.txt."""
    data = mail()
    records: dict = {}
    pages: dict = {}
    for host, addresses in ((DOMAIN, domain), (WWW, www)):
        addresses = addresses or {}
        records[f"{host} A"] = [a for a in addresses if ":" not in a]
        records[f"{host} AAAA"] = [a for a in addresses if ":" in a]
        pages[f"http://{host}/"] = {"status": 301, "headers": {"Location": f"https://{host}/"}}
        pages[f"https://{host}/"] = {"status": 200, "headers": HEADERS}
        pages[f"https://{host}/.well-known/security.txt"] = SECURITY_TXT
    data = changed(data, dns={**records, **(dns or {})}, http={**pages, **http})
    data["web"] = copy.deepcopy({DOMAIN: domain or {}, WWW: www or {}})  # the constants above stay intact
    return data


def fournet_mail() -> dict:
    """The mail and DNS of the reference case (DMARC p=none, MTA-STS testing): 29.5 points out of 36."""
    return http_only_with_redirect_elsewhere()


@dataclass
class Result:
    findings: dict[str, Finding]
    net: FixtureNetwork
    assessment: scoring.Assessment
    seconds: float

    @property
    def root(self) -> Finding:
        return self.findings["web.https_redirect"]

    def situation(self, host: str = DOMAIN) -> str:
        return self.root.outcome.evidence["observation"]["hosts"][host]["situation"]

    def state(self, check_id: str) -> str:
        """"ok", "warn", "fail", "na", "blocked", "dependency" or "error" (another cause)."""
        f = self.findings[check_id]
        if f.status is Status.ERROR:
            return "dependency" if f.outcome.evidence.get("cause") == CAUSE_DEPENDENCY else "error"
        return f.status.value


def scan(data: dict, *, deadline: float | None = None, timeout: float = 5, checks=None) -> Result:
    import time

    net = FixtureNetwork(data, NOW)
    clock = time.monotonic()
    result = asyncio.run(engine.scan(DOMAIN, checks or REGISTRY.checks(), net, timeout=timeout, now=NOW,
                                     probe_deadline=deadline))
    findings = {f.check_id: f for f in result.findings}
    return Result(findings, net, scoring.assess(list(findings.values())), time.monotonic() - clock)


TLS_CHECKS = ("tls.certificate", "tls.protocols", "tls.key")
PAGE_CHECKS = ("web.hsts", "web.csp", "web.framing", "web.nosniff", "web.referrer", "web.server_banner",
               "web.security_txt")
