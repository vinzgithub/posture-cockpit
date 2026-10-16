# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Version 0.4, T7: every recorded world and the demo domain keep the statuses, score and coverage of
0.3.2, except on the lines of the matrix that change them.

``data/reference-0.3.2.json`` holds what the 0.3.2 rules give on these worlds: the code of commit
d1053ac (0.3.2 plus the corrected recorded network, where an expired certificate fails verification
as on the real network), run on the worlds of this file on 16 October 2026.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from posture_cockpit.core import engine, scoring
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.registry import Registry
from posture_cockpit.scanner import DEMO_DOMAIN, demo_data
from worlds import (
    DOMAIN,
    NOW,
    changed,
    dkim_key,
    healthy,
    http_only_with_redirect_elsewhere,
    redirect_elsewhere_https_refused,
    with_certificate,
)

REFERENCE = json.loads((Path(__file__).parent / "data" / "reference-0.3.2.json").read_text())


def _tls(change):
    data = healthy()
    change(data["tls"])
    return data


WORLDS = {
    "healthy": healthy,
    "no_mail": lambda: changed(healthy(), dns={f"{DOMAIN} MX": [], f"{DOMAIN} TXT": [],
                                               f"_dmarc.{DOMAIN} TXT": None}),
    "weak_everything": lambda: changed(
        healthy(), dns={f"{DOMAIN} TXT": ["v=spf1 +all"], f"_dmarc.{DOMAIN} TXT": ["v=DMARC1; p=none"],
                        f"selector1._domainkey.{DOMAIN} TXT": [f"p={dkim_key(1024)}"], f"{DOMAIN} DS": [],
                        f"{DOMAIN} CAA": [], f"{DOMAIN} NS": ["ns1.example.net."], f"_mta-sts.{DOMAIN} TXT": [],
                        f"_smtp._tls.{DOMAIN} TXT": []},
        http={f"http://www.{DOMAIN}/": {"status": 200}}),
    "expiring_weak_key": lambda: with_certificate(expires_in_days=5, key_type="RSA", key_bits=1024),
    "untrusted_issuer": lambda: with_certificate(trusted=False, problem="unable to get local issuer certificate"),
    "no_website": lambda: changed(healthy(), dns={f"{DOMAIN} A": [], f"www.{DOMAIN} A": []}),
    "http_only_with_redirect_elsewhere": http_only_with_redirect_elsewhere,
    "redirect_elsewhere_https_refused": redirect_elsewhere_https_refused,
    "certificate_expired": lambda: with_certificate(expires_in_days=-3),
    "certificate_self_signed": lambda: with_certificate(trusted=False, problem="self-signed certificate"),
    "tls10_on_www": lambda: _tls(lambda tls: tls[f"www.{DOMAIN}"].__setitem__("TLSv1", True)),
    "no_tls13": lambda: _tls(lambda tls: [versions.__setitem__("TLSv1.3", False) for versions in tls.values()]),
    "demo": lambda: demo_data(DEMO_DOMAIN),
}

# What 0.4 changes, by world, and why (the line of the matrix).
CHANGES = {
    # M9 / M39 (option Q4-B): the root no longer judges the certificate; the authentication cap applies.
    "untrusted_issuer": {"score": 79, "statuses": {"web.https_redirect": "ok"}},
    "certificate_expired": {"score": 79, "statuses": {"web.https_redirect": "ok"}},
    "certificate_self_signed": {"score": 79, "statuses": {"web.https_redirect": "ok"}},
    # M30: the domain refuses, www gives nothing conclusive: same score, the global grade withheld.
    "redirect_elsewhere_https_refused": {"grade": None},
}


@pytest.mark.parametrize("name", WORLDS)
def test_0_3_2_results_are_kept_except_on_the_lines_that_change(name):
    domain = DEMO_DOMAIN if name == "demo" else DOMAIN
    result = asyncio.run(engine.scan(domain, Registry.discover().checks(), FixtureNetwork(WORLDS[name](), NOW),
                                     timeout=5, now=NOW))
    a = scoring.assess(result.findings)
    expected = dict(REFERENCE[name])
    change = CHANGES.get(name, {})
    statuses = {**expected["statuses"], **change.get("statuses", {})}
    assert {f.check_id: f.status.value for f in result.findings} == statuses
    assert (a.score, a.grade, round(a.coverage, 4)) == (
        change.get("score", expected["score"]), change.get("grade", expected["grade"]), expected["coverage"])


def test_the_reference_covers_every_world():
    assert set(REFERENCE) == set(WORLDS)
