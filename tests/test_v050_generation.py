# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: the generation of the rules (core/generation.py).

The verdicts and scores of a set of test worlds are recorded in
tests/data/generation-<GENERATION>.json. When a change of the checks or of the scoring changes
them, this test fails: raise GENERATION, then write the new file with
``python tests/test_v050_generation.py``. Scans of two generations are never compared."""

import asyncio
import json
import sys
from pathlib import Path

import pytest

import https_worlds
import worlds
from posture_cockpit.core import engine, generation, scoring
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.registry import Registry
from posture_cockpit.scanner import DEMO_DOMAIN, demo_data

DATA = Path(__file__).parent / "data"


def mail_unanswered(data: dict, domain: str = worlds.DOMAIN) -> dict:
    """``data`` where every question about the mail of ``domain`` times out."""
    for name in (domain, f"_dmarc.{domain}", f"_mta-sts.{domain}", f"_smtp._tls.{domain}"):
        data["dns"][f"{name} TXT"] = "timeout"
    data["dns"][f"{domain} MX"] = "timeout"
    return data


def unreachable(domain: str = worlds.DOMAIN) -> dict:
    """Name servers answer, nothing else does: too little is known to score."""
    return mail_unanswered({"dns": {
        f"{domain} SOA": ["ns1.example.net. hostmaster.example.org. 1 7200 3600 1209600 300"],
        f"{domain} NS": ["ns1.example.net.", "ns2.example.net."],
        f"{domain} A": ["192.0.2.20"], f"www.{domain} A": ["192.0.2.20"]}}, domain)


H = https_worlds
WORLDS = {
    "healthy": (worlds.DOMAIN, worlds.healthy),
    "http_only_redirect_elsewhere": (worlds.DOMAIN, worlds.http_only_with_redirect_elsewhere),
    "redirect_elsewhere_https_refused": (worlds.DOMAIN, worlds.redirect_elsewhere_https_refused),
    "certificate_expiring": (worlds.DOMAIN, lambda: worlds.with_certificate(expires_in_days=9)),
    "demo": (DEMO_DOMAIN, lambda: demo_data(DEMO_DOMAIN)),
    "https_ok": (worlds.DOMAIN, lambda: H.site({H.V4A: H.OK})),
    "https_blocked": (worlds.DOMAIN, lambda: H.site({H.V4A: H.REFUSED})),
    "https_undetermined": (worlds.DOMAIN, lambda: H.site({H.V4A: H.REFUSED, H.V6A: H.TIMEOUT})),
    "https_partial": (worlds.DOMAIN, lambda: H.site({H.V4A: H.REFUSED, H.V4B: H.OK})),
    "https_obsolete": (worlds.DOMAIN, lambda: H.site({H.V4A: H.OBSOLETE})),
    "mail_unanswered": (worlds.DOMAIN, lambda: mail_unanswered(worlds.healthy())),
    "unreachable": (worlds.DOMAIN, unreachable),
    "nothing": (worlds.DOMAIN, dict),
}


def fingerprint() -> dict:
    registry = Registry.discover()
    result = {}
    for name, (domain, make) in WORLDS.items():
        scan = asyncio.run(engine.scan(domain, registry.checks(), FixtureNetwork(make(), worlds.NOW), timeout=5,
                                       now=worlds.NOW))
        a = scoring.assess(scan.findings)
        result[name] = {
            "score": a.score, "grade": a.grade, "evaluation": a.evaluation,
            "coverage": round(a.coverage, 6),
            "score_final": None if a.score_final is None else round(a.score_final, 6),
            "cap_reasons": list(a.cap_reasons), "grade_withheld_reason": a.grade_withheld_reason,
            "statuses": {f.check_id: f.status.value for f in sorted(scan.findings, key=lambda f: f.check_id)},
        }
    return result


def test_the_rules_are_those_of_their_generation():
    recorded = json.loads((DATA / f"generation-{generation.GENERATION}.json").read_text())
    assert recorded["generation"] == generation.GENERATION
    now = fingerprint()
    changed = sorted(name for name in WORLDS if now[name] != recorded["worlds"].get(name))
    assert not changed, (
        f"The verdicts or the scores changed for {changed}. If the change of the rules is intended, "
        "raise GENERATION in core/generation.py and write the new file: python tests/test_v050_generation.py")


def test_the_worlds_cover_the_states_that_matter():
    recorded = json.loads((DATA / f"generation-{generation.GENERATION}.json").read_text())["worlds"]
    assert {"complete", "partial", "undetermined", "not_evaluated"} <= {w["evaluation"] for w in recorded.values()}
    assert any("blocked" in w["statuses"].values() for w in recorded.values())


@pytest.mark.parametrize(("version", "expected"), [
    ("0.4.0", 4), ("0.4.1", 4),
    ("0.1.0", None), ("0.2.0", None), ("0.3.0", None), ("0.3.1", None), ("0.3.2", None),
    ("0.4.1rc1", None), ("0.4.0.dev0", None), ("0.5.0.dev1", None), ("", None), (None, None),
])
def test_only_the_released_versions_whose_rules_are_known_have_a_generation(version, expected):
    assert generation.of_version(version) == expected


if __name__ == "__main__":
    target = DATA / f"generation-{generation.GENERATION}.json"
    target.write_text(json.dumps({"generation": generation.GENERATION, "worlds": fingerprint()},
                                 indent=1, sort_keys=True) + "\n")
    print(f"written: {target}", file=sys.stderr)
