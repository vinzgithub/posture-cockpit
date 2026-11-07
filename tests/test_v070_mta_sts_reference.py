# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The results of mail.mta_sts, frozen before version 0.7 shares its reading of the policy.

Prerequisite P2 of PR-C. Version 0.7 moves the reading of the MTA-STS policy (the TXT record of
``_mta-sts``, the addresses of ``mta-sts.<domain>``, the HTTPS request and the parsing) into one
reading per scan, shared by mail.mta_sts and mail.smtp_starttls (``ctx.shared``). mail.mta_sts
must not notice: the reference file tests/data/mta-sts-reference.json was written by this test on
the code of ``6c9f321`` (integration/v0.7.0 after PR-B2), before any change to mail.py, and the
test holds the check to it after.

For each world, the whole finding is compared: status, message, parameters, evidence (with the
order of its keys), remedy, and the questions the check asked, in their order. The worlds cover
every exit of the check: no MX, null MX, no record, records of another protocol, a bad or doubled
record, no address for ``mta-sts.<domain>``, a refused, timed out or untrusted HTTPS, a status other
than 200, a policy with faulty fields, the modes none, testing and enforce, MX not covered in
testing and in enforce, wildcards, a short max_age, and the questions that time out (errors of the
engine). To write the file again (never to make a change pass): ``python tests/test_v070_mta_sts_reference.py``.
"""

import asyncio
import dataclasses
import json
import sys
from pathlib import Path

import pytest

from posture_cockpit.core import engine
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.registry import Registry
from worlds import DOMAIN, NOW, changed, healthy

REFERENCE = Path(__file__).parent / "data" / "mta-sts-reference.json"
URL = f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt"
TXT = f"_mta-sts.{DOMAIN} TXT"


def policy(mode: str = "enforce", mx: tuple[str, ...] = ("mx.example.net",), max_age: str = "604800",
           extra: str = "") -> dict:
    lines = ["version: STSv1", f"mode: {mode}", *(f"mx: {m}" for m in mx), f"max_age: {max_age}"]
    return {URL: {"status": 200, "body": "\n".join(lines) + "\n" + extra}}


def without(data: dict, section: str, *keys: str) -> dict:
    for key in keys:
        data[section].pop(key, None)
    return data


WORLDS = {
    "enforce": healthy,
    "no_mx": lambda: without(healthy(), "dns", f"{DOMAIN} MX"),
    "null_mx": lambda: changed(healthy(), dns={f"{DOMAIN} MX": ["0 ."]}),
    "mx_timeout": lambda: changed(healthy(), dns={f"{DOMAIN} MX": "timeout"}),
    "missing": lambda: without(healthy(), "dns", TXT),
    "other_txt_only": lambda: changed(healthy(), dns={TXT: ["hello world"]}),
    "sts_v2_only": lambda: changed(healthy(), dns={TXT: ["v=STSv2; id=1"]}),
    "bad_record": lambda: changed(healthy(), dns={TXT: ["v=STSv1; id="]}),
    "two_records": lambda: changed(healthy(), dns={TXT: ["v=STSv1; id=1", "v=STSv1; id=2"]}),
    "record_and_noise": lambda: changed(healthy(), dns={TXT: ["v=STSv1; id=20261012", "hello"]}),
    "txt_timeout": lambda: changed(healthy(), dns={TXT: "timeout"}),
    "no_policy_address": lambda: without(healthy(), "dns", f"mta-sts.{DOMAIN} A"),
    "policy_address_v6": lambda: without(changed(healthy(), dns={f"mta-sts.{DOMAIN} AAAA": ["2001:db8::10"]}),
                                         "dns", f"mta-sts.{DOMAIN} A"),
    "policy_address_timeout": lambda: changed(healthy(), dns={f"mta-sts.{DOMAIN} A": "timeout"}),
    "refused": lambda: without(healthy(), "http", URL),
    "http_timeout": lambda: changed(healthy(), http={URL: "timeout"}),
    "not_found": lambda: changed(healthy(), http={URL: {"status": 404, "body": "no"}}),
    "redirect": lambda: changed(healthy(), http={URL: {"status": 301, "headers": {"Location": "https://x/"}}}),
    "untrusted": lambda: changed(healthy(), certificates={f"mta-sts.{DOMAIN}": {"trusted": False}}),
    "expired_certificate": lambda: changed(healthy(), certificates={f"mta-sts.{DOMAIN}": {"expires_in_days": -3}}),
    "bad_policy": lambda: changed(healthy(), http={URL: {"status": 200, "body": "version: STSv1\nmode: strict\n"}}),
    "empty_policy": lambda: changed(healthy(), http={URL: {"status": 200, "body": ""}}),
    "none": lambda: changed(healthy(), http=policy("none")),
    "testing": lambda: changed(healthy(), http=policy("testing")),
    "testing_uncovered": lambda: changed(healthy(), http=policy("testing", ("mx.other.example",))),
    "enforce_uncovered": lambda: changed(healthy(), http=policy("enforce", ("mx.other.example",))),
    "enforce_partly_covered": lambda: changed(
        healthy(), dns={f"{DOMAIN} MX": ["10 mx.example.net.", "20 backup.example.com."]}, http=policy()),
    "wildcard": lambda: changed(healthy(), http=policy("enforce", ("*.example.net",))),
    "wildcard_too_deep": lambda: changed(healthy(), dns={f"{DOMAIN} MX": ["10 a.mx.example.net."]},
                                         http=policy("enforce", ("*.example.net",))),
    "short_max_age": lambda: changed(healthy(), http=policy("enforce", max_age="3600")),
    "testing_short_max_age": lambda: changed(healthy(), http=policy("testing", max_age="3600")),
    "unknown_field": lambda: changed(healthy(), http=policy(extra="color: blue\n")),
}


def finding(name: str) -> dict:
    """The finding of mail.mta_sts alone on the world ``name``, and the questions it asked."""
    net = FixtureNetwork(WORLDS[name](), NOW)
    check = Registry.discover().get("mail.mta_sts")
    result = asyncio.run(engine.scan(DOMAIN, [check], net, timeout=5, now=NOW))
    outcome = result.findings[0].outcome
    remedy = None if outcome.remedy is None else json.loads(json.dumps(dataclasses.asdict(outcome.remedy),
                                                                       default=str))
    return {"status": outcome.status.value, "summary": outcome.summary, "params": dict(outcome.params),
            # The order of the keys of the evidence is part of what is shown: kept as a list of pairs.
            "evidence": json.loads(json.dumps(list(outcome.evidence.items()), default=str)),
            "remedy": remedy, "signals": sorted(outcome.signals), "asked": list(net.asked)}


@pytest.mark.parametrize("name", list(WORLDS))
def test_mail_mta_sts_gives_the_results_recorded_before_the_shared_reading(name):
    """P2 (PR-C), T05: mail.mta_sts gives, on each world, the finding and the questions recorded on the
    code before the reading of the policy was shared: status, message, parameters, evidence and the order
    of its keys, remedy, questions asked and their order."""
    recorded = json.loads(REFERENCE.read_text(encoding="utf-8"))
    assert recorded["recorded_on"] == "6c9f3218e05675a0a6a4f4121a534861b33620e9"
    assert finding(name) == recorded["worlds"][name]


def test_the_reference_covers_every_exit_of_the_check():
    """P2 (PR-C): the worlds reach every message of mail.mta_sts, and the errors of the engine."""
    recorded = json.loads(REFERENCE.read_text(encoding="utf-8"))["worlds"]
    assert set(recorded) == set(WORLDS)
    summaries = {w["summary"] for w in recorded.values()}
    assert {"mail.no_inbound", "mail.mta_sts.missing", "mail.mta_sts.bad_record", "mail.mta_sts.no_policy",
            "mail.mta_sts.bad_certificate", "mail.mta_sts.bad_policy", "mail.mta_sts.disabled",
            "mail.mta_sts.mx_mismatch", "mail.mta_sts.testing", "mail.mta_sts.short_max_age",
            "mail.mta_sts.enforce"} <= summaries
    assert {w["status"] for w in recorded.values()} == {"ok", "warn", "fail", "na", "error"}


if __name__ == "__main__":
    REFERENCE.write_text(json.dumps({
        "recorded_on": sys.argv[1] if len(sys.argv) > 1 else "6c9f3218e05675a0a6a4f4121a534861b33620e9",
        "worlds": {name: finding(name) for name in WORLDS}}, indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8")
