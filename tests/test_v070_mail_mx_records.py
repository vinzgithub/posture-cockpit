# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The MX helpers of checks/mail.py, frozen before version 0.7 shares them with the SMTP probe.

Version 0.7 makes ``_mx_records()`` (preference and host of each MX record) the source of
``_mx_hosts()``, so that the SMTP probe reads the MX exactly as the mail checks do. The mail
checks must not notice: these tests were written and run on the code of version 0.6.1 (at
``2c1991e``), before any change to mail.py, and they hold it to the same results after.

- The hosts ``_mx_hosts()`` gives, compared with a copy of its 0.6.1 code on MX answers of every
  kind: preferences in any order, duplicates, root dots, case, null MX alone or among others, no
  MX, a name that does not exist, a question that times out, records without preference, an
  empty record.
- The findings of the MX, SPF, MTA-STS and TLS-RPT checks on 17 worlds, recorded on 0.6.1:
  status and message in clear, and a digest of the whole finding (parameters, evidence, remedy).
  A difference shows the finding in full.
"""

import asyncio
import dataclasses
import hashlib
import json

import pytest

from posture_cockpit.checks import mail
from posture_cockpit.core.errors import ConnectionTimedOut
from posture_cockpit.core.extension import CheckContext
from posture_cockpit.core.fixture import FixtureNetwork
from worlds import DOMAIN, NOW, changed, healthy, run


# ------------------------------------------------------------- _mx_hosts, against its 0.6.1 code
async def reference_mx_hosts(ctx: CheckContext) -> list[str]:
    """_mx_hosts() of version 0.6.1, copied as it was (without its cache, which changes nothing here)."""
    records = (await ctx.net.dns(ctx.domain, "MX")).records
    hosts = [r.split()[-1].lower().rstrip(".") for r in records]
    return [h for h in hosts if h]


MX_ANSWERS = {
    "one MX": ["10 mx.example.org."],
    "preferences in any order, case": ["20 B.Example.ORG.", "10 a.example.org", "5 c.example.org."],
    "duplicates": ["10 mx.example.org.", "10 mx.example.org.", "20 MX.example.org"],
    "null MX": ["0 ."],
    "null MX among others": ["0 .", "10 mx.example.org."],
    "a dot alone, another preference": ["10 ."],
    "no MX": [],
    "name does not exist": None,
    "question times out": "timeout",
    "no preference": ["mx.example.org."],
    "extra spaces": ["10   mx.example.org.  "],
    "an address": ["10 192.0.2.25."],
    "an underscore": ["10 MX_1.Example.org."],
    "an A-label": ["10 xn--caf-dma.example."],
    "an empty record": ["10 mx.example.org.", ""],
}


async def outcome(function, records) -> tuple[str, object]:
    ctx = CheckContext(DOMAIN, FixtureNetwork({"dns": {f"{DOMAIN} MX": records}}, NOW), NOW)
    try:
        return "hosts", await function(ctx)
    except Exception as e:  # the very exception is what must not change
        return "raises", type(e).__name__


@pytest.mark.parametrize("records", MX_ANSWERS.values(), ids=MX_ANSWERS.keys())
def test_mx_hosts_gives_what_it_gave_in_0_6_1(records):
    """F01, Q05 (version 0.7 shares the MX reading with the SMTP probe): the same hosts, in the same order,
    duplicates kept, or the same exception, as the 0.6.1 code."""
    expected = asyncio.run(outcome(reference_mx_hosts, records))
    assert asyncio.run(outcome(mail._mx_hosts, records)) == expected


def test_a_failed_mx_question_still_raises_a_network_error():
    """F01: a timeout is not taken for "no MX": the check that asked gets the error."""
    assert asyncio.run(outcome(mail._mx_hosts, "timeout")) == ("raises", ConnectionTimedOut.__name__)


# ------------------------------------------------- the mail checks, against their 0.6.1 results
POLICY = f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt"


def with_mx(records, **dns):
    return changed(healthy(), dns={f"{DOMAIN} MX": records, **dns})


WORLDS = {
    "healthy": healthy,
    "priorities out of order": lambda: with_mx(
        ["20 MX2.Example.NET.", "10 mx.example.net.", "30 mx3.example.net"],
        **{"mx2.example.net A": ["192.0.2.26"], "mx3.example.net AAAA": ["2001:db8::25"]}),
    "duplicates and dots": lambda: with_mx(["10 mx.example.net.", "10 mx.example.net.", "20 MX.example.net"]),
    "null MX": lambda: with_mx(["0 ."]),
    "null MX among others": lambda: with_mx(["0 .", "10 mx.example.net."]),
    "no MX": lambda: with_mx([]),
    "MX name does not exist": lambda: with_mx(None),
    "MX question times out": lambda: with_mx("timeout"),
    "MX is an address": lambda: with_mx(["10 192.0.2.25."]),
    "MX without address": lambda: with_mx(["10 nowhere.example.net."]),
    "MX without preference": lambda: with_mx(["mx.example.net."]),
    "MX host times out": lambda: with_mx(["10 mx.example.net."], **{"mx.example.net A": "timeout"}),
    "SPF missing, MX present": lambda: changed(healthy(), dns={f"{DOMAIN} TXT": []}),
    "SPF missing, null MX": lambda: changed(healthy(), dns={f"{DOMAIN} TXT": [], f"{DOMAIN} MX": ["0 ."]}),
    "TLS-RPT missing": lambda: changed(healthy(), dns={f"_smtp._tls.{DOMAIN} TXT": []}),
    "MTA-STS testing, MX not covered": lambda: changed(
        with_mx(["10 mx.example.net.", "20 backup.example.net."], **{"backup.example.net A": ["192.0.2.27"]}),
        http={POLICY: {"status": 200, "body": "version: STSv1\nmode: testing\nmx: mx.example.net\nmax_age: 604800\n"}}),
    "MTA-STS enforce, MX not covered": lambda: with_mx(
        ["10 other.example.net."], **{"other.example.net A": ["192.0.2.28"]}),
}
CHECKS = ("mail.mx", "mail.spf", "mail.mta_sts", "mail.tls_rpt")


def plain(finding) -> list:
    """The whole finding as plain data: status, message, parameters, evidence, remedy."""
    o = finding.outcome
    remedy = None if o.remedy is None else dataclasses.asdict(o.remedy)
    return json.loads(json.dumps([o.status.value, o.summary, dict(o.params), dict(o.evidence), remedy],
                                 default=str, sort_keys=True))


def digest(value: list) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


# Recorded on version 0.6.1 (2c1991e), before any change to mail.py: status, message, digest of the finding.
GOLDEN = {
    "MTA-STS enforce, MX not covered": {
        "mail.mta_sts": ("fail", "mail.mta_sts.mx_mismatch", "df3a5c999fa6d5a6"),
        "mail.mx": ("info", "mail.mx.list", "4aa39e8cfc3b6061"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("ok", "mail.tls_rpt.present", "3f5b80a4ce2df62f")},
    "MTA-STS testing, MX not covered": {
        "mail.mta_sts": ("warn", "mail.mta_sts.mx_mismatch", "cf37e60aa83ab586"),
        "mail.mx": ("info", "mail.mx.list", "272d59c95c3a466e"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("ok", "mail.tls_rpt.present", "3f5b80a4ce2df62f")},
    "MX host times out": {
        "mail.mta_sts": ("ok", "mail.mta_sts.enforce", "22cff1ea2b4ec09b"),
        "mail.mx": ("info", "mail.mx.list", "087a505b5be4e558"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("ok", "mail.tls_rpt.present", "3f5b80a4ce2df62f")},
    "MX is an address": {
        "mail.mta_sts": ("fail", "mail.mta_sts.mx_mismatch", "e2c58e9b5cb09edf"),
        "mail.mx": ("warn", "mail.mx.address", "2e064489457116f6"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("ok", "mail.tls_rpt.present", "3f5b80a4ce2df62f")},
    "MX name does not exist": {
        "mail.mta_sts": ("na", "mail.no_inbound", "6d4b6c1134cacdef"),
        "mail.mx": ("info", "mail.mx.none", "e35684670932d0ac"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("na", "mail.no_inbound", "6d4b6c1134cacdef")},
    "MX question times out": {
        "mail.mta_sts": ("error", "check.error.network_timeout", "440a8c58bd02eb63"),
        "mail.mx": ("error", "check.error.network_timeout", "440a8c58bd02eb63"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("error", "check.error.network_timeout", "440a8c58bd02eb63")},
    "MX without address": {
        "mail.mta_sts": ("fail", "mail.mta_sts.mx_mismatch", "ed527d79c717802b"),
        "mail.mx": ("warn", "mail.mx.unresolved", "e59d0c4c9f98d6bd"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("ok", "mail.tls_rpt.present", "3f5b80a4ce2df62f")},
    "MX without preference": {
        "mail.mta_sts": ("ok", "mail.mta_sts.enforce", "22cff1ea2b4ec09b"),
        "mail.mx": ("info", "mail.mx.list", "f3097decdc6dd692"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("ok", "mail.tls_rpt.present", "3f5b80a4ce2df62f")},
    "SPF missing, MX present": {
        "mail.mta_sts": ("ok", "mail.mta_sts.enforce", "22cff1ea2b4ec09b"),
        "mail.mx": ("info", "mail.mx.list", "087a505b5be4e558"),
        "mail.spf": ("fail", "mail.spf.missing", "d9fdd81f18504865"),
        "mail.tls_rpt": ("ok", "mail.tls_rpt.present", "3f5b80a4ce2df62f")},
    "SPF missing, null MX": {
        "mail.mta_sts": ("na", "mail.no_inbound", "6d4b6c1134cacdef"),
        "mail.mx": ("info", "mail.mx.none", "e0bf87d25c20d478"),
        "mail.spf": ("fail", "mail.spf.missing", "4b1049f77e752ced"),
        "mail.tls_rpt": ("na", "mail.no_inbound", "6d4b6c1134cacdef")},
    "TLS-RPT missing": {
        "mail.mta_sts": ("ok", "mail.mta_sts.enforce", "22cff1ea2b4ec09b"),
        "mail.mx": ("info", "mail.mx.list", "087a505b5be4e558"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("warn", "mail.tls_rpt.missing", "e5cf802d6a6c3011")},
    "duplicates and dots": {
        "mail.mta_sts": ("ok", "mail.mta_sts.enforce", "22cff1ea2b4ec09b"),
        "mail.mx": ("info", "mail.mx.list", "d3c830d5e813d313"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("ok", "mail.tls_rpt.present", "3f5b80a4ce2df62f")},
    "healthy": {
        "mail.mta_sts": ("ok", "mail.mta_sts.enforce", "22cff1ea2b4ec09b"),
        "mail.mx": ("info", "mail.mx.list", "087a505b5be4e558"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("ok", "mail.tls_rpt.present", "3f5b80a4ce2df62f")},
    "no MX": {
        "mail.mta_sts": ("na", "mail.no_inbound", "6d4b6c1134cacdef"),
        "mail.mx": ("info", "mail.mx.none", "e35684670932d0ac"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("na", "mail.no_inbound", "6d4b6c1134cacdef")},
    "null MX": {
        "mail.mta_sts": ("na", "mail.no_inbound", "6d4b6c1134cacdef"),
        "mail.mx": ("info", "mail.mx.none", "e0bf87d25c20d478"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("na", "mail.no_inbound", "6d4b6c1134cacdef")},
    "null MX among others": {
        "mail.mta_sts": ("ok", "mail.mta_sts.enforce", "22cff1ea2b4ec09b"),
        "mail.mx": ("warn", "mail.mx.null_mixed", "86944380611f8a57"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("ok", "mail.tls_rpt.present", "3f5b80a4ce2df62f")},
    "priorities out of order": {
        "mail.mta_sts": ("fail", "mail.mta_sts.mx_mismatch", "017b8204cb7755b3"),
        "mail.mx": ("info", "mail.mx.list", "0d11e95c24259b6d"),
        "mail.spf": ("ok", "mail.spf.ok", "13ac276b5717992b"),
        "mail.tls_rpt": ("ok", "mail.tls_rpt.present", "3f5b80a4ce2df62f")},
}


def test_the_worlds_are_those_recorded():
    """Q06: no world was added or removed without recording its results on 0.6.1."""
    assert set(WORLDS) == set(GOLDEN)


@pytest.mark.parametrize("world", sorted(WORLDS))
def test_the_mail_checks_give_what_they_gave_in_0_6_1(world):
    """F01, Q05: MX, SPF, MTA-STS and TLS-RPT give exactly their 0.6.1 findings (status, message, parameters,
    evidence, remedy) on MX of every kind: priorities, duplicates, null MX, no MX, DNS errors, addresses."""
    findings = run(WORLDS[world](), *CHECKS)
    actual = {check: plain(findings[check]) for check in CHECKS}
    for check in CHECKS:
        status, summary, expected = GOLDEN[world][check]
        assert (actual[check][0], actual[check][1], digest(actual[check])) == (status, summary, expected), \
            f"{world}, {check}: {json.dumps(actual[check], ensure_ascii=False)}"
