# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""mail.smtp_starttls inside a scan: its deadline with the MTA-STS policy, and the grouped recheck (PR-C).

Prerequisite P1: the policy is read once per scan with mail.mta_sts (``ctx.shared``), and the SMTP check
waits for it only until its own deadline, min(12 s, CHECK_TIMEOUT − 2 s): a policy that never comes must
not keep the check until the engine stops it, which would throw its observations away
(check.error.timeout). The test runs on the real network of the laboratory (local DNS server, fake SMTP
server with the test authority, LabNetwork of tests/smtp_lab.py), the HTTPS request of the policy held
forever. Then R6: rechecking mail.mta_sts or mail.smtp_starttls runs both, on one reading of the policy.
"""

import asyncio
import time

import pytest

from local_servers import LOOPBACK, TestPki, dns_server
from posture_cockpit.config import Config
from posture_cockpit.core import engine
from posture_cockpit.core.extension import SmtpSettings
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import Status
from posture_cockpit.core.registry import Registry
from posture_cockpit.scanner import Scanner
from smtp_lab import LabNetwork
from smtp_servers import Script, smtp_server
from worlds import DOMAIN, EHLO, NOW, changed, healthy, with_smtp

CHECKS = ("mail.mta_sts", "mail.smtp_starttls")
MX = f"mx1.{DOMAIN}"
URL = f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt"


class HeldPolicy(LabNetwork):
    """The laboratory's network, where the HTTPS request of the MTA-STS policy never gets an answer."""

    async def http_get(self, url: str, *, verify: bool = False):
        assert url == URL
        await asyncio.Event().wait()


def test_p1_a_held_policy_never_costs_the_smtp_observations(tmp_path):
    """P1, T03, F02, F06: CHECK_TIMEOUT = 4 (deadline 2 s), the MX answers at once with a valid certificate,
    the policy is held forever. The SMTP check returns before the engine stops it, with its observations
    (TLS verified, F05.10) and the policy said unreadable at the deadline: readiness unconfirmed. Only
    mail.mta_sts, waiting for its own answer, ends with the engine's timeout."""
    (tmp_path / "lab").mkdir()
    pki = TestPki(tmp_path / "lab")
    zone = {DOMAIN: {"MX": [f"10 {MX}."]}, MX: {"A": ["127.0.0.2"]},
            f"_mta-sts.{DOMAIN}": {"TXT": ['"v=STSv1; id=20261107"']}, f"mta-sts.{DOMAIN}": {"A": ["127.0.0.9"]}}
    registry = Registry.discover()

    async def main(check_ids):
        async with dns_server(zone) as (_, dns_port), \
                smtp_server(Script(tls=pki.server_context(MX)), "127.0.0.2") as (_, port):
            net = HeldPolicy([LOOPBACK], timeout=2, dns_port=dns_port, smtp_port=port, pki=pki, domain=DOMAIN,
                             ehlo_name=EHLO)
            start = time.monotonic()
            result = await engine.scan(DOMAIN, [registry.get(c) for c in check_ids], net, timeout=4,
                                       smtp=SmtpSettings(True, EHLO))
            return {f.check_id: f for f in result.findings}, time.monotonic() - start

    alone, elapsed = asyncio.run(main(["mail.smtp_starttls"]))
    assert 2.0 <= elapsed < 4 - 1  # back at its deadline, long before the engine's 4 s
    both, _ = asyncio.run(main(CHECKS))
    for findings in (alone, both):
        finding = findings["mail.smtp_starttls"]
        assert (finding.status, finding.outcome.evidence["rule"]) == (Status.OK, "F05.10")
        address = finding.outcome.evidence["mx"][0]["addresses"][0]
        assert address["seen"] == "verified" and address["observations"][0]["dialogue"]["tls_version"]
        readiness = finding.outcome.evidence["readiness"]
        assert (readiness["state"], readiness["causes"]) == ("unconfirmed", ["policy_unreadable"])
        assert readiness["policy"]["detail"] == "deadline"
    assert both["mail.mta_sts"].outcome.summary == "check.error.timeout"


# ------------------------------------------------------------------ R6: the grouped recheck
def scanner(tmp_path, data: dict, probe: bool, nets: list) -> Scanner:
    config = Config(data_dir=tmp_path, smtp_probe=probe, smtp_ehlo_name=EHLO if probe else None)

    def factory(domain: str) -> FixtureNetwork:
        nets.append(FixtureNetwork(data, NOW, domain=domain, ehlo_name=EHLO if probe else None))
        return nets[-1]

    return Scanner(Registry.discover(), config, network_factory=factory)


@pytest.mark.parametrize("check_id", CHECKS)
def test_r6_either_check_rechecks_both_on_one_reading(tmp_path, check_id):
    """R6, F06: rechecking mail.mta_sts or mail.smtp_starttls gives both findings, from one network and one
    reading of the policy (the HTTPS request made once)."""
    nets: list = []
    s = scanner(tmp_path, with_smtp(healthy(), {"192.0.2.25": "tls_verified"}), True, nets)
    findings = asyncio.run(s.recheck_group(DOMAIN, check_id))
    assert sorted(f.check_id for f in findings) == sorted(CHECKS)
    assert len(nets) == 1 and nets[0].asked.count(f"http {URL}") == 1
    by_id = {f.check_id: f for f in findings}
    assert by_id["mail.mta_sts"].status is Status.OK and by_id["mail.smtp_starttls"].status is Status.OK


def test_r6_with_the_probe_off_the_recheck_gives_na_and_no_smtp(tmp_path):
    """R6, F05.01: probe off, rechecking mail.mta_sts gives the SMTP check NA, without any SMTP attempt."""
    nets: list = []
    s = scanner(tmp_path, with_smtp(healthy(), {"192.0.2.25": "tls_verified"}), False, nets)
    by_id = {f.check_id: f for f in asyncio.run(s.recheck_group(DOMAIN, "mail.mta_sts"))}
    assert by_id["mail.smtp_starttls"].status is Status.NA
    assert not [q for q in nets[0].asked if q.startswith("smtp ")]


def test_r6_an_unreadable_policy_leaves_the_smtp_verdict_to_its_observations(tmp_path):
    """R6, R4, F05.06, F06: the policy request times out: mail.mta_sts is an error of the engine, the SMTP
    check keeps its own verdict (a refused certificate without enforce in force: WARN) and says the policy
    unreadable."""
    nets: list = []
    data = changed(with_smtp(healthy(), {"192.0.2.25": "certificate_refused"}), http={URL: "timeout"})
    s = scanner(tmp_path, data, True, nets)
    by_id = {f.check_id: f for f in asyncio.run(s.recheck_group(DOMAIN, "mail.smtp_starttls"))}
    assert by_id["mail.mta_sts"].outcome.summary == "check.error.network_timeout"
    smtp = by_id["mail.smtp_starttls"]
    assert (smtp.status, smtp.outcome.evidence["rule"]) == (Status.WARN, "F05.06")
    assert smtp.outcome.evidence["readiness"]["policy"]["state"] == "unreadable"


def test_r6_other_checks_are_rechecked_alone(tmp_path):
    """R6: a check outside the group (DMARC) is still rechecked alone."""
    nets: list = []
    s = scanner(tmp_path, healthy(), True, nets)
    assert [f.check_id for f in asyncio.run(s.recheck_group(DOMAIN, "mail.dmarc"))] == ["mail.dmarc"]
