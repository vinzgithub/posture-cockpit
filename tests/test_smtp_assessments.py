# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Opt-in MX assessments cannot conceal untested or unreachable mail exchangers."""
import pytest

from posture_cockpit.checks.smtp_probe import SmtpObservation
from posture_cockpit.checks.smtp_status import SmtpState, all_mx_verified
from posture_cockpit.core.egress import INTERNET
from posture_cockpit.core.engine import smtp_assessments
from posture_cockpit.core.network import DnsAnswer, NetworkError


class FakeNetwork:
    policy = INTERNET

    def __init__(self):
        self.visited = []

    async def dns(self, domain, kind):
        assert kind == "MX"
        return DnsAnswer(("10 mx1.example.org.", "20 mx2.example.org.", "30 mx3.example.org."))

    async def smtp_ehlo_for_domain(self, domain, host, *, verify_tls):
        self.visited.append(host)
        if host == "mx2.example.org":
            raise NetworkError("port 25 unreachable")
        return SmtpObservation(host, (), True, True, True)


@pytest.mark.asyncio
async def test_opt_in_only_and_every_mx_visible():
    net = FakeNetwork()
    assert await smtp_assessments("example.org", net) == ()
    assert net.visited == []
    results = await smtp_assessments("example.org", net, enabled=True, max_hosts=2)
    assert [r.state for r in results] == [
        SmtpState.VERIFIED, SmtpState.NOT_EVALUATED, SmtpState.NOT_EVALUATED,
    ]
    assert results[1].reason == "probe_failed"
    assert results[2].reason == "not_probed"
    assert net.visited == ["mx1.example.org", "mx2.example.org"]
    assert not all_mx_verified(
        ("mx1.example.org", "mx2.example.org", "mx3.example.org"), results
    )


@pytest.mark.asyncio
async def test_invalid_limit_before_any_dns():
    with pytest.raises(ValueError, match="host limit"):
        await smtp_assessments("example.org", FakeNetwork(), enabled=True, max_hosts=6)
