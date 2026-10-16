# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The recorded network must judge certificate dates as the real network does (version 0.4).

Until 0.3.2, a recorded certificate that had expired was still "trusted" by the
fixture: the HTTPS check passed, and the expired-certificate world scored 88/A,
when the real network (where verification checks the dates) gives 78/B. These
tests pin the real behaviour first, then the fixture's.
"""

from __future__ import annotations

import asyncio
from ipaddress import ip_network

import pytest

from local_servers import LOOPBACK, TestPki, dns_server, http_reply, http_server
from posture_cockpit.core import UntrustedCertificate, scoring
from posture_cockpit.core.egress import EgressPolicy
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.network import LiveNetwork
from worlds import DOMAIN, NOW, run, with_certificate


@pytest.fixture(autouse=True)
def no_proxy(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)


def _real(tmp_path, days: int, valid_from_days: int):
    """What the real network says of a server whose certificate has these dates."""
    pki = TestPki(tmp_path)

    async def main():
        async with dns_server({"site.lab": {"A": [LOOPBACK]}}) as (_, dns_port), \
                http_server(http_reply(), tls=pki.server_context("site.lab", days=days,
                                                                 valid_from_days=valid_from_days)) as (_, port):
            policy = EgressPolicy(networks=(ip_network("127.0.0.1/32"),), ports=frozenset({port}), name="lab")
            net = LiveNetwork([LOOPBACK], 3, policy=policy, dns_port=dns_port, trusted_ca=pki.pem)
            cert = await net.certificate("site.lab", port)
            with pytest.raises(UntrustedCertificate) as refused:
                await net.http_get(f"https://site.lab:{port}/", verify=True)
            return cert, refused.value

    return asyncio.run(main())


def _fixture(**values):
    net = FixtureNetwork(with_certificate(**values), NOW)

    async def main():
        cert = await net.certificate(f"www.{DOMAIN}")
        with pytest.raises(UntrustedCertificate) as refused:
            await net.http_get(f"https://www.{DOMAIN}/", verify=True)
        return cert, refused.value

    return asyncio.run(main())


def test_the_real_network_does_not_trust_an_expired_certificate(tmp_path):
    cert, refused = _real(tmp_path, days=-3, valid_from_days=-30)
    assert not cert.trusted and cert.problem == "certificate has expired"
    assert refused.problem == "certificate has expired"


def test_the_real_network_does_not_trust_a_certificate_not_yet_valid(tmp_path):
    cert, refused = _real(tmp_path, days=60, valid_from_days=5)
    assert not cert.trusted and cert.problem == "certificate is not yet valid"
    assert refused.problem == "certificate is not yet valid"


def test_the_fixture_judges_an_expired_certificate_as_the_real_network(tmp_path):
    real, _ = _real(tmp_path, days=-3, valid_from_days=-30)
    cert, refused = _fixture(expires_in_days=-3)
    assert (cert.trusted, cert.problem) == (real.trusted, real.problem)
    assert refused.problem == real.problem


def test_the_fixture_judges_a_certificate_not_yet_valid_as_the_real_network(tmp_path):
    real, _ = _real(tmp_path, days=60, valid_from_days=5)
    cert, refused = _fixture(expires_in_days=60, lifetime_days=55)  # valid from 5 days from now
    assert (cert.trusted, cert.problem) == (real.trusted, real.problem)
    assert refused.problem == real.problem


def test_a_problem_given_by_the_world_wins_over_the_dates():
    cert, refused = _fixture(expires_in_days=-3, trusted=False, problem="self-signed certificate")
    assert cert.problem == refused.problem == "self-signed certificate"


def test_the_expired_certificate_world_scores_as_on_the_real_network():
    """The certificate check finds it expired. Until step 2 the HTTPS root refused it too (78 B, two
    critical for one fault); from step 3 (matrix M39, option Q4-B) the root is compliant and the
    authentication cap applies: 79 B."""
    findings = run(with_certificate(expires_in_days=-3))
    assert findings["tls.certificate"].outcome.summary == "tls.certificate.expired"
    assert findings["web.https_redirect"].outcome.summary == "web.https_redirect.ok"
    result = scoring.assess(list(findings.values()))
    assert (result.score, result.grade, result.cap_reasons) == (79, "B", (scoring.CAP_AUTHENTICATION,))
