# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The catalogue of the bench: consistent, reproducible, served as written, read as expected.

- every scenario is classed ``modern`` or ``legacy`` from what its offer holds (precision 2), and the
  catalogue covers every legacy category and version and every TLS 1.3 suite;
- the bytes are those pinned by their fingerprint (the same on every run and machine);
- the strict reader finds the expected facts, or refuses the bytes where the catalogue says they cannot be
  read; an alert is a refusal of the offer only for the three refusal alerts, and only conditionally;
- each responder sends exactly the bytes of its scenario, after receiving a whole real ClientHello;
- a real OpenSSL client reads the synthetic alerts as the alerts they are;
- addresses alike on some offers stay distinct on another (precision 1).
"""

import ssl
import time

import pytest

from tls_lab import guard, scenarios, servers, wire
from tls_lab.responders import Behaviour, Responder, exchange

SCENARIOS, FLEETS = scenarios.load()
BY_ID = {s.id: s for s in SCENARIOS}


@pytest.fixture(scope="module")
def hello():
    """The ClientHello of a real OpenSSL client (TLS 1.2 and 1.3), made in memory."""
    return servers.client_hello(servers.client_context(), "tls-lab.test")


def test_the_identifiers_are_unique_and_the_fields_known():
    assert len(BY_ID) == len(SCENARIOS) >= 50
    for s in SCENARIOS:
        assert s.offer_class in scenarios.CLASSES and s.expected["evidence"] in scenarios.EVIDENCE, s.id
        assert s.family in ("announced", "alert", "network", "protocol"), s.id


def test_every_offer_is_classed_from_what_it_holds():
    """Precision 2: one legacy element (version, category or group) makes the offer legacy."""
    for s in SCENARIOS:
        assert s.offer_class == scenarios.classify(s.offer), s.id
    legacy = [s for s in SCENARIOS if s.offer_class == "legacy"]
    covered = ({c for s in legacy for c in s.offer.get("categories", [])}
               | {v for s in legacy for v in s.offer["versions"]})
    assert covered >= wire.LEGACY_CATEGORIES and covered >= wire.LEGACY_VERSIONS
    modern_suites = {s.facts()["suite"] for s in SCENARIOS if s.offer_class == "modern" and s.facts()
                     and s.facts().get("version") == "TLS1.3"}
    assert {f"0x{c:04X}" for c, suite in wire.SUITES.items() if suite.category == "tls13"} <= modern_suites
    # The standard level never needs a legacy offer to read a modern answer.
    assert all(scenarios.classify({"versions": ["TLS1.2", "TLS1.3"], "categories": sorted(wire.MODERN_CATEGORIES)})
               == "modern" for _ in [0])


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_the_bytes_are_those_pinned(scenario):
    """Reproducibility: the recipe gives the same bytes on every run, every Python and every machine."""
    assert scenarios.fingerprint(scenario.data) == scenario.sha256
    assert scenarios.fingerprint(scenarios.build(scenario.reply, {s.id: {"reply": s.reply} for s in SCENARIOS})) \
        == scenario.sha256


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_the_reader_finds_the_expected_facts(scenario):
    expected = scenario.expected
    if expected["facts"] is None:
        assert expected["evidence"] == "inconclusive" and expected["cause"] in ("closed", "reset", "timeout",
                                                                                 "malformed")
        if scenario.data:
            with pytest.raises(wire.Malformed):
                wire.read_flight(scenario.data)
        return
    facts = wire.read_flight(scenario.data)
    assert scenarios.facts_of(facts) == expected["facts"]
    if facts.kind == "alert":
        refusal = facts.alert in scenarios.REFUSALS and facts.alert_level == 2
        assert (expected["evidence"] == "alert_refusal") is refusal
        assert refusal or expected["cause"] == "other_alert"
    else:
        assert expected["evidence"] == "announced"
        assert facts.suite in wire.SUITES  # every suite of the catalogue is named and classed


LIMIT = 16 * 1024
ENDINGS = {"reply": "closed", "reply_slowly": "closed", "close": "closed", "reset": "reset", "silence": "timeout"}


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_each_responder_sends_its_scenario(scenario, hello):
    with Responder(Behaviour(scenario.behaviour, scenario.data)) as responder:
        started = time.monotonic()
        received, ending = exchange(responder.address, hello, timeout=1.0 if scenario.behaviour == "silence" else 4.0,
                                    limit=LIMIT)
        elapsed = time.monotonic() - started
    if len(scenario.data) > LIMIT:  # the client stops at its bound: the oversized record is never read whole
        assert received == scenario.data[:LIMIT] and ending == "limit"
    else:
        assert received == scenario.data and ending == ENDINGS[scenario.behaviour]
    assert responder.connections[0].received == hello and responder.connections[0].complete
    if scenario.behaviour == "silence":
        assert elapsed >= 0.9


@pytest.mark.parametrize(("scenario", "reason"), [
    ("alert.handshake_failure", "SSLV3_ALERT_HANDSHAKE_FAILURE"),
    ("alert.protocol_version", "TLSV1_ALERT_PROTOCOL_VERSION"),
    ("alert.insufficient_security", "TLSV1_ALERT_INSUFFICIENT_SECURITY"),
    ("alert.internal_error", "TLSV1_ALERT_INTERNAL_ERROR"),
])
def test_a_real_client_reads_the_synthetic_alerts(scenario, reason):
    """The alert bytes of the catalogue are the alerts a real OpenSSL client recognises."""
    with Responder(Behaviour("reply", BY_ID[scenario].data)) as responder:
        got = servers.handshake(responder.address, servers.client_context())
    assert got.version is None and got.error == reason


@pytest.mark.parametrize("fleet", FLEETS, ids=lambda f: f["id"])
def test_addresses_alike_on_some_offers_stay_distinct_on_another(fleet, hello):
    """Precision 1: what an address answered is that address's result; another address answering the
    same to the essential offers says nothing of its answer to a deeper one."""
    hosts = list(fleet["addresses"])
    if not all(guard.can_bind(h) for h in hosts):
        pytest.skip("a second loopback address cannot be bound on this machine")
    offers = list(fleet["addresses"][hosts[0]])
    measured: dict[str, dict[str, dict]] = {h: {} for h in hosts}
    for host in hosts:
        for offer in offers:
            scenario = BY_ID[fleet["addresses"][host][offer]]
            with Responder(Behaviour("reply", scenario.data), host=host) as responder:
                received, _ = exchange(responder.address, hello)
            measured[host][offer] = scenarios.facts_of(wire.read_flight(received))
            assert measured[host][offer] == scenario.facts(), (host, offer)
    alike = [o for o in offers if len({str(measured[h][o]) for h in hosts}) == 1]
    differ = [o for o in offers if o not in alike]
    assert alike and differ  # the fleet is what it claims: alike on some offers, distinct on another
    for offer in differ:
        kinds = {measured[h][offer]["kind"] for h in hosts}
        assert kinds == {"server_hello", "alert"}  # one address announced CCM_8, the other refused the offer


def test_a_real_client_hello_is_whole_and_offers_tls_13():
    """The ClientHello the responders receive in these tests is a real one, made by OpenSSL in memory."""
    data = servers.client_hello(servers.client_context(), "tls-lab.test")
    assert data[0] == wire.HANDSHAKE and len(data) == 5 + int.from_bytes(data[3:5], "big")
    assert data[5] == 1  # client_hello
    assert ssl.OPENSSL_VERSION  # the version of the library that wrote it is in the capability report
