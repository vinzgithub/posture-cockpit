# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The real behaviour of TLS 1.2 and TLS 1.3, beside the synthetic fixtures (precision 3 of the review of R1).

Real OpenSSL servers and clients of the bench talk through a recording relay (servers.Relay). For each
exchange, two independent views must agree:

- what OpenSSL itself reports (version and suite negotiated, or the reason of its refusal);
- what the bench's strict reader (wire.py) reads in the server's first flight, as recorded.

This checks the reader, and so the oracle of the catalogue, against the real thing: the TLS 1.2 ServerHello
and its ServerKeyExchange (ECDHE curve, DHE prime size), the TLS 1.3 ServerHello and a real
HelloRetryRequest (its random is the constant of RFC 8446 §4.1.3), the alerts of a real refusal. Where the
``openssl`` tool is installed, it plays the peers the ``ssl`` module cannot (a TLS 1.3 suite or group chosen);
without it, those tests are skipped and counted as skipped.
"""

import shutil
import socket
import ssl
import subprocess
import time

import pytest

from tls_lab import scenarios, servers, wire
from tls_lab.servers import Relay, ServerConfig, TlsServer

OPENSSL = shutil.which("openssl")


def suite_codes() -> dict[str, int]:
    """IANA codes of the suites this OpenSSL knows, by OpenSSL name (from the library, not from the bench)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    return {c["name"]: c["id"] & 0xFFFF for c in ctx.get_ciphers()}


def through_relay(config: ServerConfig, certs, client: ssl.SSLContext):
    """One real handshake through the recording relay: what OpenSSL reports, and the server's first flight."""
    with TlsServer(config, certs) as server, Relay(server.address) as relay:
        outcome = servers.handshake(relay.address, client)
        deadline = time.monotonic() + 5
        while not relay.transcripts or not relay.transcripts[0].to_client:
            assert time.monotonic() < deadline, "nothing recorded"
            time.sleep(0.01)
        time.sleep(0.05)
        recorded = bytes(relay.transcripts[0].to_client)
    return outcome, server.outcomes, wire.plaintext_prefix(recorded)


TLS12 = [
    ("ecdhe-p256", ServerConfig("ecdhe-p256", maximum="TLS1.2", ciphers="ECDHE-RSA-AES128-GCM-SHA256",
                                curve="prime256v1"), {"group": 0x0017}),
    ("ecdhe-x25519", ServerConfig("ecdhe-x25519", maximum="TLS1.2", ciphers="ECDHE-RSA-AES256-GCM-SHA384",
                                  curve="X25519"), {"group": 0x001D}),
    ("ecdhe-p384-cbc", ServerConfig("ecdhe-p384-cbc", maximum="TLS1.2", ciphers="ECDHE-RSA-AES128-SHA",
                                    curve="secp384r1"), {"group": 0x0018}),
    ("chacha20", ServerConfig("chacha20", maximum="TLS1.2", ciphers="ECDHE-RSA-CHACHA20-POLY1305"), {}),
    ("dhe-2048", ServerConfig("dhe-2048", maximum="TLS1.2", ciphers="DHE-RSA-AES128-GCM-SHA256", dh="dh2048.pem",
                              offer_class="legacy"), {"dh_bits": 2048}),
    ("ecdsa", ServerConfig("ecdsa", maximum="TLS1.2", ciphers="ECDHE-ECDSA-AES128-GCM-SHA256", cert="ec256"), {}),
]


@pytest.mark.parametrize(("name", "config", "expected"), TLS12, ids=[t[0] for t in TLS12])
def test_tls12_as_openssl_negotiates_it_and_as_the_reader_reads_it(certs, name, config, expected):
    client = servers.client_context(maximum="TLS1.2", ciphers=config.ciphers)  # Python's default list drops SHA-1
    outcome, served, flight = through_relay(config, certs, client)
    assert outcome.version == "TLS1.2" and served[0].suite == outcome.suite, outcome
    facts = wire.read_flight(flight)
    assert facts.kind == "server_hello" and facts.version == "TLS1.2"
    assert facts.suite == suite_codes()[outcome.suite]
    assert facts.messages[0] == wire.SERVER_HELLO and facts.messages[-1] == wire.SERVER_HELLO_DONE
    assert wire.SERVER_KEY_EXCHANGE in facts.messages and wire.CERTIFICATE in facts.messages
    for key, value in expected.items():
        assert getattr(facts, key) == value, (key, getattr(facts, key))


def test_tls12_dhe_with_a_1024_bit_prime_is_read_as_such(certs):
    """A legacy configuration (the extended level only), at security level 0 on both sides."""
    config = ServerConfig("dhe-1024", maximum="TLS1.2", ciphers="DHE-RSA-AES128-GCM-SHA256", seclevel=0,
                          dh="dh1024.pem", offer_class="legacy")
    outcome, _, flight = through_relay(config, certs, servers.client_context(maximum="TLS1.2", seclevel=0))
    assert outcome.version == "TLS1.2", outcome
    assert wire.read_flight(flight).dh_bits == 1024


def test_tls13_server_hello_as_openssl_negotiates_it(certs):
    outcome, _, flight = through_relay(ServerConfig("tls13", minimum="TLS1.3"), certs, servers.client_context())
    assert outcome.version == "TLS1.3", outcome
    first = wire.records(flight)[0]
    facts = wire.read_flight(wire.record(*first[:1], first[2], first[1]))
    assert facts.kind == "server_hello" and facts.version == "TLS1.3"
    assert facts.suite == suite_codes()[outcome.suite] and wire.SUITES[facts.suite].category == "tls13"
    assert facts.group in wire.GROUPS  # x25519, or X25519MLKEM768 with OpenSSL 3.5 and later


def test_a_real_hello_retry_request_names_the_group_the_server_wants(certs):
    """The server accepts only P-256; the client's first key share is another group: OpenSSL answers with a
    HelloRetryRequest whose random is the constant of RFC 8446, then the handshake completes."""
    config = ServerConfig("tls13-p256", minimum="TLS1.3", curve="prime256v1")
    outcome, _, flight = through_relay(config, certs, servers.client_context())
    assert outcome.version == "TLS1.3", outcome
    content_type, version, body = wire.records(flight)[0]
    assert body[6:38] == wire.HRR_RANDOM
    facts = wire.read_flight(wire.record(content_type, body, version))
    assert facts.kind == "hello_retry_request" and facts.version == "TLS1.3" and facts.group == 0x0017
    built = wire.read_flight(wire.flight(wire.hello_retry_request(facts.suite, 0x0017)))
    assert scenarios.facts_of(built) == scenarios.facts_of(facts)  # the synthetic HRR reads the same


@pytest.mark.parametrize(("server", "client", "alert", "reason"), [
    (ServerConfig("only-13", minimum="TLS1.3"), {"maximum": "TLS1.2"}, "protocol_version",
     "TLSV1_ALERT_PROTOCOL_VERSION"),
    (ServerConfig("aead-only", maximum="TLS1.2", ciphers="ECDHE-RSA-AES256-GCM-SHA384"),
     {"maximum": "TLS1.2", "ciphers": "AES128-SHA", "seclevel": 0}, "handshake_failure",
     "SSLV3_ALERT_HANDSHAKE_FAILURE"),
])
def test_a_real_refusal_is_the_alert_of_the_catalogue(certs, server, client, alert, reason):
    """What a real OpenSSL server sends when nothing of the offer suits it: the alert the catalogue's refusal
    scenarios hold, byte for byte apart from the record version."""
    outcome, _, flight = through_relay(server, certs, servers.client_context(**client))
    assert outcome.version is None and outcome.error == reason
    facts = wire.read_flight(flight)
    assert facts.kind == "alert" and facts.alert == alert and facts.alert_level == 2
    synthetic = {s.id: s for s in scenarios.load()[0]}[f"alert.{alert}"]
    assert flight[0] == synthetic.data[0] and flight[5:] == synthetic.data[5:]


@pytest.mark.parametrize("version", ["TLS1.0", "TLS1.1"])
def test_a_legacy_version_when_this_openssl_still_allows_it(certs, version):
    """Old versions at security level 0 (legacy, the extended level only); skipped where the library refuses."""
    config = ServerConfig(f"only-{version}", minimum=version, maximum=version, seclevel=0, offer_class="legacy")
    try:
        outcome, _, flight = through_relay(config, certs, servers.client_context(version, version, seclevel=0))
    except ssl.SSLError as error:
        pytest.skip(f"{version} refused by this OpenSSL: {error.reason}")
    if outcome.version is None:
        pytest.skip(f"{version} refused by this OpenSSL: {outcome.error}")
    facts = wire.read_flight(flight)
    assert facts.version == version == outcome.version and facts.suite == suite_codes()[outcome.suite]


# ------------------------------------------------------------- openssl as the peer the ssl module cannot be
def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def s_server(certs):
    """``openssl s_server`` on 127.0.0.1 with the given options, stopped after the test."""
    if not OPENSSL:
        pytest.skip("openssl is not installed")
    started = []

    def start(*options: str) -> tuple[str, int]:
        port = free_port()
        cert, key = certs["rsa2048"]
        command = [OPENSSL, "s_server", "-accept", f"127.0.0.1:{port}", "-cert", str(cert),
                   "-key", str(key), "-quiet", *options]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,  # noqa: S603 - the bench's own arguments
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        started.append(process)
        deadline = time.monotonic() + 5
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                assert process.poll() is None, process.stderr.read().decode()
                assert time.monotonic() < deadline, "s_server did not start"
                time.sleep(0.05)
        return "127.0.0.1", port

    yield start
    for process in started:
        process.kill()
        process.wait(5)


def s_client(address: tuple, *options: str) -> str:
    """Run ``openssl s_client`` once; returns what it printed (for the diagnosis of a refusal)."""
    command = [OPENSSL, "s_client", "-connect", f"{address[0]}:{address[1]}", *options]
    done = subprocess.run(command, input=b"", capture_output=True, timeout=10, check=False)  # noqa: S603 - the bench's own
    return (done.stdout + done.stderr).decode(errors="replace")


def recorded_by(address: tuple, *client_options: str) -> tuple[bytes, str]:
    with Relay(address) as relay:
        said = s_client(relay.address, *client_options)
        time.sleep(0.05)
        flight = wire.plaintext_prefix(bytes(relay.transcripts[0].to_client)) if relay.transcripts else b""
    return flight, said


def openssl_version() -> str:
    done = subprocess.run([OPENSSL, "version"], capture_output=True, timeout=5, check=False)  # noqa: S603
    return done.stdout.decode().strip()


def test_tls13_ccm_8_chosen_by_openssl_reads_as_the_catalogue_says(s_server):
    """The ssl module cannot offer CCM_8; openssl can: the suite code of the catalogue is the real one.

    At security level 0 on both sides. Some builds of openssl refuse it even so: the test is then skipped,
    counted, with the version and what openssl said, never passed by default."""
    suite = "TLS_AES_128_CCM_8_SHA256"
    level = ("-cipher", "ALL:@SECLEVEL=0")
    address = s_server("-ciphersuites", suite, "-tls1_3", *level)
    flight, said = recorded_by(address, "-tls1_3", "-ciphersuites", suite, *level)
    content_type, version, body = wire.records(flight)[0]
    facts = wire.read_flight(wire.record(content_type, body, version))
    if facts.kind == "alert":
        lines = [line for line in said.splitlines() if "error" in line.lower() or "alert" in line.lower()][:3]
        pytest.skip(f"{openssl_version()} refuses CCM_8 here (alert {facts.alert}): {' | '.join(lines)}")
    assert facts.version == "TLS1.3" and facts.suite == 0x1305 and wire.SUITES[0x1305].name == suite


def test_a_real_hello_retry_request_for_p384(s_server):
    """openssl chooses the groups on both sides: the client's first share is x25519, the server wants P-384."""
    address = s_server("-tls1_3", "-groups", "P-384")
    flight, _ = recorded_by(address, "-tls1_3", "-groups", "X25519:P-384")
    content_type, version, body = wire.records(flight)[0]
    facts = wire.read_flight(wire.record(content_type, body, version))
    assert facts.kind == "hello_retry_request" and facts.group == 0x0018
