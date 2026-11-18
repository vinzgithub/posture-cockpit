# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The guard of the bench refuses, before any packet, whatever is not this machine (precision 5)."""

import ipaddress
import socket
import subprocess

import pytest

from posture_cockpit.core import egress
from tls_lab import guard
from tls_lab.responders import Behaviour, Responder, exchange

TEST_NET = "192.0.2.10"  # RFC 5737: documentation addresses, never routed


@pytest.mark.parametrize("address", [(TEST_NET, 443), ("2001:db8::1", 443), ("8.8.8.8", 53)])
def test_a_connection_elsewhere_is_refused_before_it_is_made(address):
    family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    if family == socket.AF_INET6 and not guard.can_bind(guard.LOOPBACK_V6):
        pytest.skip("no IPv6 on this machine")
    with socket.socket(family, socket.SOCK_STREAM) as sock, pytest.raises(guard.NotLoopback):
        sock.connect(address)


def test_a_datagram_a_bind_and_a_name_elsewhere_are_refused():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, pytest.raises(guard.NotLoopback):
        udp.sendto(b"x", (TEST_NET, 53))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, pytest.raises(guard.NotLoopback):
        tcp.bind(("0.0.0.0", 0))
    with pytest.raises(guard.NotLoopback):
        socket.getaddrinfo("example.com", 443)
    with pytest.raises(guard.NotLoopback):
        socket.create_connection(("example.com", 443), timeout=1)


def test_only_openssl_may_run_and_only_towards_this_machine():
    with pytest.raises(guard.NotLoopback):
        subprocess.run(["curl", "https://example.com"], check=False)  # noqa: S607 - refused before it runs
    with pytest.raises(guard.NotLoopback):
        subprocess.run(["openssl", "s_client", "-connect", f"{TEST_NET}:443"], check=False)  # noqa: S603,S607
    assert guard._openssl_ok(["openssl", "s_client", "-connect", "127.0.0.1:4433"])
    assert guard._openssl_ok(["/usr/bin/openssl", "s_server", "-accept", "[::1]:4433"])


def test_this_machine_stays_reachable():
    with Responder(Behaviour("reply", b"hello")) as responder:
        assert exchange(responder.address, b"\x16\x03\x01\x00\x00") == (b"hello", "closed")


def test_the_guard_is_off_outside_the_bench_and_the_egress_policy_untouched():
    """The guard acts only while a test of the bench runs; the product's policy still refuses the loopback."""
    assert guard.active()
    with guard.loopback_only():
        pass
    assert not guard.active()  # the nested guard turned it off; the fixture's own exit is idempotent
    guard._state["on"] = True
    with pytest.raises(egress.DestinationBlocked):
        egress.EgressPolicy().check("localhost", ipaddress.ip_address("127.0.0.1"), 443)
