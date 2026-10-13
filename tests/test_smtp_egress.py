# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail-closed public MX selection tests; no network access."""

import pytest

from posture_cockpit.checks.smtp_egress import allowed_smtp_mx_addresses


def test_accepts_only_public_ips_for_declared_mx():
    assert allowed_smtp_mx_addresses(
        "MX.Example.ORG.", ["mx.example.org"], ["8.8.8.8", "2001:4860:4860::8888"]
    ) == ("8.8.8.8", "2001:4860:4860::8888")


@pytest.mark.parametrize(("host", "mx", "addresses", "internal"), [
    ("not-mx.example.org", ["mx.example.org"], ["8.8.8.8"], False),
    ("127.0.0.1", ["127.0.0.1"], ["127.0.0.1"], False),
    ("mx.example.org", ["mx.example.org"], ["127.0.0.1"], False),
    ("mx.example.org", ["mx.example.org"], ["169.254.169.254"], False),
    ("mx.example.org", ["mx.example.org"], ["192.168.1.10"], False),
    ("mx.example.org", ["mx.example.org"], ["8.8.8.8", "10.0.0.1"], False),
    ("mx.example.org", ["mx.example.org"], [], False),
    ("mx.example.org", ["mx.example.org"], ["8.8.8.8"], True),
])
def test_refuses_unsafe_smtp_destinations(host, mx, addresses, internal):
    with pytest.raises(ValueError):
        allowed_smtp_mx_addresses(host, mx, addresses, internal=internal)



@pytest.mark.parametrize("host", [
    "mx.example.org\n", "mx..example.org", "-mx.example.org",
    "mx-.example.org", "mx_example.org", "localhost",
    "a" * 64 + ".example.org", "mx.example.org:25",
])
def test_rejects_invalid_mx_hostnames(host):
    with pytest.raises(ValueError, match="eligible declared MX"):
        allowed_smtp_mx_addresses(host, [host], ["8.8.8.8"])
