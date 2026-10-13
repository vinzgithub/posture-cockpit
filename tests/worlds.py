# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Recorded answers for test domains, and a helper to run checks against them."""

import asyncio
import base64
import copy
from datetime import UTC, datetime
from functools import cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from posture_cockpit.core import engine
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import Finding
from posture_cockpit.core.registry import Registry

DOMAIN = "example.org"
NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)


@cache
def dkim_key(bits: int) -> str:
    """A DKIM public key of ``bits`` bits, base64. Below 1024 bits, cryptography refuses to make a key
    pair: a public key with an arbitrary modulus is enough to publish."""
    if bits < 1024:
        key = rsa.RSAPublicNumbers(65537, (1 << (bits - 1)) | 0x1234567 | 1).public_key()
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


def healthy() -> dict:
    """A domain where every check passes."""
    headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Server": "nginx",
    }
    cert = {"issuer": "Let's Encrypt", "expires_in_days": 60, "key_type": "EC", "key_bits": 256,
            "names": [DOMAIN, f"www.{DOMAIN}"]}
    return {
        "dns": {
            f"{DOMAIN} SOA": ["ns1.example.net. hostmaster.example.org. 1 7200 3600 1209600 300"],
            f"{DOMAIN} NS": ["ns1.example.net.", "ns2.example.net."],
            f"{DOMAIN} A": ["192.0.2.10"],
            f"www.{DOMAIN} A": ["192.0.2.10"],
            f"{DOMAIN} MX": ["10 mx.example.net."],
            f"{DOMAIN} TXT": ["v=spf1 mx include:_spf.example.net -all"],
            "_spf.example.net TXT": ["v=spf1 ip4:198.51.100.0/24 -all"],
            f"_dmarc.{DOMAIN} TXT": [f"v=DMARC1; p=reject; rua=mailto:dmarc@{DOMAIN}"],
            f"selector1._domainkey.{DOMAIN} TXT": [f"v=DKIM1; k=rsa; p={dkim_key(2048)}"],
            f"_mta-sts.{DOMAIN} TXT": ["v=STSv1; id=20261012"],
            f"_smtp._tls.{DOMAIN} TXT": [f"v=TLSRPTv1; rua=mailto:tls@{DOMAIN}"],
            f"{DOMAIN} DS": ["12345 13 2 ABCDEF"],
            f"{DOMAIN} DNSKEY": ["257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxL"],
            "mx.example.net A": ["192.0.2.25"],
            f"mta-sts.{DOMAIN} A": ["192.0.2.10"],
            f"{DOMAIN} CAA": ['0 issue "letsencrypt.org"'],
        },
        "certificates": {DOMAIN: dict(cert), f"www.{DOMAIN}": dict(cert)},
        "tls": {host: {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}
                for host in (DOMAIN, f"www.{DOMAIN}")},
        "http": {
            f"http://{DOMAIN}/": {"status": 301, "headers": {"Location": f"https://www.{DOMAIN}/"}},
            f"http://www.{DOMAIN}/": {"status": 301, "headers": {"Location": f"https://www.{DOMAIN}/"}},
            f"https://{DOMAIN}/": {"status": 301, "headers": {"Location": f"https://www.{DOMAIN}/"}},
            f"https://www.{DOMAIN}/": {"status": 200, "headers": headers},
            f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt":
                {"status": 200, "body": "version: STSv1\nmode: enforce\nmx: mx.example.net\nmax_age: 604800\n"},
            f"https://{DOMAIN}/.well-known/security.txt":
                {"status": 200, "body": f"Contact: mailto:security@{DOMAIN}\nExpires: 2027-10-01T00:00:00Z\n"},
        },
    }


def http_only_with_redirect_elsewhere() -> dict:
    """The domain as fournet.one was on 13 October 2026: plain HTTP redirects to another site,
    HTTPS on the domain itself never answers, DMARC in monitoring (p=none), MTA-STS in testing.
    The mail checks pass; the ten web and TLS checks cannot be evaluated (85/100, coverage 54 %)."""
    data = healthy()
    silent = {url: "timeout" for url in data["http"]
              if url.startswith((f"https://{DOMAIN}/", f"https://www.{DOMAIN}/"))}
    elsewhere = {"status": 301, "headers": {"Location": "https://elsewhere.example.net/"}}
    return changed(
        data,
        dns={f"_dmarc.{DOMAIN} TXT": [f"v=DMARC1; p=none; rua=mailto:dmarc@{DOMAIN}"]},
        http={**silent, f"http://{DOMAIN}/": elsewhere, f"http://www.{DOMAIN}/": elsewhere,
              f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt":
                  {"status": 200, "body": "version: STSv1\nmode: testing\nmx: mx.example.net\nmax_age: 604800\n"}},
        certificates={host: "timeout" for host in data["certificates"] if not host.startswith("mta-sts.")},
    )


def with_certificate(**values) -> dict:
    """The healthy domain, with these values for its certificates."""
    data = healthy()
    for host in data["certificates"]:
        data["certificates"][host].update(values)
    return data


def changed(data: dict, **sections) -> dict:
    """A copy of ``data`` with some answers replaced: changed(d, dns={"x TXT": [...]})."""
    result = copy.deepcopy(data)
    for section, values in sections.items():
        result[section].update(values)
    return result


def run(data: dict, *check_ids: str, domain: str = DOMAIN, registry: Registry | None = None) -> dict[str, Finding]:
    """Runs some checks (all of them when none is given) and returns their findings by id."""
    registry = registry or Registry.discover()
    checks = [registry.get(c) for c in check_ids] if check_ids else registry.checks()
    result = asyncio.run(engine.scan(domain, checks, FixtureNetwork(data, NOW), timeout=5, now=NOW))
    return {f.check_id: f for f in result.findings}


def one(data: dict, check_id: str, registry: Registry | None = None) -> Finding:
    return run(data, check_id, registry=registry)[check_id]
