# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A :class:`~.network.Network` that answers from recorded data instead of the Internet.

Used by the tests and by the demo domain. The data is a plain dictionary
(usually loaded from JSON)::

    {
      "dns": {
        "example.org TXT": ["v=spf1 include:_spf.example.net -all"],
        "_dmarc.example.org TXT": [],          # the name exists, no record
        "old.example.org A": null              # the name does not exist (NXDOMAIN)
      },
      "certificates": {
        "www.example.org": {"issuer": "Let's Encrypt", "expires_in_days": 9, "key_type": "RSA",
                            "key_bits": 2048, "trusted": true, "protocol": "TLSv1.3"}
      },
      "tls": {"www.example.org": {"TLSv1": false, "TLSv1.1": false, "TLSv1.2": true, "TLSv1.3": true}},
      "http": {
        "https://www.example.org/": {"status": 200, "headers": {"Strict-Transport-Security": "max-age=31536000"}}
      }
    }

A DNS question that is not listed gets an empty answer. A certificate, TLS
version or URL that is not listed raises :class:`~.network.Refused`, as a
server with nothing listening would; the value ``"timeout"`` (for a URL, a
certificate or a DNS question) raises :class:`~.errors.ConnectionTimedOut`, as
LiveNetwork does. ``http_get(url, verify=True)`` raises
:class:`~.network.UntrustedCertificate` when the URL's host has a certificate
listed with ``"trusted": false``. Certificate dates are given relative to ``now`` so a
demo always looks the same, whatever the day.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from .errors import ConnectionTimedOut
from .network import Certificate, DnsAnswer, HttpReply, Refused, UntrustedCertificate


class FixtureNetwork:
    def __init__(self, data: Mapping[str, Any], now: datetime | None = None):
        self.now = now or datetime.now(UTC)
        self._dns = {self._dns_key(*key.rsplit(" ", 1)): value for key, value in data.get("dns", {}).items()}
        self._certificates = data.get("certificates", {})
        self._tls = data.get("tls", {})
        self._http = data.get("http", {})
        # Every question asked, in order: the tests use it to prove a check stays passive.
        self.asked: list[str] = []

    @staticmethod
    def _dns_key(name: str, rtype: str) -> str:
        return f"{name.lower().rstrip('.')} {rtype.upper()}"

    async def dns(self, name: str, rtype: str) -> DnsAnswer:
        key = self._dns_key(name, rtype)
        self.asked.append(f"dns {key}")
        if key not in self._dns:
            return DnsAnswer(())
        records = self._dns[key]
        if records is None:
            return DnsAnswer((), exists=False)
        if records == "timeout":
            raise ConnectionTimedOut(f"DNS {key}: Timeout")
        return DnsAnswer(tuple(records))

    async def certificate(self, host: str, port: int = 443) -> Certificate:
        self.asked.append(f"certificate {host}")
        if host not in self._certificates:
            raise Refused(f"TLS {host}:{port}: connection refused")
        if self._certificates[host] == "timeout":
            raise ConnectionTimedOut(f"TLS {host}:{port}: timeout")
        c = self._certificates[host]
        expires = self.now + timedelta(days=float(c.get("expires_in_days", 90)))
        return Certificate(
            host=host, subject=c.get("subject", host), names=tuple(c.get("names", [host])),
            issuer=c.get("issuer", "Let's Encrypt"),
            not_before=expires - timedelta(days=float(c.get("lifetime_days", 90))), not_after=expires,
            key_type=c.get("key_type", "EC"), key_bits=int(c.get("key_bits", 256)),
            trusted=bool(c.get("trusted", True)), problem=c.get("problem", ""), protocol=c.get("protocol", "TLSv1.3"),
        )

    async def accepts_tls(self, host: str, version: str, port: int = 443) -> bool | None:
        self.asked.append(f"tls {host} {version}")
        if host not in self._tls:
            raise Refused(f"TLS {host}:{port}: connection refused")
        return self._tls[host].get(version)

    async def http_get(self, url: str, *, verify: bool = False) -> HttpReply:
        self.asked.append(f"http {url}")
        if url not in self._http:
            raise Refused(f"HTTP {url}: connection refused")
        if self._http[url] == "timeout":
            raise ConnectionTimedOut(f"HTTP {url}: ReadTimeout")
        host = urlsplit(url).hostname or ""
        certificate = self._certificates.get(host, {})
        if verify and url.startswith("https:") and not certificate.get("trusted", True):
            raise UntrustedCertificate(url, certificate.get("problem", "certificate not trusted"))
        r = self._http[url]
        headers = {name.lower(): value for name, value in r.get("headers", {}).items()}
        return HttpReply(url, int(r.get("status", 200)), headers, r.get("body", ""))
