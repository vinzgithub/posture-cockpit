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
listed with ``"trusted": false``, or whose dates do not cover ``now`` (expired, or
not yet valid), as TLS verification does on the real network. Certificate dates are
given relative to ``now`` so a demo always looks the same, whatever the day.

Version 0.4: the questions asked of one address (``tls_at``, ``http_at``,
``accepts_tls_at``) follow the host's answers above by default, on every address
of the host: its certificate missing means port 443 refused, ``"timeout"`` means
no answer, and its ``tls`` versions say which offers succeed. A ``"web"`` section
changes what one address does, attempt after attempt::

    "web": {"example.org": {"192.0.2.10": {
        "443": ["reset", "ok"],                 # by attempt; or one value; or by offer:
                                                # {"default": "alert:handshake_failure", "*": "ok"}
        "versions": {"TLSv1": true},            # versions this address accepts, over the host's
        "certificate": {"expires_in_days": -3}, # this address's certificate, over the host's
        "80": {"status": 200},                  # http://host/ on this address, or "refused", "timeout"…
        "https": "reset",                       # https://host/ on this address, once TLS is up
        "http": {"https://example.org/x": {...}}  # any other URL on this address
    }}}

An outcome is ``"ok"`` (``"ok:TLSv1.2"`` to set the version), ``"refused"``,
``"reset"``, ``"close"``, ``"alert:<name>"``, ``"timeout"``, ``"hang"`` (no
answer until the caller gives up: for the deadlines), ``"unreachable"`` (no
route from here), ``"policy"`` (refused by the scan's rule) or ``"untestable"``
(this machine cannot offer that old version). A list gives one value per
attempt, the last one repeated. Every connection is logged in ``connections``
and counted in ``open_connections`` while it lasts.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import Counter
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

from .egress import DestinationBlocked
from .errors import (
    ConnectionClosed,
    ConnectionReset,
    ConnectionTimedOut,
    LegacyUnsupported,
    NetworkError,
    TLSAlert,
    TLSHandshakeError,
    Unreachable,
)
from .network import Certificate, DnsAnswer, HttpReply, Refused, TlsSession, UntrustedCertificate

MODERN = ("TLSv1.3", "TLSv1.2")
LEGACY = ("TLSv1.1", "TLSv1")


class FixtureNetwork:
    def __init__(self, data: Mapping[str, Any], now: datetime | None = None):
        self.now = now or datetime.now(UTC)
        self._dns = {self._dns_key(*key.rsplit(" ", 1)): value for key, value in data.get("dns", {}).items()}
        self._certificates = data.get("certificates", {})
        self._tls = data.get("tls", {})
        self._http = data.get("http", {})
        self._web = data.get("web", {})
        # Every question asked, in order: the tests use it to prove a check stays passive.
        self.asked: list[str] = []
        # Version 0.4: every connection to an address, and how many are open right now.
        self.connections: list[dict[str, Any]] = []
        self.open_connections = 0
        self.peak_connections = 0
        self._attempts: Counter[tuple] = Counter()
        self._accepts: dict[tuple, bool | None] = {}
        self._negotiated: set[tuple[str, str]] = set()

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
        self._negotiated.update((host, a) for a in self._addresses(host))
        return self._certificate(host, c, c.get("protocol", "TLSv1.3"))

    def _certificate(self, host: str, c: Mapping[str, Any], protocol: str) -> Certificate:
        not_before, not_after = self._validity(c)
        problem = self._problem(c)
        return Certificate(
            host=host, subject=c.get("subject", host), names=tuple(c.get("names", [host])),
            issuer=c.get("issuer", "Let's Encrypt"), not_before=not_before, not_after=not_after,
            key_type=c.get("key_type", "EC"), key_bits=int(c.get("key_bits", 256)),
            trusted=not problem, problem=problem, protocol=protocol,
        )

    def _addresses(self, host: str) -> list[str]:
        return [a for rtype in ("A", "AAAA") for a in (self._dns.get(self._dns_key(host, rtype)) or [])
                if isinstance(a, str)]

    def _validity(self, c: Mapping[str, Any]) -> tuple[datetime, datetime]:
        expires = self.now + timedelta(days=float(c.get("expires_in_days", 90)))
        return expires - timedelta(days=float(c.get("lifetime_days", 90))), expires

    def _problem(self, c: Mapping[str, Any]) -> str:
        """Why verification refuses this certificate, as the real network words it; "" when it does not.

        In order: a ``problem`` given by the world, with or without ``"trusted": false``;
        then ``"trusted": false`` alone (a generic problem); then the dates, as TLS verification
        checks them (until 0.3.2 an expired certificate was still trusted here). ``"trusted": true``
        never overrides the dates: the real network has no such switch."""
        problem = str(c.get("problem") or "")
        if problem:
            return problem
        if not c.get("trusted", True):
            return "certificate not trusted"
        not_before, not_after = self._validity(c)
        if self.now > not_after:
            return "certificate has expired"
        if self.now < not_before:
            return "certificate is not yet valid"
        return ""

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
        problem = self._problem(certificate) if isinstance(certificate, Mapping) else ""
        if verify and url.startswith("https:") and problem:
            raise UntrustedCertificate(url, problem)
        if url.startswith("https:"):
            self._negotiated.update((host, a) for a in self._addresses(host))
        r = self._http[url]
        headers = {name.lower(): value for name, value in r.get("headers", {}).items()}
        return HttpReply(url, int(r.get("status", 200)), headers, r.get("body", ""))

    # ------------------------------------------------- one address (0.4)
    def negotiated(self) -> frozenset[tuple[str, str]]:
        return frozenset(self._negotiated)

    def _at(self, host: str, address: str) -> Mapping[str, Any]:
        return self._web.get(host, {}).get(address, {})

    def _versions(self, host: str, address: str) -> Mapping[str, bool | None]:
        versions = dict(self._tls.get(host) or {"TLSv1.2": True, "TLSv1.3": True})
        versions.update(self._at(host, address).get("versions", {}))
        return versions

    def _derived(self, host: str, address: str, offer: str) -> str:
        """What port 443 of ``address`` does by default: what the host's answers say."""
        certificate = self._certificates.get(host)
        if certificate is None:
            return "refused"
        if certificate == "timeout":
            return "timeout"
        versions = self._versions(host, address)
        if offer == "default":
            accepted = [v for v in MODERN if versions.get(v)]
            return f"ok:{accepted[0]}" if accepted else "alert:tlsv1_alert_protocol_version"
        if versions.get(offer) is None and offer in LEGACY:
            return "untestable"
        return f"ok:{offer}" if versions.get(offer) else "alert:tlsv1_alert_protocol_version"

    def _tls_outcome(self, host: str, address: str, offer: str, consume: bool = True) -> str:
        """The outcome of this attempt; ``consume=False`` reads what the address does once settled."""
        spec = self._at(host, address).get("443")
        key: tuple = (host, address, "443")
        if isinstance(spec, Mapping):
            spec = spec.get(offer, spec.get("*"))
            key = (*key, offer)
        if spec is None:
            return self._derived(host, address, offer)
        if isinstance(spec, list):
            index = self._attempts[key] if consume else len(spec) - 1
            if consume:
                self._attempts[key] += 1
            spec = spec[min(index, len(spec) - 1)]
        if spec == "ok":  # answers normally: what its versions say for this offer ("ok:<version>" forces one)
            return self._derived(host, address, offer)
        return str(spec)

    @contextlib.asynccontextmanager
    async def _connection(self, kind: str, host: str, address: str, port: int, offer: str = "",
                          legacy: bool = False) -> AsyncIterator[None]:
        self.connections.append({"kind": kind, "host": host, "address": address, "port": port,
                                 "offer": offer, "legacy": legacy})
        self.open_connections += 1
        self.peak_connections = max(self.peak_connections, self.open_connections)
        try:
            yield
        finally:
            self.open_connections -= 1

    async def _fail(self, outcome: str, where: str, host: str, address: str, port: int, stage: str) -> None:
        """Raises what ``outcome`` stands for; returns for an "ok…" outcome."""
        if outcome.startswith("ok"):
            return
        error: NetworkError
        if outcome == "hang":
            await asyncio.Event().wait()  # until the caller is cancelled
            raise AssertionError("unreachable")
        if outcome == "refused":
            error, stage = Refused(f"{where}: connection refused"), "tcp"
        elif outcome == "reset":
            error = ConnectionReset(f"{where}: connection reset")
        elif outcome == "close":
            error = ConnectionClosed(f"{where}: connection closed")
        elif outcome.startswith("alert:"):
            error = TLSAlert(f"{where}: {outcome[6:]}", outcome[6:])
        elif outcome == "timeout":
            error = ConnectionTimedOut(f"{where}: no answer ({stage})")
        elif outcome == "unreachable":
            error, stage = Unreachable(f"{where}: network is unreachable"), "tcp"
        elif outcome == "untestable":
            error = LegacyUnsupported(f"{where}: this machine cannot offer this version")
        else:
            error = TLSHandshakeError(f"{where}: {outcome}")
        error.stage = stage
        raise error

    def _policy(self, outcome: str, host: str, address: str, port: int) -> None:
        if outcome == "policy":
            raise DestinationBlocked(host, ip_address(address), port, "private")

    async def tls_at(self, host: str, address: str, offer: str = "default", *, port: int = 443,
                     verify: bool = True) -> TlsSession:
        self.asked.append(f"tls {host} {address} {offer}")
        outcome = self._tls_outcome(host, address, offer)
        self._policy(outcome, host, address, port)
        async with self._connection("tls", host, address, port, offer, legacy=offer in LEGACY):
            await self._fail(outcome, f"TLS {host} ({address}) port {port}, {offer}", host, address, port, "tls")
        version = outcome[3:] if outcome.startswith("ok:") else _highest(offer)
        certificate = self._certificates.get(host)
        values = {**(certificate if isinstance(certificate, Mapping) else {}),
                  **self._at(host, address).get("certificate", {})}
        self._negotiated.add((host, address))
        return TlsSession(host, address, version, self._certificate(host, values, version))

    async def accepts_tls_at(self, host: str, address: str, version: str, *, port: int = 443) -> bool | None:
        key = (host, address, version, port)
        if key not in self._accepts:
            try:
                await self.tls_at(host, address, version, port=port, verify=False)
                self._accepts[key] = True
            except LegacyUnsupported:
                self._accepts[key] = None
            except (TLSHandshakeError, ConnectionReset):
                self._accepts[key] = False
        return self._accepts[key]

    async def http_at(self, url: str, address: str, *, offer: str = "default", cache: bool = True) -> HttpReply:
        self.asked.append(f"http {url} @{address}" + ("" if offer == "default" else f" {offer}"))
        legacy = offer in LEGACY
        parts = urlsplit(url)
        host = parts.hostname or ""
        https = parts.scheme == "https"
        port = parts.port or (443 if https else 80)
        where = f"HTTP {url} ({address})"
        at = self._at(host, address)
        shorthand = at.get("https" if https else "80") if parts.path in ("", "/") else None
        reply = at.get("http", {}).get(url, shorthand)
        if reply is None:
            reply = self._http.get(url, "refused")
        if https:  # the TLS part first, as on the network, with what the address does once settled
            tls = self._tls_outcome(host, address, offer, consume=False)
            self._policy(tls, host, address, port)
            if not tls.startswith("ok"):
                async with self._connection("http", host, address, port, legacy=legacy):
                    await self._fail(tls, where, host, address, port, "tls")
        if isinstance(reply, str):
            self._policy(reply, host, address, port)
        async with self._connection("http", host, address, port, legacy=legacy):
            if isinstance(reply, str):
                await self._fail(reply, where, host, address, port, "http")
                raise AssertionError(reply)
        if https:
            self._negotiated.add((host, address))
        headers = {name.lower(): value for name, value in reply.get("headers", {}).items()}
        return HttpReply(url, int(reply.get("status", 200)), headers, reply.get("body", ""))


def _highest(offer: str) -> str:
    return "TLSv1.3" if offer == "default" else offer
