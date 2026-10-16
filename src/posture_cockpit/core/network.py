# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Everything the checks may ask the outside world, behind one small interface.

Checks never open a socket themselves: they call the methods of :class:`Network`.
This keeps every check *passive* (DNS queries, a TLS handshake, one HTTP GET
without following redirects, nothing else) and lets the tests and the demo
replace the network with recorded answers (:mod:`.fixture`).

Version 0.4 adds the same questions asked of one given address of a name
(:meth:`LiveNetwork.tls_at`, :meth:`LiveNetwork.http_at`), for the HTTPS probe
(:mod:`.https_probe`) and the checks that depend on it: every published address
is tested, with the audited name as TLS SNI and HTTP ``Host``.

:class:`LiveNetwork` is the real implementation. One instance is used per scan:

- it remembers its answers, so two checks asking the same question send it once;
- it applies the :class:`~.egress.EgressPolicy` to every connection. A host name
  is resolved once per scan, each address is checked against the policy, and the
  socket is opened to that checked address (the name is only used for TLS SNI,
  certificate verification and the HTTP ``Host`` header). Redirections are not
  followed here: a check that follows one asks again, and the new destination
  goes through the same rule;
- it bounds what a scan may cost: a time limit on every operation and a maximum
  number of DNS queries and connections (:class:`Limits`).
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import socket
import ssl
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Protocol, TypeVar

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import h11
import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from .. import __version__
from . import legacy_tls
from .egress import INTERNET, Address, DestinationBlocked, EgressPolicy, parse_address
from .errors import (
    ConnectionClosed,
    ConnectionReset,
    ConnectionTimedOut,
    LegacyUnsupported,
    NetworkError,
    Refused,
    TLSAlert,
    TLSHandshakeError,
    Unreachable,
)

USER_AGENT = f"PostureCockpit/{__version__} (+https://github.com/vinzgithub/posture-cockpit)"
MAX_BODY = 64 * 1024  # bytes of a web page kept for the checks
TLS_VERSIONS = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
# Version 0.4: what a TLS attempt on one address offers. "default" is a browser's offer, TLS 1.2 and 1.3.
OFFERS: Mapping[str, tuple[str, str]] = {
    "default": ("TLSv1.2", "TLSv1.3"),
    "TLSv1.3": ("TLSv1.3", "TLSv1.3"),
    "TLSv1.2": ("TLSv1.2", "TLSv1.2"),
    "TLSv1.1": ("TLSv1.1", "TLSv1.1"),
    "TLSv1": ("TLSv1", "TLSv1"),
}
_TLS_VERSION = {"TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1.3": ssl.TLSVersion.TLSv1_3}
# No route from this machine: the address could not be tested from here (no IPv6, for instance).
_UNREACHABLE = frozenset({errno.ENETUNREACH, errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL})
# Errors of this machine's own TLS library, before anything reached the server.
_LOCAL_TLS = frozenset({"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE"})

__all__ = [
    "MAX_BODY", "OFFERS", "TLS_VERSIONS", "USER_AGENT", "Certificate", "DestinationBlocked", "DnsAnswer",
    "HttpReply", "Limits", "LiveNetwork", "Network", "NetworkError", "Refused", "TlsSession", "UntrustedCertificate",
]


class UntrustedCertificate(NetworkError):
    """Raised by ``http_get(url, verify=True)`` when the server's certificate is not valid.

    This is an answer, not a technical failure: the server was reached and
    presented a certificate this machine does not trust (``problem`` says why)."""

    def __init__(self, url: str, problem: str):
        self.url = url
        self.problem = problem
        super().__init__(f"HTTP {url}: certificate not trusted ({problem})")


@dataclass(frozen=True)
class DnsAnswer:
    """Records of one name and type, in their usual text form.

    TXT strings are joined without quotes; MX records read ``"10 mx.example.org."``."""

    records: tuple[str, ...] = ()
    exists: bool = True  # False when the name does not exist at all (NXDOMAIN)


@dataclass(frozen=True)
class Certificate:
    """The certificate a server presents, and whether this machine trusts it."""

    host: str
    subject: str
    names: tuple[str, ...]  # DNS names the certificate covers
    issuer: str
    not_before: datetime
    not_after: datetime
    key_type: str           # "RSA", "EC", "Ed25519"…
    key_bits: int
    trusted: bool           # chain verified (system store, plus the perimeter's CA) and name matches
    problem: str = ""       # why it is not trusted
    protocol: str = ""      # TLS version negotiated, e.g. "TLSv1.3"


@dataclass(frozen=True)
class TlsSession:
    """A TLS negotiation that succeeded on one address (version 0.4)."""

    host: str
    address: str
    version: str              # negotiated, e.g. "TLSv1.2"
    certificate: Certificate  # trusted and problem as a browser would judge it


@dataclass(frozen=True)
class HttpReply:
    url: str
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)  # lower-case names
    body: str = ""

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class Network(Protocol):
    """What a check may ask. Every method raises :class:`NetworkError` when it gets no answer.

    Implementations may define these methods with ``async def``."""

    def dns(self, name: str, rtype: str) -> Awaitable[DnsAnswer]: ...

    def certificate(self, host: str, port: int = 443) -> Awaitable[Certificate]: ...

    def accepts_tls(self, host: str, version: str, port: int = 443) -> Awaitable[bool | None]:
        """Whether the server accepts this TLS version (one of :data:`TLS_VERSIONS`).

        None when this machine cannot try it (its own TLS library refuses old versions)."""
        ...

    def http_get(self, url: str, *, verify: bool = False) -> Awaitable[HttpReply]:
        """One GET, without following redirects.

        By default the certificate of an ``https`` URL is not verified: the TLS
        checks judge it, and the other checks only read headers. With
        ``verify=True`` (a policy file that must be served over valid HTTPS, as
        MTA-STS requires), an invalid certificate raises :class:`UntrustedCertificate`."""
        ...

    # Version 0.4: one given address of a name, the name as SNI and Host.
    def tls_at(self, host: str, address: str, offer: str = "default", *, port: int = 443,
               verify: bool = True) -> Awaitable[TlsSession]:
        """One TLS negotiation with ``address``, offering :data:`OFFERS` ``[offer]``, then closed.

        Never cached: each call is one attempt. With ``verify``, a certificate that fails
        verification is still read (a second negotiation without verification) and returned
        untrusted, with the problem. Raises a :class:`NetworkError` that says where it stopped."""
        ...

    def accepts_tls_at(self, host: str, address: str, version: str, *, port: int = 443) -> Awaitable[bool | None]:
        """Whether ``address`` accepts this TLS version: a handshake only, closed at once.

        None when this machine cannot offer it. A timeout or a closed port raises."""
        ...

    def http_at(self, url: str, address: str, *, offer: str = "default", cache: bool = True) -> Awaitable[HttpReply]:
        """One GET of ``url`` on ``address``, without following redirects nor verifying the certificate.

        ``offer``: for an ``https`` URL, the TLS offer that negotiated with this address (:data:`OFFERS`);
        TLS 1.0 and 1.1 come from :mod:`.legacy_tls`, for an address that speaks nothing newer.
        ``cache=False``: not shared, and stopped with the caller (the probe)."""
        ...

    def negotiated(self) -> frozenset[tuple[str, str]]:
        """(name, address) of every TLS negotiation that succeeded so far in the scan."""
        ...


@dataclass(frozen=True)
class Limits:
    """What one scan may cost. Answers taken from the cache are free."""

    dns_queries: int = 400
    connections: int = 80            # TLS handshakes and HTTP requests
    operation_seconds: float = 20.0  # one question, all attempts included
    # Version 0.4: the HTTPS probe, by attempt; at worst 16 addresses, about 8 connections each.
    probe_connections: int = 160


T = TypeVar("T")


class LiveNetwork:
    """The real network. Create one per scan: it caches answers for that scan only.

    ``policy``: where connections may go (default: public addresses, ports 80 and 443).
    ``nameservers``: resolvers to query (IP addresses); empty means those of the system.
    ``trusted_ca``: extra certificate authorities in PEM, trusted on top of the
    system's (an internal CA). Certificate verification itself is never turned off."""

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 6.0, *,
                 policy: EgressPolicy = INTERNET, trusted_ca: str = "", dns_port: int = 53,
                 limits: Limits | None = None):
        self.timeout = timeout
        self.policy = policy
        self.limits = limits or Limits()
        self._trusted_ca = trusted_ca
        self._verified: ssl.SSLContext | None = None
        self._resolver = dns.asyncresolver.Resolver(configure=not nameservers)
        self._resolver.port = dns_port  # before the servers: dnspython applies it when they are set
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.lifetime = timeout
        self._cache: dict[tuple, asyncio.Future[Any]] = {}
        self._spent = {"dns": 0, "connections": 0, "probe": 0}
        self._contexts: dict[tuple[str, bool], ssl.SSLContext | None] = {}
        self._negotiated: set[tuple[str, str]] = set()

    async def _cached(self, key: tuple, make: Callable[[], Awaitable[T]]) -> T:
        # The task is shared: a second caller waits for the first answer.
        if key not in self._cache:
            self._spend("dns" if key[0] == "dns" else "connections")
            self._cache[key] = asyncio.ensure_future(self._bounded(key, make))
        # shield(): a caller that times out must not cancel the answer the others wait for.
        return await asyncio.shield(self._cache[key])

    def _spend(self, kind: str) -> None:
        allowed = {"dns": self.limits.dns_queries, "connections": self.limits.connections,
                   "probe": self.limits.probe_connections}[kind]
        if self._spent[kind] >= allowed:
            raise NetworkError(f"limit of {allowed} {kind} per scan reached")
        self._spent[kind] += 1

    async def _bounded(self, key: tuple, make: Callable[[], Awaitable[T]]) -> T:
        # Shielded work outlives the check that asked for it: it needs its own deadline.
        try:
            return await asyncio.wait_for(make(), self.limits.operation_seconds)
        except TimeoutError:
            seconds = self.limits.operation_seconds
            raise ConnectionTimedOut(f"{' '.join(map(str, key))}: no answer in {seconds:g} s") from None

    def close(self) -> None:
        """Cancels the work still running once the scan is over (left by checks that timed out)."""
        for task in self._cache.values():
            task.cancel()

    # ------------------------------------------------------------------ DNS
    async def dns(self, name: str, rtype: str) -> DnsAnswer:
        return await self._cached(("dns", name.lower().rstrip("."), rtype.upper()), lambda: self._dns(name, rtype))

    async def _dns(self, name: str, rtype: str) -> DnsAnswer:
        try:
            answer = await self._resolver.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer((), exists=False)
        except dns.exception.DNSException as e:  # timeout, no server answering, malformed name…
            raise (ConnectionTimedOut if isinstance(e, dns.exception.Timeout) else NetworkError)(
                f"DNS {rtype} {name}: {e.__class__.__name__}") from e
        if answer.rrset is None:
            return DnsAnswer(())
        return DnsAnswer(tuple(_record_text(r) for r in answer.rrset))

    # ---------------------------------------------------------- destinations
    async def _destinations(self, host: str, port: int) -> list[Address]:
        """Addresses to connect to for ``host:port``, all allowed by the policy.

        At most one IPv4 and one IPv6 address, IPv4 first. The name is resolved
        through :meth:`dns`, so once per scan: every connection of the scan goes
        to the addresses checked here. Raises :class:`DestinationBlocked` when
        every address of the name is refused."""
        literal = parse_address(host)
        if literal is not None:
            candidates = [literal]
        else:
            answers = await asyncio.gather(self.dns(host, "A"), self.dns(host, "AAAA"), return_exceptions=True)
            candidates = [address for answer in answers if isinstance(answer, DnsAnswer)
                          for address in map(parse_address, answer.records) if address is not None]
            if not candidates:
                error = next((a for a in answers if isinstance(a, BaseException)), None)
                if isinstance(error, NetworkError):
                    raise error
                raise NetworkError(f"{host}: no address")
        allowed: list[Address] = []
        refused: DestinationBlocked | None = None
        for address in candidates:
            try:
                self.policy.check(host, address, port)
            except DestinationBlocked as e:
                refused = refused or e
                continue
            allowed.append(address)
        if not allowed:
            assert refused is not None
            raise refused
        ipv4 = next((a for a in allowed if a.version == 4), None)
        ipv6 = next((a for a in allowed if a.version == 6), None)
        return [a for a in (ipv4, ipv6) if a is not None]

    async def _connect(self, host: str, port: int, context: ssl.SSLContext) -> asyncio.StreamWriter:
        """A TLS connection to an allowed address of ``host``, with ``host`` as SNI and certificate name.

        TLS errors and a connection reset during the handshake are raised as they
        are (the server answered); an address that cannot be reached makes way for the next."""
        failure: BaseException | None = None
        for address in await self._destinations(host, port):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(str(address), port, ssl=context, server_hostname=host), self.timeout)
                self._negotiated.add((host, str(address)))
                return writer
            except (ssl.SSLError, ConnectionResetError):
                raise
            except (OSError, TimeoutError) as e:
                failure = e
        if isinstance(failure, ConnectionRefusedError):
            raise Refused(f"TLS {host}:{port}: connection refused")
        if isinstance(failure, TimeoutError):
            raise ConnectionTimedOut(f"TLS {host}:{port}: connection timed out")
        raise NetworkError(f"TLS {host}:{port}: {failure or 'unreachable'}")

    def _verified_context(self) -> ssl.SSLContext:
        """Full verification: the system's authorities, plus the perimeter's own CA when there is one."""
        if self._verified is None:
            context = ssl.create_default_context()
            if self._trusted_ca:
                context.load_verify_locations(cadata=self._trusted_ca)
            self._verified = context
        return self._verified

    # ------------------------------------------------------------------ TLS
    async def certificate(self, host: str, port: int = 443) -> Certificate:
        return await self._cached(("cert", host, port), lambda: self._certificate(host, port))

    async def _certificate(self, host: str, port: int) -> Certificate:
        # First with full verification. If it fails, connect again without
        # verification to read the certificate and say what is wrong with it.
        try:
            der, protocol = await self._handshake(host, port, self._verified_context())
            return _parse_certificate(host, der, protocol, trusted=True)
        except ssl.SSLCertVerificationError as e:
            problem = e.verify_message or str(e)
        der, protocol = await self._handshake(host, port, _unverified_context())
        return _parse_certificate(host, der, protocol, trusted=False, problem=problem)

    async def _handshake(self, host: str, port: int, context: ssl.SSLContext) -> tuple[bytes, str]:
        try:
            writer = await self._connect(host, port, context)
        except ssl.SSLCertVerificationError:
            raise
        except ConnectionResetError as e:
            raise ConnectionReset(f"TLS {host}:{port}: connection reset") from e
        except ssl.SSLError as e:
            raise TLSHandshakeError(f"TLS {host}:{port}: {e}") from e
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            der = ssl_object.getpeercert(binary_form=True)
            return der, ssl_object.version() or ""
        finally:
            await _close(writer)

    async def accepts_tls(self, host: str, version: str, port: int = 443) -> bool | None:
        return await self._cached(("tls", host, version, port), lambda: self._accepts_tls(host, version, port))

    async def _accepts_tls(self, host: str, version: str, port: int) -> bool | None:
        # Only the protocol version matters here; old versions need the isolated legacy context.
        context = (legacy_tls.context(version, version) if version in legacy_tls.VERSIONS
                   else _unverified_context(version, version))
        if context is None:
            return None
        try:
            writer = await self._connect(host, port, context)
        except ssl.SSLError as e:
            # Our own library cannot speak this version: we do not know the answer.
            if e.reason in ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "UNSUPPORTED_PROTOCOL"):
                return None
            return False  # the server refused the handshake
        except ConnectionResetError:
            return False  # some servers refuse an old version by dropping the connection
        await _close(writer)
        return True

    # ----------------------------------------------------------------- HTTP
    async def http_get(self, url: str, *, verify: bool = False) -> HttpReply:
        return await self._cached(("http", url, verify), lambda: self._http_get(url, verify))

    async def _http_get(self, url: str, verify: bool) -> HttpReply:
        try:
            target = httpx.URL(url)
        except httpx.InvalidURL as e:
            raise NetworkError(f"HTTP {url}: invalid URL") from e
        if target.scheme not in ("http", "https") or not target.raw_host:
            raise NetworkError(f"HTTP {url}: only http and https URLs are fetched")
        host = target.raw_host.decode("ascii")
        port = target.port or (443 if target.scheme == "https" else 80)
        headers = {"Host": _host_header(host, target.port), "User-Agent": USER_AGENT}
        # The name goes in the TLS handshake (SNI) and is what the certificate is checked against.
        extensions = {"sni_hostname": host} if target.scheme == "https" and parse_address(host) is None else {}
        # Certificates are judged by the TLS checks; here the checks usually only
        # read headers, so an invalid certificate must not hide them, unless asked.
        tls: ssl.SSLContext | bool = self._verified_context() if verify else False
        failure: BaseException | None = None
        for address in await self._destinations(host, port):
            async with httpx.AsyncClient(verify=tls, trust_env=False, follow_redirects=False,
                                         timeout=self.timeout) as client:
                try:
                    async with client.stream("GET", target.copy_with(host=str(address)), headers=headers,
                                             extensions=extensions) as response:
                        if target.scheme == "https":
                            self._negotiated.add((host, str(address)))
                        return await _read_reply(url, response)
                except (httpx.ConnectError, httpx.ConnectTimeout) as e:
                    problem = _certificate_problem(e)
                    if problem is not None:
                        raise UntrustedCertificate(url, problem) from e
                    failure = e  # this address cannot be reached: try the next one
                except httpx.TimeoutException as e:
                    # Connected, but the reply did not come in time (read, write or pool timeout):
                    # the same diagnosis as a connection that times out.
                    raise ConnectionTimedOut(f"HTTP {url}: {e.__class__.__name__}") from e
                except httpx.HTTPError as e:
                    raise NetworkError(f"HTTP {url}: {e.__class__.__name__}") from e
        if failure is not None and _caused_by(failure, ConnectionRefusedError):
            raise Refused(f"HTTP {url}: connection refused")
        if isinstance(failure, httpx.ConnectTimeout) or (failure and _caused_by(failure, TimeoutError)):
            raise ConnectionTimedOut(f"HTTP {url}: connection timed out")
        if failure is not None and _caused_by(failure, ConnectionResetError):
            raise ConnectionReset(f"HTTP {url}: connection reset")
        raise NetworkError(f"HTTP {url}: {failure.__class__.__name__ if failure else 'unreachable'}")


    # ------------------------------------------------- one address (0.4)
    def negotiated(self) -> frozenset[tuple[str, str]]:
        return frozenset(self._negotiated)

    def _offer_context(self, offer: str, verify: bool) -> ssl.SSLContext | None:
        """The context of one offer; old versions come from :mod:`.legacy_tls` only."""
        if (offer, verify) not in self._contexts:
            low, high = OFFERS[offer]
            if low in legacy_tls.VERSIONS:
                built = legacy_tls.context(low, high, verify=verify, trusted_ca=self._trusted_ca)
            elif verify:
                built = ssl.create_default_context()
                if self._trusted_ca:
                    built.load_verify_locations(cadata=self._trusted_ca)
                built.minimum_version, built.maximum_version = _TLS_VERSION[low], _TLS_VERSION[high]
            else:
                built = _unverified_context(low, high)
            self._contexts[(offer, verify)] = built
        return self._contexts[(offer, verify)]

    async def _open_at(self, host: str, address: Address, port: int, context: ssl.SSLContext | None,
                       stage: list[str]) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """A connection to this very address, after the policy said yes; TLS when ``context`` is given,
        with ``host`` as SNI. ``stage[0]`` follows the progress, for the caller's messages."""
        self.policy.check(host, address, port)  # raises DestinationBlocked: nothing is sent
        stage[0] = "tcp"
        try:
            sock = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        except OSError as e:  # this machine cannot even make the socket (IPv6 absent)
            raise Unreachable(f"{host} ({address}) port {port}: {e.strerror or e}") from e
        try:
            sock.setblocking(False)
            await asyncio.get_running_loop().sock_connect(sock, (str(address), port))
            if context is None:
                stage[0] = "http"
                return await asyncio.open_connection(sock=sock)
            stage[0] = "tls"
            return await asyncio.open_connection(sock=sock, ssl=context, ssl_handshake_timeout=self.timeout,
                                                 server_hostname=host)
        except BaseException:
            sock.close()  # a transport that took it over has closed it already: closing twice is harmless
            raise

    async def tls_at(self, host: str, address: str, offer: str = "default", *, port: int = 443,
                     verify: bool = True) -> TlsSession:
        self._spend("probe")
        return await self._tls_at(host, address, offer, port, verify)

    async def _tls_at(self, host: str, address: str, offer: str, port: int, verify: bool) -> TlsSession:
        try:
            return await self._session(host, address, offer, port, verify)
        except ssl.SSLCertVerificationError as e:
            # The server negotiated: its certificate is what failed. Read it without verification.
            problem = e.verify_message or str(e)
            session = await self._session(host, address, offer, port, verify=False)
            return replace(session, certificate=replace(session.certificate, trusted=False, problem=problem))

    async def _session(self, host: str, address: str, offer: str, port: int, verify: bool) -> TlsSession:
        target = _address(address)
        context = self._offer_context(offer, verify)
        where = f"TLS {host} ({address}) port {port}, {offer}"
        if context is None:
            raise LegacyUnsupported(f"{where}: this machine cannot offer this version")
        stage = ["tcp"]
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(self.timeout):
                _, writer = await self._open_at(host, target, port, context, stage)
            ssl_object = writer.get_extra_info("ssl_object")
            der = ssl_object.getpeercert(binary_form=True)
            version = ssl_object.version() or ""
        except ssl.SSLCertVerificationError:
            if verify:
                raise
            raise TLSHandshakeError(f"{where}: certificate refused without verification") from None
        except (DestinationBlocked, NetworkError):
            raise
        except BaseException as e:
            if isinstance(e, asyncio.CancelledError):
                raise
            raise _classified(e, where, stage[0]) from e
        finally:
            if writer is not None:
                writer.transport.abort()  # no close_notify to wait for: the attempt is over
        if not der:
            raise TLSHandshakeError(f"{where}: no certificate")
        self._negotiated.add((host, address))
        return TlsSession(host, address, version,
                          _parse_certificate(host, der, version, trusted=verify))

    async def accepts_tls_at(self, host: str, address: str, version: str, *, port: int = 443) -> bool | None:
        return await self._cached(("tls_at", host, address, version, port),
                                  lambda: self._accepts_tls_at(host, address, version, port))

    async def _accepts_tls_at(self, host: str, address: str, version: str, port: int) -> bool | None:
        try:
            await self._tls_at(host, address, version, port, verify=False)
        except LegacyUnsupported:
            return None
        except (TLSHandshakeError, ConnectionReset):  # an alert, a reset or a silent close: refused
            return False
        return True

    async def http_at(self, url: str, address: str, *, offer: str = "default", cache: bool = True) -> HttpReply:
        if not cache:
            self._spend("probe")
            return await self._http_at(url, address, offer)
        return await self._cached(("http_at", url, address, offer), lambda: self._http_at(url, address, offer))

    async def _http_at(self, url: str, address: str, offer: str) -> HttpReply:
        try:
            target = httpx.URL(url)
        except httpx.InvalidURL as e:
            raise NetworkError(f"HTTP {url}: invalid URL") from e
        if target.scheme not in ("http", "https") or not target.raw_host:
            raise NetworkError(f"HTTP {url}: only http and https URLs are fetched")
        host = target.raw_host.decode("ascii")
        port = target.port or (443 if target.scheme == "https" else 80)
        context: ssl.SSLContext | None = None
        if target.scheme == "https":
            context = self._offer_context(offer, verify=False)
            if context is None:
                raise LegacyUnsupported(f"HTTP {url} ({address}): this machine cannot offer {offer}")
        where = f"HTTP {url} ({address})"
        stage = ["tcp"]
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await self._open_at(host, _address(address), port, context, stage)
                stage[0] = "http"
                reply = await _exchange(url, reader, writer, _host_header(host, target.port),
                                        target.raw_path.decode("ascii") or "/")
        except (DestinationBlocked, NetworkError):
            raise
        except BaseException as e:
            if isinstance(e, asyncio.CancelledError):
                raise
            raise _classified(e, where, stage[0]) from e
        finally:
            if writer is not None:
                writer.transport.abort()
        if context is not None:
            self._negotiated.add((host, address))
        return reply


# ---------------------------------------------------------------- helpers
def _address(text: str) -> Address:
    address = parse_address(text)
    if address is None:
        raise NetworkError(f"{text}: not an address")
    return address


def _classified(error: BaseException, where: str, stage: str) -> NetworkError:
    """What made a connection to one address fail, as a :class:`NetworkError` that keeps the stage."""
    result: NetworkError
    if isinstance(error, TimeoutError):
        result = ConnectionTimedOut(f"{where}: no answer ({stage})")
    elif isinstance(error, ConnectionRefusedError):
        result = Refused(f"{where}: connection refused")
    elif isinstance(error, ssl.SSLError):
        reason = error.reason or ""
        if reason in _LOCAL_TLS:
            result = LegacyUnsupported(f"{where}: this machine cannot offer this version ({reason})")
        elif isinstance(error, ssl.SSLEOFError) or reason == "UNEXPECTED_EOF_WHILE_READING":
            result = ConnectionClosed(f"{where}: closed during the negotiation")
        elif "ALERT" in reason or reason in ("UNSUPPORTED_PROTOCOL", "WRONG_VERSION_NUMBER", "TLSV1_UNRECOGNIZED_NAME"):
            result = TLSAlert(f"{where}: {reason.lower()}", reason.lower())
        else:
            result = TLSHandshakeError(f"{where}: {reason or error}")
    elif isinstance(error, ConnectionResetError):
        # asyncio reports a connection closed during the negotiation as a reset without errno.
        result = (ConnectionReset(f"{where}: connection reset") if error.errno
                  else ConnectionClosed(f"{where}: connection closed"))
    elif isinstance(error, (ConnectionAbortedError, BrokenPipeError, asyncio.IncompleteReadError, EOFError)):
        result = ConnectionClosed(f"{where}: connection closed")
    elif isinstance(error, h11.RemoteProtocolError):
        result = NetworkError(f"{where}: not a valid HTTP reply ({error})")
    elif isinstance(error, OSError) and error.errno in _UNREACHABLE:
        result = Unreachable(f"{where}: {error.strerror or error}")
    else:
        result = NetworkError(f"{where}: {error.__class__.__name__} {error}".strip())
    result.stage = stage
    return result


async def _exchange(url: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str,
                    path: str) -> HttpReply:
    """One GET on an open connection: status, headers and the first :data:`MAX_BODY` bytes of the body."""
    connection = h11.Connection(h11.CLIENT)
    request = h11.Request(method="GET", target=path, headers=[
        ("Host", host), ("User-Agent", USER_AGENT), ("Accept", "*/*"), ("Connection", "close")])
    writer.write(connection.send(request) + (connection.send(h11.EndOfMessage()) or b""))
    await writer.drain()
    response: h11.Response | None = None
    body = b""
    while len(body) < MAX_BODY:
        try:
            event = connection.next_event()
        except h11.RemoteProtocolError:
            if response is None:
                raise
            break  # a body cut short: the status and the headers are what the checks read
        if event is h11.NEED_DATA:
            data = await reader.read(65536)
            if not data and response is None:
                raise ConnectionClosed(f"HTTP {url}: closed before any reply")
            connection.receive_data(data)
            continue
        if isinstance(event, h11.Response):
            response = event
        elif isinstance(event, h11.Data):
            body += event.data
        elif isinstance(event, (h11.EndOfMessage, h11.ConnectionClosed)):
            break
    if response is None:
        raise ConnectionClosed(f"HTTP {url}: no reply")
    headers: dict[str, str] = {}
    for name, value in response.headers:
        key = name.decode("latin-1").lower()
        text = value.decode("latin-1")
        headers[key] = f"{headers[key]}, {text}" if key in headers else text
    return HttpReply(url, response.status_code, headers, body[:MAX_BODY].decode("utf-8", errors="replace"))


async def _read_reply(url: str, response: httpx.Response) -> HttpReply:
    """Status, headers and the first :data:`MAX_BODY` bytes of the body."""
    body = b""
    async for chunk in response.aiter_bytes():
        body += chunk
        if len(body) >= MAX_BODY:
            break
    headers = {name.lower(): ", ".join(response.headers.get_list(name)) for name in response.headers}
    return HttpReply(url, response.status_code, headers, body[:MAX_BODY].decode("utf-8", errors="replace"))


def _host_header(host: str, port: int | None) -> str:
    """Value of the HTTP ``Host`` header: the name, and the port when it is not the scheme's default."""
    name = f"[{host}]" if ":" in host else host
    return name if port is None else f"{name}:{port}"


def _caused_by(error: BaseException, kind: type[BaseException]) -> bool:
    seen: BaseException | None = error
    while seen is not None:
        if isinstance(seen, kind):
            return True
        seen = seen.__cause__ or seen.__context__
    return False


def _certificate_problem(error: BaseException) -> str | None:
    """Why the certificate was refused, when that is what made the connection fail."""
    seen: BaseException | None = error
    while seen is not None:
        if isinstance(seen, ssl.SSLCertVerificationError):
            return seen.verify_message or str(seen)
        seen = seen.__cause__ or seen.__context__
    return None


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(OSError, ssl.SSLError, TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), 2)


def _record_text(rdata) -> str:
    if rdata.rdtype == dns.rdatatype.TXT:
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    return rdata.to_text()


def _unverified_context(minimum: str | None = None, maximum: str | None = None) -> ssl.SSLContext:
    """For reading a certificate that failed verification, and for probing TLS 1.2 and 1.3.

    TLS 1.0 and 1.1 are never set here: they come from :mod:`.legacy_tls` only."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if minimum is not None:
        context.minimum_version = _TLS_VERSION[minimum]
    if maximum is not None:
        context.maximum_version = _TLS_VERSION[maximum]
    return context


def _name_attribute(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else ""


def _parse_certificate(host: str, der: bytes, protocol: str, trusted: bool, problem: str = "") -> Certificate:
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = tuple(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        names = ()
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, bits = "EC", key.curve.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_type, bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        key_type, bits = "Ed448", 456
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, bits = "DSA", key.key_size
    else:
        key_type, bits = type(key).__name__, 0
    issuer = (_name_attribute(cert.issuer, NameOID.ORGANIZATION_NAME)
              or _name_attribute(cert.issuer, NameOID.COMMON_NAME))
    return Certificate(
        host=host, subject=_name_attribute(cert.subject, NameOID.COMMON_NAME), names=names, issuer=issuer,
        not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc.astimezone(UTC),
        key_type=key_type, key_bits=bits, trusted=trusted, problem=problem, protocol=protocol,
    )
