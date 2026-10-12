# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Everything the checks may ask the outside world, behind one small interface.

Checks never open a socket themselves: they call the four methods of
:class:`Network`. This keeps every check *passive* (DNS queries, a TLS handshake,
one HTTP GET without following redirects, nothing else) and lets the tests and
the demo replace the network with recorded answers (:mod:`.fixture`).

:class:`LiveNetwork` is the real implementation. One instance is used per scan
and remembers its answers, so two checks asking the same question send it once.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import warnings
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol, TypeVar

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from .. import __version__

USER_AGENT = f"PostureCockpit/{__version__} (+https://github.com/vinzgithub/posture-cockpit)"
MAX_BODY = 64 * 1024  # bytes of a web page kept for the checks
TLS_VERSIONS = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")


class NetworkError(Exception):
    """A question got no usable answer (timeout, refused, DNS server failure).

    The engine reports the check as "could not be checked" rather than as a failure."""


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
    trusted: bool           # chain verified against the system store and name matches
    problem: str = ""       # why it is not trusted
    protocol: str = ""      # TLS version negotiated, e.g. "TLSv1.3"


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

    def http_get(self, url: str) -> Awaitable[HttpReply]:
        """One GET, without following redirects."""
        ...


T = TypeVar("T")


class LiveNetwork:
    """The real network. Create one per scan: it caches answers for that scan only."""

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 6.0):
        self.timeout = timeout
        self._resolver = dns.asyncresolver.Resolver(configure=not nameservers)
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.lifetime = timeout
        self._cache: dict[tuple, asyncio.Task] = {}

    async def _cached(self, key: tuple, make: Callable[[], Awaitable[T]]) -> T:
        # The task is shared: a second caller waits for the first answer.
        if key not in self._cache:
            self._cache[key] = asyncio.ensure_future(make())
        # shield(): a caller that times out must not cancel the answer the others wait for.
        return await asyncio.shield(self._cache[key])

    # ------------------------------------------------------------------ DNS
    async def dns(self, name: str, rtype: str) -> DnsAnswer:
        return await self._cached(("dns", name.lower().rstrip("."), rtype.upper()), lambda: self._dns(name, rtype))

    async def _dns(self, name: str, rtype: str) -> DnsAnswer:
        try:
            answer = await self._resolver.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer((), exists=False)
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.YXDOMAIN) as e:
            raise NetworkError(f"DNS {rtype} {name}: {e.__class__.__name__}") from e
        if answer.rrset is None:
            return DnsAnswer(())
        return DnsAnswer(tuple(_record_text(r) for r in answer.rrset))

    # ------------------------------------------------------------------ TLS
    async def certificate(self, host: str, port: int = 443) -> Certificate:
        return await self._cached(("cert", host, port), lambda: self._certificate(host, port))

    async def _certificate(self, host: str, port: int) -> Certificate:
        # First with full verification. If it fails, connect again without
        # verification to read the certificate and say what is wrong with it.
        try:
            der, protocol = await self._handshake(host, port, ssl.create_default_context())
            return _parse_certificate(host, der, protocol, trusted=True)
        except ssl.SSLCertVerificationError as e:
            problem = e.verify_message or str(e)
        der, protocol = await self._handshake(host, port, _unverified_context())
        return _parse_certificate(host, der, protocol, trusted=False, problem=problem)

    async def _handshake(self, host: str, port: int, context: ssl.SSLContext) -> tuple[bytes, str]:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host), self.timeout)
        except ssl.SSLCertVerificationError:
            raise
        except (OSError, TimeoutError, ssl.SSLError) as e:
            raise NetworkError(f"TLS {host}:{port}: {e}") from e
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            der = ssl_object.getpeercert(binary_form=True)
            return der, ssl_object.version() or ""
        finally:
            await _close(writer)

    async def accepts_tls(self, host: str, version: str, port: int = 443) -> bool | None:
        return await self._cached(("tls", host, version, port), lambda: self._accepts_tls(host, version, port))

    async def _accepts_tls(self, host: str, version: str, port: int) -> bool | None:
        context = _unverified_context()
        tls_version = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1,
                       "TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1.3": ssl.TLSVersion.TLSv1_3}[version]
        try:
            with warnings.catch_warnings():  # Python warns that TLS 1.0 is deprecated: that is the point
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = context.maximum_version = tls_version
            if version in ("TLSv1", "TLSv1.1"):
                context.set_ciphers("DEFAULT:@SECLEVEL=0")  # old versions need old ciphers
        except (ValueError, ssl.SSLError):
            return None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host), self.timeout)
        except ssl.SSLError as e:
            # Our own library cannot speak this version: we do not know the answer.
            if e.reason in ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "UNSUPPORTED_PROTOCOL"):
                return None
            return False  # the server refused the handshake
        except ConnectionResetError:
            return False  # some servers refuse an old version by dropping the connection
        except (OSError, TimeoutError) as e:
            raise NetworkError(f"TLS {host}:{port}: {e}") from e
        await _close(writer)
        return True

    # ----------------------------------------------------------------- HTTP
    async def http_get(self, url: str) -> HttpReply:
        return await self._cached(("http", url), lambda: self._http_get(url))

    async def _http_get(self, url: str) -> HttpReply:
        # Certificates are checked by the TLS checks; here we only read headers,
        # so an invalid certificate must not hide them.
        async with httpx.AsyncClient(follow_redirects=False, verify=False, timeout=self.timeout,  # noqa: S501
                                     headers={"User-Agent": USER_AGENT}) as client:
            try:
                async with client.stream("GET", url) as response:
                    body = b""
                    async for chunk in response.aiter_bytes():
                        body += chunk
                        if len(body) >= MAX_BODY:
                            break
                    headers = {name.lower(): ", ".join(response.headers.get_list(name))
                               for name in response.headers}
                    return HttpReply(str(response.url), response.status_code, headers,
                                     body[:MAX_BODY].decode("utf-8", errors="replace"))
            except httpx.HTTPError as e:
                raise NetworkError(f"HTTP {url}: {e.__class__.__name__}") from e


# ---------------------------------------------------------------- helpers
async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(OSError, ssl.SSLError, TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), 2)


def _record_text(rdata) -> str:
    if rdata.rdtype == dns.rdatatype.TXT:
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    return rdata.to_text()


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
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
