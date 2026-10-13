# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Servers started on this machine for the tests of the real network code.

Nothing here reaches another machine: a DNS server, web servers and TLS
servers listen on the loopback address and answer what the test tells them.

- :class:`LocalDns` answers DNS questions from a dictionary; an answer may be a
  function of the number of times the question was asked (DNS rebinding);
- :func:`http_server` answers every request with the same raw reply and
  records the requests it got;
- :class:`TestPki` makes a certificate authority and certificates signed by it.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import ssl
from collections import Counter
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

LOOPBACK = "127.0.0.1"

# name -> {type -> list of values, or a function (number of the question) -> list of values}.
# A name missing from the dictionary does not exist (NXDOMAIN).
Zone = dict[str, dict[str, list[str] | Callable[[int], list[str]]]]


class LocalDns(asyncio.DatagramProtocol):
    """A DNS server over UDP that answers from a dictionary, with a TTL of 0."""

    def __init__(self, zone: Zone):
        self.zone = zone
        self.questions: Counter[tuple[str, str]] = Counter()
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport):  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data, addr):  # type: ignore[override]
        query = dns.message.from_wire(data)
        question = query.question[0]
        name = question.name.to_text().rstrip(".").lower()
        rtype = dns.rdatatype.to_text(question.rdtype)
        self.questions[(name, rtype)] += 1
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        if name not in self.zone:
            response.set_rcode(dns.rcode.NXDOMAIN)
        else:
            values = self.zone[name].get(rtype, [])
            if callable(values):
                values = values(self.questions[(name, rtype)])
            if values:
                response.answer.append(dns.rrset.from_text_list(question.name, 0, "IN", rtype, values))
        assert self.transport is not None
        self.transport.sendto(response.to_wire(), addr)


@contextlib.asynccontextmanager
async def dns_server(zone: Zone) -> AsyncIterator[tuple[LocalDns, int]]:
    """Starts a :class:`LocalDns`; yields it and its port."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(lambda: LocalDns(zone), local_addr=(LOOPBACK, 0))
    try:
        yield protocol, transport.get_extra_info("sockname")[1]
    finally:
        transport.close()


@dataclass
class Requests:
    """What a test server received."""

    connections: int = 0
    heads: list[str] = field(default_factory=list)  # request line and headers of each request

    def header(self, index: int, name: str) -> str:
        for line in self.heads[index].split("\r\n")[1:]:
            key, _, value = line.partition(":")
            if key.strip().lower() == name.lower():
                return value.strip()
        return ""


def http_reply(status: str = "200 OK", headers: dict[str, str] | None = None, body: bytes = b"") -> bytes:
    lines = [f"HTTP/1.1 {status}", f"Content-Length: {len(body)}", "Connection: close"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


@contextlib.asynccontextmanager
async def http_server(reply: bytes, host: str = LOOPBACK, tls: ssl.SSLContext | None = None,
                      slow: float = 0.0) -> AsyncIterator[tuple[Requests, int]]:
    """A web server (HTTPS when ``tls`` is given) answering ``reply`` to every request.

    ``slow``: seconds to wait between each byte sent, for a server that trickles its answer."""
    received = Requests()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.connections += 1
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            received.heads.append(head.decode("latin-1"))
            if slow:
                for byte in reply:
                    writer.write(bytes([byte]))
                    await writer.drain()
                    await asyncio.sleep(slow)
            else:
                writer.write(reply)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, host, 0, ssl=tls)
    async with server:
        yield received, server.sockets[0].getsockname()[1]


@contextlib.asynccontextmanager
async def counting_server(host: str = LOOPBACK) -> AsyncIterator[tuple[Requests, int]]:
    """A server that only counts the connections it gets, and closes them."""
    received = Requests()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.connections += 1
        writer.close()

    server = await asyncio.start_server(handle, host, 0)
    async with server:
        yield received, server.sockets[0].getsockname()[1]


class TestPki:
    """A certificate authority, and certificates it signs, written to ``folder``."""

    __test__ = False  # not a test class, despite its name

    def __init__(self, folder: Path, name: str = "Lab Internal CA"):
        self.folder = folder
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name),
                                x509.NameAttribute(NameOID.ORGANIZATION_NAME, name)])
        now = dt.datetime.now(dt.UTC)
        self.certificate = (
            x509.CertificateBuilder().subject_name(self._name).issuer_name(self._name)
            .public_key(self._key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False),
                           critical=True)
            .sign(self._key, hashes.SHA256()))

    @property
    def pem(self) -> str:
        return self.certificate.public_bytes(serialization.Encoding.PEM).decode()

    def server_context(self, *names: str, days: int = 30) -> ssl.SSLContext:
        """A TLS server context with a certificate for ``names``, signed by this authority."""
        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.UTC)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
                .issuer_name(self._name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()),
                               critical=False)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(self._key, hashes.SHA256()))
        stem = self.folder / names[0]
        stem.with_suffix(".crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        stem.with_suffix(".key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(stem.with_suffix(".crt"), stem.with_suffix(".key"))
        return context
