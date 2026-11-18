# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Real TLS peers of the bench, on this machine only (version 0.8.0, PR-A).

- :class:`TlsServer`: a TLS server of the Python ``ssl`` module (the OpenSSL of the interpreter or of the
  image), configured by a :class:`ServerConfig`: versions, TLS ≤ 1.2 suites, server preference, ECDHE
  curve (which, in TLS 1.3, also limits the groups and so provokes a HelloRetryRequest), DHE parameters,
  certificate. It records what each connection negotiated, or why it failed.
- :class:`Relay`: a recording relay between a client and a server of the bench: the bytes of each direction,
  bounded, so that a transcript between two real OpenSSL peers can be read by the bench's reader
  (wire.py) and compared with what OpenSSL reports (precision 3 of the review of R1: the real behaviour of
  TLS 1.2 and TLS 1.3, beside the synthetic fixtures).
- :func:`client_hello`: the ClientHello of a real OpenSSL client, obtained in memory (no socket).
- :func:`certificates`: self-signed certificates for 127.0.0.1, made at the start of the tests with
  ``cryptography`` (already a dependency of the product): RSA 2048, RSA 1024, EC P-256.

The ``ssl`` module cannot choose, on the server side, the TLS 1.3 suites (OpenSSL keeps its defaults) nor
offer SSLv3; the optional ``openssl s_server`` covers some of it where the tool is installed (test_real_tls).
Every listening socket is bound to a loopback address; guard.py refuses anything else.
"""

from __future__ import annotations

import contextlib
import datetime
import ipaddress
import socket
import ssl
import threading
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from .guard import LOOPBACK_V4

DATA = Path(__file__).resolve().parent.parent / "data" / "tls"
TLS_VERSIONS = {"TLS1.0": ssl.TLSVersion.TLSv1, "TLS1.1": ssl.TLSVersion.TLSv1_1,
                "TLS1.2": ssl.TLSVersion.TLSv1_2, "TLS1.3": ssl.TLSVersion.TLSv1_3}
NAMES = {"TLSv1": "TLS1.0", "TLSv1.1": "TLS1.1", "TLSv1.2": "TLS1.2", "TLSv1.3": "TLS1.3"}
DEADLINE = 5.0  # seconds a connection of the bench may take


def certificates(folder: Path) -> dict[str, tuple[Path, Path]]:
    """Self-signed certificate and key files for 127.0.0.1, by kind: rsa2048, rsa1024, ec256."""
    keys = {"rsa2048": rsa.generate_private_key(65537, 2048), "rsa1024": rsa.generate_private_key(65537, 1024),  # noqa: S505 - a legacy key, on purpose
            "ec256": ec.generate_private_key(ec.SECP256R1())}
    now = datetime.datetime.now(datetime.UTC)
    made = {}
    for kind, key in keys.items():
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"tls-lab {kind}")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(LOOPBACK_V4))]),
                               critical=False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = folder / f"{kind}.pem", folder / f"{kind}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        made[kind] = (cert_path, key_path)
    return made


@dataclass(frozen=True)
class ServerConfig:
    """What a real server of the bench accepts. ``offer_class``: modern (what a recent client may meet) or
    legacy (old protocols or weak suites, the extended level of R1)."""

    name: str
    minimum: str = "TLS1.2"
    maximum: str = "TLS1.3"
    ciphers: str | None = None          # OpenSSL list for TLS ≤ 1.2; None: OpenSSL's default
    seclevel: int | None = None         # appended to the list (@SECLEVEL=n)
    server_preference: bool = True
    curve: str | None = None            # set_ecdh_curve: TLS 1.2 curve, TLS 1.3 groups
    dh: str | None = None               # file of tests/data/tls (dh1024.pem, dh2048.pem)
    cert: str = "rsa2048"
    offer_class: str = "modern"

    def context(self, certs: dict[str, tuple[Path, Path]]) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        _versions(ctx, self.minimum, self.maximum)
        cipher_list = self.ciphers or "DEFAULT"
        if self.seclevel is not None:
            cipher_list += f":@SECLEVEL={self.seclevel}"
        ctx.set_ciphers(cipher_list)
        if self.server_preference:
            ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        else:
            ctx.options &= ~ssl.OP_CIPHER_SERVER_PREFERENCE
        ctx.options |= ssl.OP_NO_TICKET  # no NewSessionTicket in a recorded TLS 1.2 transcript
        if self.curve:
            ctx.set_ecdh_curve(self.curve)
        if self.dh:
            ctx.load_dh_params(str(DATA / self.dh))
        ctx.load_cert_chain(*certs[self.cert])
        return ctx


@dataclass
class Outcome:
    version: str | None = None
    suite: str | None = None
    error: str | None = None


class TlsServer:
    """A real TLS server on a loopback address, in a thread; one handshake per connection, then closed."""

    def __init__(self, config: ServerConfig, certs: dict[str, tuple[Path, Path]], host: str = LOOPBACK_V4):
        self.config = config
        self.context = config.context(certs)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.bind((host, 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.address = self.sock.getsockname()[:2]
        self.outcomes: list[Outcome] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> TlsServer:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join(DEADLINE)
        self.sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            conn.settimeout(DEADLINE)
            outcome = Outcome()
            try:
                with self.context.wrap_socket(conn, server_side=True) as tls:
                    outcome.version, outcome.suite = NAMES.get(tls.version() or "", tls.version()), tls.cipher()[0]
                    tls.settimeout(0.2)
                    with contextlib.suppress(OSError, ssl.SSLError):
                        tls.recv(1)  # let the client finish reading before the close
            except (ssl.SSLError, OSError) as error:
                outcome.error = getattr(error, "reason", None) or type(error).__name__
                conn.close()
            self.outcomes.append(outcome)


def _versions(ctx: ssl.SSLContext, minimum: str, maximum: str) -> None:
    """Set the versions; TLS 1.0 and 1.1 are deprecated by Python, and wanted here (legacy configurations)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version, ctx.maximum_version = TLS_VERSIONS[minimum], TLS_VERSIONS[maximum]


def client_context(minimum: str = "TLS1.2", maximum: str = "TLS1.3", ciphers: str | None = None,
                   seclevel: int | None = None) -> ssl.SSLContext:
    """A real OpenSSL client that trusts any certificate: the bench measures the protocol, not the PKI."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    _versions(ctx, minimum, maximum)
    if ciphers or seclevel is not None:
        ctx.set_ciphers((ciphers or "DEFAULT") + (f":@SECLEVEL={seclevel}" if seclevel is not None else ""))
    return ctx


def handshake(address: tuple, ctx: ssl.SSLContext) -> Outcome:
    """One real handshake to ``address``: what OpenSSL negotiated, or the reason of its refusal."""
    try:
        with socket.create_connection(address, timeout=DEADLINE) as raw, ctx.wrap_socket(raw) as tls:
            return Outcome(NAMES.get(tls.version() or "", tls.version()), tls.cipher()[0])
    except ssl.SSLError as error:
        return Outcome(error=error.reason or str(error))
    except OSError as error:
        return Outcome(error=type(error).__name__)


def client_hello(ctx: ssl.SSLContext, server_name: str | None = None) -> bytes:
    """The first flight of a real OpenSSL client, written in memory: no socket, no network."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=server_name)
    with contextlib.suppress(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


@dataclass
class Transcript:
    to_server: bytearray = field(default_factory=bytearray)
    to_client: bytearray = field(default_factory=bytearray)


class Relay:
    """A loopback relay that records both directions of each connection (at most ``limit`` bytes each)."""

    def __init__(self, upstream: tuple, limit: int = 64 * 1024, host: str = LOOPBACK_V4):
        self.upstream, self.limit = upstream, limit
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.address = self.sock.getsockname()
        self.transcripts: list[Transcript] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> Relay:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join(DEADLINE)
        self.sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            transcript = Transcript()
            self.transcripts.append(transcript)
            try:
                server = socket.create_connection(self.upstream, timeout=DEADLINE)
            except OSError:
                client.close()  # nothing upstream: the client sees the connection closed, never hangs
                continue
            pumps = [threading.Thread(target=self._pump, args=(client, server, transcript.to_server), daemon=True),
                     threading.Thread(target=self._pump, args=(server, client, transcript.to_client), daemon=True)]
            for pump in pumps:
                pump.start()
            for pump in pumps:
                pump.join(DEADLINE)
            client.close()
            server.close()

    def _pump(self, source: socket.socket, target: socket.socket, record: bytearray) -> None:
        source.settimeout(DEADLINE)
        try:
            while chunk := source.recv(4096):
                if len(record) < self.limit:
                    record.extend(chunk[: self.limit - len(record)])
                target.sendall(chunk)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                target.shutdown(socket.SHUT_WR)
