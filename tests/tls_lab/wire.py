# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The bytes of the TLS bench: what a server sends first, built and read (version 0.8.0, PR-A).

Two halves, both for the bench only (never imported by the product):

- **builders** write the first flight of a server, byte for byte: records, ServerHello (TLS 1.2 and
  1.3), HelloRetryRequest, Certificate, ServerKeyExchange (ECDHE, DHE), ServerHelloDone, alerts. The
  synthetic responders (responders.py) send them; their values are fixed, so the bytes are the same on
  every run and every machine;
- a **strict reader** (:func:`read_flight`) turns a first flight into facts (version chosen, suite,
  group, key exchange, alert). It is the oracle of the bench: it checks the catalogue of scenarios and the
  transcripts recorded between real OpenSSL peers (tests/tls_lab/test_real_tls.py), and it is the target
  of the reproducible robustness tests (mutations.py). It reads only what the bench needs and refuses
  everything else with :class:`Malformed`: it is not the prober of the product, which PR-A2 will
  prototype and evaluate (gate G1).

Bounds: at most :data:`MAX_FLIGHT` bytes and :data:`MAX_RECORDS` records are read; a length is always
checked against what remains before it is used.

References: RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3, §4.1.3 HelloRetryRequest, §4.2), RFC 8422 (ECDHE),
RFC 7919 (FFDHE groups), IANA TLS registries for the codes below.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

MAX_FLIGHT = 16 * 1024  # bytes of a first flight read at most
MAX_RECORDS = 8         # records of a first flight read at most

# Record content types and handshake types.
ALERT, HANDSHAKE = 21, 22
SERVER_HELLO, CERTIFICATE, SERVER_KEY_EXCHANGE, SERVER_HELLO_DONE = 2, 11, 12, 14

VERSIONS = {0x0300: "SSLv3", 0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}
CODES = {name: code for code, name in VERSIONS.items()}

# RFC 8446 §4.1.3: the random of a HelloRetryRequest is SHA-256("HelloRetryRequest").
HRR_RANDOM = hashlib.sha256(b"HelloRetryRequest").digest()

# Extensions read or written.
EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE, EXT_RENEGOTIATION_INFO = 43, 51, 0xFF01

# Named groups (IANA "TLS Supported Groups").
GROUPS = {0x0015: "secp224r1", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x001D: "x25519",
          0x0100: "ffdhe2048", 0x11EC: "X25519MLKEM768"}

# Alert descriptions (RFC 8446 §6).
ALERTS = {0: "close_notify", 10: "unexpected_message", 40: "handshake_failure", 47: "illegal_parameter",
          50: "decode_error", 70: "protocol_version", 71: "insufficient_security", 80: "internal_error"}


@dataclass(frozen=True)
class Suite:
    code: int
    name: str
    category: str   # tls13, aead_pfs, cbc_pfs (ECDHE), dhe_aead, dhe_cbc, rsa_kex, 3des, rc4, null, export, anon
    exchange: str   # ecdhe, dhe, rsa, none (TLS 1.3: in the key_share)


# The suites the scenarios use, and those real OpenSSL peers of the bench negotiate (IANA "TLS Cipher Suites";
# OpenSSL names). Not an inventory of TLS: a suite outside it is read, never classed.
SUITES = {s.code: s for s in (
    Suite(0x1301, "TLS_AES_128_GCM_SHA256", "tls13", "none"),
    Suite(0x1302, "TLS_AES_256_GCM_SHA384", "tls13", "none"),
    Suite(0x1303, "TLS_CHACHA20_POLY1305_SHA256", "tls13", "none"),
    Suite(0x1304, "TLS_AES_128_CCM_SHA256", "tls13", "none"),
    Suite(0x1305, "TLS_AES_128_CCM_8_SHA256", "tls13", "none"),
    Suite(0xC02F, "ECDHE-RSA-AES128-GCM-SHA256", "aead_pfs", "ecdhe"),
    Suite(0xC030, "ECDHE-RSA-AES256-GCM-SHA384", "aead_pfs", "ecdhe"),
    Suite(0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256", "aead_pfs", "ecdhe"),
    Suite(0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305", "aead_pfs", "ecdhe"),
    Suite(0x009E, "DHE-RSA-AES128-GCM-SHA256", "dhe_aead", "dhe"),
    Suite(0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384", "aead_pfs", "ecdhe"),
    Suite(0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305", "aead_pfs", "ecdhe"),
    Suite(0x009F, "DHE-RSA-AES256-GCM-SHA384", "dhe_aead", "dhe"),
    Suite(0xCCAA, "DHE-RSA-CHACHA20-POLY1305", "dhe_aead", "dhe"),
    Suite(0xC013, "ECDHE-RSA-AES128-SHA", "cbc_pfs", "ecdhe"),
    Suite(0xC014, "ECDHE-RSA-AES256-SHA", "cbc_pfs", "ecdhe"),
    Suite(0xC009, "ECDHE-ECDSA-AES128-SHA", "cbc_pfs", "ecdhe"),
    Suite(0xC00A, "ECDHE-ECDSA-AES256-SHA", "cbc_pfs", "ecdhe"),
    Suite(0xC023, "ECDHE-ECDSA-AES128-SHA256", "cbc_pfs", "ecdhe"),
    Suite(0xC028, "ECDHE-RSA-AES256-SHA384", "cbc_pfs", "ecdhe"),
    Suite(0x0039, "DHE-RSA-AES256-SHA", "dhe_cbc", "dhe"),
    Suite(0x0067, "DHE-RSA-AES128-SHA256", "dhe_cbc", "dhe"),
    Suite(0xC027, "ECDHE-RSA-AES128-SHA256", "cbc_pfs", "ecdhe"),
    Suite(0x0033, "DHE-RSA-AES128-SHA", "dhe_cbc", "dhe"),
    Suite(0x002F, "AES128-SHA", "rsa_kex", "rsa"),
    Suite(0x009C, "AES128-GCM-SHA256", "rsa_kex", "rsa"),
    Suite(0x009D, "AES256-GCM-SHA384", "rsa_kex", "rsa"),
    Suite(0x003C, "AES128-SHA256", "rsa_kex", "rsa"),
    Suite(0x0035, "AES256-SHA", "rsa_kex", "rsa"),
    Suite(0x000A, "DES-CBC3-SHA", "3des", "rsa"),
    Suite(0xC012, "ECDHE-RSA-DES-CBC3-SHA", "3des", "ecdhe"),
    Suite(0x0005, "RC4-SHA", "rc4", "rsa"),
    Suite(0xC011, "ECDHE-RSA-RC4-SHA", "rc4", "ecdhe"),
    Suite(0x0002, "NULL-SHA", "null", "rsa"),
    Suite(0x003B, "NULL-SHA256", "null", "rsa"),
    Suite(0x0003, "EXP-RC4-MD5", "export", "rsa"),
    Suite(0x0008, "EXP-DES-CBC-SHA", "export", "rsa"),
    Suite(0x0034, "ADH-AES128-SHA", "anon", "dhe"),
    Suite(0xC018, "AECDH-AES128-SHA", "anon", "ecdhe"),
)}

# What a recent client could offer (the "standard" level of R1), and what only a test of old protocols
# offers (the "extended" level, reserved to the domains listed by the administrator). DHE in TLS 1.2 is
# legacy: recent browsers no longer offer it, RFC 10015 (2026) forbids it and IANA marks it "D".
MODERN_CATEGORIES = frozenset({"tls13", "aead_pfs", "cbc_pfs"})
LEGACY_CATEGORIES = frozenset({"dhe_aead", "dhe_cbc", "rsa_kex", "3des", "rc4", "null", "export", "anon"})
MODERN_VERSIONS = frozenset({"TLS1.2", "TLS1.3"})
LEGACY_VERSIONS = frozenset({"SSLv3", "TLS1.0", "TLS1.1"})
LEGACY_GROUPS = frozenset({"secp224r1"})  # below 256 bits: never offered by a recent client


# ------------------------------------------------------------------------------------------- builders
def u8(n: int) -> bytes:
    return struct.pack("!B", n)


def u16(n: int) -> bytes:
    return struct.pack("!H", n)


def u24(n: int) -> bytes:
    return struct.pack("!I", n)[1:]


def vec8(data: bytes) -> bytes:
    return u8(len(data)) + data


def vec16(data: bytes) -> bytes:
    return u16(len(data)) + data


def vec24(data: bytes) -> bytes:
    return u24(len(data)) + data


def record(content_type: int, body: bytes, version: int = 0x0303) -> bytes:
    return u8(content_type) + u16(version) + vec16(body)


def handshake(msg_type: int, body: bytes) -> bytes:
    return u8(msg_type) + vec24(body)


def extension(ext_type: int, data: bytes) -> bytes:
    return u16(ext_type) + vec16(data)


def fixed(label: str, size: int = 32) -> bytes:
    """Deterministic bytes standing for a random, a session id or a key: the same on every run."""
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"tls-lab/{label}/{counter}".encode()).digest()
        counter += 1
    return out[:size]


def server_hello(suite: int, *, version: int = 0x0303, extensions: bytes | None = None,
                 random: bytes | None = None, session_id: bytes | None = None) -> bytes:
    """A ServerHello handshake message (SSLv3 to TLS 1.2 shape: ``version`` is the one chosen)."""
    body = (u16(version) + (random or fixed(f"random/{suite:04x}/{version:04x}")) + vec8(session_id or fixed("sid"))
            + u16(suite) + u8(0))
    if extensions is None:
        extensions = extension(EXT_RENEGOTIATION_INFO, vec8(b""))
    if extensions:
        body += vec16(extensions)
    return handshake(SERVER_HELLO, body)


def server_hello_13(suite: int, group: int, *, key: bytes | None = None) -> bytes:
    """A TLS 1.3 ServerHello: legacy version 1.2, supported_versions 1.3, a key_share of ``group``."""
    share = u16(group) + vec16(key or fixed(f"share/{group:04x}", 32))
    return server_hello(suite, extensions=extension(EXT_SUPPORTED_VERSIONS, u16(0x0304))
                        + extension(EXT_KEY_SHARE, share))


def hello_retry_request(suite: int, group: int) -> bytes:
    """A HelloRetryRequest (RFC 8446 §4.1.4): a ServerHello whose random is HRR_RANDOM, naming the group."""
    return server_hello(suite, random=HRR_RANDOM, extensions=extension(EXT_SUPPORTED_VERSIONS, u16(0x0304))
                        + extension(EXT_KEY_SHARE, u16(group)))


def certificate(*ders: bytes) -> bytes:
    return handshake(CERTIFICATE, vec24(b"".join(vec24(d) for d in ders)))


def _signature(version: int) -> bytes:
    """The signature of a ServerKeyExchange: TLS 1.2 names its algorithm first (RFC 5246 §7.4.3); TLS 1.0,
    TLS 1.1 and SSLv3 do not."""
    return (u16(0x0804) if version >= 0x0303 else b"") + vec16(fixed("signature", 256))


def ecdhe_key_exchange(group: int, point_size: int, version: int = 0x0303) -> bytes:
    """A ServerKeyExchange for ECDHE on a named curve, with a placeholder signature."""
    params = u8(3) + u16(group) + vec8(fixed(f"point/{group:04x}", point_size))
    return handshake(SERVER_KEY_EXCHANGE, params + _signature(version))


def dhe_key_exchange(bits: int, signed: bool = True, version: int = 0x0303) -> bytes:
    """A ServerKeyExchange for DHE: a prime of ``bits`` bits (top bit set), g = 2, a public value;
    unsigned for an anonymous suite."""
    size = bits // 8
    prime = b"\xff" + fixed(f"prime/{bits}", size - 2) + b"\xff"
    params = vec16(prime) + vec16(b"\x02") + vec16(fixed(f"ys/{bits}", size))
    return handshake(SERVER_KEY_EXCHANGE, params + (_signature(version) if signed else b""))


def server_hello_done() -> bytes:
    return handshake(SERVER_HELLO_DONE, b"")


def alert(description: int, level: int = 2, version: int = 0x0303) -> bytes:
    return record(ALERT, u8(level) + u8(description), version)


def flight(*messages: bytes, version: int = 0x0303, split: int = 0) -> bytes:
    """Handshake messages in one record, or cut into records of ``split`` bytes (fragmentation)."""
    body = b"".join(messages)
    if not split:
        return record(HANDSHAKE, body, version)
    return b"".join(record(HANDSHAKE, body[i:i + split], version) for i in range(0, len(body), split))


# --------------------------------------------------------------------------------------------- reader
class Malformed(ValueError):
    """The bytes are not a first flight the bench can read; never a fact about the server."""


@dataclass
class Facts:
    """What a first flight says, as written; no conclusion about the server."""

    kind: str                          # server_hello, hello_retry_request, alert
    version: str | None = None         # chosen (supported_versions for TLS 1.3)
    suite: int | None = None
    group: int | None = None           # key_share (TLS 1.3) or ServerKeyExchange curve (TLS 1.2)
    dh_bits: int | None = None         # size of the DHE prime (TLS 1.2)
    alert: str | None = None
    alert_level: int | None = None
    messages: list[int] = field(default_factory=list)  # handshake types read, in order

    @property
    def suite_name(self) -> str | None:
        return None if self.suite is None else (SUITES[self.suite].name if self.suite in SUITES
                                                else f"0x{self.suite:04X}")


class _Cursor:
    def __init__(self, data: bytes):
        self.data, self.at = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.at + n > len(self.data):
            raise Malformed(f"needs {n} bytes at {self.at}, {len(self.data) - self.at} left")
        chunk = self.data[self.at:self.at + n]
        self.at += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vec(self, width: int) -> bytes:
        return self.take(int.from_bytes(self.take(width), "big"))

    def done(self) -> bool:
        return self.at == len(self.data)


def records(data: bytes) -> list[tuple[int, int, bytes]]:
    """The complete records of ``data`` (type, version, body); the bounds and the lengths checked."""
    if len(data) > MAX_FLIGHT:
        raise Malformed("flight beyond its bound")
    cursor, found = _Cursor(data), []
    while not cursor.done():
        if len(found) == MAX_RECORDS:
            raise Malformed("too many records")
        content_type, version = cursor.u8(), cursor.u16()
        body = cursor.vec(2)
        if content_type not in (ALERT, HANDSHAKE):
            raise Malformed(f"record type {content_type}")
        if version >> 8 != 3:
            raise Malformed(f"record version 0x{version:04x}")
        if not body or len(body) > 16384 + 2048:
            raise Malformed("record length")
        found.append((content_type, version, body))
    if not found:
        raise Malformed("no record")
    return found


def plaintext_prefix(data: bytes) -> bytes:
    """The leading handshake and alert records of a recorded server direction, up to the first record of
    another type (ChangeCipherSpec, application data: TLS 1.3 encrypts what follows its ServerHello). Only
    complete records are kept; a transcript longer than the bound keeps what fits."""
    cursor, end = _Cursor(data[:MAX_FLIGHT]), 0
    while not cursor.done():
        try:
            content_type = cursor.u8()
            cursor.u16()
            cursor.vec(2)
        except Malformed:
            break
        if content_type not in (ALERT, HANDSHAKE):
            break
        end = cursor.at
    return data[:end]


def read_flight(data: bytes) -> Facts:
    """The facts of a server's first flight: an alert, or a ServerHello / HelloRetryRequest and what follows
    it in the same flight (Certificate, ServerKeyExchange, ServerHelloDone). Raises :class:`Malformed`."""
    found = records(data)
    if found[0][0] == ALERT:
        if len(found) != 1 or len(found[0][2]) != 2:
            raise Malformed("alert record")
        level, description = found[0][2]
        if level not in (1, 2):
            raise Malformed("alert level")
        return Facts("alert", alert=ALERTS.get(description, f"alert_{description}"), alert_level=level)
    if any(content_type != HANDSHAKE for content_type, _, _ in found):
        raise Malformed("alert inside a handshake flight")
    stream = _Cursor(b"".join(body for _, _, body in found))
    facts: Facts | None = None
    while not stream.done():
        msg_type = stream.u8()
        body = _Cursor(stream.vec(3))
        if facts is None:
            if msg_type != SERVER_HELLO:
                raise Malformed(f"first message {msg_type}")
            facts = _server_hello(body)
        elif msg_type == SERVER_KEY_EXCHANGE:
            _key_exchange(body, facts)
        elif msg_type in (CERTIFICATE, SERVER_HELLO_DONE):
            body.take(len(body.data))  # read past: the bench needs neither
        else:
            raise Malformed(f"message {msg_type} after the hello")
        facts.messages.append(msg_type)
        if msg_type == SERVER_HELLO_DONE and not stream.done():
            raise Malformed("bytes after ServerHelloDone")
    if facts is None:
        raise Malformed("no handshake message")
    return facts


def _server_hello(body: _Cursor) -> Facts:
    legacy = body.u16()
    if legacy not in VERSIONS:
        raise Malformed(f"version 0x{legacy:04x}")
    random = body.take(32)
    if len(body.vec(1)) > 32:
        raise Malformed("session id")
    suite, compression = body.u16(), body.u8()
    if compression != 0:
        raise Malformed("compression")
    facts = Facts("hello_retry_request" if random == HRR_RANDOM else "server_hello", VERSIONS[legacy], suite)
    if body.done():
        return facts
    extensions = _Cursor(body.vec(2))
    if not body.done():
        raise Malformed("bytes after the extensions")
    seen = set()
    while not extensions.done():
        ext_type, data = extensions.u16(), _Cursor(extensions.vec(2))
        if ext_type in seen:
            raise Malformed(f"extension {ext_type} twice")
        seen.add(ext_type)
        if ext_type == EXT_SUPPORTED_VERSIONS:
            chosen = data.u16()
            if chosen != 0x0304 or not data.done():
                raise Malformed("supported_versions")
            facts.version = "TLS1.3"
        elif ext_type == EXT_KEY_SHARE:
            facts.group = data.u16()
            if facts.kind == "server_hello" and not data.vec(2):
                raise Malformed("empty key_share")
            if not data.done():
                raise Malformed("key_share")
    if facts.kind == "hello_retry_request" and (facts.version != "TLS1.3" or facts.group is None):
        raise Malformed("HelloRetryRequest without TLS 1.3 or group")
    return facts


def _key_exchange(body: _Cursor, facts: Facts) -> None:
    """ECDHE (curve_type 3, named curve) or DHE (p, g, Ys), as the suite chosen says."""
    suite = SUITES.get(facts.suite or -1)
    exchange = suite.exchange if suite else None
    if exchange == "ecdhe":
        if body.u8() != 3:
            raise Malformed("curve type")
        facts.group = body.u16()
        if not body.vec(1):
            raise Malformed("empty point")
    elif exchange == "dhe":
        prime = body.vec(2)
        if not prime or prime[0] == 0 or not body.vec(2) or not body.vec(2):
            raise Malformed("DH parameters")
        facts.dh_bits = len(prime) * 8 - (8 - prime[0].bit_length())
    else:
        raise Malformed("ServerKeyExchange for a suite without one")
    # The signature (TLS 1.2: its algorithm, then the signature; before TLS 1.2: the signature alone), or
    # nothing (anonymous suites).
    if not body.done():
        if facts.version == "TLS1.2":
            body.u16()
        body.vec(2)
    if not body.done():
        raise Malformed("bytes after the ServerKeyExchange")
