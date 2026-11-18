# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A reproducible corpus of damaged server flights (version 0.8.0, PR-A, precision 4 of the review of R1).

The corpus starts from the bytes of the catalogue (scenarios.json) and damages them with fixed strategies,
driven by a deterministic stream (:class:`Stream`): SHA-256 of a seed and a counter. The stream does not
depend on Python's ``random`` module, whose algorithms may change between versions, nor on the machine:
the same seed and count give the same inputs, in the same order, everywhere; :func:`fingerprint` proves it.

Strategies: flip one bit; set one byte to 0x00, 0xFF or any value; cut the input; add bytes at the end;
change a length field (record, handshake message, or any two bytes) to 0, ±1 or 0xFFFF; cut the records
again at another size; repeat a slice; splice two flights; random bytes.

Limits, said plainly:

- the mutations are blind to the semantics of TLS beyond lengths and record boundaries: no state machine,
  no second flight, no timing (the network anomalies are scenarios of the catalogue, not mutations);
- the corpus is as good as its seeds: the 50 replies of the catalogue;
- no coverage is measured; the tests check only that the reader under test never fails otherwise than by
  refusing the input (``Malformed``), and never takes long on one input;
- the size of the corpus is a parameter: the CI runs a few thousand inputs (``TLS_LAB_FUZZ_COUNT``), gate G1
  asks for 100 000 on the prototype of PR-A2.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator

from .scenarios import load

SEED = "tls-lab/2026.1"


class Stream:
    """Deterministic numbers from SHA-256(seed, counter): the same on every Python and every machine."""

    def __init__(self, seed: str):
        self.seed, self.counter, self.pool = seed.encode(), 0, b""

    def _bytes(self, n: int) -> bytes:
        while len(self.pool) < n:
            self.pool += hashlib.sha256(self.seed + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
        out, self.pool = self.pool[:n], self.pool[n:]
        return out

    def below(self, n: int) -> int:
        """A number in [0, n), without bias (rejection of the incomplete top range)."""
        if n <= 1:
            return 0
        size = (n.bit_length() + 7) // 8 + 1
        top = 256 ** size - (256 ** size % n)
        while True:
            value = int.from_bytes(self._bytes(size), "big")
            if value < top:
                return value % n

    def pick(self, items: list):
        return items[self.below(len(items))]

    def raw(self, n: int) -> bytes:
        return self._bytes(n)


def _flip(data: bytes, s: Stream) -> bytes:
    if not data:
        return data
    at = s.below(len(data))
    return data[:at] + bytes([data[at] ^ (1 << s.below(8))]) + data[at + 1:]


def _set(data: bytes, s: Stream) -> bytes:
    if not data:
        return data
    at = s.below(len(data))
    value = s.pick([0x00, 0xFF, s.below(256)])
    return data[:at] + bytes([value]) + data[at + 1:]


def _cut(data: bytes, s: Stream) -> bytes:
    return data[: s.below(len(data) + 1)]


def _extend(data: bytes, s: Stream) -> bytes:
    return data + s.raw(1 + s.below(64))


def _length(data: bytes, s: Stream) -> bytes:
    """A length field changed: the record's (offset 3), the first handshake message's (offset 6, 3 bytes),
    or any two bytes."""
    if len(data) < 9:
        return _flip(data, s)
    at, width = s.pick([(3, 2), (6, 3), (s.below(len(data) - 2), 2)])
    old = int.from_bytes(data[at:at + width], "big")
    new = s.pick([0, old + 1, max(old - 1, 0), 256 ** width - 1]) % 256 ** width
    return data[:at] + new.to_bytes(width, "big") + data[at + width:]


def _resplit(data: bytes, s: Stream) -> bytes:
    """The bodies of the records cut again into records of another size (headers rebuilt from the first)."""
    if len(data) < 6:
        return data
    header, body = data[:3], data[5:]
    size = 1 + s.below(64)
    return b"".join(header + len(body[i:i + size]).to_bytes(2, "big") + body[i:i + size]
                    for i in range(0, len(body), size))


def _repeat(data: bytes, s: Stream) -> bytes:
    if not data:
        return data
    start = s.below(len(data))
    end = start + 1 + s.below(min(32, len(data) - start))
    return data[:end] + data[start:end] + data[end:]


def _random(data: bytes, s: Stream) -> bytes:
    return s.raw(s.below(300))


STRATEGIES = [_flip, _set, _cut, _extend, _length, _resplit, _repeat, _random]


def seeds() -> list[bytes]:
    found, _ = load()
    return [s.data for s in found if s.data]


def corpus(count: int, seed: str = SEED) -> Iterator[bytes]:
    """``count`` damaged inputs: one to three strategies each, sometimes on two spliced flights."""
    base = seeds()
    s = Stream(seed)
    for _ in range(count):
        data = s.pick(base)
        if s.below(8) == 0:
            data = data[: s.below(len(data) + 1)] + s.pick(base)
        for _ in range(1 + s.below(3)):
            data = s.pick(STRATEGIES)(data, s)
        yield data[:20000]


def fingerprint(count: int, seed: str = SEED) -> str:
    digest = hashlib.sha256()
    for data in corpus(count, seed):
        digest.update(len(data).to_bytes(4, "big") + data)
    return digest.hexdigest()
