# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Reproducible robustness of the bench's reader (precision 4 of the review of R1).

The corpus of mutations.py is the same everywhere: its fingerprint is pinned below, for the stream of
numbers alone and for the corpus (which also depends on the catalogue: a deliberate change of a recipe
changes it, and the new value is pinned with the change). On every input, the strict reader either reads
facts or refuses the input with ``Malformed``; any other exception, or an input that takes long, fails.

The limits of these tests are those of mutations.py (blind mutations, 50 seeds, no coverage measured), and
the size of the corpus: ``TLS_LAB_FUZZ_COUNT`` (20 000 by default here; 100 000 for gate G1 in PR-A2).
"""

import hashlib
import os
import time

from tls_lab import mutations, wire

STREAM = "1982b1525f081039abb3663d90aa9cad9a62925861dcdea54bc5a92964e97949"
CORPUS = {500: "e9c1b8eb8a4b0cf45f2a265ddef3a0684a5bc16f64babe1c998f162de2e3f3ca",
          20000: "f32a14ca6f958e2054733c528a0e4f567d9d5963e08d90c52cd102d8759b06e5"}
COUNT = int(os.environ.get("TLS_LAB_FUZZ_COUNT", "20000"))
SLOW = 0.05  # seconds: one input read slower than this fails


def test_the_stream_of_numbers_is_the_same_everywhere():
    stream = mutations.Stream("tls-lab/check")
    assert hashlib.sha256(bytes(stream.below(256) for _ in range(1000))).hexdigest() == STREAM


def test_the_corpus_is_the_same_everywhere():
    for count, expected in CORPUS.items():
        assert mutations.fingerprint(count) == expected
    assert mutations.fingerprint(50, "another seed") != mutations.fingerprint(50)


def test_every_strategy_is_used_and_the_numbers_are_unbiased():
    stream = mutations.Stream("tls-lab/bias")
    counts = [0] * 6
    for _ in range(6000):
        counts[stream.below(6)] += 1
    assert all(900 < c < 1100 for c in counts)
    assert len(mutations.STRATEGIES) == 8 and len(mutations.seeds()) >= 45


def test_the_reader_only_ever_reads_or_refuses():
    """Facts or Malformed, nothing else, and never slow, on COUNT damaged inputs."""
    seen = {"malformed": 0}
    worst = 0.0
    for index, data in enumerate(mutations.corpus(COUNT)):
        started = time.perf_counter()
        try:
            kind = wire.read_flight(data).kind
        except wire.Malformed:
            kind = "malformed"
        except Exception as error:
            raise AssertionError(f"input {index} ({data[:40].hex()}…): {type(error).__name__}: {error}") from error
        wire.plaintext_prefix(data)
        worst = max(worst, time.perf_counter() - started)
        seen[kind] = seen.get(kind, 0) + 1
    assert worst < SLOW, worst
    assert sum(seen.values()) == COUNT
    # The corpus still holds readable flights: the reader is exercised past its first checks.
    assert seen.get("server_hello", 0) and seen.get("hello_retry_request", 0) and seen.get("alert", 0)
