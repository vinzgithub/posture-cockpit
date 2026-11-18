# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Synthetic responders of the bench (version 0.8.0, PR-A).

A responder is a TCP server on a loopback address that reads **one** ClientHello (at most
:data:`READ_LIMIT` bytes, within :data:`READ_DEADLINE` seconds) and then plays one fixed behaviour of
the catalogue (scenarios.py): send bytes and close, send them a few bytes at a time, close at once, reset,
stay silent. It keeps what each connection sent, so that a test can check, byte for byte, what a prober
offered (for instance, that no legacy offer reached an address not listed for the extended level).

A responder knows nothing of TLS: it does not interpret the ClientHello. The bytes it sends are those of
the scenario, the same for every offer, which is what makes the expected interpretation fixed.
"""

from __future__ import annotations

import contextlib
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

from .guard import LOOPBACK_V4

READ_LIMIT = 16 * 1024   # bytes of a ClientHello read at most
READ_DEADLINE = 2.0      # seconds to receive it
SILENCE = 3.0            # seconds a silent responder keeps the connection open
SLOW_CHUNK = 16         # bytes sent at once by a slow reply
SLOW_GAP = 0.01          # seconds between two chunks of a slow reply

BEHAVIOURS = ("reply", "reply_slowly", "close", "reset", "silence")


@dataclass
class Behaviour:
    kind: str                # one of BEHAVIOURS
    data: bytes = b""        # what "reply" and "reply_slowly" send

    def __post_init__(self) -> None:
        if self.kind not in BEHAVIOURS:
            raise ValueError(f"unknown behaviour {self.kind}")


@dataclass
class Connection:
    received: bytes = b""
    complete: bool = False   # a whole TLS record was received before the reply


@dataclass
class Responder:
    behaviour: Behaviour
    host: str = LOOPBACK_V4
    connections: list[Connection] = field(default_factory=list)

    def __post_init__(self) -> None:
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.bind((self.host, 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.address = self.sock.getsockname()[:2]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> Responder:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join(SILENCE + READ_DEADLINE + 1)
        self.sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                self._answer(conn)

    def _answer(self, conn: socket.socket) -> None:
        connection = Connection()
        self.connections.append(connection)
        connection.received, connection.complete = read_record(conn)
        kind, data = self.behaviour.kind, self.behaviour.data
        try:
            if kind == "reply":
                conn.sendall(data)
            elif kind == "reply_slowly":
                for i in range(0, len(data), SLOW_CHUNK):
                    conn.sendall(data[i:i + SLOW_CHUNK])
                    time.sleep(SLOW_GAP)
            elif kind == "reset":
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            elif kind == "silence":
                deadline = time.monotonic() + SILENCE
                conn.settimeout(0.1)
                while time.monotonic() < deadline and not self._stop.is_set():
                    try:
                        if not conn.recv(1024):
                            break
                    except TimeoutError:
                        continue
            if kind in ("reply", "reply_slowly"):
                conn.shutdown(socket.SHUT_WR)
                conn.settimeout(0.5)
                with contextlib.suppress(OSError):
                    conn.recv(1024)  # let the client read the reply before the close
        except OSError:
            pass


def read_record(conn: socket.socket) -> tuple[bytes, bool]:
    """Read until one whole TLS record is in (its 5-byte header says how long), the limit or the deadline."""
    conn.settimeout(READ_DEADLINE)
    deadline = time.monotonic() + READ_DEADLINE
    data = b""
    while len(data) < READ_LIMIT and time.monotonic() < deadline:
        if len(data) >= 5 and len(data) >= 5 + int.from_bytes(data[3:5], "big"):
            return data, True
        try:
            chunk = conn.recv(READ_LIMIT - len(data))
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    return data, len(data) >= 5 and len(data) >= 5 + int.from_bytes(data[3:5], "big")


def exchange(address: tuple, hello: bytes, timeout: float = 4.0, limit: int = 16 * 1024) -> tuple[bytes, str]:
    """A plain client of the bench: send ``hello``, read until the server closes, the limit or the timeout.
    Returns what was read and how it ended: closed, reset, timeout or limit."""
    family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(address)
        sock.sendall(hello)
        data = b""
        deadline = time.monotonic() + timeout
        while len(data) < limit:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                chunk = sock.recv(limit - len(data))
            except ConnectionResetError:
                return data, "reset"
            except TimeoutError:
                return data, "timeout"
            if not chunk:
                return data, "closed"
            data += chunk
        return data, "limit"
