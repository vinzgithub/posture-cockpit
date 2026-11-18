# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The bench never leaves the machine (version 0.8.0, PR-A, precision 5 of the review of R1).

While :func:`loopback_only` is active, an audit hook of the interpreter (PEP 578) refuses, before any
packet is sent:

- a connection, a datagram or a bind to an address that is not a loopback address (127.0.0.0/8, ::1);
- a name resolution of anything but a loopback literal or ``localhost``;
- a process other than ``openssl`` (the optional reference server and client), or an ``openssl`` given a
  host that is not a loopback address.

The hook is installed once per process (an audit hook cannot be removed) and does nothing while the guard
is off, so the rest of the suite is untouched. It covers every thread of the process, the bench's servers
included. It is a guard for the tests, not a sandbox: code in C that opens sockets without the Python
socket module, or a child process, is outside its reach; the bench starts no such code but ``openssl``,
whose arguments it checks.

The product's egress policy (core/egress.py) is neither used nor changed here: it refuses the loopback,
and the bench needs nothing else.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

_state = {"on": False, "installed": False}
_lock = threading.Lock()


class NotLoopback(PermissionError):
    """An attempt to reach something else than this machine, refused before it was made."""


def is_loopback(host: Any) -> bool:
    if host in ("localhost", b"localhost"):
        return True
    try:
        text = host.decode() if isinstance(host, bytes) else str(host)
        return ipaddress.ip_address(text.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _address_ok(address: Any) -> bool:
    if isinstance(address, tuple) and address:
        return is_loopback(address[0])
    return isinstance(address, (str, bytes))  # AF_UNIX paths: never a network


def _openssl_ok(args: Any) -> bool:
    argv = [os.fsdecode(a) for a in (args if isinstance(args, (list, tuple)) else [args])]
    if not argv or os.path.basename(argv[0]) != "openssl":
        return False
    for i, arg in enumerate(argv):
        if arg in ("-connect", "-accept") and i + 1 < len(argv):
            host = argv[i + 1].rsplit(":", 1)[0].strip("[]")
            if host and not is_loopback(host):
                return False
    return True


def _hook(event: str, args: tuple) -> None:
    if not _state["on"]:
        return
    if event in ("socket.connect", "socket.bind", "socket.sendto") and not _address_ok(args[1]):
        raise NotLoopback(f"{event} to {args[1]!r} refused by the bench")
    if event == "socket.getaddrinfo" and args[0] not in (None, "") and not is_loopback(args[0]):
        raise NotLoopback(f"name resolution of {args[0]!r} refused by the bench")
    if event == "subprocess.Popen" and not _openssl_ok(args[1]):
        raise NotLoopback(f"process {args[1]!r} refused by the bench")


def install() -> None:
    with _lock:
        if not _state["installed"]:
            sys.addaudithook(_hook)
            _state["installed"] = True


@contextmanager
def loopback_only() -> Iterator[None]:
    install()
    _state["on"] = True
    try:
        yield
    finally:
        _state["on"] = False


def active() -> bool:
    return bool(_state["on"])


LOOPBACK_V4 = "127.0.0.1"
SECOND_V4 = "127.0.0.2"  # a second address of this machine (Linux: all of 127.0.0.0/8 is local)
LOOPBACK_V6 = "::1"


def can_bind(host: str) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.bind((host, 0))
        return True
    except OSError:
        return False
