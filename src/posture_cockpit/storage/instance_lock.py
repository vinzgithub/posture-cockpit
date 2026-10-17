# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Who may use a data folder: the server and commands together, a restoration alone (0.4.1).

One lock file per data folder, ``.posture-cockpit.lock``, locked with flock(2). The server holds
it *shared* for as long as it runs, and so do the commands that read or write the database
(backup, account rescue). A restoration holds it *exclusive*, from its first check to the last
file put in place: no server can start, and no command can open the database, in between. A
server that cannot take it (a restoration in progress) refuses to start; a restoration that
cannot take it (a server running) refuses to begin. Nothing waits.

What it guarantees:

- on one host, between all its processes, containers included when they share a volume: flock
  is kept by the kernel, which they share. This is the case of a Docker volume (``local`` driver)
  and of a folder of the host mounted on /data;
- on a network file system, only what the server of that file system honours: NFSv4, and NFSv3
  with lockd, honour it (Linux turns flock into byte-range locks over NFS); SMB/CIFS mounts and
  some FUSE file systems do not share it between clients. Two hosts must never run Posture
  Cockpit on the same data folder: SQLite itself does not support it on such file systems.

Servers of 0.4.0 and earlier do not take this lock: a restoration also checks that no SQLite
connection is open (storage/backup.py, ``in_use``). Without flock (Windows), the lock does nothing.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

LOCK_NAME = ".posture-cockpit.lock"


class Busy(Exception):
    """The lock is held the other way: a server runs, or a restoration is in progress."""


class Held:
    """A lock taken; ``release()`` (or the end of the process) gives it back."""

    def __init__(self, fd: int | None):
        self._fd = fd

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)  # closing the file releases the lock
            self._fd = None


def _take(data_dir: Path, operation: int) -> Held:
    if fcntl is None:
        return Held(None)
    fd = os.open(data_dir / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, operation | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise Busy(str(data_dir)) from None
    except BaseException:
        os.close(fd)
        raise
    return Held(fd)


def shared(data_dir: Path) -> Held:
    """For the server and the commands that use the database. Busy: a restoration is in progress."""
    return _take(data_dir, fcntl.LOCK_SH if fcntl else 0)


@contextmanager
def exclusive(data_dir: Path) -> Iterator[None]:
    """For a restoration, from start to end. Busy: a server or a command uses the folder."""
    held = _take(data_dir, fcntl.LOCK_EX if fcntl else 0)
    try:
        yield
    finally:
        held.release()
