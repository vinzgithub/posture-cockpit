# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""How many scans may run: at once on the instance, and per account each hour.

A scan opens dozens of connections; without a limit, one account (or one
leaked API key) could keep the server busy, or use it to hammer a third
party. A scan over the limit is refused at once, with the reason, rather than
queued: the page or the script says so and can try again.

Kept in memory, for the process: run one uvicorn worker (the default) so the
limits hold for the whole instance.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager


class TooManyScans(Exception):
    """``reason``: ``"busy"`` (the instance runs its maximum) or ``"quota"`` (this account's hourly share)."""

    def __init__(self, reason: str, retry_after: int):
        self.reason = reason
        self.retry_after = retry_after
        super().__init__(reason)


class ScanLimiter:
    def __init__(self, concurrent: int = 4, per_hour: int = 30, clock: Callable[[], float] = time.monotonic):
        self.concurrent = concurrent
        self.per_hour = per_hour
        self._clock = clock
        self._running = 0
        self._started: dict[str, deque[float]] = {}

    @contextmanager
    def slot(self, who: str, *, counts: bool = True) -> Iterator[None]:
        """Holds one of the concurrent slots while the scan runs. Raises TooManyScans.

        ``counts=False``: does not use the hourly share (re-running a single check)."""
        now = self._clock()
        started = self._started.setdefault(who, deque())
        while started and now - started[0] >= 3600:
            started.popleft()
        if counts and len(started) >= self.per_hour:
            raise TooManyScans("quota", retry_after=int(3600 - (now - started[0])) + 1)
        if self._running >= self.concurrent:
            raise TooManyScans("busy", retry_after=10)
        if counts:
            started.append(now)
        self._running += 1
        try:
            yield
        finally:
            self._running -= 1
