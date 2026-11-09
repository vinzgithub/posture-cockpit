# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""How many scans may run: at once on the instance, and per account each hour; how many PDF reports.

A scan opens dozens of connections; without a limit, one account (or one
leaked API key) could keep the server busy, or use it to hammer a third
party. A scan over the limit is refused at once, with the reason, rather than
queued: the page or the script says so and can try again.

Kept in memory, for the process: run one uvicorn worker (the default) so the
limits hold for the whole instance.

The scheduler (0.5.0) takes its slots as the principal ``system:scheduler``, with its own
hourly share, and leaves one slot free (``keep_free``): a person is never kept waiting by it.
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
        release = self.take(who, counts=counts)
        try:
            yield
        finally:
            release()

    def take(self, who: str, *, counts: bool = True, keep_free: int = 0) -> Callable[[], None]:
        """Takes a slot and returns the function that gives it back (called once). Raises
        TooManyScans. ``keep_free``: refuses unless that many slots stay free after this one."""
        now = self._clock()
        started = self._started.setdefault(who, deque())
        while started and now - started[0] >= 3600:
            started.popleft()
        if counts and len(started) >= self.per_hour:
            raise TooManyScans("quota", retry_after=int(3600 - (now - started[0])) + 1)
        if self._running >= self.concurrent - keep_free:
            raise TooManyScans("busy", retry_after=10)
        if counts:
            started.append(now)
        self._running += 1
        released = False

        def release() -> None:
            nonlocal released
            if not released:
                released = True
                self._running -= 1
        return release

    @property
    def running(self) -> int:
        return self._running


# PDF reports (version 0.7.0, corrective 3): each is laid out in a process of its own (report/jobs.py),
# a few at once on the instance and one at a time for an account. A report over the limit is refused at
# once, never queued: the page says so and the person tries again in a moment.
REPORTS_PER_ACCOUNT = 1


class TooManyReports(Exception):
    """``reason``: ``"busy"`` (the instance makes its maximum of reports) or ``"account"`` (this account
    already waits for one)."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class ReportLimiter:
    def __init__(self, concurrent: int = 2, per_account: int = REPORTS_PER_ACCOUNT):
        self.concurrent = concurrent
        self.per_account = per_account
        self._running = 0
        self._by_account: dict[str, int] = {}

    def take(self, who: str) -> Callable[[], None]:
        """Takes a place for one report of ``who`` and returns the function that gives it back: called
        once the process of the report is gone (report/jobs.py), any further call does nothing. Raises
        TooManyReports, without taking anything."""
        if self._by_account.get(who, 0) >= self.per_account:
            raise TooManyReports("account")
        if self._running >= self.concurrent:
            raise TooManyReports("busy")
        self._running += 1
        self._by_account[who] = self._by_account.get(who, 0) + 1
        released = False

        def release() -> None:
            nonlocal released
            if not released:
                released = True
                self._running -= 1
                self._by_account[who] -= 1
                if not self._by_account[who]:
                    del self._by_account[who]
        return release

    @property
    def running(self) -> int:
        return self._running
