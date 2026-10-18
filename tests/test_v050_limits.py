# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: the limiter leaves a slot to the people, the scheduler has its own hourly share, and
the domains being scanned are known (web/limits.py, web/scanning.py)."""

import asyncio

import pytest

from helpers import DEMO, post, setup_account
from posture_cockpit.web.limits import ScanLimiter, TooManyScans
from posture_cockpit.web.scanning import scanning

SCHEDULER = "system:scheduler"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_the_scheduler_never_takes_the_last_slot():
    limiter = ScanLimiter(concurrent=3, per_hour=30)
    first = limiter.take(SCHEDULER, keep_free=1)
    second = limiter.take("user:1")
    with pytest.raises(TooManyScans) as busy:
        limiter.take(SCHEDULER, keep_free=1)
    assert busy.value.reason == "busy"
    third = limiter.take("user:2")  # a person still gets the last one
    assert limiter.running == 3
    for release in (first, second, third):
        release()
    assert limiter.running == 0


def test_a_slot_given_back_twice_counts_once():
    limiter = ScanLimiter(concurrent=2, per_hour=30)
    release = limiter.take(SCHEDULER)
    release()
    release()
    assert limiter.running == 0


def test_the_scheduler_has_its_own_hourly_share():
    clock = Clock()
    limiter = ScanLimiter(concurrent=4, per_hour=2, clock=clock)
    for _ in range(2):
        limiter.take(SCHEDULER, keep_free=1)()
    with pytest.raises(TooManyScans) as quota:
        limiter.take(SCHEDULER, keep_free=1)
    assert quota.value.reason == "quota" and quota.value.retry_after == 3601
    limiter.take("user:1")()  # the share of a person is untouched
    clock.now += 3600
    limiter.take(SCHEDULER, keep_free=1)()


def test_the_context_manager_of_the_people_is_unchanged():
    limiter = ScanLimiter(concurrent=1, per_hour=30)
    with limiter.slot("user:1"):
        assert limiter.running == 1
        with pytest.raises(TooManyScans), limiter.slot("user:2"):
            pass
    assert limiter.running == 0


def test_scanning_marks_a_domain_for_the_time_of_the_scan():
    class S:
        def __init__(self):
            self.in_progress: set[str] = set()

    s = S()
    with scanning(s, "example.org"):
        assert "example.org" in s.in_progress
        with scanning(s, "example.org"):  # a second scan of the same domain
            assert "example.org" in s.in_progress
        assert "example.org" in s.in_progress  # still there: the first one runs
    assert s.in_progress == set()


def test_a_scan_from_the_pages_marks_its_domain(client):
    setup_account(client)
    services = client.app.state.services
    seen = []
    scan = services.scanner.scan

    async def watching(domain, perimeter=None, history=None):
        seen.append(set(services.in_progress))
        await asyncio.sleep(0)
        return await scan(domain, perimeter, history=history)

    services.scanner.scan = watching
    post(client, "/domains", "/domains", domain=DEMO)
    assert seen == [{DEMO}] and services.in_progress == set()
