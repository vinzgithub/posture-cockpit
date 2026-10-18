# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""When a scheduled scan is due (0.5.0). Pure: no database, no clock of its own.

A schedule is a frequency (daily, weekly on an ISO weekday, monthly on a day of the month) and a
time of day, in minutes since midnight, in the time zone of the instance.

- An *occurrence* is one nominal local date and time. Its *slot*, ``YYYY-MM-DDTHH:MM`` in local
  time, identifies it: one run at most per domain and slot (``schedule_runs``), so a change of
  the clocks, of ``TZ`` or a clock going back never runs the same occurrence twice.
- Its *real time*, in UTC, comes from zoneinfo with ``fold = 0``: a time that does not exist (the
  spring change) moves by the length of the gap, a repeated one (autumn) is its first occurrence.
  A *spread* of 0 to 10 minutes, fixed for each domain, is added so that domains due at the same
  time do not all start together.
- A monthly day beyond the end of a month is its last day (the 31st is the 30th in April).
- Catching up: only the latest occurrence missed counts; it runs once if it is late by less than
  half a period (:data:`HALF_PERIOD`), otherwise it is noted as missed.
- After a run, the next occurrence is at least half a period later: changing the time of a
  schedule never runs a domain twice in a period.
"""

from __future__ import annotations

import calendar
import hashlib
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta, tzinfo

FREQUENCIES = ("daily", "weekly", "monthly")
DEFAULT_AT_MINUTE = 5 * 60            # 05:00, time of the instance
SPREAD = timedelta(minutes=10)        # 0 to 10 minutes, fixed for each domain
HALF_PERIOD = {"daily": timedelta(hours=12), "weekly": timedelta(hours=84), "monthly": timedelta(days=15)}
# How far to look for an occurrence: more than a period, whatever the month.
_LOOK = {"daily": 3, "weekly": 9, "monthly": 66}


@dataclass(frozen=True)
class Definition:
    frequency: str
    at_minute: int
    weekday: int | None = None      # 1 = Monday ... 7 = Sunday, weekly only
    monthday: int | None = None     # 1 to 31, monthly only

    def __post_init__(self) -> None:
        if self.frequency not in FREQUENCIES:
            raise ValueError(f"unknown frequency {self.frequency!r}")
        if not isinstance(self.at_minute, int) or not 0 <= self.at_minute <= 1439:
            raise ValueError("at_minute must be 0 to 1439")
        if (self.frequency == "weekly") != (self.weekday is not None):
            raise ValueError("a weekday goes with a weekly schedule only")
        if (self.frequency == "monthly") != (self.monthday is not None):
            raise ValueError("a day of the month goes with a monthly schedule only")
        if self.weekday is not None and not 1 <= self.weekday <= 7:
            raise ValueError("weekday must be 1 to 7")
        if self.monthday is not None and not 1 <= self.monthday <= 31:
            raise ValueError("monthday must be 1 to 31")

    @property
    def half_period(self) -> timedelta:
        return HALF_PERIOD[self.frequency]

    @property
    def time_of_day(self) -> time:
        return time(self.at_minute // 60, self.at_minute % 60)

    def falls_on(self, day: date) -> bool:
        if self.frequency == "daily":
            return True
        if self.frequency == "weekly":
            return day.isoweekday() == self.weekday
        assert self.monthday is not None
        return day.day == min(self.monthday, calendar.monthrange(day.year, day.month)[1])


@dataclass(frozen=True)
class Occurrence:
    slot: str        # nominal local date and time, YYYY-MM-DDTHH:MM
    at: datetime     # real time, UTC, spread included


def parse_time(text: str) -> int:
    """``HH:MM`` from 00:00 to 23:59 as minutes since midnight. Raises ValueError otherwise."""
    hours, sep, minutes = text.strip().partition(":")
    if sep != ":" or len(hours) != 2 or len(minutes) != 2 or not (hours + minutes).isdigit():
        raise ValueError("expected HH:MM")
    h, m = int(hours), int(minutes)
    if h > 23 or m > 59:
        raise ValueError("expected 00:00 to 23:59")
    return h * 60 + m


def format_time(at_minute: int) -> str:
    return f"{at_minute // 60:02d}:{at_minute % 60:02d}"


def spread(domain: str) -> timedelta:
    """0 to 10 minutes, the same for a domain on every instance and at every start."""
    seconds = int.from_bytes(hashlib.sha256(domain.encode()).digest()[:4], "big") % (int(SPREAD.total_seconds()) + 1)
    return timedelta(seconds=seconds)


def occurrence(definition: Definition, day: date, tz: tzinfo, domain: str) -> Occurrence:
    """The occurrence of ``day`` (which must be one of its days)."""
    nominal = datetime.combine(day, definition.time_of_day)
    real = nominal.replace(tzinfo=tz, fold=0).astimezone(UTC)
    # zoneinfo keeps the wall time of a non-existent time; the UTC instant it gives with
    # fold = 0 is that time moved by the length of the gap, which is what is wanted.
    return Occurrence(nominal.strftime("%Y-%m-%dT%H:%M"), real + spread(domain))


def _days(definition: Definition, start: date, step: int):
    for n in range(_LOOK[definition.frequency]):
        day = start + timedelta(days=n * step)
        if definition.falls_on(day):
            yield day


def latest(definition: Definition, tz: tzinfo, domain: str, now: datetime, after: datetime | None = None
           ) -> Occurrence | None:
    """The latest occurrence whose real time is at or before ``now``, and strictly after ``after``
    when given; None if there is none within a period."""
    today = now.astimezone(tz).date() + timedelta(days=1)  # the spread may carry past midnight
    for day in _days(definition, today, -1):
        found = occurrence(definition, day, tz, domain)
        if found.at <= now:
            return found if after is None or found.at > after else None
    return None


def following(definition: Definition, tz: tzinfo, domain: str, moment: datetime) -> Occurrence:
    """The first occurrence whose real time is strictly after ``moment``."""
    start = moment.astimezone(tz).date() - timedelta(days=1)
    for day in _days(definition, start, 1):
        found = occurrence(definition, day, tz, domain)
        if found.at > moment:
            return found
    raise AssertionError("no occurrence within a period")  # pragma: no cover - _LOOK covers every period


def too_late(occ: Occurrence, definition: Definition, now: datetime) -> bool:
    """Whether ``occ`` is too late to run: late by half a period or more (then it is missed)."""
    return now - occ.at >= definition.half_period
