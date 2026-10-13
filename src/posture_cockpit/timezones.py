# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Times are stored and exchanged in UTC; people read them in the instance's time zone.

The database, the API and the command line keep ISO 8601 times in UTC
(``2026-10-13T07:19:05+00:00``). Pages and PDF reports show them in the time
zone of the instance, chosen in this order:

1. ``POSTURE_COCKPIT_TIMEZONE`` (an IANA name such as ``Europe/Paris``);
2. ``TZ``, the variable most containers already set;
3. UTC.

A wrong ``POSTURE_COCKPIT_TIMEZONE`` stops the start: the operator asked for
something that does not exist. ``TZ`` may hold a POSIX rule that only the C
library understands (``CET-1CEST,M3.5.0,M10.5.0/3``): then UTC is used, with a
warning in the log.
"""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

log = logging.getLogger(__name__)

__all__ = ["UTC", "instance_zone", "local", "local_date", "offset_label", "zone"]


def zone(name: str) -> tzinfo:
    """The time zone called ``name``: an IANA name, or ``UTC``. Raises ValueError otherwise.

    A leading ``:`` is accepted, as in ``TZ=:Europe/Paris``."""
    text = name.strip().removeprefix(":")
    if text.upper() in ("UTC", "ETC/UTC", "Z"):
        return UTC
    try:
        return ZoneInfo(text)
    except (ZoneInfoNotFoundError, ValueError) as e:  # ValueError: not a valid key (absolute path, "..")
        raise ValueError(f"unknown time zone: {name!r}") from e


def instance_zone(setting: str | None, tz_variable: str | None) -> tzinfo:
    """The time zone of the instance (see the module documentation)."""
    if setting and setting.strip():
        return zone(setting)
    if tz_variable and tz_variable.strip():
        try:
            return zone(tz_variable)
        except ValueError:
            log.warning("TZ=%r is not a time zone name such as Europe/Paris: times are shown in UTC", tz_variable)
    return UTC


def local(value: str | datetime, tz: tzinfo) -> datetime:
    """A stored time in the time zone ``tz``. A time written without offset is UTC."""
    moment = datetime.fromisoformat(value) if isinstance(value, str) else value
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(tz)


def local_date(value: str | date | datetime, tz: tzinfo) -> date:
    """The calendar day of a stored time in ``tz``; a bare date (``2026-11-01``) is kept as it is."""
    if isinstance(value, datetime):
        return local(value, tz).date()
    if isinstance(value, date):
        return value
    if len(value) == 10:  # a day, not a time: an expiry date has no time zone
        return date.fromisoformat(value)
    return local(value, tz).date()


def offset_label(moment: datetime) -> str:
    """``UTC``, ``UTC+2``, ``UTC-4``, ``UTC+5:30``: the offset of an aware time, short, for readers."""
    offset = moment.utcoffset() or timedelta(0)
    if not offset:
        return "UTC"
    sign = "+" if offset > timedelta(0) else "-"
    hours, minutes = divmod(abs(int(offset.total_seconds())) // 60, 60)
    return f"UTC{sign}{hours}:{minutes:02d}" if minutes else f"UTC{sign}{hours}"
