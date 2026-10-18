# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: when a scheduled scan is due (core/schedule_time.py).

The cases of the specification (section 8), in Europe/Paris, spread taken out; then the rules:
one slot per nominal local time, the latest missed occurrence only, half a period after a run."""

from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from posture_cockpit.core import schedule_time as st
from posture_cockpit.core.schedule_time import Definition

PARIS = ZoneInfo("Europe/Paris")
DOMAIN = "example.org"
SPREAD = st.spread(DOMAIN)


def utc(*args) -> datetime:
    return datetime(*args, tzinfo=UTC)


def local(*args) -> datetime:
    return datetime(*args, tzinfo=PARIS).astimezone(UTC)


def daily(hh: int, mm: int = 0) -> Definition:
    return Definition("daily", hh * 60 + mm)


@pytest.mark.parametrize(("definition", "day", "slot", "real"), [
    # spring: 02:30 does not exist, it moves by the gap: 03:30 summer time, 01:30 UTC
    (daily(2, 30), date(2026, 3, 29), "2026-03-29T02:30", utc(2026, 3, 29, 1, 30)),
    # autumn: 02:30 happens twice, the first one counts: 02:30 summer time, 00:30 UTC
    (daily(2, 30), date(2026, 10, 25), "2026-10-25T02:30", utc(2026, 10, 25, 0, 30)),
    # the 31st of a month of 30 days is its last day
    (Definition("monthly", 300, monthday=31), date(2026, 4, 30), "2026-04-30T05:00", utc(2026, 4, 30, 3, 0)),
    (Definition("monthly", 300, monthday=31), date(2028, 2, 29), "2028-02-29T05:00", utc(2028, 2, 29, 4, 0)),
])
def test_the_cases_of_the_specification(definition, day, slot, real):
    occ = st.occurrence(definition, day, PARIS, DOMAIN)
    assert (occ.slot, occ.at - SPREAD) == (slot, real)


def test_a_repeated_hour_runs_once():
    first = st.following(daily(2, 30), PARIS, DOMAIN, utc(2026, 10, 24, 23, 0))
    second = st.following(daily(2, 30), PARIS, DOMAIN, first.at)
    assert first.slot == "2026-10-25T02:30" and second.slot == "2026-10-26T02:30"
    assert second.at - first.at == timedelta(hours=25)  # one hour more that night, never twice


def test_a_monthly_schedule_on_the_31st_runs_every_month():
    definition = Definition("monthly", 300, monthday=31)
    moment, slots = utc(2026, 1, 1), []
    for _ in range(14):
        occ = st.following(definition, PARIS, DOMAIN, moment)
        slots.append(occ.slot[:10])
        moment = occ.at
    assert slots == ["2026-01-31", "2026-02-28", "2026-03-31", "2026-04-30", "2026-05-31", "2026-06-30",
                     "2026-07-31", "2026-08-31", "2026-09-30", "2026-10-31", "2026-11-30", "2026-12-31",
                     "2027-01-31", "2027-02-28"]


def test_weekly_on_an_iso_weekday():
    monday = Definition("weekly", 300, weekday=1)
    occ = st.following(monday, PARIS, DOMAIN, utc(2026, 10, 14))
    assert occ.slot == "2026-10-19T05:00" and date(2026, 10, 19).isoweekday() == 1
    sunday = Definition("weekly", 300, weekday=7)
    assert st.following(sunday, PARIS, DOMAIN, utc(2026, 10, 14)).slot == "2026-10-18T05:00"


def test_stopped_from_sunday_to_tuesday_a_weekly_scan_runs_once():
    """Monday 05:00, the instance stopped from Sunday to Tuesday 10:00: run once, 29 h late."""
    monday = Definition("weekly", 300, weekday=1)
    last_run = local(2026, 10, 12, 5, 0) + SPREAD
    now = local(2026, 10, 20, 10, 2)
    due = st.latest(monday, PARIS, DOMAIN, now, after=last_run + monday.half_period)
    assert due is not None and due.slot == "2026-10-19T05:00"
    assert not st.too_late(due, monday, now)


def test_stopped_two_weeks_a_daily_scan_is_missed_then_runs_the_next_day():
    """Daily 05:00, the instance back at 20:00 after two weeks: 15 h late, more than 12 h."""
    definition = daily(5)
    now = local(2026, 10, 20, 20, 0)
    due = st.latest(definition, PARIS, DOMAIN, now, after=local(2026, 10, 6, 5, 0) + definition.half_period)
    assert due is not None and due.slot == "2026-10-20T05:00" and st.too_late(due, definition, now)
    assert st.following(definition, PARIS, DOMAIN, now).slot == "2026-10-21T05:00"


def test_only_the_latest_missed_occurrence_counts():
    definition = daily(5)
    due = st.latest(definition, PARIS, DOMAIN, local(2026, 10, 20, 9, 0), after=local(2026, 10, 1, 0, 0))
    assert due is not None and due.slot == "2026-10-20T05:00"  # not the 19th, nor the 2nd


def test_a_changed_time_does_not_run_twice_the_same_day():
    """Daily 05:00, run at 05:00, changed to 06:00 at 05:20: next run the day after at 06:00."""
    changed = daily(6)
    ran = local(2026, 10, 20, 5, 0) + SPREAD
    threshold = ran + changed.half_period
    for now in (local(2026, 10, 20, 5, 20), local(2026, 10, 20, 6, 30), local(2026, 10, 20, 16, 0)):
        assert st.latest(changed, PARIS, DOMAIN, now, after=threshold) is None
        assert st.following(changed, PARIS, DOMAIN, max(now, threshold)).slot == "2026-10-21T06:00"


def test_the_spread_is_fixed_for_each_domain_and_at_most_ten_minutes():
    spreads = {st.spread(f"domain-{n}.example") for n in range(500)}
    assert all(timedelta(0) <= s <= timedelta(minutes=10) for s in spreads)
    assert len(spreads) > 300  # spread over the ten minutes
    assert st.spread("example.org") == st.spread("example.org")


def test_the_slot_is_the_nominal_local_time_whatever_the_zone():
    """A change of TZ between two starts recomputes the times; the slot of a day stays the same
    string, so an occurrence already run under the former zone is never run again."""
    definition = daily(5)
    in_paris = st.occurrence(definition, date(2026, 10, 20), PARIS, DOMAIN)
    in_new_york = st.occurrence(definition, date(2026, 10, 20), ZoneInfo("America/New_York"), DOMAIN)
    assert in_paris.slot == in_new_york.slot == "2026-10-20T05:00"
    assert in_new_york.at - in_paris.at == timedelta(hours=6)


@pytest.mark.parametrize("zone", [PARIS, ZoneInfo("America/New_York"), ZoneInfo("Asia/Kolkata"), UTC])
@pytest.mark.parametrize("definition", [daily(0), daily(23, 59), daily(2, 30), Definition("weekly", 90, weekday=7),
                                        Definition("monthly", 1439, monthday=31)])
def test_occurrences_follow_each_other_for_two_years(definition, zone):
    moment, seen = utc(2026, 1, 1), set()
    while moment < utc(2028, 1, 1):
        occ = st.following(definition, zone, DOMAIN, moment)
        assert occ.at > moment and occ.slot not in seen
        seen.add(occ.slot)
        assert st.latest(definition, zone, DOMAIN, occ.at) == occ
        moment = occ.at
    expected = {"daily": 730, "weekly": 104, "monthly": 24}[definition.frequency]
    assert abs(len(seen) - expected) <= 1


@pytest.mark.parametrize(("values", "message"), [
    ({"frequency": "hourly", "at_minute": 0}, "frequency"),
    ({"frequency": "daily", "at_minute": 1440}, "at_minute"),
    ({"frequency": "daily", "at_minute": -1}, "at_minute"),
    ({"frequency": "weekly", "at_minute": 0}, "weekday"),
    ({"frequency": "daily", "at_minute": 0, "weekday": 1}, "weekday"),
    ({"frequency": "weekly", "at_minute": 0, "weekday": 8}, "weekday"),
    ({"frequency": "monthly", "at_minute": 0}, "day of the month"),
    ({"frequency": "monthly", "at_minute": 0, "monthday": 32}, "monthday"),
])
def test_a_definition_must_be_well_formed(values, message):
    with pytest.raises(ValueError, match=message):
        Definition(**values)


@pytest.mark.parametrize(("text", "minutes"), [("00:00", 0), ("05:00", 300), ("23:59", 1439), (" 12:30 ", 750)])
def test_a_time_of_day(text, minutes):
    assert st.parse_time(text) == minutes and st.format_time(minutes) == text.strip()


@pytest.mark.parametrize("text", ["24:00", "23:60", "5:00", "05:0", "05h00", "", "-1:00", "ab:cd", "05:00:00"])
def test_a_wrong_time_of_day_is_refused(text):
    with pytest.raises(ValueError):
        st.parse_time(text)


def test_the_constants_of_the_specification():
    spread, half = st.SPREAD, st.HALF_PERIOD
    assert st.DEFAULT_AT_MINUTE == 300 and spread == timedelta(minutes=10)
    assert half == {"daily": timedelta(hours=12), "weekly": timedelta(hours=84), "monthly": timedelta(days=15)}
