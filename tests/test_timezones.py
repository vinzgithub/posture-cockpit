# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Times: stored and served by the API in UTC, shown in the time zone of the instance."""

from datetime import UTC, date, datetime
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient

from helpers import DEMO, post, setup_account
from posture_cockpit.config import Config
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.i18n import Catalog
from posture_cockpit.report import report_context
from posture_cockpit.timezones import instance_zone, local, local_date, offset_label, zone
from posture_cockpit.web.app import create_app

PARIS = ZoneInfo("Europe/Paris")


# ------------------------------------------------------------- choosing the zone
def test_the_setting_wins_over_tz_which_wins_over_utc():
    assert instance_zone("America/New_York", "Europe/Paris") == ZoneInfo("America/New_York")
    assert instance_zone(None, "Europe/Paris") == PARIS
    assert instance_zone("", ":Europe/Paris") == PARIS  # glibc accepts a leading colon
    assert instance_zone(None, None) is UTC
    assert instance_zone("  ", "") is UTC
    assert zone("utc") is UTC and zone("Etc/UTC") is UTC


def test_a_wrong_setting_stops_the_start_but_a_posix_tz_falls_back_to_utc(caplog):
    with pytest.raises(ValueError, match="unknown time zone"):
        instance_zone("Europe/Pari", None)
    for bad in ("../../etc/passwd", "/etc/localtime"):  # not a zone name: refused, never read as a path
        with pytest.raises(ValueError):
            zone(bad)
    assert instance_zone(None, "CET-1CEST,M3.5.0,M10.5.0/3") is UTC
    assert "times are shown in UTC" in caplog.text


def test_config_reads_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("POSTURE_COCKPIT_TIMEZONE", raising=False)
    monkeypatch.setenv("TZ", "Europe/Paris")
    assert Config.from_env().timezone == PARIS
    monkeypatch.setenv("POSTURE_COCKPIT_TIMEZONE", "Asia/Tokyo")
    assert Config.from_env().timezone == ZoneInfo("Asia/Tokyo")
    monkeypatch.delenv("POSTURE_COCKPIT_TIMEZONE")
    monkeypatch.delenv("TZ")
    assert Config.from_env().timezone is UTC
    assert Config(data_dir=tmp_path).timezone is UTC  # tests and scripts that build Config directly


# --------------------------------------------------------------- converting
@pytest.mark.parametrize(("stored", "expected"), [
    ("2026-10-13T07:19:05+00:00", "2026-10-13 09:19"),   # summer time, UTC+2
    ("2026-12-01T07:19:05+00:00", "2026-12-01 08:19"),   # winter time, UTC+1
    ("2026-10-12T22:30:00+00:00", "2026-10-13 00:30"),   # the day changes: shown on the 13th
    ("2026-12-31T23:30:00+00:00", "2027-01-01 00:30"),   # and the year
    ("2026-03-29T00:59:00+00:00", "2026-03-29 01:59"),   # just before the clocks go forward
    ("2026-03-29T01:00:00+00:00", "2026-03-29 03:00"),   # 02:00-03:00 does not exist in Paris that night
    ("2026-10-25T00:30:00+00:00", "2026-10-25 02:30"),   # 02:30 summer time...
    ("2026-10-25T01:30:00+00:00", "2026-10-25 02:30"),   # ...and 02:30 again, winter time, an hour later
    ("2026-10-13T07:19:05", "2026-10-13 09:19"),         # no offset written: UTC
])
def test_stored_utc_times_are_shown_in_paris(stored, expected):
    assert local(stored, PARIS).strftime("%Y-%m-%d %H:%M") == expected


def test_the_repeated_hour_keeps_two_distinct_offsets():
    first = local("2026-10-25T00:30:00+00:00", PARIS)
    second = local("2026-10-25T01:30:00+00:00", PARIS)
    assert (offset_label(first), offset_label(second)) == ("UTC+2", "UTC+1")


def test_other_zones_and_offset_labels():
    moment = "2026-10-13T07:19:05+00:00"
    assert local(moment, ZoneInfo("America/New_York")).strftime("%d %H:%M") == "13 03:19"
    assert local(moment, ZoneInfo("Asia/Kolkata")).strftime("%H:%M") == "12:49"
    assert offset_label(local(moment, ZoneInfo("America/New_York"))) == "UTC-4"
    assert offset_label(local(moment, ZoneInfo("Asia/Kolkata"))) == "UTC+5:30"
    assert offset_label(local(moment, UTC)) == "UTC"


def test_a_bare_day_is_not_shifted():
    # An expiry date is a day, not an instant: no time zone may move it.
    assert local_date("2026-11-01", ZoneInfo("Pacific/Kiritimati")) == date(2026, 11, 1)
    assert local_date(date(2026, 11, 1), PARIS) == date(2026, 11, 1)
    assert local_date(datetime(2026, 10, 12, 22, 30, tzinfo=UTC), PARIS) == date(2026, 10, 13)


# ----------------------------------------------------------- pages and reports
def _app(tmp_path, world, tz):
    def network(domain):
        return FixtureNetwork(world.get(domain, {"dns": {f"{domain} SOA": None}}))

    return create_app(Config(data_dir=tmp_path, timezone=tz), network_factory=network)


def _scan_at(client, stored: str) -> None:
    """Scans the demo domain, then moves the scan to ``stored`` (UTC)."""
    post(client, "/domains", "/domains", domain=DEMO)
    services = client.app.state.services
    services.db.execute("UPDATE scans SET started_at = ?", (stored,))


@pytest.mark.parametrize(("tz", "day", "hour"), [
    (PARIS, "13 octobre 2026", "00:30"),
    (UTC, "12 octobre 2026", "22:30"),
    (ZoneInfo("America/New_York"), "12 octobre 2026", "18:30"),
])
def test_pages_show_the_local_time_and_the_api_keeps_utc(tmp_path, world, tz, day, hour):
    from posture_cockpit.security import new_token, token_hash

    with TestClient(_app(tmp_path, world, tz)) as client:
        setup_account(client)
        _scan_at(client, "2026-10-12T22:30:00+00:00")
        assert f"analysé le {day} à {hour}" in client.get(f"/domains/{DEMO}").text
        assert f"Analyse du {day} à {hour}" in client.get(f"/domains/{DEMO}/details").text
        assert f"Analysé le {day}" in client.get("/domains").text
        token = new_token()
        client.app.state.services.accounts.add_token(1, "ha", token_hash(token))
        data = client.get("/api/v1/domains", headers={"Authorization": f"Bearer {token}"}).json()
        assert data["domains"][0]["scanned_at"] == "2026-10-12T22:30:00+00:00"


def test_the_audit_log_shows_local_time_and_keeps_utc_in_the_markup(tmp_path, world):
    with TestClient(_app(tmp_path, world, PARIS)) as client:
        setup_account(client)
        services = client.app.state.services
        services.db.execute("UPDATE audit_log SET at = '2026-10-12T22:30:00+00:00'")
        from helpers import PASSWORD
        post(client, "/admin/confirm", "/admin/confirm", password=PASSWORD)
        page = client.get("/admin/audit").text
        assert '<time datetime="2026-10-12T22:30:00+00:00" title="2026-10-12 22:30 UTC">13 octobre 2026 00:30</time>' \
            in page


def test_the_report_states_the_local_time_and_its_offset(tmp_path, world):
    with TestClient(_app(tmp_path, world, PARIS)) as client:
        setup_account(client)
        _scan_at(client, "2026-10-12T22:30:00+00:00")
        services = client.app.state.services
        scan = services.scans.latest(services.scans.domain(DEMO)["id"])
    catalog = Catalog()
    paris = report_context(catalog, "fr", scan, tz=PARIS)
    assert (paris["date"], paris["time"], paris["zone"]) == ("13 octobre 2026", "00:30", "UTC+2")
    winter = report_context(catalog, "en", scan, tz=UTC)
    assert (winter["date"], winter["time"], winter["zone"]) == ("12 October 2026", "22:30", "UTC")
    # The file number keeps the UTC day, whatever the zone: it identifies the scan.
    assert paris["file_number"] == winter["file_number"] == f"20261012-{scan.id:04d}"
