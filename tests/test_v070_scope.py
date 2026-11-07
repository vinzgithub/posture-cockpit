# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The measurement scope in the history (R5, D5a, PR-C): turning the SMTP probe on or off changes what is
measured, not the domain.

Scans of one domain are made with the probe off or on on recorded worlds and stored as the instance
stores them (storage/scans.py writes each state and derives its events in the same transaction). The
nine transitions of the plan (revision 2, "Comparaisons historiques") are checked on what was stored:
the comparison (compare), the transitions of the checks (check_changes), the last conclusive verdict
(last_conclusive), the events (no score drop, coverage loss, opening or resolution from the
configuration), the latest transition of the portfolio, and the generation change, whose reason
"engine" comes first. The scope is read from the stored findings, never from the configuration.
"""

import asyncio
import json

import pytest

from posture_cockpit.core import engine, generation
from posture_cockpit.core.compare import Snapshot, check_changes, compare, last_conclusive, measurement_scope
from posture_cockpit.core.events import derive
from posture_cockpit.core.extension import SmtpSettings
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.registry import Registry
from posture_cockpit.storage.database import Database
from posture_cockpit.storage.scans import Scans
from posture_cockpit.web.portfolio import latest_transition
from worlds import DOMAIN, EHLO, NOW, healthy, with_smtp, without_website

CHECK = "mail.smtp_starttls"
OK = {"192.0.2.25": "tls_verified"}
FAIL = {"192.0.2.25": "starttls_absent"}
BLOCKED = {"192.0.2.25": "timeout"}


@pytest.fixture
def scans(tmp_path):
    return Scans(Database(tmp_path / "posture_cockpit.db"))


def result(data: dict, probe: bool):
    net = FixtureNetwork(data, NOW, domain=DOMAIN, ehlo_name=EHLO if probe else None)
    return asyncio.run(engine.scan(DOMAIN, Registry.discover().checks(), net, timeout=5, now=NOW,
                                   smtp=SmtpSettings(probe, EHLO if probe else None)))


class History:
    """One domain's scans, stored one after the other."""

    def __init__(self, scans: Scans):
        self.scans = scans
        self.domain = scans.add_domain("scope.example", None)
        self.ids: list[int] = []

    def scan(self, outcomes: dict | None, probe: bool, base=healthy) -> int:
        scan_id = self.scans.save(self.domain, result(with_smtp(base(), outcomes or OK), probe), "0.7.0", None)
        self.ids.append(scan_id)
        return scan_id

    def states(self) -> list[Snapshot]:
        """Newest first, with the identity of the domain (as Mission Control reads them)."""
        newest = self.scans.current_state(self.ids[-1])
        return [Snapshot.from_row(dict(r)) for r in self.scans.state_history(self.domain, newest["id"])]

    def events(self) -> list[tuple[str, str, str]]:
        return [(r["kind"], r["subject"], r["state"]) for r in self.scans.db.all(
            "SELECT kind, subject, state FROM events WHERE domain_id = ? ORDER BY id", (self.domain,))]


def test_the_scope_is_stored_from_what_was_measured(scans):
    """R5, D5a, F05.01: each state keeps its scope in the metrics JSON, from the stored probe_enabled of the
    SMTP outcome and the perimeter, without a column: off, on; an internal perimeter, the check absent or an
    outcome without the field give internal, absent, unknown."""
    history = History(scans)
    history.scan(OK, probe=False)
    history.scan(OK, probe=True)
    stored = [json.loads(r["metrics"])["measurement_scope"] for r in scans.db.all(
        "SELECT metrics FROM scan_states ORDER BY id")]
    assert stored == ["off", "on"]
    assert "measurement_scope" not in {r["name"] for r in scans.db.all("PRAGMA table_info(scans)")}
    assert measurement_scope({"probe_enabled": True}, internal=True) == "internal"
    assert measurement_scope(None, internal=False) == "absent"
    assert measurement_scope({"error": "TimeoutError"}, internal=False) == "unknown"


def test_scope_off_off_compares(scans):
    """R5 (transition 1): off → off: compared as usual, the check NA on both, events of the other checks only."""
    history = History(scans)
    history.scan(OK, probe=False)
    history.scan(OK, probe=False)
    current, previous = history.states()[:2]
    assert compare(previous, current).comparable and check_changes(previous, current).available
    assert history.events() == []


def test_scope_off_on_no_regression(scans):
    """R5 (transition 2), T08: off → on with a defect found (STARTTLS absent): not compared (scope), no event:
    neither the opening of the check nor a score drop, though the score fell."""
    history = History(scans)
    history.scan(OK, probe=False)
    history.scan(FAIL, probe=True)
    current, previous = history.states()[:2]
    assert current.score is not None and previous.score is not None and current.score < previous.score
    assert compare(previous, current).reason == "scope"
    assert check_changes(previous, current).reason == "scope"
    assert derive(previous, current) == () and history.events() == []


def test_scope_on_off_no_false_resolution(scans):
    """R5 (transition 3): on with a defect → off: not compared (scope), the open event is not resolved by
    turning the probe off."""
    history = History(scans)
    history.scan(OK, probe=True)
    history.scan(FAIL, probe=True)
    assert ("check", CHECK, "open") in history.events()
    history.scan(OK, probe=False)
    current, previous = history.states()[:2]
    assert compare(previous, current).reason == "scope" and derive(previous, current) == ()
    assert ("check", CHECK, "open") in history.events()  # still open: nothing proved it fixed


def test_scope_on_on_real_regression(scans):
    """R5 (transition 4), F05.03: on → on, OK → FAIL: compared, a real regression: a critical event opens."""
    history = History(scans)
    history.scan(OK, probe=True)
    history.scan(FAIL, probe=True)
    current, previous = history.states()[:2]
    comparison = compare(previous, current)
    assert comparison.comparable and [(c.check_id, c.kind) for c in comparison.changes] == [(CHECK, "regressed")]
    assert [c.severity for c in derive(previous, current) if c.subject == CHECK] == ["critical"]


def test_scope_on_on_measurement_loss(scans):
    """R5 (transition 5), F05.08, T08: on → on, OK → ERROR (port 25 blocked): a measure lost, not a security
    change: the transition is "unmeasured", no security event; a coverage loss below 90 % is a measurement event."""
    history = History(scans)
    history.scan(OK, probe=True, base=lambda: without_website(healthy()))
    history.scan(BLOCKED, probe=True, base=lambda: without_website(healthy()))
    current, previous = history.states()[:2]
    assert [(c.check_id, c.kind) for c in check_changes(previous, current).changes] == [(CHECK, "unmeasured")]
    candidates = derive(previous, current)
    assert [(c.category, c.kind, c.action) for c in candidates] == [("measurement", "coverage_loss", "open")]


def test_recheck_after_scope_change(scans):
    """R5 (transition 6), R6: a scan made with the probe off, its SMTP check rechecked once the probe is on:
    the recheck state is of another scope than the scan's: not compared, no event."""
    history = History(scans)
    scan_id = history.scan(OK, probe=False)
    findings = [f for f in result(with_smtp(healthy(), FAIL), probe=True).findings
                if f.check_id in ("mail.mta_sts", CHECK)]
    scans.save_rechecks(scan_id, findings)
    current, previous = history.states()[:2]
    assert (previous.measured, current.measured) == ("off", "on")
    assert compare(previous, current).reason == "scope" and derive(previous, current) == ()
    assert history.events() == []


def test_last_conclusive_stops_at_scope(scans):
    """R5 (transition 7): the last conclusive verdict of the check never crosses a change of scope."""
    history = History(scans)
    history.scan(FAIL, probe=True)
    history.scan(OK, probe=False)
    history.scan(BLOCKED, probe=True)
    found = last_conclusive(history.states(), CHECK)
    assert (found.state, found.reason) == (None, "scope")


def test_portfolio_ignores_scope_change(scans):
    """R5 (transition 8): the latest transition shown in the portfolio stops at a change of scope."""
    history = History(scans)
    history.scan(OK, probe=False)
    history.scan(FAIL, probe=True)
    assert latest_transition(history.states()) is None


def test_generation_change_reason_engine(scans):
    """R5 (transition 9), T08: a state of generation 4 (no SMTP check, no scope) and one of generation 5 with
    the probe on: not compared, and the reason is "engine", tested before the scope."""
    history = History(scans)
    history.scan(OK, probe=True)
    current = history.states()[0]
    old = Snapshot(at="2026-10-01T00:00:00+00:00", origin="scan", engine=4, score=100, coverage=1.0,
                   evaluation="complete", checks={k: v for k, v in current.checks.items() if k != CHECK},
                   domain_id=current.domain_id, perimeter=current.perimeter, state_id=0)
    assert generation.GENERATION == 5 and old.measured == "absent" and current.measured == "on"
    assert compare(old, current).reason == "engine" and check_changes(old, current).reason == "engine"
    assert derive(old, current) == ()


def test_two_unknown_scopes_are_never_comparable():
    """R5: a state of generation 5 holding the SMTP check without a stored scope, or with an unknown one, is
    never compared, not even with another unknown one; two states of generation 4 compare as before."""
    base = {"at": "2026-11-01T00:00:00+00:00", "origin": "scan", "engine": 5, "score": 90, "coverage": 1.0,
            "evaluation": "complete", "checks": json.dumps({CHECK: "ok"})}
    unknown = Snapshot.from_row({**base, "metrics": json.dumps({"measurement_scope": "unknown"})})
    missing = Snapshot.from_row({**base, "metrics": "{}"})
    assert (unknown.measured, missing.measured) == ("unknown", "unknown")
    assert compare(unknown, missing).reason == "scope" and compare(missing, missing).reason == "scope"
    old = {**base, "engine": 4, "checks": json.dumps({"mail.spf": "ok"}), "metrics": "{}"}
    assert compare(Snapshot.from_row(old), Snapshot.from_row({**old, "at": "2026-11-02T00:00:00+00:00"})).comparable


def test_a_recheck_of_a_check_the_scan_does_not_hold_is_not_stored(scans):
    """R6, T05: a scan without the SMTP check (made before it existed): its MTA-STS check rechecked with its
    group stores the MTA-STS finding only; the scan keeps its checks."""
    history = History(scans)
    scan_id = history.scan(OK, probe=False)
    scans.db.execute("DELETE FROM findings WHERE scan_id = ? AND check_id = ?", (scan_id, CHECK))
    findings = [f for f in result(with_smtp(healthy(), OK), probe=True).findings
                if f.check_id in ("mail.mta_sts", CHECK)]
    scans.save_rechecks(scan_id, findings)
    assert [r["check_id"] for r in scans.db.all("SELECT check_id FROM rechecks WHERE scan_id = ?", (scan_id,))] == [
        "mail.mta_sts"]


# ------------------------------------------------------------------ an error of the engine on the SMTP check
def errored(monkeypatch, how: str):
    """Makes the next scans' SMTP check end with an error of the engine, without any evidence of its scope:
    a bug in the verdict (check.error.internal) or a check that never returns (check.error.timeout)."""
    from posture_cockpit.checks import smtp_measure, smtp_verdict

    if how == "internal":
        def broken(*args, **kwargs):
            raise RuntimeError("broken verdict")
        monkeypatch.setattr(smtp_verdict, "decide", broken)
    else:
        async def never(ctx):
            await asyncio.Event().wait()
        monkeypatch.setattr(smtp_measure, "result", never)


@pytest.mark.parametrize("how", ["internal", "timeout"])
def test_an_engine_error_of_the_smtp_check_compares_nothing_and_resolves_nothing(scans, monkeypatch, how):
    """R5, F05.01 (review of PR-C): an error of the engine on the SMTP check (a bug, or the engine's timeout)
    leaves no probe_enabled: the state is of unknown scope. Nothing is compared across it, in either direction:
    no comparison, no check transition, no last conclusive verdict found beyond it, no event derived (opening,
    resolution, score drop, coverage loss). The event opened before it stays open: no false resolution, even
    when the next scan finds the check OK again."""
    history = History(scans)
    history.scan(OK, probe=True)
    history.scan(FAIL, probe=True)
    opened = history.events()
    assert ("check", CHECK, "open") in opened
    with monkeypatch.context() as patch:
        errored(patch, how)
        if how == "timeout":
            scan_id = scans.save(history.domain, asyncio.run(engine.scan(
                DOMAIN, Registry.discover().checks(), FixtureNetwork(with_smtp(healthy(), OK), NOW, domain=DOMAIN,
                                                                     ehlo_name=EHLO),
                timeout=0.5, now=NOW, smtp=SmtpSettings(True, EHLO))), "0.7.0", None)
            history.ids.append(scan_id)
        else:
            history.scan(OK, probe=True)
    error, before = history.states()[:2]
    assert error.checks[CHECK] == "error" and (before.measured, error.measured) == ("on", "unknown")
    stored = scans.db.one("SELECT metrics FROM scan_states ORDER BY id DESC LIMIT 1")["metrics"]
    assert json.loads(stored)["measurement_scope"] == "unknown"
    assert compare(before, error).reason == "scope" and check_changes(before, error).reason == "scope"
    assert derive(before, error) == () and history.events() == opened
    assert (last_conclusive(history.states(), CHECK).state, last_conclusive(history.states(), CHECK).reason) == (
        None, "scope")
    history.scan(OK, probe=True)  # the probe works again, the check is OK
    after, error = history.states()[:2]
    assert compare(error, after).reason == "scope" and derive(error, after) == ()
    assert history.events() == opened  # still open: the fix is not confirmed across an unknown state


def test_a_recheck_whose_smtp_check_errors_is_of_unknown_scope(scans, monkeypatch):
    """R5, R6 (review of PR-C): a grouped recheck whose SMTP finding is an error of the engine: the recheck
    state is of unknown scope, compared with nothing, and resolves nothing."""
    history = History(scans)
    history.scan(OK, probe=True)
    scan_id = history.scan(FAIL, probe=True)
    opened = history.events()
    errored(monkeypatch, "internal")
    findings = [f for f in result(with_smtp(healthy(), OK), probe=True).findings
                if f.check_id in ("mail.mta_sts", CHECK)]
    assert [f.outcome.summary for f in findings if f.check_id == CHECK] == ["check.error.internal"]
    scans.save_rechecks(scan_id, findings)
    current, previous = history.states()[:2]
    assert (current.origin, current.measured) == ("recheck", "unknown")
    assert compare(previous, current).reason == "scope" and derive(previous, current) == ()
    assert history.events() == opened
