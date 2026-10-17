# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Database schema, as a list of migrations applied in order (see database.py).

Append new migrations at the end; never change one that has been released.
A migration is an SQL script, or a function given the open connection inside
the migration's transaction.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Sequence

from ..core import scoring
from ..core.model import Finding

Migration = str | Callable[[sqlite3.Connection], None]


def _scores_with_coverage(conn: sqlite3.Connection) -> None:
    """3 — version 0.2.0: a scan may be "not evaluated", and keeps its coverage and perimeter.

    The table is rebuilt (SQLite cannot drop NOT NULL from a column), then the
    score, grade and coverage of every stored scan are computed again from its
    findings and rechecks with the rules of core/scoring.py. With the same
    weights, a scan whose coverage reaches 50 % keeps its score; below, it
    becomes "not evaluated" (0.1.0 gave 100/A when nothing could be checked);
    below 90 %, an A becomes a B. The findings themselves are not touched, and
    the database was copied to backups/ before this migration.
    """
    conn.execute("""
        CREATE TABLE scans_new (
            id INTEGER PRIMARY KEY,
            domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            started_at TEXT NOT NULL,
            duration_ms INTEGER NOT NULL,
            score INTEGER,                        -- NULL: not evaluated; updated after each recheck
            grade TEXT,                           -- NULL: not evaluated
            coverage REAL NOT NULL DEFAULT 1,     -- weight evaluated / weight applicable, 0 to 1
            version TEXT NOT NULL,                -- application version that ran the scan
            started_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            perimeter TEXT NOT NULL DEFAULT ''    -- internal perimeter at the time of the scan ('' = Internet)
        )""")
    conn.execute("INSERT INTO scans_new(id, domain_id, started_at, duration_ms, score, grade, version, started_by) "
                 "SELECT id, domain_id, started_at, duration_ms, score, grade, version, started_by FROM scans")
    conn.execute("DROP TABLE scans")
    conn.execute("ALTER TABLE scans_new RENAME TO scans")
    conn.execute("CREATE INDEX scans_by_domain ON scans(domain_id, started_at)")
    for (scan_id,) in conn.execute("SELECT id FROM scans").fetchall():
        current: dict[str, Finding] = {}
        for check_id, category, weight, status, outcome in conn.execute(
                "SELECT check_id, category, weight, status, outcome FROM findings WHERE scan_id = ? ORDER BY rowid",
                (scan_id,)).fetchall():
            current[check_id] = Finding.from_stored(check_id, category, weight, status, json.loads(outcome))
        for check_id, status, outcome in conn.execute(
                "SELECT check_id, status, outcome FROM rechecks WHERE scan_id = ?", (scan_id,)).fetchall():
            if check_id in current:
                original = current[check_id]
                current[check_id] = Finding.from_stored(check_id, original.category, original.weight, status,
                                                        json.loads(outcome))
        result = scoring.assess(list(current.values()))
        conn.execute("UPDATE scans SET score = ?, grade = ?, coverage = ? WHERE id = ?",
                     (result.score, result.grade, result.coverage, scan_id))


# 5 — version 0.5.0. Additive only: every table of 0.5.0, and no stored value recalculated.
_SCHEMA_5 = """
ALTER TABLE scans ADD COLUMN via TEXT CHECK (via IN ('web', 'api', 'schedule'));  -- NULL before 0.5.0
ALTER TABLE scans ADD COLUMN engine INTEGER;   -- generation of the rules (core/generation.py); NULL: unknown

-- One schedule per domain (filled from step 4 of 0.5.0).
CREATE TABLE schedules (
    domain_id INTEGER PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
    frequency TEXT NOT NULL CHECK (frequency IN ('daily', 'weekly', 'monthly')),
    weekday INTEGER CHECK (weekday BETWEEN 1 AND 7),
    monthday INTEGER CHECK (monthday BETWEEN 1 AND 31),
    at_minute INTEGER NOT NULL CHECK (at_minute BETWEEN 0 AND 1439),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    next_run_at TEXT,
    failures INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    CHECK ((frequency = 'weekly') = (weekday IS NOT NULL)),
    CHECK ((frequency = 'monthly') = (monthday IS NOT NULL)));

-- One row per scheduled slot, claimed by one process at a time (a lease), at most two attempts.
CREATE TABLE schedule_runs (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    slot TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('running', 'done', 'failed', 'skipped', 'interrupted', 'missed')),
    reason TEXT NOT NULL DEFAULT '',
    claim TEXT NOT NULL,
    owner TEXT NOT NULL,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    attempts INTEGER NOT NULL DEFAULT 1 CHECK (attempts BETWEEN 1 AND 2),
    claimed_at TEXT NOT NULL,
    lease_until TEXT,
    finished_at TEXT,
    CHECK ((state = 'running') = (lease_until IS NOT NULL)),
    UNIQUE (domain_id, slot));
CREATE INDEX schedule_runs_by_domain ON schedule_runs(domain_id, claimed_at);
CREATE INDEX schedule_runs_running ON schedule_runs(state) WHERE state = 'running';
CREATE UNIQUE INDEX schedule_runs_one_scan ON schedule_runs(scan_id) WHERE scan_id IS NOT NULL;

-- The measured state of a scan, at each moment it changed: when it was made, after each
-- recheck. Never changed afterwards (rows are only added; they go with their scan).
CREATE TABLE scan_states (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    at TEXT NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('scan', 'recheck', 'legacy')),
    engine INTEGER,
    score INTEGER,
    grade TEXT,
    coverage REAL NOT NULL,
    evaluation TEXT NOT NULL CHECK (evaluation IN ('not_evaluated', 'undetermined', 'partial', 'complete')),
    metrics TEXT NOT NULL,   -- JSON: the metrics of schema 4 at that moment
    checks TEXT NOT NULL);   -- JSON: check id -> status at that moment
CREATE INDEX scan_states_by_scan ON scan_states(scan_id, at);
CREATE TRIGGER scan_states_append_only BEFORE UPDATE ON scan_states
    BEGIN SELECT RAISE(ABORT, 'scan_states is append-only'); END;

-- What changed and deserves attention (filled from step 5 of 0.5.0).
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    category TEXT NOT NULL CHECK (category IN ('security', 'measurement', 'technical')),
    kind TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK (state IN ('open', 'resolved', 'notice')),
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'warning', 'info')),
    opened_at TEXT NOT NULL,
    opened_scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    resolution TEXT,
    detail TEXT NOT NULL DEFAULT '{}');
CREATE UNIQUE INDEX events_open_domain ON events(domain_id, kind, subject)
    WHERE state = 'open' AND domain_id IS NOT NULL;
CREATE UNIQUE INDEX events_open_instance ON events(kind, subject)
    WHERE state = 'open' AND domain_id IS NULL;
CREATE INDEX events_by_time ON events(opened_at);

ALTER TABLE users ADD COLUMN events_seen_at TEXT;
"""

# Frozen with migration 5, like the rest of it: the generation of the rules of the released
# versions a database of schema 4 can hold (core/generation.py, RELEASED), and the coverage below
# which a scan is partial (core/scoring.py, FULL_COVERAGE).
GENERATIONS_OF_SCHEMA_4 = {"0.4.0": 4, "0.4.1": 4}
FULL_COVERAGE_OF_SCHEMA_4 = 0.9

# The metrics of schema 4, stored in each scan and in each of its states (0.5.0).
METRICS = ("score_raw", "score_cap", "score_final", "diagnostic_coverage", "checks_blocked",
           "addresses_discovered", "addresses_attempted", "addresses_conclusive",
           "grade_withheld_reason", "cap_reasons")


def stored_evaluation(score: int | None, coverage: float, grade_withheld_reason: str | None,
                      full_coverage: float = FULL_COVERAGE_OF_SCHEMA_4) -> str:
    """The evaluation of a scan from its stored columns, as Assessment.evaluation gives it."""
    if score is None:
        return "not_evaluated"
    if grade_withheld_reason is not None:
        return "undetermined"
    return "partial" if coverage < full_coverage else "complete"


def _stored_metrics(row: sqlite3.Row | tuple, names: Sequence[str]) -> dict:
    values = dict(zip(names, row, strict=True))
    metrics = {name: values[name] for name in METRICS}
    try:  # stored as JSON text; a value that does not decode is kept as it is, never dropped
        decoded = json.loads(metrics["cap_reasons"]) if metrics["cap_reasons"] is not None else None
        if decoded is None or isinstance(decoded, list):
            metrics["cap_reasons"] = decoded
    except (TypeError, ValueError):
        pass
    return metrics


def _schema_5(conn: sqlite3.Connection) -> None:
    """5 — version 0.5.0: scheduled scans, their runs, events, the origin and the generation of
    the rules of each scan, and the timeline of its measured states.

    Nothing stored is recalculated and the code of the scoring is never called. Every existing scan
    gets its generation (exact versions only, see GENERATIONS_OF_SCHEMA_4) and one state, made of
    its stored values: a scan never rechecked gets a ``scan`` state at the time it was made; a
    rechecked scan gets a single ``legacy`` state at the time of its last recheck, its stored
    values being those after that recheck. No state is made up for the moment before a recheck:
    those values were overwritten and are not known."""
    from .database import _statements  # database.py imports this module

    for statement in _statements(_SCHEMA_5):
        conn.execute(statement)
    for version, generation in GENERATIONS_OF_SCHEMA_4.items():
        conn.execute("UPDATE scans SET engine = ? WHERE version = ?", (generation, version))
    columns = ("id", "started_at", "engine", "score", "grade", "coverage", *METRICS)
    for row in conn.execute(f"SELECT {', '.join(columns)} FROM scans ORDER BY id").fetchall():  # noqa: S608
        values = dict(zip(columns, row, strict=True))
        checks = {check_id: status for check_id, status in conn.execute(
            "SELECT check_id, status FROM findings WHERE scan_id = ? ORDER BY rowid", (values["id"],))}
        rechecks = conn.execute("SELECT check_id, status, checked_at FROM rechecks WHERE scan_id = ?",
                                (values["id"],)).fetchall()
        for check_id, status, _ in rechecks:
            if check_id in checks:
                checks[check_id] = status
        at, origin = (max(r[2] for r in rechecks), "legacy") if rechecks else (values["started_at"], "scan")
        conn.execute(
            "INSERT INTO scan_states(scan_id, at, origin, engine, score, grade, coverage, evaluation, metrics, checks)"
            " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (values["id"], at, origin, values["engine"], values["score"], values["grade"], values["coverage"],
             stored_evaluation(values["score"], values["coverage"], values["grade_withheld_reason"]),
             json.dumps(_stored_metrics(row, columns), sort_keys=True), json.dumps(checks, sort_keys=True)))


MIGRATIONS: list[Migration] = [
    # 1 — version 0.1.0
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        pw_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        must_change_password INTEGER NOT NULL DEFAULT 0,  -- set when an administrator chose the password
        lang TEXT NOT NULL DEFAULT 'fr'
    );

    -- Two-factor authentication. A row without enabled_at is a setup in progress.
    CREATE TABLE totp (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        secret TEXT NOT NULL,
        last_step INTEGER NOT NULL DEFAULT 0,  -- last time step used: older codes are refused
        enabled_at TEXT
    );

    CREATE TABLE recovery_codes (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash TEXT NOT NULL,
        used_at TEXT
    );

    CREATE TABLE api_tokens (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        last_used TEXT
    );

    -- Domains are shared by every account of the instance.
    CREATE TABLE domains (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,                -- normalized: lower case, ASCII
        created_at TEXT NOT NULL,
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        dns_host TEXT NOT NULL DEFAULT ''         -- DNS host chosen on the plan page ('' = detected)
    );

    CREATE TABLE scans (
        id INTEGER PRIMARY KEY,
        domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
        started_at TEXT NOT NULL,
        duration_ms INTEGER NOT NULL,
        score INTEGER NOT NULL,                   -- updated after each recheck
        grade TEXT NOT NULL,
        version TEXT NOT NULL,                    -- application version that ran the scan
        started_by INTEGER REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE INDEX scans_by_domain ON scans(domain_id, started_at);

    -- What the scan found. Never changed afterwards.
    CREATE TABLE findings (
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        check_id TEXT NOT NULL,
        category TEXT NOT NULL,
        weight INTEGER NOT NULL,
        status TEXT NOT NULL,
        outcome TEXT NOT NULL,                    -- JSON, see Finding.outcome_json()
        PRIMARY KEY (scan_id, check_id)
    );

    -- A check run again from the plan ("Vérifier"): the latest result replaces
    -- the finding when the score is computed, the plan keeps its order.
    CREATE TABLE rechecks (
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        check_id TEXT NOT NULL,
        status TEXT NOT NULL,
        outcome TEXT NOT NULL,
        checked_at TEXT NOT NULL,
        PRIMARY KEY (scan_id, check_id)
    );
    """,
    # 2 — version 0.2.0: internal perimeters, audit log
    """
    -- An internal perimeter: the private networks a scan may reach, the DNS
    -- servers and the certificate authority to use there (see core/egress.py).
    CREATE TABLE perimeters (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        networks TEXT NOT NULL,                   -- CIDR, one per line, inside the private ranges
        nameservers TEXT NOT NULL DEFAULT '',     -- IP addresses, one per line ('' = those of the system)
        ports TEXT NOT NULL DEFAULT '443 80',     -- ports a scan may connect to
        ca_pem TEXT NOT NULL DEFAULT '',          -- extra certificate authorities, PEM
        created_at TEXT NOT NULL,
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
    );

    -- NULL: the domain is scanned from the Internet. Otherwise only administrators
    -- see it and scan it, inside its perimeter.
    ALTER TABLE domains ADD COLUMN perimeter_id INTEGER REFERENCES perimeters(id) ON DELETE RESTRICT;

    -- Who did what: sign-ins, account and perimeter changes, internal scans.
    CREATE TABLE audit_log (
        id INTEGER PRIMARY KEY,
        at TEXT NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        username TEXT NOT NULL DEFAULT '',        -- kept when the account is deleted
        action TEXT NOT NULL,                     -- e.g. "login.failed", "perimeter.created", "scan.internal"
        target TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '{}',        -- JSON
        client TEXT NOT NULL DEFAULT ''           -- address of the browser or script
    );
    CREATE INDEX audit_log_by_time ON audit_log(at);
    """,
    _scores_with_coverage,
    # 4 — additive only: old observations are never recalculated.
    """
    ALTER TABLE scans ADD COLUMN score_raw REAL;
    ALTER TABLE scans ADD COLUMN score_cap REAL;
    ALTER TABLE scans ADD COLUMN score_final REAL;
    ALTER TABLE scans ADD COLUMN diagnostic_coverage REAL;
    ALTER TABLE scans ADD COLUMN checks_blocked INTEGER;
    ALTER TABLE scans ADD COLUMN addresses_discovered INTEGER;
    ALTER TABLE scans ADD COLUMN addresses_attempted INTEGER;
    ALTER TABLE scans ADD COLUMN addresses_conclusive INTEGER;
    ALTER TABLE scans ADD COLUMN grade_withheld_reason TEXT;
    ALTER TABLE scans ADD COLUMN cap_reasons TEXT;
    """,
    _schema_5,
]
