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
from collections.abc import Callable

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
]
