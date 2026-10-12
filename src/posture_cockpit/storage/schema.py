# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Database schema, as a list of migrations applied in order (see database.py).

Append new scripts at the end; never change one that has been released.
"""

MIGRATIONS: list[str] = [
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
]
