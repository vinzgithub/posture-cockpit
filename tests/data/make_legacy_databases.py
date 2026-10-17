# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Writes the SQL dump of a database made by an earlier release, for test_v041_migrations.py.

Run it with the code of that release, never with the current one:

    git archive v0.3.0 | tar -x -C /tmp/v0.3.0
    PYTHONPATH=/tmp/v0.3.0/src:/tmp/v0.3.0/tests python tests/data/make_legacy_databases.py \\
        tests/data/database-v0.3.0.sql

The database holds what a real instance holds: an administrator (password "correct horse 42"),
a second account, an API token, the demo scan with a recheck, a scan of example.org, audit entries.
"""

import asyncio
import sqlite3
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

import worlds
from posture_cockpit import __version__
from posture_cockpit.core import engine
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.registry import Registry
from posture_cockpit.scanner import DEMO_DOMAIN, demo_data
from posture_cockpit.security import hash_password, token_hash
from posture_cockpit.storage import Accounts, AuditLog, Database, Scans

PASSWORD = "correct horse 42"
TOKEN = "legacy-api-token-for-tests-0123456789"


def main(target: str) -> None:
    registry = Registry.discover()

    def scan(domain, data, days_ago):
        at = worlds.NOW - timedelta(days=days_ago)
        return asyncio.run(engine.scan(domain, registry.checks(), FixtureNetwork(data, at), now=at))

    with tempfile.TemporaryDirectory() as folder:
        db = Database(Path(folder) / "posture_cockpit.db")
        accounts, scans, audit = Accounts(db), Scans(db), AuditLog(db)
        admin = accounts.create("vincent", hash_password(PASSWORD), is_admin=True, lang="fr")
        accounts.create("lecteur", hash_password(PASSWORD), lang="en")
        accounts.add_token(admin, "home-assistant", token_hash(TOKEN))
        demo = scans.add_domain(DEMO_DOMAIN, admin)
        first = scans.save(demo, scan(DEMO_DOMAIN, demo_data(DEMO_DOMAIN), 3), __version__, admin)
        fixed = next(f for f in scan(DEMO_DOMAIN, demo_data(DEMO_DOMAIN), 2).findings if f.status.value == "ok")
        scans.save_recheck(first, fixed)
        other = scans.add_domain(worlds.DOMAIN, admin)
        scans.save(other, scan(worlds.DOMAIN, worlds.healthy(), 1), __version__, admin)
        audit.record("setup", user=accounts.get(admin), client="192.0.2.10")
        audit.record("login", user=accounts.get(admin), client="192.0.2.10")
        db.close()
        with sqlite3.connect(Path(folder) / "posture_cockpit.db") as conn:
            dump = "\n".join(conn.iterdump())
    Path(target).write_text(f"-- Database made by Posture Cockpit {__version__} (tests/data/make_legacy_databases.py)\n"
                            + dump + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
