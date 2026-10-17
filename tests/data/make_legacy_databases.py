# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Writes the SQL dump of a database made by an earlier release, for test_v041_migrations.py.

Run it with the code of that release, never with the current one:

    git archive v0.3.0 | tar -x -C /tmp/v0.3.0
    PYTHONPATH=/tmp/v0.3.0/src:/tmp/v0.3.0/tests python tests/data/make_legacy_databases.py \\
        tests/data/database-v0.3.0.sql

The database holds what a real instance holds: an administrator (password "correct horse 42"),
a second account, an API token, the demo scan with a recheck, a scan of example.org, audit entries.

With ``--rich`` (code of 0.4.1 and later), it also holds what 0.5.0 must carry over: two-factor
authentication with recovery codes, an internal perimeter and a domain scanned in it, a provisional
scan (HTTPS availability undetermined) and a scan without a score:

    git archive v0.4.1 | tar -x -C /tmp/v0.4.1
    PYTHONPATH=/tmp/v0.4.1/src:/tmp/v0.4.1/tests python tests/data/make_legacy_databases.py --rich \\
        tests/data/database-v0.4.1.sql
"""

import asyncio
import json
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


def _renamed(data: dict, domain: str) -> dict:
    """A world of the tests, for another domain name (domain names are unique in a database)."""
    return json.loads(json.dumps(data).replace(worlds.DOMAIN, domain))


def _unreachable(domain: str) -> dict:
    """A name that answers, and nothing else (DNS timeouts for mail, no web server): no score."""
    data = {"dns": {f"{domain} SOA": ["ns1.example.net. hostmaster.example.org. 1 7200 3600 1209600 300"],
                    f"{domain} NS": ["ns1.example.net.", "ns2.example.net."],
                    f"{domain} A": ["192.0.2.20"], f"www.{domain} A": ["192.0.2.20"]}}
    for name in (domain, f"_dmarc.{domain}", f"_mta-sts.{domain}", f"_smtp._tls.{domain}"):
        data["dns"][f"{name} TXT"] = "timeout"
    data["dns"][f"{domain} MX"] = "timeout"
    return data


def rich(db: Database, accounts: Accounts, scans: Scans, audit: AuditLog, admin: int, scan) -> None:
    import https_worlds
    from posture_cockpit.storage import Perimeters
    from posture_cockpit.storage.perimeters import parse_form

    accounts.start_totp_setup(admin, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
    accounts.enable_totp(admin, 0, [token_hash(f"legacy-recovery-code-{n}") for n in range(8)])
    perimeter = Perimeters(db).create(parse_form("siege", "10.20.0.0/16", "10.20.0.53", "443", ""), admin)
    internal = scans.add_domain("intranet.siege.example", admin, perimeter)
    scans.save(internal, scan("intranet.siege.example", _renamed(worlds.healthy(), "intranet.siege.example"), 2),
               __version__, admin, "siege")
    provisional = scans.add_domain("provisoire.example", admin)
    undetermined = https_worlds.site({https_worlds.V4A: https_worlds.REFUSED, https_worlds.V6A: https_worlds.TIMEOUT})
    scans.save(provisional, scan("provisoire.example", _renamed(undetermined, "provisoire.example"), 1),
               __version__, admin)
    silent = scans.add_domain("muet.example", admin)
    scans.save(silent, scan("muet.example", _unreachable("muet.example"), 1), __version__, admin)
    audit.record("totp.enabled", user=accounts.get(admin), client="192.0.2.10")
    audit.record("perimeter.created", user=accounts.get(admin), target="siege", client="192.0.2.10")


def main(target: str, *, with_more: bool = False) -> None:
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
        if with_more:
            rich(db, accounts, scans, audit, admin, scan)
        db.close()
        with sqlite3.connect(Path(folder) / "posture_cockpit.db") as conn:
            dump = "\n".join(conn.iterdump())
    Path(target).write_text(f"-- Database made by Posture Cockpit {__version__} (tests/data/make_legacy_databases.py)\n"
                            + dump + "\n")


if __name__ == "__main__":
    main(sys.argv[-1], with_more="--rich" in sys.argv[1:-1])
