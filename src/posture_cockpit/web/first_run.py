# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The first account, protected by a one-time setup code (0.4.1).

While no account exists, whoever reaches ``/setup`` first would become the administrator.
So at each start without any account, the instance draws a random code, writes it to the
server log (``docker compose logs``) and keeps only its SHA-256 in ``meta.setup_code``.
``/setup`` asks for it; it is consumed, atomically, with the creation of the first account.
``POSTURE_COCKPIT_SETUP_CODE`` sets the code instead (automated installations); it is
then never written to the log.

Instances that already have accounts never see the code: nothing changes for them.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets

from ..config import normalize_setup_code
from ..storage import Accounts, Database

META_KEY = "setup_code"
# Without 0/O and 1/I, which are read one for the other. 12 characters: 60 bits.
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
GROUPS, GROUP_LENGTH = 3, 4

log = logging.getLogger("uvicorn.error")


def new_code() -> str:
    return "-".join("".join(secrets.choice(ALPHABET) for _ in range(GROUP_LENGTH)) for _ in range(GROUPS))


def _digest(code: str) -> str:
    return hashlib.sha256(normalize_setup_code(code).encode()).hexdigest()


def prepare(db: Database, configured: str = "") -> str:
    """Stores the hash of the code of this start (a new one unless configured) and returns the code."""
    code = configured or new_code()
    db.set_meta(META_KEY, _digest(code))
    return code


def clear(db: Database) -> None:
    db.delete_meta(META_KEY)


def announce(code: str, configured: bool) -> None:
    """Writes the code to the server log, in English and in French."""
    if configured:
        log.warning("No account yet: open /setup and enter the setup code set in POSTURE_COCKPIT_SETUP_CODE.")
        log.warning("Aucun compte : ouvrez /setup et saisissez le code défini dans POSTURE_COCKPIT_SETUP_CODE.")
        return
    log.warning("No account yet: open /setup and enter this setup code to create the administrator account.")
    log.warning("Aucun compte : ouvrez /setup et saisissez ce code d'initialisation pour créer le compte "
                "administrateur.")
    log.warning("Setup code / code d'initialisation : %s", code)


def matches(db: Database, code: str) -> bool:
    stored = db.get_meta(META_KEY)
    return bool(normalize_setup_code(code)) and stored is not None and hmac.compare_digest(stored, _digest(code))


def consume(db: Database, code: str) -> bool:
    """Removes the code if it is this one. Only one request can succeed."""
    if not normalize_setup_code(code):
        return False
    return db.execute("DELETE FROM meta WHERE key = ? AND value = ?", (META_KEY, _digest(code))).rowcount == 1


def create_administrator(db: Database, accounts: Accounts, code: str, username: str, pw_hash: str,
                         lang: str) -> int | None:
    """Consumes the code and creates the first account in one transaction: both happen, or neither.

    None when an account already exists or the code is not (or no longer) the right one; the
    write lock is taken first, so that two requests, from two processes even, run one after
    the other and only one succeeds. Any error rolls both back: the code stays valid."""
    with db.transaction(immediate=True):
        if accounts.count() > 0 or not consume(db, code):
            return None
        return accounts.create(username, pw_hash, is_admin=True, lang=lang)
