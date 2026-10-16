# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Accounts: users, roles, sessions, two-factor authentication and API keys.

Secrets are never stored in clear: passwords are scrypt hashes, recovery codes
and API keys SHA-256 hashes (see :mod:`posture_cockpit.security`).
"""

from __future__ import annotations

import secrets

from .database import Database, Row, utcnow


class Accounts:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ users
    def count(self) -> int:
        return int(self.db.value("SELECT COUNT(*) FROM users"))

    def create(self, username: str, pw_hash: str, *, is_admin: bool = False,
               must_change_password: bool = False, lang: str = "fr") -> int:
        """A new account, with a session epoch of its own.

        SQLite gives the id of a deleted account to the next one. Without a fresh epoch,
        the new account would start with the default one, which the session cookies of
        the deleted account may still carry: they would open the new account."""
        with self.db.transaction():
            cur = self.db.execute(
                "INSERT INTO users(username, pw_hash, created_at, is_admin, must_change_password, lang)"
                " VALUES(?, ?, ?, ?, ?, ?)",
                (username, pw_hash, utcnow(), int(is_admin), int(must_change_password), lang))
            user_id = int(cur.lastrowid or 0)
            self.new_session_epoch(user_id)
        return user_id

    def get(self, user_id: int) -> Row | None:
        return self.db.one("SELECT * FROM users WHERE id = ?", (user_id,))

    def by_name(self, username: str) -> Row | None:
        return self.db.one("SELECT * FROM users WHERE username = ?", (username,))

    def name_taken(self, username: str) -> bool:
        return self.db.one("SELECT 1 FROM users WHERE lower(username) = lower(?)", (username,)) is not None

    def all(self) -> list[Row]:
        return self.db.all("SELECT u.*, (t.enabled_at IS NOT NULL) AS totp_on FROM users u "
                           "LEFT JOIN totp t ON t.user_id = u.id ORDER BY lower(u.username)")

    def set_password(self, user_id: int, pw_hash: str, must_change: bool = False) -> None:
        self.db.execute("UPDATE users SET pw_hash = ?, must_change_password = ? WHERE id = ?",
                        (pw_hash, int(must_change), user_id))

    def set_admin(self, user_id: int, is_admin: bool) -> None:
        self.db.execute("UPDATE users SET is_admin = ? WHERE id = ?", (int(is_admin), user_id))

    def set_lang(self, user_id: int, lang: str) -> None:
        self.db.execute("UPDATE users SET lang = ? WHERE id = ?", (lang, user_id))

    def delete(self, user_id: int) -> None:
        """The account and everything that belongs to it. Domains stay: they are shared."""
        with self.db.transaction():
            self.db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            self.db.delete_meta(f"session_epoch:{user_id}")

    # --------------------------------------------------------------- sessions
    # The session cookie carries the user's "epoch". Changing it signs out
    # every browser of that user (after a password or 2FA change).
    def session_epoch(self, user_id: int) -> str:
        return self.db.get_meta(f"session_epoch:{user_id}") or "0"

    def new_session_epoch(self, user_id: int) -> str:
        epoch = secrets.token_hex(8)
        self.db.set_meta(f"session_epoch:{user_id}", epoch)
        return epoch

    # ------------------------------------------- two-factor authentication
    def totp(self, user_id: int) -> Row | None:
        return self.db.one("SELECT * FROM totp WHERE user_id = ?", (user_id,))

    def totp_enabled(self, user_id: int) -> bool:
        row = self.totp(user_id)
        return bool(row and row["enabled_at"])

    def start_totp_setup(self, user_id: int, secret: str) -> None:
        """Stores a new secret, unless two-factor authentication is already on."""
        self.db.execute(
            "INSERT INTO totp(user_id, secret, last_step, enabled_at) VALUES(?, ?, 0, NULL) "
            "ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, last_step = 0, enabled_at = NULL "
            "WHERE totp.enabled_at IS NULL", (user_id, secret))

    def enable_totp(self, user_id: int, step: int, code_hashes: list[str]) -> None:
        with self.db.transaction():
            self.db.execute("UPDATE totp SET enabled_at = ?, last_step = ? WHERE user_id = ?",
                            (utcnow(), step, user_id))
            self._replace_recovery_codes(user_id, code_hashes)

    def set_totp_last_step(self, user_id: int, step: int) -> None:
        self.db.execute("UPDATE totp SET last_step = MAX(last_step, ?) WHERE user_id = ?", (step, user_id))

    def disable_totp(self, user_id: int) -> None:
        with self.db.transaction():
            self.db.execute("DELETE FROM totp WHERE user_id = ?", (user_id,))
            self.db.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))

    def _replace_recovery_codes(self, user_id: int, code_hashes: list[str]) -> None:
        self.db.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
        self.db.executemany("INSERT INTO recovery_codes(user_id, code_hash) VALUES(?, ?)",
                            [(user_id, h) for h in code_hashes])

    def replace_recovery_codes(self, user_id: int, code_hashes: list[str]) -> None:
        with self.db.transaction():
            self._replace_recovery_codes(user_id, code_hashes)

    def use_recovery_code(self, user_id: int, code_hash: str) -> bool:
        """Marks the code as used; False when it does not exist or was already used."""
        cur = self.db.execute(
            "UPDATE recovery_codes SET used_at = ? WHERE id = (SELECT id FROM recovery_codes "
            "WHERE user_id = ? AND code_hash = ? AND used_at IS NULL LIMIT 1)", (utcnow(), user_id, code_hash))
        return cur.rowcount == 1

    def recovery_codes_left(self, user_id: int) -> int:
        return int(self.db.value("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
                                 (user_id,)))

    # --------------------------------------------------------------- API keys
    def add_token(self, user_id: int, name: str, token_hash: str) -> None:
        self.db.execute("INSERT INTO api_tokens(user_id, name, token_hash, created_at) VALUES(?, ?, ?, ?)",
                        (user_id, name, token_hash, utcnow()))

    def tokens(self, user_id: int) -> list[Row]:
        return self.db.all("SELECT id, name, created_at, last_used FROM api_tokens WHERE user_id = ? ORDER BY id",
                           (user_id,))

    def check_token(self, token_hash: str) -> int | None:
        """The id of the user the key belongs to, or None."""
        row = self.db.one("SELECT id, user_id FROM api_tokens WHERE token_hash = ?", (token_hash,))
        if row is None:
            return None
        self.db.execute("UPDATE api_tokens SET last_used = ? WHERE id = ?", (utcnow(), row["id"]))
        return int(row["user_id"])

    def revoke_token(self, user_id: int, token_id: int) -> None:
        self.db.execute("DELETE FROM api_tokens WHERE id = ? AND user_id = ?", (token_id, user_id))
