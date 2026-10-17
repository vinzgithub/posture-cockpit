#!/usr/bin/env python3
# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fingerprint of the data of a Posture Cockpit instance, to check an update and a rollback (0.5.0).

    data-fingerprint.py --salt-file SALT DATA_DIR|DATABASE|BACKUP.tar.gz  > E0.json
    data-fingerprint.py compare E0.json E1.json [--except TABLE|TABLE.COLUMN ...]

What it gives, as JSON: the schema, the result of SQLite's integrity and foreign key checks,
counts (accounts, administrators, two-factor authentications, API keys, domains, scans...),
and for each table its number of rows, a digest of each column and, for the tables that are
not bulky, a digest of each cell by row. The identity of a row (its primary key: a number or a
name defined by the application, such as a meta key) is shown; no value of the database is.
The session key appears only as the SHA-256 of its file.

The digests are HMAC-SHA-256, keyed with the salt file: without it, a digest cannot be matched
against guessed values (a user name, an administrator flag). The salt file is created (32
random bytes, readable by its owner only) when it does not exist. Fingerprints are comparable
only when made with the same salt: keep it beside them on the test host, never with a report,
and delete it with them.

"compare" tells what the second fingerprint changed in the first: tables, columns and rows
removed, cells changed, and what was added. It exits with 0 when nothing of the first was
removed or changed (apart from what --except lists), 1 otherwise.

Read only: the database is opened read-only and immutable, so that neither it nor its folder
change (no journal, no lock file). A non-empty write-ahead log means the instance is running
or was not stopped cleanly: the script then refuses, rather than miss what the log holds.
Standard library only (it runs with the Python of the image: python3 - ARGS < this file).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import tarfile
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Any

FORMAT = 1
DB_NAME, KEY_NAME = "posture_cockpit.db", ".secret_key"
# Bulky tables: digests by column only (their rows follow the scans and the log of actions).
COLUMNS_ONLY = {"findings", "audit_log"}
COUNTS = {
    "users": "SELECT COUNT(*) FROM users",
    "administrators": "SELECT COUNT(*) FROM users WHERE is_admin = 1",
    "two_factor": "SELECT COUNT(*) FROM totp WHERE enabled_at IS NOT NULL",
    "recovery_codes_unused": "SELECT COUNT(*) FROM recovery_codes WHERE used_at IS NULL",
    "api_keys": "SELECT COUNT(*) FROM api_tokens",
    "perimeters": "SELECT COUNT(*) FROM perimeters",
    "domains": "SELECT COUNT(*) FROM domains",
    "scans": "SELECT COUNT(*) FROM scans",
    "findings": "SELECT COUNT(*) FROM findings",
    "rechecks": "SELECT COUNT(*) FROM rechecks",
    "scan_states": "SELECT COUNT(*) FROM scan_states",
    "schedules": "SELECT COUNT(*) FROM schedules",
    "schedule_runs": "SELECT COUNT(*) FROM schedule_runs",
    "events": "SELECT COUNT(*) FROM events",
    "audit_log": "SELECT COUNT(*) FROM audit_log",
}


class Refused(Exception):
    """The fingerprint cannot be made; the message says why and what to do."""


def salt_of(path: Path) -> bytes:
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
    salt = path.read_bytes()
    if len(salt) < 16:
        raise Refused(f"{path}: a salt file holds at least 16 bytes.")
    return salt


def _cell(value: Any) -> bytes:
    if value is None:
        return b"n"
    if isinstance(value, int):
        return b"i" + str(value).encode()
    if isinstance(value, float):
        return b"f" + value.hex().encode()
    if isinstance(value, str):
        return b"t" + value.encode("utf-8", "surrogatepass")
    return b"b" + bytes(value)


def _open(db: Path) -> sqlite3.Connection:
    wal = db.with_name(db.name + "-wal")
    if wal.exists() and wal.stat().st_size > 0:
        raise Refused(f"{wal} is not empty: Posture Cockpit is running or was not stopped cleanly. Stop it "
                      "(docker compose stop), then run this again.")
    if not db.is_file():
        raise Refused(f"There is no database at {db}.")
    return sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro&immutable=1", uri=True)


def _quoted(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _tables(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def _table(conn: sqlite3.Connection, table: str, salt: bytes, by_row: bool) -> dict[str, Any]:
    info = conn.execute(f"PRAGMA table_info({_quoted(table)})").fetchall()
    columns = [r[1] for r in info]
    identity = [r[1] for r in sorted((r for r in info if r[5]), key=lambda r: r[5])] or ["rowid"]
    names = ", ".join("rowid" if c == "rowid" else _quoted(c) for c in identity)
    # Names read from the database itself, quoted.
    query = f"SELECT {names}, {', '.join(map(_quoted, columns))} FROM {_quoted(table)} ORDER BY {names}"  # noqa: S608
    sums = {c: hashlib.sha256() for c in columns}
    rows: dict[str, dict[str, str]] = {}
    count = 0
    for row in conn.execute(query):
        count += 1
        ident = json.dumps(list(row[:len(identity)]), ensure_ascii=False)
        cells = {}
        for name, value in zip(columns, row[len(identity):], strict=True):
            digest = hmac.new(salt, f"{table}\0{name}\0".encode() + _cell(value), "sha256").hexdigest()[:16]
            sums[name].update(f"{ident}\0{digest}\n".encode())
            cells[name] = digest
        if by_row:
            rows[ident] = cells
    result: dict[str, Any] = {"rows": count, "key": identity,
                              "columns": {c: sums[c].hexdigest()[:32] for c in columns}}
    if by_row:
        result["by_row"] = rows
    return result


def fingerprint_db(db: Path, key: Path | None, salt: bytes) -> dict[str, Any]:
    with closing(_open(db)) as conn:
        tables = _tables(conn)
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall()) if "meta" in tables else {}
        result: dict[str, Any] = {
            "format": FORMAT,
            "salt_id": hashlib.sha256(b"posture-cockpit-fingerprint\0" + salt).hexdigest()[:12],
            "schema": int(meta.get("schema_version") or 0),
            "integrity": conn.execute("PRAGMA integrity_check").fetchone()[0],
            "broken_references": len(conn.execute("PRAGMA foreign_key_check").fetchall()),
            "counts": {name: conn.execute(query).fetchone()[0] for name, query in COUNTS.items()
                       if query.split(" FROM ")[1].split()[0] in tables},
            "tables": {t: _table(conn, t, salt, t not in COLUMNS_ONLY) for t in tables},
        }
    if key is not None and key.is_file():
        result["session_key"] = {"present": True, "sha256": hashlib.sha256(key.read_bytes()).hexdigest()}
        result["session_key_mode"] = oct(key.stat().st_mode & 0o777)  # shown, not compared
    else:
        result["session_key"] = {"present": False}
    body = {name: result[name] for name in ("schema", "tables", "session_key")}
    result["fingerprint"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return result


def fingerprint(path: Path, salt: bytes) -> dict[str, Any]:
    """Of a data folder, a database file, or a backup archive (read without restoring it)."""
    if path.is_dir():
        return fingerprint_db(path / DB_NAME, path / KEY_NAME, salt)
    if path.name.endswith((".tar.gz", ".tgz")):
        with tempfile.TemporaryDirectory(prefix="pc-fingerprint-") as folder:
            os.chmod(folder, 0o700)
            with tarfile.open(path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name in (DB_NAME, KEY_NAME) and member.isfile():
                        source = tar.extractfile(member)
                        assert source is not None
                        target = Path(folder) / member.name
                        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(fd, "wb") as out:
                            out.write(source.read())
            return fingerprint_db(Path(folder) / DB_NAME, Path(folder) / KEY_NAME, salt)
    return fingerprint_db(path, path.with_name(KEY_NAME), salt)


def compare(old: dict[str, Any], new: dict[str, Any], excepted: set[str]) -> tuple[bool, dict[str, Any]]:
    """What ``new`` removed or changed of ``old``, and what it added. True when nothing of ``old``
    was removed or changed, apart from the tables and columns listed in ``excepted``."""
    if old.get("salt_id") != new.get("salt_id"):
        raise Refused("The two fingerprints were not made with the same salt: they cannot be compared.")
    report: dict[str, Any] = {"tables": {}, "added_tables": sorted(set(new["tables"]) - set(old["tables"]))}
    kept = True
    for table, before in old["tables"].items():
        after = new["tables"].get(table)
        if after is None:
            report["tables"][table] = {"removed": True}
            kept = kept and table in excepted
            continue
        common = [c for c in before["columns"] if c in after["columns"]]
        entry: dict[str, Any] = {"rows": [before["rows"], after["rows"]]}
        removed_columns = [c for c in before["columns"] if c not in after["columns"]]
        added_columns = [c for c in after["columns"] if c not in before["columns"]]
        if removed_columns:
            entry["removed_columns"] = removed_columns
        if added_columns:
            entry["added_columns"] = added_columns
        if "by_row" in before and "by_row" in after:
            old_rows, new_rows = before["by_row"], after["by_row"]
            removed = [i for i in old_rows if i not in new_rows]
            added = [i for i in new_rows if i not in old_rows]
            changed = {i: [c for c in common if old_rows[i][c] != new_rows[i][c]]
                       for i in old_rows if i in new_rows}
            changed = {i: cols for i, cols in changed.items() if cols}
            if removed:
                entry["removed_rows"] = removed
            if added:
                entry["added_rows"] = added
            if changed:
                entry["changed_rows"] = changed
            touched = {c for cols in changed.values() for c in cols} | (set(common) if removed else set())
        else:
            touched = {c for c in common if before["columns"][c] != after["columns"][c]}
            if touched:
                entry["changed_columns"] = sorted(touched)
        if set(entry) - {"rows"}:
            report["tables"][table] = entry
        if table not in excepted and (removed_columns or any(f"{table}.{c}" not in excepted for c in touched)):
            kept = False
    report["session_key"] = ("unchanged" if old["session_key"] == new["session_key"]
                             else "added" if not old["session_key"]["present"] else "changed")
    kept = kept and report["session_key"] in ("unchanged", "added")
    report["identical"] = old["fingerprint"] == new["fingerprint"]
    report["kept"] = kept
    return kept, report


def _text(report: dict[str, Any]) -> str:
    lines = [f"identical: {'yes' if report['identical'] else 'no'}; everything of the first kept: "
             f"{'yes' if report['kept'] else 'NO'}; session key: {report['session_key']}"]
    if report["added_tables"]:
        lines.append(f"added tables: {', '.join(report['added_tables'])}")
    for table, entry in report["tables"].items():
        if entry.get("removed"):
            lines.append(f"{table}: REMOVED")
            continue
        parts = [f"rows {entry['rows'][0]} -> {entry['rows'][1]}"]
        for name, label in (("removed_rows", "REMOVED rows"), ("added_rows", "added rows")):
            if name in entry:
                parts.append(f"{label} {len(entry[name])}: {' '.join(entry[name])}")
        if "changed_rows" in entry:
            parts.append("CHANGED rows " + "; ".join(f"{i} ({', '.join(c)})" for i, c in entry["changed_rows"].items()))
        for name, label in (("changed_columns", "CHANGED columns"), ("removed_columns", "REMOVED columns"),
                            ("added_columns", "added columns")):
            if name in entry:
                parts.append(f"{label}: {', '.join(entry[name])}")
        lines.append(f"{table}: " + "; ".join(parts))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        if argv[:1] == ["compare"]:
            parser = argparse.ArgumentParser(prog="data-fingerprint.py compare")
            parser.add_argument("first", type=Path)
            parser.add_argument("second", type=Path)
            parser.add_argument("--except", dest="excepted", action="append", default=[],
                                help="a table or TABLE.COLUMN whose changes are expected (repeatable)")
            parser.add_argument("--json", action="store_true")
            args = parser.parse_args(argv[1:])
            kept, report = compare(json.loads(args.first.read_text()), json.loads(args.second.read_text()),
                                   set(args.excepted))
            print(json.dumps(report, indent=1, sort_keys=True) if args.json else _text(report))
            return 0 if kept else 1
        parser = argparse.ArgumentParser(prog="data-fingerprint.py", description=__doc__.split("\n\n")[0])
        parser.add_argument("path", type=Path, help="data folder, database file or backup archive")
        parser.add_argument("--salt-file", type=Path, required=True,
                            help="file of the salt of the digests (created if absent; keep it private)")
        args = parser.parse_args(argv)
        print(json.dumps(fingerprint(args.path, salt_of(args.salt_file)), indent=1, sort_keys=True))
        return 0
    except (Refused, OSError, sqlite3.DatabaseError, tarfile.TarError, ValueError, KeyError) as error:
        print(f"data-fingerprint: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
