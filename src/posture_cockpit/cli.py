# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Command line tools.

Scan a domain from a terminal (handy while writing an extension; nothing is saved):

    posture-cockpit scan example.org
    posture-cockpit scan example.org --json
    posture-cockpit extensions

Rescue an account, on the server (the data folder comes from POSTURE_COCKPIT_DATA_DIR):

    posture-cockpit reset-password <username>
    posture-cockpit disable-totp <username>
    posture-cockpit make-admin <username>

Back up and restore an instance (storage/backup.py), see what a data folder holds:

    posture-cockpit backup [--output FILE|-]        while the server runs
    posture-cockpit check-backup FILE|-
    posture-cockpit restore FILE|- [--replace]      server stopped
    posture-cockpit info

With Docker Compose: ``docker compose exec posture-cockpit posture-cockpit <command>``
(``docker compose exec -T`` for a backup sent to the standard output).
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys
from pathlib import Path

from . import __version__
from .config import Config, StartupError
from .core import engine, scoring
from .core.network import NetworkError
from .core.registry import Registry
from .i18n import LOCALES, Catalog, finding_summary
from .scanner import Scanner
from .security import MIN_PASSWORD_LENGTH, hash_password
from .storage import Accounts, backup, instance_lock, open_database, upgrade
from .storage.schema import MIGRATIONS

SYMBOLS = {"blocked": "⊘", "ok": "✓", "warn": "!", "fail": "✗", "na": "–", "info": "i", "error": "?"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="posture-cockpit", description="Posture Cockpit command line tools.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a domain and print the result (nothing is saved)")
    scan.add_argument("domain")
    scan.add_argument("--json", action="store_true", help="print the findings as JSON")
    scan.add_argument("--lang", choices=LOCALES, default="fr")
    sub.add_parser("extensions", help="list the extensions and their checks")
    for name, text in (("reset-password", "set a new password for an account"),
                       ("disable-totp", "turn off two-factor authentication (lost phone and recovery codes)"),
                       ("make-admin", "give an account the administrator role")):
        sub.add_parser(name, help=text).add_argument("username")
    save = sub.add_parser("backup", help="write a consistent backup (database and session key), server running or not")
    save.add_argument("--output", "-o", help="file to write, or - for the standard output "
                                             "(default: a new file in the backups folder of the data folder)")
    verify = sub.add_parser("check-backup", help="check a backup completely, without restoring it")
    verify.add_argument("source", help="backup file, or - for the standard input")
    load = sub.add_parser("restore", help="restore a backup (stop the server first)")
    load.add_argument("source", help="backup file, or - for the standard input")
    load.add_argument("--replace", action="store_true",
                      help="replace the data of this instance (a copy of it is kept in the backups folder)")
    sub.add_parser("info", help="version, data folder, schema and content of the database")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args.domain, args.json, args.lang)
        if args.command == "extensions":
            return _extensions()
        if args.command == "backup":
            return _backup(args.output)
        if args.command == "check-backup":
            return _restore(args.source, check_only=True)
        if args.command == "restore":
            return _restore(args.source, replace=args.replace)
        if args.command == "info":
            return _info()
        return _account(args.command, args.username)
    except (StartupError, backup.BackupError) as error:
        print(f"posture-cockpit: {error}", file=sys.stderr)
        return 2


# ---------------------------------------------------------------------- scan
def _scan(typed: str, as_json: bool, lang: str) -> int:
    try:
        domain = engine.normalize_domain(typed)
    except ValueError:
        print(f"Not a domain name: {typed}", file=sys.stderr)
        return 2
    registry = Registry.discover()
    for error in registry.errors:
        print(f"Extension not loaded: {error.source}: {error.error}", file=sys.stderr)
    scanner = Scanner(registry, Config.from_env())
    try:
        problem = asyncio.run(scanner.preflight(domain))
    except NetworkError as e:
        problem = f"DNS unreachable ({e})"
    if problem:
        print({"unknown": f"{domain} does not exist.",
               "empty": f"The DNS gives no record at all for {domain}: check the name, or the resolver "
                        "(POSTURE_COCKPIT_NAMESERVERS)."}.get(problem, problem), file=sys.stderr)
        return 1
    result = asyncio.run(scanner.scan(domain))
    assessment = scoring.assess(result.findings)
    if as_json:
        print(json.dumps({"domain": domain, "score": assessment.score, "grade": assessment.grade,
                          "coverage": round(assessment.coverage, 3),
                          "findings": [{"check": f.check_id, "status": f.status.value, **f.outcome_json()}
                                       for f in result.findings]}, ensure_ascii=False, indent=2))
        return 0
    catalog = Catalog(registry.messages)
    verdict = (f"{assessment.score}/100 ({assessment.grade or catalog.text(lang, 'v04.undetermined')})"
               if assessment.score is not None
               else catalog.text(lang, "score.not_evaluated"))
    coverage = catalog.text(lang, "score.coverage", {"evaluated": assessment.evaluated,
                                                     "applicable": assessment.applicable,
                                                     "percent": assessment.coverage_percent})
    print(f"{domain} — {verdict} — {coverage} — {result.duration_ms} ms\n")
    for f in result.findings:
        summary = finding_summary(catalog, lang, f, domain)
        print(f"  {SYMBOLS[f.status.value]} {f.check_id:<22} {summary}")
    plan = scoring.plan(result.findings)
    if plan.unknown:
        print(catalog.text(lang, "projection.excluded"))
        for check_id in plan.unknown:
            print(f"  {check_id}")
    if plan.priorities:
        print(catalog.text(lang, "projection." + plan.target_kind))
        projected = (f" (score {plan.now.score} → {plan.target.score})"
                     if plan.target_kind == "estimated" and plan.now.score is not None else "")
        print(f"\nPriorities{projected}:")
        for item in plan.priorities:
            effect = f"{item.gain:+d}" if item.gain is not None else "?"
            print(f"  {effect:<4} {item.finding.check_id}")
    return 0


def _extensions() -> int:
    registry = Registry.discover()
    for extension in registry.extensions:
        print(f"{extension.id} {extension.version} — {extension.name}: {extension.description}")
        for check in extension.checks:
            print(f"    {check.id:<24} category={check.category:<6} weight={check.weight}")
    for error in registry.errors:
        print(f"NOT LOADED {error.source}: {error.error}")
    return 1 if registry.errors else 0


# ------------------------------------------------------------------- backups
def _data_dir() -> Path:
    return Config.from_env().data_dir


def _shared(data_dir: Path) -> instance_lock.Held:
    """The lock a command that uses the database shares with the server (storage/instance_lock.py)."""
    try:
        return instance_lock.shared(data_dir)
    except instance_lock.Busy:
        raise backup.BackupError(f"A restoration is in progress on {data_dir}: "
                                 "try again once it is finished.") from None


def _backup(output: str | None) -> int:
    data_dir = _data_dir()
    if data_dir.is_dir():
        held = _shared(data_dir)
        try:
            return _write_backup(data_dir, output)
        finally:
            held.release()
    return _write_backup(data_dir, output)


def _write_backup(data_dir: Path, output: str | None) -> int:
    if output == "-":
        if sys.stdout.isatty():
            print("posture-cockpit: the backup is binary: redirect it to a file (> backup.tar.gz), "
                  "with docker compose exec -T.", file=sys.stderr)
            return 2
        manifest = backup.create(data_dir, sys.stdout.buffer)
        sys.stdout.buffer.flush()
        where = "standard output"
    else:
        path, manifest = backup.create_file(data_dir, Path(output) if output else None)
        where = str(path)
    found = manifest["counts"]
    print(f"Backup written to {where}: schema {manifest['schema']}, {found['users']} account(s), "
          f"{found['domains']} domain(s), {found['scans']} scan(s), session key "
          f"{'included' if '.secret_key' in manifest['files'] else 'absent'}.", file=sys.stderr)
    return 0


def _restore(source: str, *, replace: bool = False, check_only: bool = False) -> int:
    data_dir = _data_dir()
    if source == "-":
        stream = sys.stdin.buffer
        if sys.stdin.isatty():
            print("posture-cockpit: send the backup on the standard input (< backup.tar.gz), "
                  "with docker compose run -T.", file=sys.stderr)
            return 2
        result = backup.check(stream, data_dir) if check_only else backup.restore(data_dir, stream, replace=replace)
    else:
        with open(source, "rb") as stream_file:
            result = (backup.check(stream_file, data_dir) if check_only
                      else backup.restore(data_dir, stream_file, replace=replace))
    found = result["counts"]
    summary = (f"schema {result['schema']} (version {result['version']}, {result['created_at']}), "
               f"{found['users']} account(s), {found['domains']} domain(s), {found['scans']} scan(s)")
    if check_only:
        print(f"Backup complete and readable: {summary}.")
        return 0
    print(f"Backup restored into {data_dir}: {summary}.")
    for path in result["kept"]:
        print(f"The former data is kept in {path}.")
    if result["new_key"]:
        print("The backup holds no session key: a new one was made, every browser signs in again.")
    if result["schema"] < len(MIGRATIONS):
        print(f"The database will be migrated from schema {result['schema']} to {len(MIGRATIONS)} "
              "at the next start (a copy is made first).")
    return 0


def _info() -> int:
    data_dir = _data_dir()
    db_path = data_dir / backup.DB_NAME
    print(f"Posture Cockpit {__version__}, schema {len(MIGRATIONS)}")
    print(f"Data folder: {data_dir}")
    if not db_path.is_file():
        print("Database: none yet (created at the first start)")
        return 0
    schema = backup.schema_of(db_path)
    state = ("up to date" if schema == len(MIGRATIONS) else "migrated at the next start" if schema < len(MIGRATIONS)
             else "NEWER than this version: it will refuse to start")
    found = backup.counts(db_path)
    print(f"Database: schema {schema} ({state}), {found['users']} account(s), {found['domains']} domain(s), "
          f"{found['scans']} scan(s)")
    key = data_dir / backup.KEY_NAME
    print(f"Session key: {'present' if key.is_file() else 'absent'}"
          + (f", permissions {oct(key.stat().st_mode & 0o777)}" if key.is_file() else ""))
    if 0 < schema < len(MIGRATIONS):
        needed, free = upgrade.space_needed(db_path), upgrade.free_space(data_dir)
        print(f"Before migrating, the next start writes a verified backup to {data_dir / 'backups'} "
              f"(needs {needed / 1024**2:.1f} MB free; {free / 1024**2:.1f} MB free now).")
    last = upgrade.last_upgrade_backup(db_path)
    if last is not None:
        present = (data_dir / str(last.get("path", ""))).is_file()
        print(f"Backup before the last update: {last.get('path')} (schema {last.get('from_schema')} to "
              f"{last.get('to_schema')}, {last.get('created_at')}, verified"
              f"{'' if present else ', NO LONGER in the backups folder'})")
    return 0


# ------------------------------------------------------------------ accounts
def _account(command: str, username: str) -> int:
    config = Config.from_env()
    held = _shared(config.data_dir) if config.data_dir.is_dir() else None
    try:
        # Like the server: a verified backup archive before any migration (storage/upgrade.py).
        db = open_database(config, say=lambda line: print(line, file=sys.stderr))
        try:
            return _change_account(Accounts(db), command, username)
        finally:
            db.close()
    finally:
        if held:
            held.release()


def _change_account(accounts: Accounts, command: str, username: str) -> int:
    user = accounts.by_name(username)
    if user is None:
        print(f"Unknown user: {username}", file=sys.stderr)
        return 1
    if command == "reset-password":
        password = getpass.getpass("New password: ")
        if len(password) < MIN_PASSWORD_LENGTH:
            print(f"Password too short (at least {MIN_PASSWORD_LENGTH} characters).", file=sys.stderr)
            return 1
        if password != getpass.getpass("Confirm: "):
            print("Passwords do not match.", file=sys.stderr)
            return 1
        accounts.set_password(user["id"], hash_password(password))
        accounts.new_session_epoch(user["id"])
        print("Password updated. Every browser has been signed out.")
    elif command == "disable-totp":
        if accounts.totp(user["id"]) is None:
            print("Two-factor authentication is not enabled for this account.")
            return 0
        accounts.disable_totp(user["id"])
        accounts.new_session_epoch(user["id"])
        print("Two-factor authentication disabled. Every browser has been signed out.")
        print("Sign in with the password only, then turn it on again in Settings.")
    elif command == "make-admin":
        accounts.set_admin(user["id"], True)
        print(f"{username} is now an administrator.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
