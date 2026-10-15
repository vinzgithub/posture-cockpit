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

In the Docker image: ``docker exec -it posture-cockpit posture-cockpit <command>``.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys

from .config import Config
from .core import engine, scoring
from .core.network import NetworkError
from .core.registry import Registry
from .i18n import LOCALES, Catalog, finding_summary
from .scanner import Scanner
from .security import MIN_PASSWORD_LENGTH, hash_password
from .storage import Accounts, Database

SYMBOLS = {"ok": "✓", "warn": "!", "fail": "✗", "na": "–", "info": "i", "error": "?"}


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "scan":
        return _scan(args.domain, args.json, args.lang)
    if args.command == "extensions":
        return _extensions()
    return _account(args.command, args.username)


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
    verdict = (f"{assessment.score}/100 ({assessment.grade})" if assessment.score is not None
               else catalog.text(lang, "score.not_evaluated"))
    coverage = catalog.text(lang, "score.coverage", {"evaluated": assessment.evaluated,
                                                     "applicable": assessment.applicable,
                                                     "percent": assessment.coverage_percent})
    print(f"{domain} — {verdict} — {coverage} — {result.duration_ms} ms\n")
    for f in result.findings:
        summary = finding_summary(catalog, lang, f, domain)
        print(f"  {SYMBOLS[f.status.value]} {f.check_id:<22} {summary}")
    plan = scoring.plan(result.findings)
    if plan.priorities:
        projected = f" (score {plan.now.score} → {plan.target.score})" if plan.now.score is not None else ""
        print(f"\nPriorities{projected}:")
        for item in plan.priorities:
            print(f"  +{item.gain:<3} {item.finding.check_id}")
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


# ------------------------------------------------------------------ accounts
def _account(command: str, username: str) -> int:
    accounts = Accounts(Database(Config.from_env().db_path))
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
