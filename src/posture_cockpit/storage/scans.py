# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Domains and their scans.

A scan is saved with all its findings and never changes afterwards. When the
user clicks "Vérifier" on the plan, that one check runs again and its result
is saved as a *recheck* of the scan: the current state of the domain is the
scan's findings with their latest rechecks applied (:meth:`Scan.current`),
while the plan keeps the order computed from the original findings.

A new full scan creates a new row, so the history of scores stays available.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..core import scoring
from ..core.engine import ScanResult
from ..core.model import Finding
from .database import Database, Row, utcnow


@dataclass(frozen=True)
class Recheck:
    finding: Finding
    checked_at: str


@dataclass(frozen=True)
class Scan:
    id: int
    domain_id: int
    domain: str
    started_at: str
    duration_ms: int
    score: int        # current score, rechecks included
    grade: str
    version: str
    findings: list[Finding]                       # as found by the scan
    rechecks: dict[str, Recheck] = field(default_factory=dict)  # by check id

    def current(self) -> list[Finding]:
        """The findings with the latest recheck of each one applied."""
        return [self.rechecks[f.check_id].finding if f.check_id in self.rechecks else f for f in self.findings]


def _finding(row: Row) -> Finding:
    return Finding.from_stored(row["check_id"], row["category"], row["weight"], row["status"],
                               json.loads(row["outcome"]))


class Scans:
    def __init__(self, db: Database):
        self.db = db

    # ---------------------------------------------------------------- domains
    def add_domain(self, name: str, user_id: int | None, perimeter_id: int | None = None) -> int:
        """Id of the domain, created if needed (in ``perimeter_id``, or on the Internet).

        A domain keeps the perimeter it was created in: callers check it first."""
        row = self.db.one("SELECT id FROM domains WHERE name = ?", (name,))
        if row:
            return int(row["id"])
        cur = self.db.execute("INSERT INTO domains(name, created_at, created_by, perimeter_id) VALUES(?, ?, ?, ?)",
                              (name, utcnow(), user_id, perimeter_id))
        return int(cur.lastrowid or 0)

    def domain(self, name: str) -> Row | None:
        """The domain, with the name of its perimeter (``perimeter``, None on the Internet)."""
        return self.db.one("SELECT d.*, p.name AS perimeter FROM domains d "
                           "LEFT JOIN perimeters p ON p.id = d.perimeter_id WHERE d.name = ?", (name,))

    def domains(self, *, internal: bool) -> list[Row]:
        """Every domain with its latest scan (id, score, grade, date), most recently scanned first.

        ``internal``: include the domains of internal perimeters (for administrators only)."""
        return self.db.all(
            "SELECT d.*, p.name AS perimeter, s.id AS scan_id, s.score, s.grade, s.started_at FROM domains d "
            "LEFT JOIN perimeters p ON p.id = d.perimeter_id "
            "LEFT JOIN scans s ON s.id = (SELECT id FROM scans WHERE domain_id = d.id"
            " ORDER BY started_at DESC, id DESC LIMIT 1) "
            "WHERE ? OR d.perimeter_id IS NULL "
            "ORDER BY s.started_at IS NULL, s.started_at DESC, d.name", (int(internal),))

    def set_dns_host(self, domain_id: int, host_id: str) -> None:
        self.db.execute("UPDATE domains SET dns_host = ? WHERE id = ?", (host_id, domain_id))

    def delete_domain(self, domain_id: int) -> None:
        """The domain and all its scans."""
        self.db.execute("DELETE FROM domains WHERE id = ?", (domain_id,))

    # ------------------------------------------------------------------ scans
    def save(self, domain_id: int, result: ScanResult, version: str, user_id: int | None) -> int:
        value = scoring.score(result.findings)
        with self.db.transaction():
            cur = self.db.execute(
                "INSERT INTO scans(domain_id, started_at, duration_ms, score, grade, version, started_by)"
                " VALUES(?, ?, ?, ?, ?, ?, ?)",
                (domain_id, result.started_at.replace(microsecond=0).isoformat(), result.duration_ms, value,
                 scoring.grade(value), version, user_id))
            scan_id = int(cur.lastrowid or 0)
            self.db.executemany(
                "INSERT INTO findings(scan_id, check_id, category, weight, status, outcome) VALUES(?, ?, ?, ?, ?, ?)",
                [(scan_id, f.check_id, f.category, f.weight, f.status.value, json.dumps(f.outcome_json()))
                 for f in result.findings])
        return scan_id

    def latest(self, domain_id: int) -> Scan | None:
        scan_id = self.db.value("SELECT id FROM scans WHERE domain_id = ? ORDER BY started_at DESC, id DESC LIMIT 1",
                                (domain_id,))
        return self.get(scan_id) if scan_id else None

    def get(self, scan_id: int) -> Scan | None:
        row = self.db.one("SELECT s.*, d.name AS domain FROM scans s JOIN domains d ON d.id = s.domain_id "
                          "WHERE s.id = ?", (scan_id,))
        if row is None:
            return None
        findings = [_finding(r) for r in self.db.all("SELECT * FROM findings WHERE scan_id = ? ORDER BY rowid",
                                                     (scan_id,))]
        originals = {f.check_id: f for f in findings}
        rechecks = {}
        for r in self.db.all("SELECT * FROM rechecks WHERE scan_id = ?", (scan_id,)):
            original = originals.get(r["check_id"])
            if original is not None:
                rechecked = Finding.from_stored(r["check_id"], original.category, original.weight, r["status"],
                                                json.loads(r["outcome"]))
                rechecks[r["check_id"]] = Recheck(rechecked, r["checked_at"])
        return Scan(row["id"], row["domain_id"], row["domain"], row["started_at"], row["duration_ms"], row["score"],
                    row["grade"], row["version"], findings, rechecks)

    def history(self, domain_id: int, limit: int = 24) -> list[Row]:
        """Scores of the last scans, oldest first (for the trend line)."""
        rows = self.db.all("SELECT id, started_at, score, grade FROM scans WHERE domain_id = ? "
                           "ORDER BY started_at DESC, id DESC LIMIT ?", (domain_id, limit))
        return list(reversed(rows))

    def save_recheck(self, scan_id: int, finding: Finding) -> int:
        """Stores the new result of one check and returns the scan's updated score."""
        with self.db.transaction():
            self.db.execute(
                "INSERT INTO rechecks(scan_id, check_id, status, outcome, checked_at) VALUES(?, ?, ?, ?, ?) "
                "ON CONFLICT(scan_id, check_id) DO UPDATE SET status = excluded.status, outcome = excluded.outcome, "
                "checked_at = excluded.checked_at",
                (scan_id, finding.check_id, finding.status.value, json.dumps(finding.outcome_json()), utcnow()))
            scan = self.get(scan_id)
            assert scan is not None
            value = scoring.score(scan.current())
            self.db.execute("UPDATE scans SET score = ?, grade = ? WHERE id = ?",
                            (value, scoring.grade(value), scan_id))
        return value
