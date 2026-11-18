# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Results this version cannot explain (version 0.7.1, D7).

A scan recorded by a newer version may hold findings of checks this version does not have: an
observation of a later TLS audit, or a check added after 0.7. Such a finding is *unknown* here: this
version has no title for it (``<check>.title`` is in neither catalogue). The catalogue, not the
registry, decides, so that the pages and the PDF agree: it holds the texts of the built-in checks and
of the installed extensions alike.

What this version does with an unknown finding:

- it shows it apart, as recorded (:func:`view`): its identifier, its stored status and weight, the
  version that recorded the scan and its raw evidence. Every string is bounded here (identifier,
  version, category, evidence) and escaped by the templates (autoescape in both environments): nothing
  is marked safe, nothing is worded from a key the catalogue does not hold, so no raw key reaches a page
  or the PDF;
- it never proposes it: not in the plan of fixes, not among the candidates of a simulation, never
  hypothesized by one (core/scoring.py, ``frozen``), not among the checks not evaluated, not in the
  transitions of Mission Control or of the dashboard, not counted among the checks of the annex;
- it changes no number: the score, the grade, the coverage and the API are computed as in 0.7.0, from
  every stored finding with its stored weight. An informative result (INFO, NA) has no part in them; a
  result a newer version scored keeps the weight that version gave it, so the score is the one 0.7.0
  gives, and the one the newer version stored while its rules are those of this generation;
- comparisons and events read the stored statuses as before: a state this version writes holds the
  unknown findings as they were recorded (a recheck never runs them), so none of them changes there.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import Any

from . import __version__
from .core.model import Finding
from .i18n import LOCALES, Catalog

SHOWN_ID = 80          # characters of an identifier shown
SHOWN_TEXT = 40        # characters of a version or of a category name shown
SHOWN_ITEMS = 30       # unknown results listed at most on a page
SHOWN_IDS = 8          # identifiers named at most in the line of the PDF
SHOWN_EVIDENCE = 4096  # characters of the JSON of an evidence shown on a page


def bounded(value: Any, most: int) -> str:
    """A stored string as shown: at most ``most`` characters, then an ellipsis."""
    text = str(value)
    return text if len(text) <= most else text[:most] + "…"


def known(catalog: Catalog, check_id: str) -> bool:
    """Whether this version can name the check: its title is in a catalogue."""
    key = f"{check_id}.title"
    return any(catalog.has(lang, key) for lang in LOCALES)


def unknown_ids(catalog: Catalog, findings: Iterable[Finding]) -> frozenset[str]:
    return frozenset(f.check_id for f in findings if not known(catalog, f.check_id))


def known_only(catalog: Catalog, findings: Iterable[Finding]) -> list[Finding]:
    return [f for f in findings if known(catalog, f.check_id)]


def title(catalog: Catalog, lang: str, check_id: str) -> str:
    """The title of a check, or a generic one with its bounded identifier: never a raw key."""
    if known(catalog, check_id):
        return catalog.text(lang, f"{check_id}.title")
    return catalog.text(lang, "unknown.check", {"id": bounded(check_id, SHOWN_ID)})


def category(catalog: Catalog, lang: str, name: str) -> str:
    """The label of a category, or a generic one with its bounded name."""
    key = f"category.{name}"
    if any(catalog.has(code, key) for code in LOCALES):
        return catalog.text(lang, key)
    return catalog.text(lang, "unknown.category", {"name": bounded(name, SHOWN_TEXT)})


def _evidence(evidence: Any) -> tuple[str, int, bool]:
    """The JSON of an evidence as shown (bounded), its whole size in bytes, and whether it was cut."""
    if not evidence:
        return "", 0, False
    text = json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True, default=str)
    size = len(text.encode("utf-8"))
    if len(text) <= SHOWN_EVIDENCE:
        return text, size, False
    return text[:SHOWN_EVIDENCE] + "\n…", size, True


def view(catalog: Catalog, lang: str, findings: Sequence[Finding], recorded_by: str) -> dict[str, Any] | None:
    """The unknown findings of a scan, ready to show apart; None when there is none."""
    unknown = [f for f in findings if not known(catalog, f.check_id)]
    if not unknown:
        return None
    items = []
    for f in unknown[:SHOWN_ITEMS]:
        evidence, size, cut = _evidence(f.outcome.evidence)
        items.append({
            "id": bounded(f.check_id, SHOWN_ID), "status": f.status.value,
            "status_label": catalog.text(lang, f"status.{f.status.value}"),
            # Applicable or blocked: part of the score or of a coverage, with the weight it was stored with.
            "weighted": f.status.diagnostic, "weight": f.weight,
            "category": category(catalog, lang, f.category),
            "evidence": evidence, "cut": cut, "shown_kib": f"{SHOWN_EVIDENCE / 1024:.0f}",
            "kib": f"{size / 1024:.0f}",
        })
    return {"results": items, "count": len(unknown), "more": len(unknown) - len(items),
            "version": bounded(recorded_by, SHOWN_TEXT), "current": __version__}


def report_line(catalog: Catalog, lang: str, findings: Sequence[Finding]) -> str:
    """The one line of the PDF on the unknown findings, "" when there is none."""
    ids = [bounded(f.check_id, SHOWN_ID) for f in findings if not known(catalog, f.check_id)]
    if not ids:
        return ""
    named = ", ".join(ids[:SHOWN_IDS])
    more = len(ids) - SHOWN_IDS
    if more > 0:
        named += " " + catalog.text(lang, "unknown.more_ids", {"n": more})
    return catalog.text(lang, "unknown.report", {"n": len(ids), "ids": named})
