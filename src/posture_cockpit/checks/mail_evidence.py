# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""What the evidence and the texts of mail.mx and mail.mta_sts keep (version 0.7.0, correction 4).

A DNS answer can publish thousands of MX, a policy thousands of patterns: the checks decide on all of them,
in memory (mail.py); this module only shapes what is stored and shown of their outcome, with the bounds and
the functions of correction 2 (smtp_evidence.py), and never decides anything:

- each list of the evidence (:data:`LISTS`) keeps :data:`~smtp_evidence.EVIDENCE_MX` entries, those that
  make the verdict first (:func:`_determining`: a null MX, an address given as MX, an MX without address, an
  invalid pattern, an MX the policy does not cover, a record naming MTA-STS), then the others; the entries
  kept stay in their order, and the number left out is kept beside the list (``<list>_omitted``), exactly;
- the strings of the policy and of the TXT records keep :data:`~smtp_evidence.TEXT` characters, the last
  one "…"; the names (MX, hosts) are kept whole: the DNS bounds them;
- the list of a message (``hosts``) keeps :data:`HOSTS` names then "…" (smtp_evidence.listed), and the number
  left out (``omitted``); ``n``, ``mode``, ``max_age`` and the other parameters are kept as they are;
- the whole evidence, as storage/scans.py writes it, never exceeds :data:`~smtp_evidence.LIMIT_BYTES`:
  should names full of escaped characters still exceed it, every string of the lists is shortened
  (:data:`~smtp_evidence.SHORT`), then the lists keep one entry, then none, their counts exact.

Within every bound, an outcome is returned as it is: an ordinary domain keeps its evidence and its texts
byte for byte. Applied twice, the bounding changes nothing more. :func:`bounded` shapes what a check
returns; storage/scans.py applies :func:`shown` to the findings stored before this correction, to show
them bounded, never to rewrite them (A7: the original stays a download away).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import Any

from ..core.egress import parse_address
from ..core.model import Outcome
from ..core.network import mx_record
from .records import mx_pattern_ok
from .smtp_evidence import EVIDENCE_MX, LIMIT_BYTES, MORE, SHORT, TEXT, listed, size

CHECKS = ("mail.mx", "mail.mta_sts")
HOSTS = EVIDENCE_MX  # names kept in the list of a message (D1)
# The lists of the evidence of each check; those whose strings are cut (policy, TXT records).
LISTS = {"mail.mx": ("mx", "unresolved"), "mail.mta_sts": ("records", "ignored", "mx_patterns", "uncovered")}
TEXTS = ("records", "ignored", "mx_patterns")
# (entries kept by list, characters kept by string: None keeps the names whole), in turn, while the
# evidence exceeds the limit.
STEPS: tuple[tuple[int, int | None], ...] = ((EVIDENCE_MX, None), (EVIDENCE_MX, SHORT), (1, SHORT), (0, SHORT))

Evidence = dict[str, Any]


def bounded(check_id: str, outcome: Outcome) -> Outcome:
    """The outcome of mail.mx or mail.mta_sts as it is stored and shown: its status, its message, its remedy
    and its signals unchanged, its evidence and the list of its message bounded."""
    evidence = bound(check_id, outcome.evidence)
    params = bound_params(outcome.params)
    if evidence == outcome.evidence and params == outcome.params:
        return outcome
    return replace(outcome, evidence=evidence, params=params)


def shown(check_id: str, data: dict[str, Any]) -> None:
    """A finding of mail.mx or mail.mta_sts as storage/scans.py read it (``data``, its stored outcome): its
    evidence and its parameters bounded to be shown, in ``data`` only. The evidence of a scan stored before
    this correction then says so (``bounds``, with its size), as correction 2 does for SMTP: its original is
    downloaded whole (routes/domains.py)."""
    evidence = data.get("evidence")
    if isinstance(evidence, dict):
        data["evidence"] = bound(check_id, evidence, original=True)
    params = data.get("params")
    if isinstance(params, dict):
        data["params"] = bound_params(params)


def bound(check_id: str, evidence: Mapping[str, Any], *, original: bool = False,
          limit: int = LIMIT_BYTES) -> Evidence:
    """``evidence`` with each of its lists bounded (:data:`STEPS`), within ``limit`` bytes; the same when
    nothing exceeds a bound. ``original``: stored before this correction, bounded only to be shown."""
    draft = dict(evidence)
    for most, chars in STEPS:
        draft = dict(evidence)
        for key in LISTS.get(check_id, ()):
            _cut(draft, key, most, chars, _determining(check_id, key, evidence))
        if size(draft) <= limit:
            break
    if original and draft != evidence:
        draft["bounds"] = {"limit_bytes": limit, "source": "display", "original_bytes": size(evidence)}
    return draft


def bound_params(params: Mapping[str, Any]) -> Mapping[str, Any]:
    """The parameters of a message, its list of hosts bounded to :data:`HOSTS` names then "…", with the
    number left out (``omitted``); the same parameters when the list is within the bound or already cut."""
    hosts = params.get("hosts")
    if not isinstance(hosts, str) or "omitted" in params:
        return params
    items = hosts.split(", ")  # as mail.py joins them: a name never holds ", " (a space is escaped)
    if len(items) <= HOSTS:
        return params
    text, left = listed(items, HOSTS)
    return {**params, "hosts": text, "omitted": left}


def _cut(evidence: Evidence, key: str, most: int, chars: int | None,
         determining: Callable[[Any], bool]) -> None:
    values = evidence.get(key)
    if not isinstance(values, list):
        return
    limit = chars if chars is not None else TEXT if key in TEXTS else None
    shortened = [_short(value, limit) for value in values]
    if len(values) <= most and shortened == values:
        return
    first = [i for i, value in enumerate(values) if determining(value)]
    chosen = set(first)
    kept = sorted((first + [i for i in range(len(values)) if i not in chosen])[:most])
    evidence[key] = [shortened[i] for i in kept]
    if len(kept) < len(values):
        evidence[f"{key}_omitted"] = int(evidence.get(f"{key}_omitted", 0)) + len(values) - len(kept)


def _short(value: Any, chars: int | None) -> Any:
    """A string of more than ``chars`` characters cut to ``chars``, its last one "…" (cut once only)."""
    if chars is None or not isinstance(value, str) or len(value) <= chars:
        return value
    return value[:chars - 1] + MORE


def _determining(check_id: str, key: str, evidence: Mapping[str, Any]) -> Callable[[Any], bool]:
    """Whether an entry of the list ``key`` makes the verdict, kept before the others (correction 4)."""
    if key == "mx" and check_id == "mail.mx":
        unresolved = {h for h in evidence.get("unresolved") or () if isinstance(h, str)}

        def cited(record: Any) -> bool:
            try:
                host = mx_record(str(record))[1]
            except IndexError:  # an empty record: nothing it could name
                return False
            return host == "" or parse_address(host) is not None or host in unresolved

        return cited
    if key == "mx_patterns":
        return lambda pattern: not (isinstance(pattern, str) and mx_pattern_ok(pattern))
    if key == "ignored":
        return lambda record: False
    return lambda entry: True  # unresolved, uncovered, records: each one is cited
