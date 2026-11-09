# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""What the evidence of mail.smtp_starttls keeps, within a strict size (version 0.7.0, correction 2).

The verdict and the readiness are decided on the whole probe, in memory (smtp_verdict.decide and
readiness); this module only shapes what is stored of it, from the structured evidence they built, and
never decides anything. :func:`bound` returns the evidence that is persisted, and the same evidence the
details, the PDF and the API read.

A DNS answer can publish thousands of MX or addresses, a certificate thousands of names: each list is
bounded, and the number of what it left out is kept beside it (``*_omitted``), exactly:

- the MX (A2): every MX selected for the measure with all it showed; the MX the message names (F05.08
  names one without a conclusion); one MX for each other cause of a measure not made (an invalid name,
  beyond the sample); then the others in their order, up to :data:`EVIDENCE_MX` entries at every stage.
  They are listed in the order of the probe (preference, then name), and ``silent_mx`` keeps the entries
  of the silent MX listed. The discovery keeps every invalid record, so several entries may carry one
  name: each is one MX, the one named is kept once (its first entry), and ``silent_mx`` matches them
  entry by entry, never by name alone (R1 of the review of PR #50);
- the addresses of an MX: every address attempted, with its observations, then :data:`EXTRA_ADDRESSES`
  not attempted (A3), never shown as measured: their ``seen`` stays ``unmeasured`` with its cause;
- the names of a certificate (:data:`CERTIFICATE_NAMES`, the MX name first when it is one of them: one
  occurrence moved, a repeated name kept and counted like any other, R2 of the review of PR #50), the
  names and patterns of the policy (:data:`POLICY_NAMES`, the MX kept first), the aliases of an MX, the
  items of a list in a note (:data:`NOTE_ITEMS`, then "…", the count of the note staying exact).

``counts`` (recorded by the measure) gives the addresses discovered, attempted, conclusive and what they
showed; :func:`bound` adds those represented in the evidence and those left out (A5).

The whole evidence, as storage/scans.py writes it (``json.dumps``, its defaults), never exceeds
:data:`LIMIT_BYTES` (A4). When the bounded lists still exceed it, the stages of :data:`STAGES` apply in
turn, the next only if the size is still beyond the limit, always in this order: the addresses not
attempted, then the MX kept for no reason but their order, then the optional diagnostics (the text of the
replies beyond their first line, the EHLO keywords, the partial lines, most names of a certificate, the
details of a diagnostic reading), then the observations of the attempts that showed nothing conclusive,
then everything but the essentials, then everything but the core: the verdict as recorded (``rule``,
``readiness``), the exhaustive counts and the omitted ones, the MX the message names with its cause.
What stays is never cut silently: ``bounds`` says the stage reached and whether the evidence is complete
(nothing left out at all); a core still beyond the limit says so (``within_limit``) rather than lose it.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Mapping
from typing import Any

LIMIT_BYTES = 65_536    # the evidence, as written in the database, at most (A4)
EVIDENCE_MX = 16        # MX kept, beyond those the measure needs (A2)
EXTRA_ADDRESSES = 4     # addresses not attempted kept by MX, after every address attempted (A3)
CERTIFICATE_NAMES = 16  # names kept of a certificate (A3)
POLICY_NAMES = 16       # names kept of a list of the policy: covered, uncovered, patterns (A3)
NOTE_ITEMS = 8          # items kept of a list in a note (A3)
ALIASES = 4             # aliases (CNAME) kept of an MX
TEXT = 255              # characters kept of a string of a certificate or of the policy
SHORT = 120             # characters kept of a detail once the diagnostics are reduced
MORE = "…"              # the last item of a list in a note when items were left out
STAGES = ("limits", "extras", "mx", "diagnostics", "observations", "essentials", "core")
LIST_PARAMS = ("addresses", "hosts", "target")  # the parameters of the notes that are lists

Evidence = dict[str, Any]


def size(evidence: Mapping[str, Any]) -> int:
    """The bytes of ``evidence`` as storage/scans.py writes it (json.dumps with its defaults: ASCII)."""
    return len(json.dumps(evidence).encode())


def listed(items: list[str], most: int = NOTE_ITEMS) -> tuple[str, int]:
    """A list of a note: its first ``most`` items joined, then "…" when others were left out; and how many."""
    left = max(len(items) - most, 0)
    if most <= 0:
        return (MORE if left else ""), left
    shown = ", ".join(items[:most])
    return (f"{shown}, {MORE}" if left else shown), left


def bound(evidence: Mapping[str, Any], *, named: str = "", limit: int = LIMIT_BYTES,
          original: bool = False) -> Evidence:
    """The evidence to store and show: every list bounded, the whole within ``limit`` bytes.

    ``named``: the MX the message of the outcome names (its ``host``), always kept. ``original``: the
    evidence was stored before this bounding (an older scan), bounded only to be shown; ``bounds`` then
    says so, with its size. Evidence without a probe (probe off) is returned as it is."""
    if "exhaustivity" not in evidence:
        return dict(evidence)
    if isinstance(evidence.get("bounds"), Mapping):
        return dict(evidence)  # already bounded: the same evidence (idempotent)
    before = size(evidence)
    draft = copy.deepcopy(dict(evidence))
    omitted = _limits(draft, named)
    for stage, reduce in zip(STAGES, (None, *_REDUCTIONS), strict=True):
        if reduce is not None:
            reduce(draft, named)
            omitted = True
        draft["bounds"] = _marker(limit, stage, complete=not omitted, original=before if original else None)
        if size(draft) <= limit:
            return draft
    draft["bounds"]["within_limit"] = False  # the core alone is beyond the limit: said, never lost
    return draft


def _marker(limit: int, stage: str, *, complete: bool, original: int | None) -> dict[str, Any]:
    marker: dict[str, Any] = {"limit_bytes": limit, "stage": stage, "complete": complete}
    if original is not None:
        marker.update(source="display", original_bytes=original)
    return marker


# ---------------------------------------------------------------- stage "limits": every list bounded (A2, A3)
def _limits(evidence: Evidence, named: str) -> bool:
    """Bounds every list in place; True when anything was left out or cut."""
    cut = False
    all_mx: list[dict[str, Any]] = evidence.get("mx", [])
    causes = _silent_causes(evidence)
    counts = _counts(evidence)
    keep = _selected(all_mx, named, causes)
    evidence["mx"] = [all_mx[i] for i in keep]
    left = len(all_mx) - len(keep)
    evidence["mx_omitted"] = int(evidence.get("mx_omitted", 0)) + left
    cut |= left > 0
    cut |= _keep_silent(evidence, all_mx, set(keep))
    kept_names = {m.get("name") for m in evidence["mx"]}
    for mx in evidence["mx"]:
        cut |= _addresses(mx, EXTRA_ADDRESSES)
        cut |= _cut_list(mx, "cname", ALIASES)
        for address in mx.get("addresses", []):
            for observation in address.get("observations", []):
                certificate = (observation.get("dialogue") or {}).get("certificate")
                if isinstance(certificate, dict):
                    cut |= _certificate(certificate, str(mx.get("name", "")), CERTIFICATE_NAMES, TEXT)
    policy = (evidence.get("readiness") or {}).get("policy")
    if isinstance(policy, dict):
        cut |= _policy(policy, kept_names, POLICY_NAMES)
    for note in evidence.get("notes", []):
        cut |= _note(note, NOTE_ITEMS)
    if counts is not None:
        _represent(evidence, counts)
        cut |= counts["omitted"] > 0
    return cut


def _counts(evidence: Evidence) -> dict[str, Any] | None:
    """The exact counts of the addresses, as the measure recorded them; derived from the rows of an older
    evidence (which kept every address of the MX it kept)."""
    found = (evidence.get("counts") or {}).get("addresses")
    if isinstance(found, dict):
        return found
    rows = [a for m in evidence.get("mx", []) for a in m.get("addresses", [])]
    if not rows and not (evidence.get("exhaustivity") or {}).get("addresses"):
        return None
    seen = {k: sum(a.get("seen") == k for a in rows)
            for k in ("verified", "starttls_absent", "certificate_refused", "unmeasured")}
    derived = {"discovered": int((evidence.get("exhaustivity") or {}).get("addresses", len(rows))),
               "attempted": sum(bool(_attempted(a)) for a in rows),
               "conclusive": len(rows) - seen["unmeasured"], **seen, "source": "rows"}
    evidence.setdefault("counts", {})["addresses"] = derived
    return derived


def _represent(evidence: Evidence, counts: dict[str, Any]) -> None:
    represented = sum(len(m.get("addresses", [])) for m in evidence.get("mx", []))
    counts["represented"] = represented
    counts["omitted"] = max(int(counts.get("discovered", represented)) - represented, 0)


def _attempted(address: Mapping[str, Any]) -> bool:
    return bool(address.get("observations") or address.get("interrupted"))


def _silent_causes(evidence: Mapping[str, Any]) -> dict[Any, Any]:
    """The cause of each silent MX, as F05.08 listed it (by name)."""
    return {s.get("name"): s.get("cause") for s in evidence.get("silent_mx", []) if isinstance(s, Mapping)}


def _cause(mx: Mapping[str, Any], causes: Mapping[Any, Any]) -> str:
    """The cause of a measure not made on an MX not selected for the measure: its own, as F05.08 listed it,
    else an invalid name or beyond the sample."""
    listed_cause = causes.get(mx.get("name"))
    if listed_cause:
        return str(listed_cause)
    if not mx.get("valid", True):
        return "invalid_name"
    return "sample" if mx.get("reason") == "sample" else str(mx.get("cause") or "other")


def _measured(mx: Mapping[str, Any]) -> bool:
    """An MX selected for the measure: a valid name, within the sample (MAX_MX at most, each name once)."""
    return bool(mx.get("valid", True)) and not mx.get("cause")


def _named_at(found: list[dict[str, Any]], named: str) -> int | None:
    """The position of the MX the message names, once: its first entry. The discovery keeps every invalid
    record, so several MX may carry the same name (each its own entry, the same cause); decide() names the
    first silent MX of the most specific cause, which is the first of its name."""
    return next((i for i, m in enumerate(found) if named and m.get("name") == named), None)


def _needed(found: list[dict[str, Any]], named: str, causes: Mapping[Any, Any]) -> list[int]:
    """The positions of the MX the evidence needs, in their priority (A2): every MX selected for the measure,
    the MX named (one entry), then the first MX of each other cause of a measure not made."""
    order = [i for i, m in enumerate(found) if _measured(m)]
    at = _named_at(found, named)
    if at is not None and at not in order:
        order.append(at)
    taken = set(order)
    seen_causes: set[str] = set()
    for i, mx in enumerate(found):
        if not _measured(mx):
            cause = _cause(mx, causes)
            if cause not in seen_causes:
                seen_causes.add(cause)
                if i not in taken:
                    order.append(i)
                    taken.add(i)
    return order


def _selected(all_mx: list[dict[str, Any]], named: str, causes: Mapping[Any, Any]) -> list[int]:
    """The positions of the MX kept (A2), :data:`EVIDENCE_MX` at most, in the order of the probe: those the
    evidence needs first, then the others in their order, within the room left."""
    order = _needed(all_mx, named, causes)
    taken = set(order)
    order += [i for i in range(len(all_mx)) if i not in taken]
    return sorted(order[:EVIDENCE_MX])


def _keep_silent(evidence: Evidence, found: list[dict[str, Any]], keep: set[int]) -> bool:
    """``silent_mx`` restricted to the MX kept: ``found`` is ``mx`` before, ``keep`` the positions kept in it.
    ``silent_mx`` lists the silent MX of the probe in its order, one entry for each, as ``mx`` does; several
    MX may carry the same name, so the k-th entry of a name is the k-th MX of that name in ``found``, never
    every MX of it (an older evidence, which kept fewer MX, leaves the others without one: left out). True
    when any entry is left out, counted exactly in ``silent_mx_omitted``."""
    silent = evidence.get("silent_mx")
    if not isinstance(silent, list):
        return False
    places: dict[Any, list[int]] = {}
    for i, mx in enumerate(found):
        places.setdefault(mx.get("name"), []).append(i)
    seen: dict[Any, int] = {}
    kept = []
    for entry in silent:
        name = entry.get("name") if isinstance(entry, Mapping) else None
        k = seen.get(name, 0)
        seen[name] = k + 1
        where = places.get(name, [])
        if k < len(where) and where[k] in keep:
            kept.append(entry)
    left = len(silent) - len(kept)
    evidence["silent_mx"] = kept
    if left:
        evidence["silent_mx_omitted"] = int(evidence.get("silent_mx_omitted", 0)) + left
    return left > 0


def _addresses(mx: dict[str, Any], extra: int) -> bool:
    found = mx.get("addresses", [])
    attempted = [a for a in found if _attempted(a)]
    others = [a for a in found if not _attempted(a)]
    kept = {id(a) for a in attempted + others[:extra]}
    mx["addresses"] = [a for a in found if id(a) in kept]
    left = len(found) - len(mx["addresses"])
    if left:
        mx["addresses_omitted"] = int(mx.get("addresses_omitted", 0)) + left
    return left > 0


def _cut_list(holder: dict[str, Any], key: str, most: int) -> bool:
    values = holder.get(key)
    if not isinstance(values, list) or len(values) <= most:
        return False
    holder[key] = values[:most]
    holder[f"{key}_omitted"] = int(holder.get(f"{key}_omitted", 0)) + len(values) - most
    return True


def _text(value: Any, most: int) -> tuple[Any, bool]:
    if isinstance(value, str) and len(value) > most:
        return value[:most] + MORE, True
    return value, False


def _certificate(certificate: dict[str, Any], mx_name: str, most: int, chars: int) -> bool:
    """The names of a certificate: the MX name first when it is one of them (its first occurrence, moved; any
    other occurrence stays where it was), then the others in their order; kept and omitted add up to them."""
    cut = False
    names = [str(n) for n in certificate.get("names", [])]
    ordered = names
    if mx_name in names:
        at = names.index(mx_name)
        ordered = [names[at], *names[:at], *names[at + 1:]]
    if len(ordered) > most:
        certificate["names_omitted"] = int(certificate.get("names_omitted", 0)) + len(ordered) - most
        cut = True
    if names:
        shortened = []
        for name in ordered[:most]:
            value, long = _text(name, chars)
            shortened.append(value)
            cut |= long
        certificate["names"] = shortened
    for key in ("subject", "issuer"):
        if key in certificate:
            certificate[key], long = _text(certificate[key], chars)
            cut |= long
    return cut


def _policy(policy: dict[str, Any], kept: set[Any], most: int) -> bool:
    cut = False
    for key in ("covered", "uncovered"):
        names = policy.get(key)
        if isinstance(names, list) and len(names) > most:
            first = [i for i, n in enumerate(names) if n in kept]
            rest = [i for i, n in enumerate(names) if n not in kept]
            keep = sorted((first + rest)[:most])
            policy[key] = [names[i] for i in keep]
            policy[f"{key}_omitted"] = int(policy.get(f"{key}_omitted", 0)) + len(names) - most
            cut = True
    cut |= _cut_list(policy, "mx_patterns", most)
    if isinstance(policy.get("mx_patterns"), list):
        shortened = [_text(p, TEXT) for p in policy["mx_patterns"]]
        policy["mx_patterns"] = [p for p, _ in shortened]
        cut |= any(long for _, long in shortened)
    if isinstance(policy.get("detail"), str):
        errors = policy["detail"].split(", ")
        if len(errors) > most // 2:
            policy["detail"], left = listed(errors, most // 2)
            policy["detail_omitted"] = int(policy.get("detail_omitted", 0)) + left
            cut = True
        policy["detail"], long = _text(policy["detail"], TEXT * 2)
        cut |= long
    return cut


def _note(note: Any, most: int) -> bool:
    """A list in a note, bounded; a note written bounded already (ending with "…") stays as it is."""
    params = note.get("params") if isinstance(note, dict) else None
    if not isinstance(params, dict):
        return False
    cut = bool(params.get("omitted"))
    for key in LIST_PARAMS:
        value = params.get(key)
        if not isinstance(value, str):
            continue
        items = value.split(", ")
        if items[-1] == MORE:
            continue
        if len(items) > most:
            params[key], left = listed(items, most)
            params["omitted"] = int(params.get("omitted", 0)) + left
            cut = True
    return cut


# ---------------------------------------------------------------- the stages beyond the limits (A4)
def _extras(evidence: Evidence, named: str) -> None:
    """The addresses not attempted go: only the attempts stay."""
    for mx in evidence.get("mx", []):
        _addresses(mx, 0)
    _recount(evidence)


def _mx(evidence: Evidence, named: str) -> None:
    """The MX kept for their order only go: those the measure, the message or a cause need stay."""
    found = evidence.get("mx", [])
    needed = sorted(_needed(found, named, _silent_causes(evidence))[:EVIDENCE_MX])
    evidence["mx"] = [found[i] for i in needed]
    evidence["mx_omitted"] = int(evidence.get("mx_omitted", 0)) + len(found) - len(needed)
    _keep_silent(evidence, found, set(needed))
    kept = {m.get("name") for m in evidence["mx"]}
    policy = (evidence.get("readiness") or {}).get("policy")
    if isinstance(policy, dict):
        _policy(policy, kept, POLICY_NAMES // 4)
    _recount(evidence)


_DIAGNOSTICS = ("capabilities", "partial", "quit_reply")  # "altered" stays: it proves the keywords masked


def _diagnostics(evidence: Evidence, named: str) -> None:
    """The optional diagnostics go: the text of a reply beyond its first line, the EHLO keywords, the partial
    lines, most names of a certificate, the details of a diagnostic reading; the lists of the notes and of
    the policy keep one item, the aliases one."""
    for mx in evidence.get("mx", []):
        _cut_list(mx, "cname", 1)
        for address in mx.get("addresses", []):
            for observation in address.get("observations", []):
                dialogue = observation.get("dialogue")
                if not isinstance(dialogue, dict):
                    if isinstance(observation.get("detail"), str):
                        observation["detail"], _ = _text(observation["detail"], SHORT)
                    continue
                for key in ("banner", "ehlo", "starttls"):
                    reply = dialogue.get(key)
                    if isinstance(reply, dict) and isinstance(reply.get("text"), list):
                        reply["text"] = reply["text"][:1]
                if "capabilities" in dialogue:
                    dialogue["capabilities_count"] = len(dialogue["capabilities"])
                for key in _DIAGNOSTICS:
                    dialogue.pop(key, None)
                for key in ("detail", "verify_message"):
                    if key in dialogue:
                        dialogue[key], _ = _text(dialogue[key], SHORT)
                certificate = dialogue.get("certificate")
                if isinstance(certificate, dict):
                    _certificate(certificate, str(mx.get("name", "")), 4, SHORT)
                if observation.get("purpose") == "read_certificate":
                    for key in ("banner", "ehlo", "starttls"):
                        dialogue.pop(key, None)
    policy = (evidence.get("readiness") or {}).get("policy")
    if isinstance(policy, dict):
        _policy(policy, {m.get("name") for m in evidence.get("mx", [])}, 2)
    for note in evidence.get("notes", []):
        _note_shorten(note, 1)


def _note_shorten(note: Any, most: int) -> None:
    params = note.get("params") if isinstance(note, dict) else None
    if not isinstance(params, dict):
        return
    for key in LIST_PARAMS:
        value = params.get(key)
        if isinstance(value, str):
            items = [i for i in value.split(", ") if i != MORE]
            if len(items) > most:
                params[key], left = listed(items, most)
                params["omitted"] = int(params.get("omitted", 0)) + left


def _observations(evidence: Evidence, named: str) -> None:
    """The observations of the attempts that showed nothing conclusive keep what they were and why."""
    for mx in evidence.get("mx", []):
        for address in mx.get("addresses", []):
            if address.get("seen") == "unmeasured":
                address["observations"] = [_reduced(o) for o in address.get("observations", [])]


def _reduced(observation: Mapping[str, Any], *, keep: tuple[str, ...] = ()) -> dict[str, Any]:
    reduced = {k: observation[k] for k in ("purpose", "consumed", "socket", "cause", "reason") if k in observation}
    dialogue = observation.get("dialogue")
    if isinstance(dialogue, Mapping):
        reduced["dialogue"] = {k: dialogue[k] for k in ("stage", "reason", *keep) if k in dialogue}
        certificate = dialogue.get("certificate")
        if keep and isinstance(certificate, Mapping):
            reduced["dialogue"]["certificate"] = {k: certificate[k] for k in ("names", "names_omitted", "not_after",
                                                                              "verified") if k in certificate}
    return reduced


_DETERMINING = ("tls_version", "tls_cipher", "verify_code", "verify_message")


def _essentials(evidence: Evidence, named: str) -> None:
    """Everything but the essentials goes: each MX, its addresses and what they showed, the facts that decided
    (the dialogue's stage and reason, TLS, the verification and the end of the certificate)."""
    for mx in evidence.get("mx", []):
        for key in ("cname", "dns_errors"):
            if isinstance(mx.get(key), list):
                mx[f"{key}_omitted"] = int(mx.get(f"{key}_omitted", 0)) + len(mx[key])
                del mx[key]
        for address in mx.get("addresses", []):
            determining = address.get("seen") in ("verified", "starttls_absent", "certificate_refused")
            address["observations"] = [_reduced(o, keep=_DETERMINING if determining else ())
                                       for o in address.get("observations", [])]
    policy = (evidence.get("readiness") or {}).get("policy")
    if isinstance(policy, dict):
        _policy(policy, set(), 0)
    for note in evidence.get("notes", []):
        _note_shorten(note, 0)
    # ``silent_mx`` stays as it is: it lists only the MX kept (MAX_MX measured at most, the one named and one
    # for each cause), each with its own cause, which the rows show.


_CORE = ("rule", "probe_enabled", "perspective", "deadline", "deadline_reached", "exhaustivity", "counts",
         "null_mx", "discovery_error", "mx_omitted", "silent_mx_omitted")


def _core(evidence: Evidence, named: str) -> None:
    """The core only: the verdict as recorded, the readiness, the exhaustive and omitted counts, the MX the
    message names with its cause."""
    found_mx = evidence.get("mx", [])
    at = _named_at(found_mx, named)
    _keep_silent(evidence, found_mx, set() if at is None else {at})
    silent = evidence.get("silent_mx")
    readiness = evidence.get("readiness") or {}
    policy = readiness.get("policy")
    kept: Evidence = {k: evidence[k] for k in _CORE if k in evidence}
    kept["readiness"] = {"state": readiness.get("state"), "causes": readiness.get("causes", []),
                         "policy": None if not isinstance(policy, Mapping) else
                         {k: v for k, v in policy.items() if not isinstance(v, list)}}
    kept["mx"] = [{"name": m.get("name"), "preference": m.get("preference"), "valid": m.get("valid"),
                   "addresses_omitted": len(m.get("addresses", [])) + int(m.get("addresses_omitted", 0))}
                  for m in ([] if at is None else [found_mx[at]])]
    kept["mx_omitted"] = int(evidence.get("mx_omitted", 0)) + len(found_mx) - len(kept["mx"])
    if isinstance(silent, list):  # the entry of the MX named, its cause; the others counted
        kept["silent_mx"] = silent
        kept["silent_mx_omitted"] = int(evidence.get("silent_mx_omitted", 0))
    if isinstance(evidence.get("discovery_error"), str):
        kept["discovery_error"], _ = _text(evidence["discovery_error"], SHORT)
    notes = [{"key": n.get("key"), "params": {k: v for k, v in (n.get("params") or {}).items()
                                             if k not in LIST_PARAMS}}
             for n in evidence.get("notes", []) if isinstance(n, Mapping)]
    if notes:
        kept["notes"] = notes
    evidence.clear()
    evidence.update(kept)
    counts = (evidence.get("counts") or {}).get("addresses")
    if isinstance(counts, dict):
        _represent(evidence, counts)


def _recount(evidence: Evidence) -> None:
    counts = (evidence.get("counts") or {}).get("addresses")
    if isinstance(counts, dict):
        _represent(evidence, counts)


_REDUCTIONS: tuple[Callable[[Evidence, str], None], ...] = (_extras, _mx, _diagnostics, _observations,
                                                            _essentials, _core)
