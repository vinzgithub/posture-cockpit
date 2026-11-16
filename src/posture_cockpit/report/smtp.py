# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""What the details page and the PDF show of mail.smtp_starttls (version 0.7, PR-D).

A reading of the evidence the check stored, never a new decision: the verdict (F05) and the
readiness for enforce (F06) were given by checks/smtp_verdict.py when the scan was made, and are
shown as stored, in the words of the catalogues, whatever the configuration is now. The probe off,
an engine error (no structured evidence) or a scan made before 0.7 give no view (:func:`view`
returns None) and the page shows what it shows for any check.

The view reads, in order (progressive reading): the readiness for enforce, apart from the verdict,
with its causes and its limit (measured from this instance, no guarantee of delivery from the
Internet); one row per MX and address (name, preference, address and family, the stages the dialogue
reached with their reply codes, TLS, the certificate: verified, refused, or read without
verification for the diagnosis, and the result or the exact cause of a measure not made: per address
from the probe, per MX from ``silent_mx``, never the global cause of F05.08 on every server); the
limits of the measure (addresses, connections, budget, deadline), and how many MX the evidence left out
(``mx_omitted``: invalid names or beyond the sample, never contacted; every MX measured is kept). The
notes of the evidence are not repeated: the text of every finding already ends with them
(i18n.finding_summary).

The evidence is bounded when it is stored (checks/smtp_evidence.py, correction 2 of 0.7.0): what it left
out is said where it was, from its exact counts, never shown as measured: a row per MX for the addresses
left out, "and N others" for the aliases, the names of a certificate and of a policy; the addresses
discovered, attempted, conclusive, listed and left out; the stage of reduction when the lists alone did not
fit (``bounds``); and, for a scan stored before, its evidence bounded only to be shown, the original kept
whole (storage/scans.py).

Every string from the network (MX names, aliases, banner, certificate names, verification messages, the
names a policy covers) is data: it is returned as text, bounded for the eye (:data:`SHOWN_CHARS`, and
:data:`SHOWN_NAMES` names in a list, then how many more), and the templates escape it (autoescape in both
environments). Nothing here is marked safe; the whole value stays in the stored evidence, which the
details show as JSON after this block.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from ..core.network import Limits

KEY = "mail.smtp_starttls"
BUDGET = Limits().smtp_attempts
FAMILIES = {4: "IPv4", 6: "IPv6"}
# The colour of each state of readiness, from the badges of the statuses: confirmed, to fix, open.
READINESS_BADGES = {"ready": "ok", "compatible": "ok", "to_fix": "warn", "unconfirmed": "error",
                    "not_applicable": "na"}
SHOWN_CHARS = 200  # a string from the network shown at most this long (B1 already bounds what it keeps)
SHOWN_NAMES = 8    # names shown at most in a list (the MX a policy covers or leaves out)
# Aliases of one MX shown at most in its cell (a name has one CNAME, RFC 1034 §3.6.2): with a name and the
# certificate, a row of the PDF stays shorter than a page, so that no row is ever split (R3 of the review).
SHOWN_ALIASES = 2
# A word from the network longer than this (a name, a banner, a certificate name) may be broken where it
# must, in the cells listed in a row's ``wrap``; a shorter one is never cut, as host names usually are.
LONG_WORD = 40
WRAPPED = ("mx", "cname", "banner")
Text = Callable[..., str]


def _bounded(value: Any) -> str:
    text = str(value)
    return text if len(text) <= SHOWN_CHARS else text[:SHOWN_CHARS] + "…"


def _names(names: Iterable[Any], t: Text, most: int = SHOWN_NAMES, omitted: Any = 0) -> str:
    """Names from the network as one bounded line: each bounded, ``most`` at most, then how many more,
    those the evidence left out (``omitted``, its exact count) included."""
    shown = [_bounded(n) for n in names]
    more = max(len(shown) - most, 0) + int(omitted or 0)
    if not shown:
        return t("smtp.names_omitted", n=more) if more else ""
    line = ", ".join(shown[:most])
    return line + (" " + t("smtp.more", n=more) if more else "")


def _long(text: str) -> bool:
    return any(len(word) > LONG_WORD for word in text.split())


def _wrap(row: dict[str, Any]) -> dict[str, Any]:
    """The row, with the cells where a word is long enough to be broken (R2 of the review of PR-D)."""
    row["wrap"] = [k for k in WRAPPED if _long(row[k])] + (
        ["certificate"] if any(_long(line) for line in row["certificate"]) else [])
    return row


def view(evidence: Mapping[str, Any] | None, t: Text) -> dict[str, Any] | None:
    """The SMTP part of a finding, ready to show; None when the evidence holds no structured result."""
    if not isinstance(evidence, Mapping) or "rule" not in evidence or "readiness" not in evidence:
        return None
    found = evidence.get("bounds")
    bounds: Mapping[str, Any] = found if isinstance(found, Mapping) else {}
    return {"rule": evidence["rule"], "readiness": _readiness(evidence["readiness"], t),
            "rows": [row for mx in evidence.get("mx", []) for row in _rows(mx, evidence, t)],
            "limits": _limits(evidence, t), "omitted": int(evidence.get("mx_omitted") or 0),
            "core": bounds.get("stage") == "core", "counts": _counts(evidence, t),
            "reduced": _reduced(bounds, t), "display": _display(bounds, t),
            "probe_enabled": bool(evidence.get("probe_enabled"))}


def _kib(n: Any) -> str:
    return f"{int(n or 0) / 1024:.0f}"


def _counts(evidence: Mapping[str, Any], t: Text) -> str:
    """The addresses discovered, attempted, conclusive, listed and left out (A5), when any was left out."""
    counts = (evidence.get("counts") or {}).get("addresses")
    if not isinstance(counts, Mapping) or not int(counts.get("omitted") or 0):
        return ""
    return t("smtp.counts", **{k: int(counts.get(k) or 0) for k in ("discovered", "attempted", "conclusive",
                                                                      "represented", "omitted")})


def _reduced(bounds: Mapping[str, Any], t: Text) -> str:
    """The stage of reduction (A4) when the bounded lists alone did not fit, and a core still beyond."""
    stage = bounds.get("stage")
    if not stage or stage == "limits":
        return ""
    text = t("smtp.reduced", kib=_kib(bounds.get("limit_bytes")), stage=t(f"smtp.stage.{stage}"))
    return text + (" " + t("smtp.over_limit") if bounds.get("within_limit") is False else "")


def _display(bounds: Mapping[str, Any], t: Text) -> str:
    """An evidence stored before the bounding, bounded only to be shown (A7): its size, the original kept."""
    if bounds.get("source") != "display":
        return ""
    return t("smtp.display_bounded", kib=_kib(bounds.get("original_bytes")), limit=_kib(bounds.get("limit_bytes")))


def _readiness(readiness: Mapping[str, Any], t: Text) -> dict[str, Any]:
    state = readiness.get("state", "unconfirmed")
    policy = readiness.get("policy")
    shown = None
    if isinstance(policy, Mapping):
        shown = {"state": policy.get("state", ""), "label": t(f"{KEY}.policy.{policy.get('state', 'unreadable')}"),
                 "covered": _names(policy.get("covered", []), t, omitted=policy.get("covered_omitted")),
                 "uncovered": _names(policy.get("uncovered", []), t, omitted=policy.get("uncovered_omitted"))}
    return {"state": state, "label": t(f"{KEY}.readiness.{state}"), "badge": READINESS_BADGES.get(state, "na"),
            "causes": [t(f"{KEY}.readiness.cause.{c}") for c in readiness.get("causes", [])],
            "policy": shown, "scope": t(f"{KEY}.readiness.scope")}


def _listed_cause(mx: Mapping[str, Any], evidence: Mapping[str, Any]) -> str:
    return str(next((s["cause"] for s in evidence.get("silent_mx", []) if s.get("name") == mx.get("name")), "") or "")


def _mx_cause(mx: Mapping[str, Any], evidence: Mapping[str, Any]) -> str:
    """The cause proper to this MX: from ``silent_mx`` (F05.08) when the verdict listed it, else from what
    the MX itself shows (an invalid name, beyond the sample, the DNS, no address)."""
    listed = _listed_cause(mx, evidence)
    if listed:
        return listed
    if not mx.get("valid", True):
        return "invalid_name"
    if mx.get("reason") == "sample":
        return "sample"
    return "dns" if mx.get("dns_errors") or mx.get("discovery_complete") is False else "no_address"


def _rows(mx: Mapping[str, Any], evidence: Mapping[str, Any], t: Text) -> list[dict[str, Any]]:
    base = {"mx": _bounded(mx.get("name", "")), "preference": mx.get("preference"),
            "cname": _names(mx.get("cname", []), t, SHOWN_ALIASES, omitted=mx.get("cname_omitted"))}
    empty = {"address": "", "family": "", "stage": "", "codes": "", "banner": "", "tls": "", "certificate": []}
    addresses = mx.get("addresses", [])
    left = int(mx.get("addresses_omitted") or 0)
    rows = [_wrap({**base, **_address(a, t)}) for a in addresses]
    if not addresses and (_listed_cause(mx, evidence) or not left):
        cause = _mx_cause(mx, evidence)
        rows.append(_wrap({**base, **empty, "result": t(f"smtp.cause.{cause}"), "kind": "unmeasured", "cause": cause}))
    if left:  # the addresses the evidence left out: never attempted, unless it was reduced to its core
        core = (evidence.get("bounds") or {}).get("stage") == "core"
        rows.append(_wrap({**base, **empty, "result": t("smtp.addresses_omitted" if core else "smtp.addresses_untried",
                                                         n=left), "kind": "left_out", "cause": ""}))
    return rows


def _address(address: Mapping[str, Any], t: Text) -> dict[str, Any]:
    observations = address.get("observations", [])
    verify = next((o for o in observations if o.get("purpose") == "verify"), None)
    reading = next((o for o in observations if o.get("purpose") == "read_certificate"), None)
    dialogue = verify.get("dialogue") if verify else None
    seen = address.get("seen", "unmeasured")
    cause = address.get("unmeasured", "")
    d: Mapping[str, Any] = dialogue or {}
    replies = [d[k] for k in ("banner", "ehlo", "starttls") if k in d]  # the stages reached, with their codes
    row: dict[str, Any] = {
        "address": address.get("address", ""), "family": FAMILIES.get(int(address.get("family") or 0), ""),
        "stage": t(f"{KEY}.stage.{d['stage']}") if d else "",
        "codes": " · ".join(str(r["code"]) for r in replies),
        "banner": _bounded((d.get("banner", {}).get("text") or [""])[0]),
        "tls": " · ".join(v for v in (d.get("tls_version", ""), d.get("tls_cipher", "")) if v),
        "certificate": _certificate(seen, dialogue, reading, address, t), "kind": seen, "cause": cause}
    if seen == "unmeasured":
        detail = t(f"{KEY}.reason.{dialogue['reason']}") if dialogue else ""
        row["result"] = t(f"smtp.cause.{cause or 'tool'}") + (f" ({detail})" if detail else "")
    else:
        row["result"] = t(f"{KEY}.reason.{seen if seen != 'verified' else 'tls_verified'}")
    return row


def _certificate(seen: str, dialogue: Mapping[str, Any] | None, reading: Mapping[str, Any] | None,
                 address: Mapping[str, Any], t: Text) -> list[str]:
    """The lines of the certificate cell: verified, refused (with the verification's own words), and the
    diagnostic reading, which verifies nothing (F03), or its interruption by the deadline."""
    lines: list[str] = []
    if seen == "verified" and dialogue and "certificate" in dialogue:
        lines.append(t("smtp.cert.verified"))
        lines.extend(_certificate_lines(dialogue["certificate"], t))
    elif seen == "certificate_refused" and dialogue:
        lines.append(t("smtp.cert.refused", code=str(dialogue.get("verify_code", "")),
                       message=_bounded(dialogue.get("verify_message", ""))))
        read = reading.get("dialogue") if reading else None
        if read and "certificate" in read:
            lines.append(t("smtp.cert.diagnostic"))
            lines.extend(_certificate_lines(read["certificate"], t))
        elif "read_certificate" in address.get("interrupted", []) or (read and read.get("reason") == "deadline") or (
                reading and reading.get("reason") == "deadline"):
            lines.append(t("smtp.cert.reading_interrupted"))
    return lines


def _certificate_lines(certificate: Mapping[str, Any], t: Text) -> list[str]:
    return [t("smtp.cert.names", names=_certificate_names(certificate, t)),
            t("smtp.cert.issuer", issuer=_bounded(certificate.get("issuer", ""))),
            t("smtp.cert.until", date=str(certificate.get("not_after", ""))[:10])]


def _certificate_names(certificate: Mapping[str, Any], t: Text) -> str:
    """The names of a certificate in :data:`SHOWN_CHARS` characters: whole names while they fit (the first
    bounded when it alone is longer), then how many more, those the evidence left out included."""
    names = [str(n) for n in certificate.get("names", [])]
    left = int(certificate.get("names_omitted") or 0)
    if not names:
        subject = _bounded(certificate.get("subject", ""))
        if not left:
            return subject
        return f"{subject} {t('smtp.more', n=left)}" if subject else t("smtp.names_omitted", n=left)
    shown = [_bounded(names[0])]
    for name in names[1:]:
        if len(", ".join([*shown, name])) > SHOWN_CHARS:
            break
        shown.append(name)
    more = len(names) - len(shown) + left
    return ", ".join(shown) + (" " + t("smtp.more", n=more) if more else "")


def _limits(evidence: Mapping[str, Any], t: Text) -> str:
    counts = evidence.get("exhaustivity")
    if not isinstance(counts, Mapping):
        return ""
    text = t("smtp.limits", mx=counts.get("mx", 0), addresses=counts.get("addresses", 0),
             sockets=counts.get("sockets", 0), dialogues=counts.get("dialogues", 0),
             spent=counts.get("budget_spent", 0), budget=BUDGET, seconds=int(evidence.get("deadline", 0)))
    return text + (" " + t("smtp.limits_reached") if evidence.get("deadline_reached") else "")
