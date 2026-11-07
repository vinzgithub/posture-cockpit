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
notes; the limits of the measure (addresses, connections, budget, deadline).

Every string from the network (banner, certificate names, verification messages) is data: it is
returned as text, and the templates escape it (autoescape in both environments). Nothing here is
marked safe.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from ..core.network import Limits

KEY = "mail.smtp_starttls"
BUDGET = Limits().smtp_attempts
FAMILIES = {4: "IPv4", 6: "IPv6"}
SHOWN_CHARS = 200  # a string from the network shown at most this long (B1 already bounds what it keeps)


def _bounded(value: Any) -> str:
    text = str(value)
    return text if len(text) <= SHOWN_CHARS else text[:SHOWN_CHARS] + "…"
Text = Callable[..., str]


def view(evidence: Mapping[str, Any] | None, t: Text) -> dict[str, Any] | None:
    """The SMTP part of a finding, ready to show; None when the evidence holds no structured result."""
    if not isinstance(evidence, Mapping) or "rule" not in evidence or "readiness" not in evidence:
        return None
    return {"rule": evidence["rule"], "readiness": _readiness(evidence["readiness"], t),
            "rows": [row for mx in evidence.get("mx", []) for row in _rows(mx, evidence, t)],
            "notes": [t(n["key"], **n.get("params", {})) for n in evidence.get("notes", [])],
            "limits": _limits(evidence, t), "probe_enabled": bool(evidence.get("probe_enabled"))}


def _readiness(readiness: Mapping[str, Any], t: Text) -> dict[str, Any]:
    state = readiness.get("state", "unconfirmed")
    policy = readiness.get("policy")
    shown = None
    if isinstance(policy, Mapping):
        shown = {"state": policy.get("state", ""), "label": t(f"{KEY}.policy.{policy.get('state', 'unreadable')}"),
                 "covered": list(policy.get("covered", [])), "uncovered": list(policy.get("uncovered", []))}
    return {"state": state, "label": t(f"{KEY}.readiness.{state}"),
            "causes": [t(f"{KEY}.readiness.cause.{c}") for c in readiness.get("causes", [])],
            "policy": shown, "scope": t(f"{KEY}.readiness.scope")}


def _mx_cause(mx: Mapping[str, Any], evidence: Mapping[str, Any]) -> str:
    """The cause proper to this MX: from ``silent_mx`` (F05.08) when the verdict listed it, else from what
    the MX itself shows (an invalid name, beyond the sample, the DNS, no address)."""
    listed = next((s["cause"] for s in evidence.get("silent_mx", []) if s.get("name") == mx.get("name")), None)
    if listed:
        return str(listed)
    if not mx.get("valid", True):
        return "invalid_name"
    if mx.get("reason") == "sample":
        return "sample"
    return "dns" if mx.get("dns_errors") or mx.get("discovery_complete") is False else "no_address"


def _rows(mx: Mapping[str, Any], evidence: Mapping[str, Any], t: Text) -> list[dict[str, Any]]:
    base = {"mx": mx.get("name", ""), "preference": mx.get("preference"),
            "cname": ", ".join(mx.get("cname", []))}
    addresses = mx.get("addresses", [])
    if not addresses:
        cause = _mx_cause(mx, evidence)
        return [{**base, "address": "", "family": "", "stage": "", "codes": "", "banner": "", "tls": "",
                 "certificate": [], "result": t(f"smtp.cause.{cause}"), "kind": "unmeasured", "cause": cause}]
    return [{**base, **_address(a, t)} for a in addresses]


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
    names = ", ".join(str(n) for n in certificate.get("names", [])) or certificate.get("subject", "")
    return [t("smtp.cert.names", names=_bounded(names)),
            t("smtp.cert.issuer", issuer=_bounded(certificate.get("issuer", ""))),
            t("smtp.cert.until", date=str(certificate.get("not_after", ""))[:10])]


def _limits(evidence: Mapping[str, Any], t: Text) -> str:
    counts = evidence.get("exhaustivity")
    if not isinstance(counts, Mapping):
        return ""
    text = t("smtp.limits", mx=counts.get("mx", 0), addresses=counts.get("addresses", 0),
             sockets=counts.get("sockets", 0), dialogues=counts.get("dialogues", 0),
             spent=counts.get("budget_spent", 0), budget=BUDGET, seconds=int(evidence.get("deadline", 0)))
    return text + (" " + t("smtp.limits_reached") if evidence.get("deadline_reached") else "")
