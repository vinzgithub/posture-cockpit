# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pure, conservative interpretation of the action actually proposed by a Remedy.

Historical JSON has no expectation. Known actions are adapted in memory only;
unknown historical actions never acquire an automatic OK transition.
"""
from __future__ import annotations

from dataclasses import replace

from .model import Finding, Status


def _dmarc_record_status(text: str) -> Status | None:
    from ..checks.records import parse_dmarc

    record = parse_dmarc(text)
    if not record.starts_right or record.policy not in ("none", "quarantine", "reject"):
        return None
    if record.policy == "none":
        return Status.WARN
    if record.errors or record.testing or record.pct < 100 or record.subdomain_policy == "none":
        return Status.WARN
    return Status.OK


def _known_expectation(finding: Finding) -> tuple[bool, Status | None]:
    """(known action type, expected first-step status). No I/O or observation mutation."""
    remedy = finding.outcome.remedy
    assert remedy is not None
    key = finding.outcome.summary
    if finding.check_id == "mail.dmarc" and key.startswith("mail.dmarc."):
        kind = key.removeprefix("mail.dmarc.")
        additions = [c.value for c in remedy.dns if c.action == "add" and c.rtype == "TXT"]
        if additions:
            return True, _dmarc_record_status(additions[0]) if len(additions) == 1 else None
        if kind in ("missing", "malformed", "monitoring_inherited", "monitoring_no_reports"):
            return True, Status.WARN
        if kind in ("testing", "partial", "partial_reject"):
            from ..checks.records import parse_dmarc, tags

            records = finding.outcome.evidence.get("records", ())
            if not isinstance(records, (list, tuple)) or len(records) != 1 or not isinstance(records[0], str):
                return True, None
            # An inherited policy's effective sp/np cannot be inferred from p alone.
            if finding.outcome.params.get("policy") != parse_dmarc(records[0]).policy:
                return True, None
            remove = "t" if kind == "testing" else "pct"
            proposed = "; ".join(f"{k}={v}" for k, v in tags(records[0]) if k != remove)
            return True, _dmarc_record_status(proposed)
        # Alternatives, diagnostic advice, or a record to be chosen by the operator.
        return True, None
    if finding.check_id == "mail.mx" and key in {"mail.mx.null_mixed", "mail.mx.address", "mail.mx.unresolved"}:
        return True, Status.INFO
    if finding.check_id == "mail.mta_sts" and key.startswith("mail.mta_sts."):
        if remedy.message == "mail.mta_sts.message":
            return True, Status.WARN  # deployment starts in testing, never enforce implicitly
        if key.endswith(".mx_mismatch"):
            evidence = finding.outcome.evidence
            if evidence.get("mode") == "testing":
                return True, Status.WARN
            age = evidence.get("max_age")
            if type(age) is not int:
                return True, None
            return True, Status.WARN if age < 86400 else Status.OK
        if key == "mail.mta_sts.testing":
            age = finding.outcome.evidence.get("max_age")
            if type(age) is not int:
                return True, None
            return True, Status.WARN if age < 86400 else Status.OK
        if key == "mail.mta_sts.short_max_age":
            return True, Status.OK
        return True, None
    if finding.check_id == "web.csp" and remedy.message == "web.csp.message":
        return True, Status.WARN  # Report-Only does not enforce a policy
    if finding.check_id == "web.https_redirect":
        if remedy.message in ("web.https_redirect.verify.message", "web.https_redirect.refused.message"):
            return True, None  # verification only, or restore/remove-address alternatives
        if remedy.message in {"web.https_redirect.message", "web.https_redirect.external.message",
                              "web.https_redirect.restore.message", "web.https_redirect.obsolete.message"}:
            return True, Status.OK
    if key == "dns.dnssec.broken":
        return True, None  # republish keys (OK) or remove DS (WARN): no choice made
    if finding.check_id == "mail.spf":
        if key in {"mail.spf.multiple", "mail.spf.syntax", "mail.spf.broken_include", "mail.spf.too_many_lookups"}:
            return True, None  # record/terms to retain depend on an operator choice
        if key in {"mail.spf.pass_all", "mail.spf.neutral", "mail.spf.no_all"}:
            from ..checks.records import parse_spf

            records = finding.outcome.evidence.get("records", ())
            if not isinstance(records, (list, tuple)) or len(records) != 1 or not isinstance(records[0], str):
                return True, None
            return True, Status.WARN if parse_spf(records[0]).uses_ptr else Status.OK
    if finding.check_id == "tls.protocols" and key == "tls.protocols.obsolete":
        support = finding.outcome.evidence.get("accepted")
        if not isinstance(support, dict) or not support or any(
            not isinstance(answers, dict) for answers in support.values()
        ):
            return True, None
        # Disabling the last protocols may remove HTTPS entirely on an address.
        if any(a.get("TLSv1.2") is False and a.get("TLSv1.3") is False for a in support.values()):
            return True, None
        if all(a.get("TLSv1.3") is True for a in support.values()):
            return True, Status.OK
        if any(a.get("TLSv1.3") is False for a in support.values()):
            return True, Status.WARN
        return True, None
    ordinary = {
        "mail.spf": {"missing", "ptr"},
        "mail.dkim": {"weak_key", "unreadable", "short_key"},
        "mail.tls_rpt": {"missing", "invalid"},
        "tls.certificate": {"expired", "untrusted", "expires_soon", "expires"},
        "tls.protocols": {"no_tls13"},
        "tls.key": {"weak"},
        "web.hsts": {"missing", "invalid", "disabled", "short"},
        "web.framing": {"missing", "permissive", "obsolete"},
        "web.nosniff": {"missing"},
        "web.referrer": {"missing", "unsafe"},
        "web.server_banner": {"version"},
        "web.security_txt": {"missing", "invalid", "expired"},
        "dns.nameservers": {"single"},
        "dns.dnssec": {"off"},
        "dns.caa": {"missing", "excludes_current"},
    }
    if key in {f"{finding.check_id}.{kind}" for kind in ordinary.get(finding.check_id, ())}:
        return True, Status.OK
    return False, None


def expected_status(finding: Finding) -> Status | None:
    """Current built-in actions prevail; explicit extension expectations survive storage."""
    remedy = finding.outcome.remedy
    if remedy is None:
        return None
    known, status = _known_expectation(finding)
    return status if known else remedy.expect


def with_expectation(finding: Finding, *, historical: bool = False) -> Finding:
    remedy = finding.outcome.remedy
    if remedy is None:
        return finding
    known, status = _known_expectation(finding)
    expected = status if known else None if historical else remedy.expect
    return replace(finding, outcome=replace(finding.outcome, remedy=replace(remedy, expect=expected)))


def historical_remedy(finding: Finding) -> Finding:
    return with_expectation(finding, historical=True)
