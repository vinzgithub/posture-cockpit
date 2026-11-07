# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The verdict of mail.smtp_starttls (matrix F05) and the readiness for MTA-STS enforce (F06).

The SMTP probe (smtp_measure.py) observes; this module decides, and nothing else does. Version
0.7.0, revision 3 of the specification, §3.

:func:`decide` is the only function that gives the check a status (``ok``, ``warn``, ``fail``,
``na``, ``not_evaluated``; a test of the syntax tree refuses any other caller for this check). It
reads the observations from top to bottom and returns at the first line of matrix F05 that
applies, in the business order of §3: not applicable (F05.01, F05.02) → defects proven (FAIL,
F05.03, F05.04) → warnings proven (WARN, F05.06, F05.07) → an MX without any conclusive observation
(ERROR, F05.08) → OK on the MX tested, with notes when the measure is incomplete (F05.09) or without
(F05.10). The line is kept in the evidence (``rule``). F05.11 and F05.12 add notes to whatever line
applies; they never decide. A missing measure never hides a defect proven elsewhere, and nothing is
said of TLS without a dialogue that proves it.

What counts as proven (plan, revision 2, "Règles de classification"):

- **STARTTLS absent** (F05.03): the one stop of a *nominal* dialogue (complete 220 greeting,
  well-formed 250 reply to EHLO, keywords not masked) without the STARTTLS keyword. Masked keywords
  (``XXXXXXXA``) are an inspection on the path, never an absence (core/smtp.py stops at
  ``esmtp_altered``): ERROR.
- **Certificate refused** (F05.04, F05.06): the verifying negotiation refused the chain or the name
  (PKIX, DNS-ID in the SAN of the published MX name, RFC 8461 §4.1). Its gravity depends on the
  policy only: FAIL when a policy is in force in ``enforce`` mode (senders that apply it do not
  deliver to that server, RFC 8461 §5), WARN otherwise, a policy missing or unreadable included (R4).
- **Certificate expiring** (F05.07, D3a): verified, and its end of validity, counted from the time
  of the scan as checks/tls.py counts it, within 20 days (urgent within 10). Never "invalid".
- **No TLS version defect in 0.7.0** (F05.05, D1b): an alert or a version refused goes to F05.08.
- **No reply to STARTTLS is a defect** (D2b): 4xx, 5xx, 500/502 after announcing it, all ERROR.
- **OK without a policy** (D4a): the verdict reads the SMTP observations only; a domain without
  MTA-STS whose servers all verify is OK. The policy weighs on the readiness (F06), not on OK.
- **One conclusive address per MX gives OK** (A2b, as the HTTPS checks do): the other addresses
  of that MX, untested (no IPv6 route here, deadline, sample), are said in the notes, and the
  readiness for enforce stays unconfirmed.

:func:`readiness` gives the separate indicator F06, from the same observations and the policy,
never from the status of the check: "ready according to the measures made from this instance"
needs the whole published inbound path measured and valid, and a valid policy covering every MX.
Port 25 reached from this instance never proves that mail is delivered from the Internet.

A policy "in force in enforce mode" (F05.04, F06) is one senders apply (RFC 8461): exactly one valid
TXT record (§3.1), the policy served over HTTPS with a certificate verified and status 200 (§3.3),
its fields valid (§3.2), mode ``enforce``. Anything short of that is not in force.

Other references: RFC 3207 §4 (STARTTLS), RFC 7505 (null MX), RFC 2181 §10.3 (an MX is not an
alias), RFC 5321 §5.1.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from ..core import Effort, Outcome, Remedy, fail, na, not_evaluated, ok, warn
from ..core.network import SmtpObservation
from ..core.smtp import Attempt, Reason, Reply
from .records import MtaStsPolicy, mx_matches
from .smtp_measure import AddressProbe, MxProbe, ProbeResult
from .tls import EXPIRY_CRITICAL_DAYS, EXPIRY_WARNING_DAYS

KEY = "mail.smtp_starttls"
PERSPECTIVE = "instance"  # what was measured was measured from this instance's network (§5)


# ---------------------------------------------------------------- the MTA-STS policy, as senders see it
class PolicyState(StrEnum):
    """What the scan's reading of the MTA-STS policy is worth to a sender (RFC 8461)."""

    ENFORCE = "enforce"          # in force: senders refuse a server that does not verify
    TESTING = "testing"          # valid, reports only
    DISABLED = "none"            # valid, mode none: MTA-STS switched off
    MISSING = "missing"          # no TXT record naming the protocol
    INVALID = "invalid"          # senders ignore it: bad TXT record, untrusted certificate, faulty fields
    UNAVAILABLE = "unavailable"  # announced, but not served (no address, refused, status other than 200)
    UNREADABLE = "unreadable"    # this scan could not read it (timeout, error, the probe's deadline)


# Where mail.mta_sts's reading stopped (checks/mail.py, MtaStsReading.stage) → what it is worth.
READING_STATES = {
    "missing": PolicyState.MISSING,
    "bad_record": PolicyState.INVALID,      # §3.1: senders ignore the record
    "untrusted": PolicyState.INVALID,       # §3.3: a policy behind an untrusted certificate is ignored
    "no_address": PolicyState.UNAVAILABLE,
    "refused": PolicyState.UNAVAILABLE,
    "status": PolicyState.UNAVAILABLE,      # §3.3: only a 200 counts
}


@dataclass(frozen=True)
class PolicyView:
    """The policy as F05.04 and F06 read it, with the MX it covers (§4.1 patterns)."""

    state: PolicyState
    mode: str = ""
    mx_patterns: tuple[str, ...] = ()
    covered: tuple[str, ...] = ()
    uncovered: tuple[str, ...] = ()
    max_age: int | None = None
    detail: str = ""  # why it could not be read

    @property
    def in_force(self) -> bool:
        """Senders apply it in enforce mode: an invalid certificate stops delivery (F05.04)."""
        return self.state is PolicyState.ENFORCE

    def evidence(self) -> dict[str, Any]:
        result: dict[str, Any] = {"state": self.state.value, "mode": self.mode, "mx_patterns": list(self.mx_patterns),
                                  "covered": list(self.covered), "uncovered": list(self.uncovered),
                                  "max_age": self.max_age}
        if self.detail:
            result["detail"] = self.detail
        return result


def policy_view(stage: str, policy: MtaStsPolicy | None, mx_names: Sequence[str], *, detail: str = "") -> PolicyView:
    """What a reading of the policy stopped at ``stage`` is worth; ``stage`` "unreadable" with ``detail``
    when the reading raised or the probe's deadline came first."""
    if stage == "unreadable" or (stage == "read" and policy is None):
        return PolicyView(PolicyState.UNREADABLE, detail=detail)
    if stage != "read":
        return PolicyView(READING_STATES[stage])
    assert policy is not None
    if policy.errors:  # §3.2: a policy with a faulty field is ignored
        return PolicyView(PolicyState.INVALID, policy.mode, policy.mx, max_age=policy.max_age,
                          detail=", ".join(policy.errors))
    covered = tuple(h for h in mx_names if any(mx_matches(p, h) for p in policy.mx))
    uncovered = tuple(h for h in mx_names if h not in covered)
    state = {"enforce": PolicyState.ENFORCE, "testing": PolicyState.TESTING}.get(policy.mode, PolicyState.DISABLED)
    return PolicyView(state, policy.mode, policy.mx, covered, uncovered, policy.max_age)


# ---------------------------------------------------------------- what one address showed (facts, not verdicts)
class Seen(StrEnum):
    """What the verifying attempt on one address proved, if anything."""

    VERIFIED = "verified"                        # STARTTLS, TLS 1.2 or 1.3, certificate valid for the MX name
    STARTTLS_ABSENT = "starttls_absent"          # nominal dialogue, STARTTLS not announced
    CERTIFICATE_REFUSED = "certificate_refused"  # the chain or the name refused
    UNMEASURED = "unmeasured"                    # nothing conclusive on TLS (see unmeasured())


def seen(address: AddressProbe) -> Seen:
    attempt = _dialogue(address)
    if attempt is None:
        return Seen.UNMEASURED
    if attempt.reason is Reason.TLS_VERIFIED:
        return Seen.VERIFIED
    # core/smtp.py stops at esmtp_altered before looking for STARTTLS; the second test only guards it.
    if attempt.reason is Reason.STARTTLS_ABSENT and not attempt.altered:
        return Seen.STARTTLS_ABSENT
    if attempt.reason is Reason.CERTIFICATE_REFUSED:
        return Seen.CERTIFICATE_REFUSED
    return Seen.UNMEASURED


# Why an address, or an MX, gave nothing conclusive: one word per family of causes, for the texts.
_DIALOGUE_CAUSES = {
    Reason.BANNER_REFUSED: "smtp_refused", Reason.EHLO_REFUSED: "smtp_refused",
    Reason.ESMTP_ALTERED: "altered",
    Reason.STARTTLS_TEMPORARY: "starttls_refused", Reason.STARTTLS_POLICY_REFUSAL: "starttls_refused",
    Reason.STARTTLS_UNAVAILABLE: "starttls_refused", Reason.STARTTLS_DIALOGUE_ERROR: "starttls_refused",
    Reason.TLS_VERSION_REFUSED: "tls_version",  # D1b: never a FAIL in 0.7.0
    Reason.TLS_DIALOGUE_ERROR: "tls", Reason.TLS_HANDSHAKE_ERROR: "tls",
    Reason.MALFORMED_REPLY: "protocol", Reason.REPLY_TOO_LARGE: "protocol", Reason.UNSOLICITED_DATA: "protocol",
    Reason.CLOSED: "network", Reason.TIMEOUT: "network",
    Reason.DEADLINE: "deadline",
}
# The cause shown first when several MX gave nothing: the most specific about the server or the path.
CAUSE_ORDER = ("altered", "smtp_refused", "starttls_refused", "tls_version", "tls", "protocol", "policy",
               "no_route", "network", "dns", "no_address", "invalid_name", "deadline", "budget", "sample", "tool")


def unmeasured(address: AddressProbe) -> str:
    """The family of causes for which ``address`` gave nothing conclusive (one of CAUSE_ORDER)."""
    observation = address.verification
    if observation is None:
        return {"sample": "sample", "deadline": "deadline"}.get(address.reason, "tool")
    if observation.dialogue is not None:
        return _DIALOGUE_CAUSES.get(observation.dialogue.reason, "tool")
    if observation.cause == "network":
        return "no_route" if observation.reason == "no_route" else "network"
    if observation.cause == "budget":
        return "deadline" if observation.reason == "deadline" else "budget"
    # policy: the anti-SSRF rule, or an address outside this scan's DNS (S02) — a measure not made.
    return {"policy": "policy", "invalid_mx_name": "invalid_name"}.get(observation.cause, "tool")


def _mx_cause(mx: MxProbe) -> str:
    if not mx.valid:
        return "invalid_name"
    if not mx.addresses:
        return "dns" if mx.dns_errors or not mx.discovery_complete else "no_address"
    return min((unmeasured(a) for a in mx.addresses), key=CAUSE_ORDER.index)


def _dialogue(address: AddressProbe) -> Attempt | None:
    observation = address.verification
    return None if observation is None else observation.dialogue


def _expiring(addresses: list[AddressProbe], now: datetime) -> list[tuple[int, AddressProbe]]:
    """The verified addresses whose certificate ends within EXPIRY_WARNING_DAYS, soonest first.

    Days are counted as checks/tls.py counts them, from the time of the scan, never the wall clock (R2)."""
    result = []
    for address in addresses:
        attempt = _dialogue(address)
        if seen(address) is Seen.VERIFIED and attempt is not None and attempt.certificate is not None:
            days = (attempt.certificate.not_after - now).days
            if days <= EXPIRY_WARNING_DAYS:
                result.append((days, address))
    return sorted(result, key=lambda pair: pair[0])


# ---------------------------------------------------------------- the verdict: matrix F05, top to bottom
def decide(probe: ProbeResult | None, policy: PolicyView | None, now: datetime) -> Outcome:
    """The verdict of mail.smtp_starttls. ``probe`` is None when the probe is off (nothing was asked);
    ``policy`` is None when no policy was read (probe off, or no MX)."""
    ready = readiness(probe, policy, now)

    # F05.01 — the probe is off on this instance (A1a): not applicable, and nothing was measured. An
    # internal perimeter never gets here (the engine gives NA to checks registered internal=False);
    # the second test only guards it.
    if probe is None or not probe.enabled:
        return na(f"{KEY}.probe_off", _evidence(None, "F05.01", ready, []))
    if probe.internal:
        return na(f"{KEY}.internal", _evidence(probe, "F05.01", ready, []))

    # F05.02 — the domain receives no mail: no MX, or a valid null MX alone (RFC 7505). A failed MX
    # question is not "no MX", and an MX with an invalid name is not a null MX (P3): both go on.
    if not probe.mx and not probe.discovery_error:
        return na("mail.no_inbound", _evidence(probe, "F05.02", ready, []))

    notes = _notes(probe)  # F05.11 and F05.12, and the coverage notes of A2b: whatever line applies
    addresses = probe.addresses
    absent = [a for a in addresses if seen(a) is Seen.STARTTLS_ABSENT]
    refused = [a for a in addresses if seen(a) is Seen.CERTIFICATE_REFUSED]

    # F05.03 — STARTTLS not announced at the end of a nominal dialogue: the server receives in clear.
    if absent:
        return fail(f"{KEY}.starttls_absent", _remedy("starttls"), _evidence(probe, "F05.03", ready, notes),
                    **_where(absent))

    # F05.04 — a certificate refused while a policy is in force in enforce mode: senders that apply
    # it do not deliver to that server (RFC 8461 §5).
    if refused and policy is not None and policy.in_force:
        return fail(f"{KEY}.certificate_enforce", _remedy("certificate"),
                    _evidence(probe, "F05.04", ready, notes), **_where(refused))

    # F05.05 — a TLS version defect would be a FAIL here. D1b: in 0.7.0 no observation proves it well
    # enough (no TLS 1.0/1.1 reconnection, an alert alone may come from the path); such observations
    # are not conclusive and go to F05.08. No branch until a sufficient proof is defined.

    # F05.06 — a certificate refused without a policy in force in enforce mode (missing, testing,
    # none, unreadable: R4): delivery stays opportunistic, enforce cannot be switched on safely.
    if refused:
        return warn(f"{KEY}.certificate_invalid", _remedy("certificate"),
                    _evidence(probe, "F05.06", ready, notes), **_where(refused))

    # F05.07 — a valid certificate that expires within 20 days (D3a), urgent within 10 days: the
    # renewal probably failed. Still valid: never "invalid", never FAIL.
    expiring = _expiring(addresses, now)
    if expiring:
        days = expiring[0][0]
        urgent = days <= EXPIRY_CRITICAL_DAYS
        return warn(f"{KEY}.certificate_expiring" + ("_urgent" if urgent else ""), _remedy("expiry"),
                    _evidence(probe, "F05.07", ready, notes),
                    **_where([a for _, a in expiring]), days=max(days, 0))

    # F05.08 — no defect proven, and at least one MX gave nothing conclusive (or the MX question
    # failed): not evaluated, with everything observed kept. Network, DNS, port 25, no route, delays,
    # budget, deadline, SMTP refusals (421/554, EHLO), masked keywords, STARTTLS refused, TLS not
    # concluded (D1b, D2b), the anti-SSRF rule: measures not made, never defects of the target.
    silent = [m for m in _retained(probe) if not any(seen(a) is Seen.VERIFIED for a in m.addresses)]
    if probe.discovery_error or silent:
        cause = "dns" if probe.discovery_error else min(map(_mx_cause, silent), key=CAUSE_ORDER.index)
        host = silent[0].name if silent else ""
        return not_evaluated(f"{KEY}.unmeasured.{cause}", _evidence(probe, "F05.08", ready, notes),
                             host=host, n=len(silent))

    # F05.09 — every MX kept has a verified address, nothing is proven wrong, but some published
    # address, MX or answer was not measured (A2b): OK, and the notes say what is missing.
    if not complete(probe):
        return ok(f"{KEY}.ok_partial", _evidence(probe, "F05.09", ready, notes), n=len(_retained(probe)))

    # F05.10 — every published MX and address measured and valid (D4a: with or without a policy).
    return ok(f"{KEY}.ok", _evidence(probe, "F05.10", ready, notes), n=len(_retained(probe)))


def _retained(probe: ProbeResult) -> list[MxProbe]:
    """The MX the probe kept (MAX_MX at most): those beyond the sample are notes (F05.11), not silences."""
    return [m for m in probe.mx if m.reason != "sample"]


def complete(probe: ProbeResult) -> bool:
    """The whole published inbound path was measured and verified: the MX question answered, no MX
    beyond the sample, every MX resolved without error, every one of its addresses verified."""
    return (not probe.discovery_error and bool(probe.mx)
            and all(m.valid and m.reason != "sample" and m.discovery_complete and not m.dns_errors and m.addresses
                    and all(seen(a) is Seen.VERIFIED for a in m.addresses) for m in probe.mx))


def _where(addresses: list[AddressProbe]) -> dict[str, str | int]:
    first = addresses[0]
    return {"host": first.mx_name, "address": first.address, "n": len(addresses)}


def _remedy(kind: str) -> Remedy:
    # expect=None: once fixed, the verdict still depends on the other MX and addresses, which this
    # finding does not know; the plan must not promise a status (no projected gain).
    minutes = {"starttls": 60, "certificate": 60, "expiry": 30}[kind]
    return Remedy(minutes, Effort.DELEGATE, message=f"{KEY}.{kind}_message", expect=None)


# ---------------------------------------------------------------- F06: readiness for MTA-STS enforce
class Readiness(StrEnum):
    READY = "ready"                    # "Prêt selon les mesures réalisées depuis cette instance" (testing in force)
    COMPATIBLE = "compatible"          # "Compatible avec la politique enforce en vigueur" (R7)
    TO_FIX = "to_fix"                  # a proven defect prevents enforce
    UNCONFIRMED = "unconfirmed"        # "Impossible à confirmer"
    NOT_APPLICABLE = "not_applicable"  # the domain receives no mail


def readiness(probe: ProbeResult | None, policy: PolicyView | None, now: datetime) -> dict[str, Any]:
    """Indicator F06, separate from the verdict: never "ready" because the check is OK.

    In order: probe off or internal → unconfirmed; no inbound mail → not applicable; a proven defect
    (STARTTLS absent, certificate refused, an MX the valid policy does not cover) → to fix; then
    unconfirmed for every limit of the policy or of the measure (all are listed); only a complete,
    verified measure with a valid policy covering every MX, and no MX that is an alias, is ready
    (policy in testing) or compatible (policy in force in enforce)."""
    policy_evidence = None if policy is None else policy.evidence()
    if probe is None or not probe.enabled or probe.internal:
        cause = "internal" if probe is not None and probe.internal else "probe_off"
        return {"state": Readiness.UNCONFIRMED.value, "causes": [cause], "policy": policy_evidence}
    if not probe.mx and not probe.discovery_error:
        return {"state": Readiness.NOT_APPLICABLE.value, "causes": [], "policy": policy_evidence}

    defects = []
    if any(seen(a) is Seen.STARTTLS_ABSENT for a in probe.addresses):
        defects.append("starttls_absent")
    if any(seen(a) is Seen.CERTIFICATE_REFUSED for a in probe.addresses):
        defects.append("certificate_invalid")
    if policy is not None and policy.state in (PolicyState.ENFORCE, PolicyState.TESTING) and policy.uncovered:
        defects.append("mx_uncovered")
    if defects:
        return {"state": Readiness.TO_FIX.value, "causes": defects, "policy": policy_evidence}

    causes = []
    state = PolicyState.UNREADABLE if policy is None else policy.state
    if state not in (PolicyState.ENFORCE, PolicyState.TESTING):
        causes.append({PolicyState.MISSING: "policy_missing", PolicyState.DISABLED: "policy_disabled",
                       PolicyState.INVALID: "policy_invalid", PolicyState.UNAVAILABLE: "policy_unavailable"}
                      .get(state, "policy_unreadable"))
    if not complete(probe):
        causes.append("incomplete")
    if any(m.cname for m in probe.mx):
        causes.append("mx_cname")  # RFC 2181 §10.3: to look into before enforce
    if causes:
        return {"state": Readiness.UNCONFIRMED.value, "causes": causes, "policy": policy_evidence}
    done = Readiness.COMPATIBLE if state is PolicyState.ENFORCE else Readiness.READY
    return {"state": done.value, "causes": [], "policy": policy_evidence}


# ---------------------------------------------------------------- notes (F05.11, F05.12, A2b) and evidence
def _notes(probe: ProbeResult) -> list[dict[str, Any]]:
    """What the verdict does not say by itself: limits of the measure and anomalies of publication."""
    notes: list[dict[str, Any]] = []
    counts = probe.exhaustivity()
    if not complete(probe):  # A2b: an OK on some addresses says nothing of the others
        verified = sum(seen(a) is Seen.VERIFIED for a in probe.addresses)
        notes.append({"key": f"{KEY}.note.coverage", "params": {
            "mx": counts["mx"], "addresses": counts["addresses"], "verified": verified}})
    untested: dict[str, list[str]] = {}
    for address in probe.addresses:
        if seen(address) is Seen.UNMEASURED:
            untested.setdefault(unmeasured(address), []).append(address.address)
    for cause in sorted(untested, key=CAUSE_ORDER.index):
        notes.append({"key": f"{KEY}.note.untested.{cause}", "params": {
            "addresses": ", ".join(untested[cause]), "n": len(untested[cause])}})
    beyond = [m.name for m in probe.mx if m.reason == "sample"]
    if beyond:  # F05.11: never ready on a sample
        notes.append({"key": f"{KEY}.note.sample", "params": {"hosts": ", ".join(beyond), "n": len(beyond)}})
    incomplete = [m.name for m in probe.mx if m.valid and m.reason != "sample"
                  and (m.dns_errors or not m.discovery_complete)]
    if incomplete:  # F05.11
        notes.append({"key": f"{KEY}.note.dns_incomplete", "params": {"hosts": ", ".join(incomplete)}})
    for mx in probe.mx:
        if mx.cname:  # F05.12: a publication anomaly, never a TLS failure; the MX name stays the TLS name
            notes.append({"key": f"{KEY}.note.cname", "params": {"host": mx.name, "target": ", ".join(mx.cname)}})
    for address in probe.addresses:
        if seen(address) is Seen.CERTIFICATE_REFUSED and address.reading is None and not address.reading_interrupted:
            # F03: no reading of the certificate (budget or one already made for this MX): what the
            # refusal said is all there is; nothing else about the certificate is invented.
            notes.append({"key": f"{KEY}.note.verify_only", "params": {"address": address.address}})
        if address.reading_interrupted:
            notes.append({"key": f"{KEY}.note.reading_interrupted", "params": {"address": address.address}})
    if probe.deadline_reached:
        notes.append({"key": f"{KEY}.note.deadline", "params": {"seconds": int(probe.deadline)}})
    return notes


EVIDENCE_MX = 16  # MX kept in the evidence (8 measured at most, the rest named): bounds the stored JSON


def _evidence(probe: ProbeResult | None, rule: str, ready: dict[str, Any],
              notes: list[dict[str, Any]]) -> dict[str, Any]:
    """The structured proof (§5): bounded, without a secret, the same keys on every line of F05. The
    policy as it was evaluated is in ``readiness`` (F06), with the state and its causes."""
    evidence: dict[str, Any] = {"rule": rule, "probe_enabled": probe is not None and probe.enabled,
                                "perspective": PERSPECTIVE, "readiness": ready}
    if probe is not None:
        evidence.update({
            "deadline": probe.deadline, "deadline_reached": probe.deadline_reached,
            "exhaustivity": probe.exhaustivity(), "null_mx": probe.null_mx,
            "mx": [_mx(m) for m in probe.mx[:EVIDENCE_MX]]})
        if probe.discovery_error:
            evidence["discovery_error"] = probe.discovery_error
    if notes:
        evidence["notes"] = notes
    return evidence


def _mx(mx: MxProbe) -> dict[str, Any]:
    result: dict[str, Any] = {"name": mx.name, "preference": mx.preference, "valid": mx.valid,
                              "addresses": [_address(a) for a in mx.addresses]}
    for key, value in (("cname", list(mx.cname)), ("dns_errors", mx.dns_errors), ("cause", mx.cause),
                       ("reason", mx.reason)):
        if value:
            result[key] = value
    if mx.valid and mx.reason != "sample":
        result["discovery_complete"] = mx.discovery_complete
    return result


def _address(address: AddressProbe) -> dict[str, Any]:
    result: dict[str, Any] = {"address": address.address, "family": address.family, "seen": seen(address).value,
                              "observations": [_observation(o) for o in address.observations]}
    if seen(address) is Seen.UNMEASURED:
        result["unmeasured"] = unmeasured(address)
    for key, value in (("cause", address.cause), ("reason", address.reason), ("interrupted", address.interrupted)):
        if value:
            result[key] = value
    return result


def _observation(observation: SmtpObservation) -> dict[str, Any]:
    result: dict[str, Any] = {"purpose": str(observation.purpose), "consumed": observation.consumed,
                              "socket": observation.socket}
    if observation.dialogue is None:
        result.update(cause=observation.cause, reason=observation.reason, detail=observation.detail)
        return result
    a = observation.dialogue
    dialogue: dict[str, Any] = {"stage": a.stage.value, "reason": a.reason.value}
    for key, reply in (("banner", a.banner), ("ehlo", a.ehlo), ("starttls", a.starttls)):
        if reply is not None:
            dialogue[key] = _reply(reply)
    optional: dict[str, Any] = {
        "capabilities": list(a.capabilities), "altered": list(a.altered), "tls_version": a.tls_version,
        "tls_cipher": a.tls_cipher, "verify_code": a.verify_code, "verify_message": a.verify_message,
        "detail": a.detail, "partial": list(a.partial), "quit_reply": a.quit_reply}
    dialogue.update({k: v for k, v in optional.items() if v not in (None, "", [])})
    if a.certificate is not None:
        c = a.certificate
        dialogue["certificate"] = {
            "subject": c.subject, "names": list(c.names), "issuer": c.issuer,
            "not_before": c.not_before.isoformat(), "not_after": c.not_after.isoformat(),
            "key_type": c.key_type, "key_bits": c.key_bits,
            # Read without verification (a diagnostic reading) or verified: only the latter is trusted.
            "verified": observation.purpose == "verify" and a.reason is Reason.TLS_VERIFIED}
    result["dialogue"] = dialogue
    return result


def _reply(reply: Reply) -> dict[str, Any]:
    result: dict[str, Any] = {"code": reply.code, "text": list(reply.text), "lines": reply.lines}
    if reply.enhanced:
        result["enhanced"] = reply.enhanced
    return result
