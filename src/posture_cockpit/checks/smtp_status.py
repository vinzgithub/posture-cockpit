# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Conservative, score-independent interpretation of SMTP observations.

This module has no network access and never turns missing evidence into an OK
finding. The UI and report can consume these normalized states in a later step.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .smtp_probe import SmtpObservation


class SmtpState(StrEnum):
    VERIFIED = "verified"
    TLS_FAILED = "tls_failed"
    STARTTLS_REJECTED = "starttls_rejected"
    STARTTLS_MISSING = "starttls_missing"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True)
class SmtpAssessment:
    mx: str
    state: SmtpState
    reason: str
    tls_protocol: str = ""
    certificate_issuer: str = ""
    certificate_days_remaining: int | None = None


def assess_smtp(mx: str, observation: SmtpObservation | None = None,
                *, error: Exception | None = None) -> SmtpAssessment:
    """Summarize evidence without claiming TLS validity from EHLO/SMTP 220 alone.

    Only a completed, verified TLS handshake earns VERIFIED. An unreachable or
    unprobed MX is NOT_EVALUATED, never STARTTLS_MISSING or VERIFIED.
    """
    if observation is None:
        reason = "not_probed"
        if isinstance(error, TimeoutError):
            reason = "timeout"
        elif isinstance(error, ConnectionRefusedError):
            reason = "connection_refused"
        elif isinstance(error, OSError):
            reason = "connection_failed"
        elif error is not None:
            reason = "probe_failed"
        return SmtpAssessment(mx, SmtpState.NOT_EVALUATED, reason)
    if observation.mx.lower().rstrip(".") != mx.lower().rstrip("."):
        return SmtpAssessment(mx, SmtpState.NOT_EVALUATED, "mx_mismatch")
    if not observation.starttls_advertised:
        return SmtpAssessment(mx, SmtpState.STARTTLS_MISSING, "not_advertised")
    if observation.starttls_accepted is False:
        return SmtpAssessment(mx, SmtpState.STARTTLS_REJECTED, "smtp_refused")
    if observation.tls_verified is False:
        return SmtpAssessment(mx, SmtpState.TLS_FAILED, "tls_verification_failed")
    if observation.tls_verified is True and observation.starttls_accepted is True:
        return SmtpAssessment(
            mx, SmtpState.VERIFIED, "tls_verified",
            tls_protocol=observation.tls_protocol,
            certificate_issuer=observation.certificate_issuer,
            certificate_days_remaining=observation.certificate_days_remaining,
        )
    return SmtpAssessment(mx, SmtpState.NOT_EVALUATED, "tls_not_verified")


def all_mx_verified(expected_mx: tuple[str, ...],
                    assessments: tuple[SmtpAssessment, ...]) -> bool:
    """Fail closed when any declared MX is missing, duplicated or not verified."""
    expected = [mx.lower().rstrip(".") for mx in expected_mx]
    actual = [item.mx.lower().rstrip(".") for item in assessments]
    return bool(expected) and len(expected) == len(set(expected)) and sorted(expected) == sorted(actual) and all(
        item.state is SmtpState.VERIFIED for item in assessments
    )
