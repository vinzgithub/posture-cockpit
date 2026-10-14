# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""No real sockets: SMTP evidence must not be overstated."""
from posture_cockpit.checks.smtp_probe import SmtpObservation
from posture_cockpit.checks.smtp_status import SmtpState, all_mx_verified, assess_smtp
from posture_cockpit.core.network import SmtpProbeStageError


def observation(**kwargs):
    return SmtpObservation("mx.example.org", ("250-mx", "250 STARTTLS"), True, **kwargs)


def test_missing_or_unreachable_is_not_evaluated():
    assert assess_smtp("mx.example.org").state is SmtpState.NOT_EVALUATED
    assert assess_smtp("mx.example.org", error=TimeoutError()).reason == "timeout"


def test_advertised_or_accepted_is_not_proof_of_tls():
    assert assess_smtp("mx.example.org", observation()).state is SmtpState.NOT_EVALUATED
    assert assess_smtp("mx.example.org", observation(starttls_accepted=True)).state is SmtpState.NOT_EVALUATED


def test_refused_and_failed_are_not_verified():
    assert assess_smtp("mx.example.org", observation(starttls_accepted=False)).state is SmtpState.STARTTLS_REJECTED
    failed = assess_smtp("mx.example.org", observation(starttls_accepted=True, tls_verified=False))
    assert failed.state is SmtpState.TLS_FAILED


def test_no_starttls_is_distinct_from_network_error():
    result = assess_smtp("mx.example.org", SmtpObservation("mx.example.org", ("250 hello",), False))
    assert result.state is SmtpState.STARTTLS_MISSING


def test_verified_requires_completed_verified_handshake():
    result = assess_smtp("mx.example.org", observation(
        starttls_accepted=True, tls_verified=True, tls_protocol="TLSv1.3",
        certificate_issuer="Example CA", certificate_days_remaining=42))
    assert result.state is SmtpState.VERIFIED
    assert result.certificate_days_remaining == 42


def test_wrong_mx_not_counted():
    assert assess_smtp("other.example.org", observation(
        starttls_accepted=True, tls_verified=True)).state is SmtpState.NOT_EVALUATED


def test_all_declared_mx_required_before_enforce_advice():
    first = assess_smtp("mx.example.org", observation(starttls_accepted=True, tls_verified=True))
    assert all_mx_verified(("mx.example.org",), (first,))
    assert not all_mx_verified(("mx.example.org", "mx2.example.org"), (first,))
    assert not all_mx_verified(("mx.example.org",), (first, first))
    assert not all_mx_verified((), ())


def test_smtp_stage_errors_are_safe_and_not_evaluated():
    for stage in ("dns", "egress", "smtp_protocol"):
        assessment = assess_smtp("mx.example.org", error=SmtpProbeStageError(stage))
        assert assessment.state is SmtpState.NOT_EVALUATED
        assert assessment.reason == "stage_" + stage
