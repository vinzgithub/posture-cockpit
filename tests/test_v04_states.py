# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Version 0.4: the blocked state, the HTTPS family of checks and the verdicts they declare."""

from __future__ import annotations

import pytest

from posture_cockpit.core import Extension, Finding, Outcome, Role, Signal, Status, blocked, ok
from posture_cockpit.core.registry import Registry
from posture_cockpit.core.scoring import HTTPS
from worlds import (
    healthy,
    http_only_with_redirect_elsewhere,
    redirect_elsewhere_https_refused,
    run,
    with_certificate,
)

HTTPS_CHECKS = {
    "web.https_redirect": (Role.ROOT, {Status.OK, Status.FAIL}),
    "tls.certificate": (Role.DEPENDENT, {Status.OK, Status.WARN, Status.FAIL}),
    "tls.protocols": (Role.DEPENDENT, {Status.OK, Status.WARN, Status.FAIL}),
    "tls.key": (Role.DEPENDENT, {Status.OK, Status.FAIL}),
    **{f"web.{name}": (Role.DEPENDENT, {Status.OK, Status.WARN})
       for name in ("hsts", "csp", "framing", "nosniff", "referrer", "server_banner", "security_txt")},
}


def test_a_blocked_check_counts_only_in_the_diagnostic_coverage():
    assert not Status.BLOCKED.scored
    assert not Status.BLOCKED.applicable
    assert Status.BLOCKED.diagnostic
    assert all(s.diagnostic == (s.applicable or s is Status.BLOCKED) for s in Status)


def test_the_https_family_is_declared_with_its_verdicts():
    registry = Registry.discover()
    family = {c.id: c for c in registry.checks() if c.family == HTTPS}
    assert set(family) == set(HTTPS_CHECKS)
    for check_id, (role, verdicts) in HTTPS_CHECKS.items():
        assert family[check_id].role is role and family[check_id].verdicts == frozenset(verdicts), check_id
    others = [c for c in registry.checks() if c.family is None]
    assert others and all(c.role is None and c.verdicts is None for c in others)


def test_the_floors_of_the_dependents_add_up_to_20_points_out_of_37():
    dependents = [c for c in Registry.discover().checks() if c.family == HTTPS and c.role is Role.DEPENDENT]
    assert sum(c.weight for c in dependents) == 37
    assert sum(c.weight * c.floor for c in dependents) == 20  # type: ignore[operator]
    assert {c.id: c.floor for c in dependents if c.floor != 0.5} == {"tls.key": 1.0}


@pytest.mark.parametrize("arguments, message", [
    ({"requires": "https"}, "must declare its verdicts"),
    ({"provides": "https"}, "must declare its verdicts"),
    ({"requires": "https", "verdicts": {Status.FAIL}}, "not critical"),
    ({"provides": "https", "requires": "https", "verdicts": {Status.OK}}, "cannot both"),
    ({"verdicts": {Status.OK, Status.NA}}, "OK, WARN and FAIL"),
    ({"verdicts": set()}, "OK, WARN and FAIL"),
])
def test_a_family_member_must_declare_usable_verdicts(arguments, message):
    with pytest.raises(ValueError, match=message):
        Extension("lab", name="Lab", version="1").check("x", category="web", weight=1, **arguments)


@pytest.mark.parametrize("world", [healthy, http_only_with_redirect_elsewhere, redirect_elsewhere_https_refused,
                                   lambda: with_certificate(expires_in_days=-3),
                                   lambda: with_certificate(expires_in_days=5),
                                   lambda: with_certificate(expires_in_days=15),
                                   lambda: with_certificate(trusted=False, problem="self-signed certificate"),
                                   lambda: with_certificate(key_type="RSA", key_bits=1024)])
def test_a_check_never_gives_a_verdict_it_did_not_declare(world):
    """The caps rest on the declared verdicts (hypothesis H6): a check must stay within them."""
    registry = Registry.discover()
    for finding in run(world()).values():
        check = registry.get(finding.check_id)
        assert check is not None
        if check.verdicts is not None and finding.status.scored:
            assert finding.status in check.verdicts, (finding.check_id, finding.status)


def test_findings_carry_their_place_in_the_family_as_declared():
    findings = run(healthy())
    assert (findings["web.https_redirect"].family, findings["web.https_redirect"].role) == (HTTPS, Role.ROOT)
    assert findings["tls.key"].role is Role.DEPENDENT and findings["tls.key"].floor == 1.0
    assert findings["web.hsts"].floor == 0.5
    assert findings["mail.dmarc"].family is None and findings["mail.dmarc"].floor is None


def test_a_finding_without_version_0_4_data_keeps_the_stored_shape_of_0_3():
    finding = Finding("mail.dmarc", "mail", 10, ok("mail.dmarc.enforced", {"record": "v=DMARC1"}, policy="reject"))
    assert set(finding.outcome_json()) == {"summary", "params", "evidence"}


def test_signals_and_family_survive_storage():
    outcome = Outcome(Status.FAIL, "web.https_redirect.https_unavailable",
                      signals=frozenset({Signal.HTTPS_UNDETERMINED}))
    finding = Finding("web.https_redirect", "web", 8, outcome, HTTPS, Role.ROOT, 1.0)
    data = finding.outcome_json()
    assert data["signals"] == ["https.undetermined"]
    assert data["family"] == {"name": "https", "role": "root", "floor": 1.0}
    back = Finding.from_stored("web.https_redirect", "web", 8, "fail", data)
    assert back == finding

    stopped = Finding("tls.key", "tls", 3, blocked("check.blocked", {"blocked_by": "web.https_redirect"}),
                      HTTPS, Role.DEPENDENT, 1.0)
    assert Finding.from_stored("tls.key", "tls", 3, "blocked", stopped.outcome_json()) == stopped


def test_a_finding_stored_by_0_3_has_no_signal_and_no_family():
    data = {"summary": "tls.certificate.expired", "params": {"days": 0}, "evidence": {}}
    finding = Finding.from_stored("tls.certificate", "tls", 10, "fail", data)
    assert finding.outcome.signals == frozenset() and finding.family is None and finding.role is None
