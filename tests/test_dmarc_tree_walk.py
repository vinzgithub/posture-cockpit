# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""DMARC DNS Tree Walk and RFC 9989 policy markers."""

from posture_cockpit.checks.records import parse_dmarc
from posture_cockpit.core.model import Status
from worlds import changed, healthy, run


def _check(domain, overrides):
    return run(changed(healthy(), dns=overrides), "mail.dmarc", domain=domain)["mail.dmarc"]


def test_parser_supports_psd_np_and_testing():
    value = parse_dmarc("v=DMARC1; p=reject; sp=quarantine; np=none; psd=n; t=y")
    assert value.starts_right
    assert value.psd == "n"
    assert value.non_existent_policy == "none"
    assert value.testing is True


def test_exact_record_wins_over_parent():
    f = _check("sub.example.org", {
        "_dmarc.sub.example.org TXT": ["v=DMARC1; p=none"],
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; psd=n"],
    })
    assert f.status is Status.WARN
    assert f.outcome.evidence["found_at"] == "_dmarc.sub.example.org"


def test_psd_y_stops_the_walk_before_higher_ancestors():
    f = _check("x.site.example.org", {
        "_dmarc.x.site.example.org TXT": None,
        "_dmarc.site.example.org TXT": ["v=DMARC1; p=none; psd=y"],
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; psd=n"],
    })
    assert f.status is Status.WARN
    assert f.outcome.evidence["found_at"] == "_dmarc.site.example.org"


def test_psd_policy_applies_when_no_organization_record():
    f = _check("agency.gov.fr", {
        "_dmarc.agency.gov.fr TXT": None,
        "_dmarc.gov.fr TXT": ["v=DMARC1; p=reject; psd=y"],
    })
    assert f.status is Status.OK
    assert f.outcome.evidence["found_at"] == "_dmarc.gov.fr"


def test_tld_psd_policy_can_be_inherited():
    f = _check("example.org", {
        "_dmarc.example.org TXT": None,
        "_dmarc.org TXT": ["v=DMARC1; p=reject; psd=y"],
    })
    assert f.status is Status.OK
    assert f.outcome.evidence["found_at"] == "_dmarc.org"


def test_removed_pct_tag_is_reported_as_syntax_issue():
    f = _check("example.org", {
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; pct=50"],
    })
    assert f.status is Status.WARN
    assert f.outcome.summary == "mail.dmarc.syntax"


def test_testing_mode_downgrades_enforcement():
    f = _check("example.org", {"_dmarc.example.org TXT": ["v=DMARC1; p=reject; t=y"]})
    assert f.status is Status.WARN
    assert f.outcome.summary == "mail.dmarc.testing"
    assert f.outcome.params["effective"] == "quarantine"


def test_non_existent_domain_uses_np():
    f = _check("missing.example.org", {
        "_dmarc.missing.example.org TXT": None,
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; sp=reject; np=none; psd=n"],
        "missing.example.org A": None,
    })
    assert f.status is Status.WARN
    assert f.outcome.summary == "mail.dmarc.monitoring_inherited"
    assert f.outcome.evidence["existence"] == "nxdomain"


def test_existing_domain_uses_sp_not_np():
    f = _check("active.example.org", {
        "_dmarc.active.example.org TXT": None,
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; sp=reject; np=none; psd=n"],
        "active.example.org A": [],
    })
    assert f.status is Status.OK
    assert f.outcome.evidence["existence"] == "existing"
