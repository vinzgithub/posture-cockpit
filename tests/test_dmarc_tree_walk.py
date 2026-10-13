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


def test_psd_n_is_preferred_to_nearer_psd_y():
    f = _check("x.site.example.org", {
        "_dmarc.x.site.example.org TXT": None,
        "_dmarc.site.example.org TXT": ["v=DMARC1; p=none; psd=y"],
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; psd=n"],
    })
    assert f.status is Status.OK
    assert f.outcome.evidence["found_at"] == "_dmarc.example.org"


def test_psd_policy_applies_when_no_organization_record():
    f = _check("agency.gov.fr", {
        "_dmarc.agency.gov.fr TXT": None,
        "_dmarc.gov.fr TXT": ["v=DMARC1; p=reject; psd=y"],
    })
    assert f.status is Status.OK
    assert f.outcome.evidence["found_at"] == "_dmarc.gov.fr"


def test_does_not_query_root_tld_policy():
    f = _check("example.org", {
        "_dmarc.example.org TXT": None,
        "_dmarc.org TXT": ["v=DMARC1; p=reject; psd=y"],
    })
    assert f.status is Status.FAIL


def test_removed_pct_tag_is_reported_as_syntax_issue():
    f = _check("example.org", {
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; pct=50"],
    })
    assert f.status is Status.WARN
    assert f.outcome.summary == "mail.dmarc.syntax"
