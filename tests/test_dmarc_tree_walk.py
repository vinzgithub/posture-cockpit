# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""DMARC DNS Tree Walk and RFC 9989 policy markers."""

import asyncio
from types import SimpleNamespace

from posture_cockpit.checks.mail import _dmarc_records
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


def test_removed_pct_tag_still_counts_for_rfc_7489_receivers():
    # RFC 9989 removed pct; receivers that still follow RFC 7489 apply it to half of the failing mail.
    f = _check("example.org", {
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; pct=50"],
    })
    assert f.status is Status.WARN
    assert f.outcome.summary == "mail.dmarc.partial_reject"
    assert f.outcome.params["pct"] == 50


def test_inherited_pct_is_reported_too():
    f = _check("shop.example.org", {
        "_dmarc.shop.example.org TXT": [],
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; pct=0"],
        "shop.example.org A": ["192.0.2.10"],
    })
    assert (f.status, f.outcome.summary) == (Status.WARN, "mail.dmarc.partial_reject")


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


def test_inherited_monitoring_offers_a_policy_of_the_domains_own():
    # 0.3.1 said no local record was needed: the parent (gouv.fr, say) may not be the owner's to change.
    f = _check("agency.gov.fr", {
        "_dmarc.agency.gov.fr TXT": None,
        "_dmarc.gov.fr TXT": ["v=DMARC1; p=none; rua=mailto:d@gov.fr"],
    })
    assert (f.status, f.outcome.summary) == (Status.WARN, "mail.dmarc.monitoring_inherited")
    remedy = f.outcome.remedy
    assert remedy is not None and remedy.how == "mail.dmarc.monitoring_inherited.how"
    assert [(c.action, c.rtype, c.name) for c in remedy.dns] == [("add", "TXT", "_dmarc")]
    assert remedy.dns[0].value == "v=DMARC1; p=none; rua=mailto:dmarc@agency.gov.fr"


def test_existing_domain_uses_sp_not_np():
    f = _check("active.example.org", {
        "_dmarc.active.example.org TXT": None,
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; sp=reject; np=none; psd=n"],
        "active.example.org A": [],
    })
    assert f.status is Status.OK
    assert f.outcome.evidence["existence"] == "existing"


def test_invalid_exact_policy_falls_back_to_parent():
    f = _check("sub.example.org", {
        "_dmarc.sub.example.org TXT": ["p=reject; v=DMARC1"],
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; psd=n"],
    })
    assert f.status is Status.OK
    assert f.outcome.evidence["found_at"] == "_dmarc.example.org"


def test_invalid_sp_never_reports_full_enforcement():
    f = _check("sub.example.org", {
        "_dmarc.sub.example.org TXT": None,
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; sp=invalid; rua=mailto:a@example.org"],
    })
    assert f.status is Status.WARN
    assert f.outcome.summary == "mail.dmarc.invalid_monitoring"


def test_intermediate_policy_does_not_override_psd():
    f = _check("x.organization.example", {
        "_dmarc.x.organization.example TXT": None,
        "_dmarc.organization.example TXT": None,
        "_dmarc.example TXT": ["v=DMARC1; p=reject; psd=y"],
        "_dmarc.x.example TXT": ["v=DMARC1; p=none"],
    })
    assert f.status is Status.OK
    assert f.outcome.evidence["found_at"] == "_dmarc.example"


def test_organizational_domain_immediately_below_psd_wins():
    f = _check("host.organization.example", {
        "_dmarc.host.organization.example TXT": None,
        "_dmarc.organization.example TXT": ["v=DMARC1; p=reject"],
        "_dmarc.example TXT": ["v=DMARC1; p=none; psd=y"],
    })
    assert f.status is Status.OK
    assert f.outcome.evidence["found_at"] == "_dmarc.organization.example"


def test_missing_p_monitoring_remedy_adds_quarantine_policy():
    f = _check("example.org", {
        "_dmarc.example.org TXT": ["v=DMARC1; rua=mailto:d@example.org"],
    })
    assert f.status is Status.WARN
    assert f.outcome.summary == "mail.dmarc.monitoring"
    assert any(change.action == "add" and "p=quarantine" in change.value
               for change in f.outcome.remedy.dns)


def test_multiple_local_records_do_not_mask_inherited_policy_warning():
    f = _check("sub.example.org", {
        "_dmarc.sub.example.org TXT": ["v=DMARC1; p=reject", "v=DMARC1; p=none"],
        "_dmarc.example.org TXT": ["v=DMARC1; p=reject; psd=n"],
    })
    assert f.status is Status.WARN
    assert f.outcome.summary == "mail.dmarc.multiple_inherited"
    assert f.outcome.evidence["found_at"] == "_dmarc.example.org"
    assert f.outcome.evidence["ignored_local_at"] == "_dmarc.sub.example.org"
    assert len(f.outcome.evidence["ignored_local_records"]) == 2


def test_multiple_local_records_without_parent_still_fail():
    f = _check("sub.example.org", {
        "_dmarc.sub.example.org TXT": ["v=DMARC1; p=reject", "v=DMARC1; p=none"],
        "_dmarc.example.org TXT": None,
        "_dmarc.org TXT": None,
    })
    assert f.status is Status.FAIL
    assert f.outcome.summary == "mail.dmarc.multiple"


def test_tree_walk_limits_to_eight_queries_and_skips_middle_labels():
    domain = "a.b.c.d.e.f.g.h.i.j.mail.example.com"
    asked = []

    async def txt(name):
        asked.append(name)
        return ["v=DMARC1; p=reject; psd=y"] if name == "_dmarc.com" else []

    owner, records, ignored = asyncio.run(_dmarc_records(SimpleNamespace(domain=domain, txt=txt)))
    assert owner == "com"
    assert records == ["v=DMARC1; p=reject; psd=y"]
    assert ignored == []
    assert asked == [
        "_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com",
        "_dmarc.g.h.i.j.mail.example.com",
        "_dmarc.h.i.j.mail.example.com",
        "_dmarc.i.j.mail.example.com",
        "_dmarc.j.mail.example.com",
        "_dmarc.mail.example.com",
        "_dmarc.example.com",
        "_dmarc.com",
    ]


def test_np_distinguishes_nxdomain_from_nodata():
    policy = ["v=DMARC1; p=reject; sp=reject; np=none; psd=n"]
    base = {
        "_dmarc.sub.example.org TXT": None,
        "_dmarc.example.org TXT": policy,
    }
    nxdomain = _check("sub.example.org", {**base, "sub.example.org A": None})
    nodata = _check("sub.example.org", {**base, "sub.example.org A": []})
    assert nxdomain.outcome.evidence["existence"] == "nxdomain"
    assert nxdomain.outcome.summary == "mail.dmarc.monitoring_inherited"
    assert nodata.outcome.evidence["existence"] == "existing"
    assert nodata.outcome.summary == "mail.dmarc.enforced_inherited"


def test_inherited_monitoring_has_specific_actions_in_both_languages():
    import json
    from pathlib import Path

    locales = Path(__file__).resolve().parents[1] / "src" / "posture_cockpit" / "checks" / "locales"
    for lang in ("fr", "en"):
        messages = json.loads((locales / f"mail.{lang}.json").read_text(encoding="utf-8"))
        assert messages["mail.dmarc.monitoring_inherited.action"]
        assert messages["mail.dmarc.monitoring_inherited.action"] != messages["mail.dmarc.action"]
        assert "{parent}" in messages["mail.dmarc.monitoring_inherited.how"]
