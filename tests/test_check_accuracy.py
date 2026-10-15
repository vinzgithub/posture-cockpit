# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Non-regression tests for the wrong verdicts found by the 0.2.0 audit.

Each test names the case, what 0.1.0 answered, and what the standard says.
The verdicts are checked against recorded answers (worlds.py), no network.
"""

import asyncio
from base64 import b64decode, b64encode
from ipaddress import ip_address
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key

from posture_cockpit.checks.records import mx_matches, parse_dkim, parse_dmarc, parse_spf
from posture_cockpit.core import engine, scoring
from posture_cockpit.core.egress import DestinationBlocked
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import Status
from posture_cockpit.core.registry import Registry
from worlds import (
    DOMAIN,
    NOW,
    changed,
    dkim_key,
    healthy,
    http_only_with_redirect_elsewhere,
    one,
    redirect_elsewhere_https_refused,
    run,
    with_certificate,
)

SUB = f"shop.{DOMAIN}"
HOME = f"https://www.{DOMAIN}/"


def verdict(finding):
    return finding.status, finding.outcome.summary


def with_headers(**headers):
    """The healthy domain, with these headers on the home page (None removes one)."""
    data = healthy()
    page = data["http"][HOME]["headers"]
    for name, value in headers.items():
        name = name.replace("_", "-")
        if value is None:
            page.pop(name, None)
        else:
            page[name] = value
    return data


# ===================================================================== DMARC
@pytest.mark.parametrize(("record", "expected"), [
    # RFC 7489 §6.3: pct is an integer from 0 to 100; receivers fall back to 100, the record is faulty.
    ("v=DMARC1; p=reject; pct=101", (Status.WARN, "mail.dmarc.syntax")),
    ("v=DMARC1; p=reject; pct=abc", (Status.WARN, "mail.dmarc.syntax")),
    ("v=DMARC1; p=reject; pct=-5", (Status.WARN, "mail.dmarc.syntax")),
    ("v=DMARC1; p=reject; pct=+50", (Status.WARN, "mail.dmarc.syntax")),
    # 0.3.1: OK. RFC 9989 removed pct, but receivers that still follow RFC 7489 apply it:
    # pct=0 means that no failing mail at all meets the policy there.
    ("v=DMARC1; p=reject; pct=0", (Status.WARN, "mail.dmarc.partial")),
    ("v=DMARC1; p=reject; pct=99", (Status.WARN, "mail.dmarc.partial")),
    ("v=DMARC1; p=reject; pct=100", (Status.OK, "mail.dmarc.enforced")),
    ("v=DMARC1; p=reject; pct=0100", (Status.WARN, "mail.dmarc.syntax")),   # 1*3DIGIT
    ("v=DMARC1; p=reject; pct=050", (Status.WARN, "mail.dmarc.partial")),
    # 0.1.0: OK. A report address without "mailto:" is not a URI: no report is sent.
    ("v=DMARC1; p=reject; rua=dmarc@example.org", (Status.WARN, "mail.dmarc.syntax")),
    ("v=DMARC1; p=reject; adkim=x", (Status.WARN, "mail.dmarc.syntax")),
    # 0.1.0: "missing". §6.6.3: a record that does not start with v=DMARC1 is discarded.
    ("p=reject; v=DMARC1", (Status.FAIL, "mail.dmarc.malformed")),
    ("v=DMARC1; rua=mailto:d@example.org", (Status.WARN, "mail.dmarc.monitoring")),
    # Subdomains left out of an enforced policy.
    ("v=DMARC1; p=reject; sp=none", (Status.WARN, "mail.dmarc.subdomains_open")),
    ("v=DMARC1; p=reject; sp=quarantine; rua=mailto:a@example.org,mailto:b@example.net!10m",
     (Status.OK, "mail.dmarc.enforced")),
])
def test_dmarc_follows_rfc_7489(record, expected):
    f = one(changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": [record]}), "mail.dmarc")
    assert verdict(f) == expected


def test_dmarc_syntax_names_the_faulty_tags():
    f = one(changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": ["v=DMARC1; p=reject; pct=101; rua=x@y.z"]}),
            "mail.dmarc")
    assert f.outcome.params["tags"] == "pct=101, rua=x@y.z"


def test_two_dmarc_records_cancel_each_other():
    records = ["v=DMARC1; p=reject", "v=DMARC1; p=none"]
    assert verdict(one(changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": records}), "mail.dmarc")) == \
        (Status.FAIL, "mail.dmarc.multiple")


@pytest.mark.parametrize(("parent", "expected"), [
    ("v=DMARC1; p=reject", (Status.OK, "mail.dmarc.enforced_inherited")),
    ("v=DMARC1; p=reject; sp=none", (Status.WARN, "mail.dmarc.monitoring_inherited")),
    ("v=DMARC1; p=none; sp=quarantine", (Status.OK, "mail.dmarc.enforced_inherited")),
])
def test_a_subdomain_follows_the_policy_of_its_domain(parent, expected):
    """0.1.0 reported DMARC missing on every subdomain: receivers use the organizational domain's record."""
    data = changed(healthy(), dns={f"_dmarc.{SUB} TXT": None, f"_dmarc.{DOMAIN} TXT": [parent]})
    f = run(data, "mail.dmarc", domain=SUB)["mail.dmarc"]
    assert verdict(f) == expected
    assert f.outcome.evidence["found_at"] == f"_dmarc.{DOMAIN}"


def test_a_subdomain_record_of_its_own_wins():
    data = changed(healthy(), dns={f"_dmarc.{SUB} TXT": ["v=DMARC1; p=none"],
                                   f"_dmarc.{DOMAIN} TXT": ["v=DMARC1; p=reject"]})
    assert verdict(run(data, "mail.dmarc", domain=SUB)["mail.dmarc"]) == (Status.WARN, "mail.dmarc.monitoring")


def test_dmarc_parser():
    record = parse_dmarc("v=DMARC1;p=Quarantine;sp=reject;pct=50;rua=mailto:a@example.org")
    assert (record.starts_right, record.policy, record.subdomain_policy, record.pct) == (True, "quarantine",
                                                                                         "reject", 50)
    assert record.rua == ("mailto:a@example.org",) and record.errors == ()


# ======================================================================= SPF
@pytest.mark.parametrize(("record", "expected"), [
    # 0.1.0: OK. RFC 7208 §5: an unknown mechanism or a bad address is a permanent error.
    ("v=spf1 foo -all", (Status.FAIL, "mail.spf.syntax")),
    ("v=spf1 ip4:999.1.1.1 -all", (Status.FAIL, "mail.spf.syntax")),
    ("v=spf1 ip6:192.0.2.1 -all", (Status.FAIL, "mail.spf.syntax")),
    ("v=spf1 include -all", (Status.FAIL, "mail.spf.syntax")),
    ("v=spf1 redirect=a.example.net redirect=b.example.net", (Status.FAIL, "mail.spf.syntax")),
    ("v=spf1 a:mail.example.org/24 mx//64 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all", (Status.OK, "mail.spf.ok")),
    ("v=spf1 mx ptr -all", (Status.WARN, "mail.spf.ptr")),
    ("v=spf1 mx -all exp=explain.example.org", (Status.OK, "mail.spf.ok")),
    ("v=spf1 mx ~all moo=bar", (Status.OK, "mail.spf.ok")),  # unknown modifiers are ignored
])
def test_spf_follows_rfc_7208(record, expected):
    assert verdict(one(changed(healthy(), dns={f"{DOMAIN} TXT": [record]}), "mail.spf")) == expected


@pytest.mark.parametrize("target_records", [[], None, ["v=spf1 -all", "v=spf1 ~all"], ["v=spf1 bogus -all"]])
def test_an_include_without_one_valid_spf_record_is_a_permanent_error(target_records):
    """0.1.0: OK. §5.2: an included domain without SPF (or with two, or an invalid one) gives permerror."""
    data = changed(healthy(), dns={f"{DOMAIN} TXT": ["v=spf1 include:gone.example.net -all"],
                                   "gone.example.net TXT": target_records})
    f = one(data, "mail.spf")
    assert verdict(f) == (Status.FAIL, "mail.spf.broken_include")
    assert f.outcome.params["targets"] == "gone.example.net"


def test_a_redirect_without_spf_is_a_permanent_error():
    data = changed(healthy(), dns={f"{DOMAIN} TXT": ["v=spf1 redirect=gone.example.net"]})
    assert verdict(one(data, "mail.spf")) == (Status.FAIL, "mail.spf.broken_include")


def test_spf_macros_are_not_followed():
    data = changed(healthy(), dns={f"{DOMAIN} TXT": ["v=spf1 include:%{i}._spf.example.net -all"]})
    assert verdict(one(data, "mail.spf")) == (Status.OK, "mail.spf.ok")


def test_spf_parser():
    record = parse_spf("v=spf1 +mx -include:_spf.example.net ?a ~all")
    assert record.all_qualifier == "~" and record.includes == ["_spf.example.net"] and record.lookups == 3
    assert parse_spf("v=spf1 redirect=x.example.net").redirect == "x.example.net"
    assert parse_spf("v=spf1 -all redirect=x.example.net").redirect is None  # ignored when "all" is there


# ====================================================================== DKIM
def test_an_unreadable_dkim_key_is_not_a_signature():
    """0.1.0: OK ("found"). A key that cannot be decoded makes every signature fail."""
    data = changed(healthy(), dns={f"selector1._domainkey.{DOMAIN} TXT": ["v=DKIM1; k=rsa; p=AAAAnotakey"]})
    f = one(data, "mail.dkim")
    assert verdict(f) == (Status.WARN, "mail.dkim.unreadable")
    assert f.outcome.evidence["selectors"] == {"selector1": "unreadable"}


@pytest.mark.parametrize(("record", "expected"), [
    ("v=DKIM1; k=rsa; p=", (Status.INFO, "mail.dkim.not_found")),  # revoked key: nothing to judge
    ("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", (Status.OK, "mail.dkim.found")),
    ("v=DKIM2; p=" + "A" * 20, (Status.WARN, "mail.dkim.unreadable")),
])
def test_dkim_key_records(record, expected):
    data = changed(healthy(), dns={f"selector1._domainkey.{DOMAIN} TXT": [record]})
    assert verdict(one(data, "mail.dkim")) == expected


def test_a_dkim_key_under_1024_bits_fails():
    data = changed(healthy(), dns={f"selector1._domainkey.{DOMAIN} TXT": [f"p={dkim_key(512)}"]})
    assert verdict(one(data, "mail.dkim")) == (Status.FAIL, "mail.dkim.weak_key")


def test_dkim_parser_reads_both_rsa_encodings():
    """SubjectPublicKeyInfo, as everyone publishes, and the bare RSAPublicKey of RFC 6376 §3.6.1."""
    key = load_der_public_key(b64decode(dkim_key(2048)))
    pkcs1 = b64encode(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)).decode()
    assert parse_dkim(f"p={pkcs1}").bits == 2048
    assert parse_dkim(f"p={dkim_key(2048)}").bits == 2048
    assert parse_dkim("v=spf1 -all") is None


# ======================================================================== MX
@pytest.mark.parametrize(("records", "extra", "expected"), [
    (["10 mx.example.net."], {}, (Status.INFO, "mail.mx.list")),
    (["10 lost.example.net."], {}, (Status.WARN, "mail.mx.unresolved")),
    (["10 192.0.2.25."], {}, (Status.WARN, "mail.mx.address")),
    (["0 .", "10 mx.example.net."], {}, (Status.WARN, "mail.mx.null_mixed")),
    (["0 ."], {}, (Status.INFO, "mail.mx.none")),
])
def test_mx_records(records, extra, expected):
    assert verdict(one(changed(healthy(), dns={f"{DOMAIN} MX": records, **extra}), "mail.mx")) == expected


# =================================================================== MTA-STS
POLICY_URL = f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt"


def with_policy(body=None, status=200, **dns):
    data = changed(healthy(), dns=dns)
    if body is not None:
        data["http"][POLICY_URL] = {"status": status, "body": body}
    return data


@pytest.mark.parametrize(("data", "expected"), [
    (with_policy("version: STSv1\nmode: enforce\nmx: mx.example.net\nmax_age: 604800\n"),
     (Status.OK, "mail.mta_sts.enforce")),
    (with_policy("version: STSv1\nmode: enforce\nmx: *.example.net\nmax_age: 604800\n"),
     (Status.OK, "mail.mta_sts.enforce")),
    # The policy does not list the MX: in enforce mode, senders refuse to deliver.
    (with_policy("version: STSv1\nmode: enforce\nmx: other.example.net\nmax_age: 604800\n"),
     (Status.FAIL, "mail.mta_sts.mx_mismatch")),
    (with_policy("version: STSv1\nmode: testing\nmx: other.example.net\nmax_age: 604800\n"),
     (Status.WARN, "mail.mta_sts.mx_mismatch")),
    # 0.1.0 only read "mode:". RFC 8461 §3.2: version, mode, mx and max_age are required.
    (with_policy("mode: enforce\n"), (Status.WARN, "mail.mta_sts.bad_policy")),
    (with_policy("version: STSv1\nmode: enforce\nmx: mx.example.net\nmax_age: forever\n"),
     (Status.WARN, "mail.mta_sts.bad_policy")),
    (with_policy("version: STSv1\nmode: none\nmax_age: 86400\n"), (Status.WARN, "mail.mta_sts.disabled")),
    (with_policy("version: STSv1\nmode: enforce\nmx: mx.example.net\nmax_age: 300\n"),
     (Status.WARN, "mail.mta_sts.short_max_age")),
    (with_policy("Not found", status=404), (Status.WARN, "mail.mta_sts.no_policy")),
    (with_policy(**{f"_mta-sts.{DOMAIN} TXT": ["v=STSv1;"]}), (Status.WARN, "mail.mta_sts.bad_record")),
    (with_policy(**{f"_mta-sts.{DOMAIN} TXT": ["v=STSv1; id=1", "v=STSv1; id=2"]}),
     (Status.WARN, "mail.mta_sts.bad_record")),
    (with_policy(**{f"mta-sts.{DOMAIN} A": []}), (Status.WARN, "mail.mta_sts.no_policy")),
], ids=["enforce", "wildcard", "mismatch_enforce", "mismatch_testing", "incomplete", "bad_max_age", "mode_none",
        "short_max_age", "http_404", "record_without_id", "two_records", "no_policy_host"])
def test_mta_sts_follows_rfc_8461(data, expected):
    assert verdict(one(data, "mail.mta_sts")) == expected


def test_an_mta_sts_policy_needs_a_valid_certificate():
    """0.1.0 fetched the policy without checking the certificate. §3.3: an invalid one voids the policy."""
    data = healthy()
    data["certificates"][f"mta-sts.{DOMAIN}"] = {"trusted": False, "problem": "certificate has expired"}
    f = one(data, "mail.mta_sts")
    assert verdict(f) == (Status.WARN, "mail.mta_sts.bad_certificate")
    assert f.outcome.params["problem"] == "certificate has expired"


def test_an_mta_sts_server_that_does_not_answer_is_not_evaluated():
    data = healthy()
    data["http"][POLICY_URL] = "timeout"
    assert one(data, "mail.mta_sts").status is Status.ERROR
    del data["http"][POLICY_URL]  # nothing listens: a definite answer
    assert verdict(one(data, "mail.mta_sts")) == (Status.WARN, "mail.mta_sts.no_policy")


def test_mx_patterns():
    assert mx_matches("*.example.net", "mx1.example.net")
    assert not mx_matches("*.example.net", "a.b.example.net")
    assert not mx_matches("*.example.net", "example.net")
    assert mx_matches("mx.example.net", "MX.example.net.")


# =================================================================== TLS-RPT
@pytest.mark.parametrize(("records", "expected"), [
    ([f"v=TLSRPTv1; rua=mailto:tls@{DOMAIN}"], (Status.OK, "mail.tls_rpt.present")),
    ([f"v=TLSRPTv1; rua=https://reports.{DOMAIN}/tls"], (Status.OK, "mail.tls_rpt.present")),
    ([f"v=TLSRPTv1; rua=tls@{DOMAIN}"], (Status.WARN, "mail.tls_rpt.invalid")),
    (["v=TLSRPTv1"], (Status.WARN, "mail.tls_rpt.invalid")),
    ([f"v=TLSRPTv1; rua=mailto:a@{DOMAIN}", f"v=TLSRPTv1; rua=mailto:b@{DOMAIN}"],
     (Status.WARN, "mail.tls_rpt.invalid")),
])
def test_tls_rpt_follows_rfc_8460(records, expected):
    assert verdict(one(changed(healthy(), dns={f"_smtp._tls.{DOMAIN} TXT": records}), "mail.tls_rpt")) == expected




@pytest.mark.parametrize(("records", "expected"), [
    # 0.3.1: missing. A record that names the protocol is reported when senders cannot use it.
    (["v=TLSRPTv2; rua=mailto:tls@example.org"], (Status.WARN, "mail.tls_rpt.invalid")),
    (["v=tlsrptv1; rua=mailto:tls@example.org"], (Status.WARN, "mail.tls_rpt.invalid")),
    # 0.3.1: missing (single record) or "v" (one of several). RFC 8460 §3: field-delim = *WSP ";" *WSP.
    (["v=TLSRPTv1 ; rua=mailto:tls@example.org"], (Status.OK, "mail.tls_rpt.present")),
    (["v=TLSRPTv1;\trua=mailto:tls@example.org ;"], (Status.OK, "mail.tls_rpt.present")),
    # ...but among several TXT, only those beginning with "v=TLSRPTv1;" are kept.
    (["unrelated TXT", "v=TLSRPTv1 ; rua=mailto:tls@example.org"], (Status.WARN, "mail.tls_rpt.invalid")),
    ([" v=TLSRPTv1; rua=mailto:tls@example.org"], (Status.WARN, "mail.tls_rpt.missing")),
    (["random TXT"], (Status.WARN, "mail.tls_rpt.missing")),
    (["v=TLSRPTv1; rua=mailto:one@example.org; rua=mailto:two@example.org"],
     (Status.OK, "mail.tls_rpt.present")),
    (["v=TLSRPTv1; rua=mailto:tls@example.org; bogus=value"],
     (Status.OK, "mail.tls_rpt.present")),
    (["v=TLSRPTv1; rua=mailto:tls@example.org; v=TLSRPTv1"],
     (Status.WARN, "mail.tls_rpt.invalid")),
    (["v=TLSRPTv1; rua=mailto:"], (Status.WARN, "mail.tls_rpt.invalid")),
    (["unrelated TXT", "v=TLSRPTv1; rua=mailto:tls@example.org"],
     (Status.OK, "mail.tls_rpt.present")),
    (["unrelated TXT", "v=TLSRPTv1; rua=mailto:"],
     (Status.WARN, "mail.tls_rpt.invalid")),
    (["v=TLSRPTv1; rua=https://reports.example.org/a"],
     (Status.OK, "mail.tls_rpt.present")),
    (["v=TLSRPTv1; rua=https://[invalid/"],
     (Status.WARN, "mail.tls_rpt.invalid")),
    ([], (Status.WARN, "mail.tls_rpt.missing")),
])
def test_tls_rpt_invalid_reserved_txt_is_not_absence(records, expected):
    finding = one(changed(healthy(), dns={f"_smtp._tls.{DOMAIN} TXT": records}), "mail.tls_rpt")
    assert verdict(finding) == expected


def test_custom_dkim_selector_is_found_and_audited(monkeypatch):
    monkeypatch.setenv("POSTURE_COCKPIT_DKIM_SELECTORS", "custom2026")
    data = changed(
        healthy(),
        dns={
            f"selector1._domainkey.{DOMAIN} TXT": [],
            f"custom2026._domainkey.{DOMAIN} TXT": [f"v=DKIM1; p={dkim_key(2048)}"],
        },
    )
    finding = one(data, "mail.dkim")
    assert verdict(finding) == (Status.OK, "mail.dkim.found")
    assert "custom2026" in finding.outcome.evidence["selectors"]


@pytest.mark.parametrize("selectors", [
    "custom2026,*", "bad.name", "has space", ",".join(f"s{i}" for i in range(40)),
])
def test_custom_dkim_selectors_reject_invalid_or_excessive_values(monkeypatch, selectors):
    from posture_cockpit.checks.mail import dkim_selectors

    monkeypatch.setenv("POSTURE_COCKPIT_DKIM_SELECTORS", selectors)
    with pytest.raises(ValueError):
        dkim_selectors()

# ================================================================== framing
@pytest.mark.parametrize(("csp", "xfo", "expected"), [
    # 0.1.0: OK as soon as "frame-ancestors" appeared, whatever its value.
    ("default-src 'self'; frame-ancestors *", None, (Status.WARN, "web.framing.permissive")),
    ("default-src 'self'; frame-ancestors https:", None, (Status.WARN, "web.framing.permissive")),
    # CSP Level 2+: with frame-ancestors present, browsers ignore X-Frame-Options.
    ("default-src 'self'; frame-ancestors *", "DENY", (Status.WARN, "web.framing.permissive")),
    ("default-src 'self'; frame-ancestors 'none'", None, (Status.OK, "web.framing.ok")),
    ("default-src 'self'; frame-ancestors 'self' https://partner.example", None, (Status.OK, "web.framing.ok")),
    ("default-src 'self'; frame-ancestors", None, (Status.OK, "web.framing.ok")),  # empty list means 'none'
    ("default-src 'self'", "SAMEORIGIN", (Status.OK, "web.framing.ok")),
    ("default-src 'self'", "deny", (Status.OK, "web.framing.ok")),
    ("default-src 'self'", "ALLOW-FROM https://partner.example", (Status.WARN, "web.framing.obsolete")),
    ("default-src 'self'", None, (Status.WARN, "web.framing.missing")),
])
def test_framing_protection_is_judged_on_its_value(csp, xfo, expected):
    data = with_headers(Content_Security_Policy=csp, X_Frame_Options=xfo)
    assert verdict(one(data, "web.framing")) == expected


def test_a_report_only_policy_protects_nothing():
    data = with_headers(Content_Security_Policy=None, X_Frame_Options=None)
    data["http"][HOME]["headers"]["Content-Security-Policy-Report-Only"] = "frame-ancestors 'none'"
    assert verdict(one(data, "web.framing")) == (Status.WARN, "web.framing.missing")


# ====================================================================== CSP
@pytest.mark.parametrize(("csp", "expected"), [
    # 0.1.0: OK for any CSP header, even one that restricts nothing about scripts.
    ("upgrade-insecure-requests", (Status.WARN, "web.csp.no_script")),
    ("frame-ancestors 'none'", (Status.WARN, "web.csp.no_script")),
    ("default-src 'self' 'unsafe-inline'", (Status.WARN, "web.csp.unsafe_inline")),
    ("script-src 'self' 'unsafe-inline' 'nonce-r4nd0m'", (Status.OK, "web.csp.ok")),
    ("script-src 'strict-dynamic' 'unsafe-inline' 'sha256-abc='", (Status.OK, "web.csp.ok")),
    ("script-src *", (Status.WARN, "web.csp.open")),
    ("default-src https:", (Status.WARN, "web.csp.open")),
    ("default-src 'self'; script-src 'self' cdn.example.net", (Status.OK, "web.csp.ok")),
    # Two policies are both enforced: the stricter one decides.
    ("upgrade-insecure-requests, script-src 'self'", (Status.OK, "web.csp.ok")),
])
def test_csp_must_restrict_scripts(csp, expected):
    assert verdict(one(with_headers(Content_Security_Policy=csp), "web.csp")) == expected


# ===================================================================== HSTS
@pytest.mark.parametrize(("value", "expected"), [
    ("max-age=0", (Status.WARN, "web.hsts.disabled")),  # 0.1.0: "short". RFC 6797 §6.1.1: it removes HSTS.
    ("max-age=abc", (Status.WARN, "web.hsts.invalid")),
    ("includeSubDomains", (Status.WARN, "web.hsts.invalid")),
    ('max-age="31536000"; includeSubDomains', (Status.OK, "web.hsts.ok")),
    ("max-age=86400", (Status.WARN, "web.hsts.short")),
    ("max-age=31536000, max-age=0", (Status.OK, "web.hsts.ok")),  # browsers use the first header
])
def test_hsts_values(value, expected):
    assert verdict(one(with_headers(Strict_Transport_Security=value), "web.hsts")) == expected


# ========================================================== HTTPS redirection
def test_a_redirection_chain_over_http_inside_the_domain_is_fine():
    """0.1.0: FAIL. http://www → http://domain → https://www never serves a page in clear."""
    data = changed(healthy(), http={
        f"http://www.{DOMAIN}/": {"status": 301, "headers": {"Location": f"http://{DOMAIN}/"}},
        f"http://{DOMAIN}/": {"status": 301, "headers": {"Location": f"https://www.{DOMAIN}/"}}})
    f = one(data, "web.https_redirect")
    assert verdict(f) == (Status.OK, "web.https_redirect.ok")
    assert f.outcome.evidence[f"www.{DOMAIN}"].endswith(f"https://www.{DOMAIN}/")


@pytest.mark.parametrize("http", [
    {f"http://www.{DOMAIN}/": {"status": 301, "headers": {"Location": f"http://{DOMAIN}/page"}},
     f"http://{DOMAIN}/page": {"status": 200}},                                       # ends on a page in clear
    {f"http://www.{DOMAIN}/": {"status": 302, "headers": {"Location": "http://other.example/"}}},  # leaves in clear
    {f"http://www.{DOMAIN}/": {"status": 301, "headers": {"Location": f"http://www.{DOMAIN}/"}}},  # loops
    {f"http://www.{DOMAIN}/": {"status": 404}},
])
def test_http_that_never_reaches_https_fails(http):
    assert verdict(one(changed(healthy(), http=http), "web.https_redirect")) == \
        (Status.FAIL, "web.https_redirect.missing")


ELSEWHERE = {"status": 301, "headers": {"Location": "https://elsewhere.example.net/"}}


def _redirect_elsewhere_scan(data):
    net = FixtureNetwork(data, NOW)
    result = asyncio.run(engine.scan(DOMAIN, [Registry.discover().get("web.https_redirect")], net, now=NOW))
    return result.findings[0], net.asked


def test_external_redirect_is_fine_when_the_host_also_answers_over_https():
    """0.3.1: FAIL. example.org → https://www.example.com is a business choice: what matters for the
    audited domain is that https://example.org/ itself answers with a valid certificate."""
    data = changed(healthy(), http={f"http://{DOMAIN}/": ELSEWHERE, f"http://www.{DOMAIN}/": ELSEWHERE})
    f, asked = _redirect_elsewhere_scan(data)
    assert verdict(f) == (Status.OK, "web.https_redirect.ok")
    assert f.outcome.evidence[DOMAIN] == \
        f"301 http://{DOMAIN}/ → https://elsewhere.example.net/ ; https://{DOMAIN}/ tested"
    assert f"http https://{DOMAIN}/" in asked
    assert not any("elsewhere.example.net" in line for line in asked)  # the other site is never fetched


def test_external_redirect_without_https_on_the_host_fails():
    """A third-party HTTPS page cannot prove HTTPS for the audited domain."""
    data = changed(healthy(), http={f"http://{DOMAIN}/": ELSEWHERE, f"http://www.{DOMAIN}/": ELSEWHERE})
    del data["http"][f"https://{DOMAIN}/"]
    f, _asked = _redirect_elsewhere_scan(data)
    assert verdict(f) == (Status.FAIL, "web.https_redirect.external")
    assert f.outcome.params["host"] == DOMAIN
    assert f.outcome.remedy.message == "web.https_redirect.external.message"


def test_external_redirect_with_an_untrusted_certificate_on_the_host_fails():
    data = changed(healthy(), http={f"http://{DOMAIN}/": ELSEWHERE})
    data["certificates"][DOMAIN]["trusted"] = False
    f, _asked = _redirect_elsewhere_scan(data)
    assert verdict(f) == (Status.FAIL, "web.https_redirect.bad_certificate")


def test_external_redirect_with_a_silent_host_is_not_evaluated():
    """The domain as it was on 13 October 2026: no answer is not a verdict."""
    data = changed(healthy(), http={f"http://{DOMAIN}/": ELSEWHERE, f"https://{DOMAIN}/": "timeout"})
    f, _asked = _redirect_elsewhere_scan(data)
    assert f.status is Status.ERROR
    # With every web and TLS check unanswered, too little is evaluated for a score (0.3.1: 67/100).
    assessment = scoring.assess(list(run(http_only_with_redirect_elsewhere()).values()))
    assert assessment.score is None and assessment.coverage < 0.5
    refused = scoring.assess(list(run(redirect_elsewhere_https_refused()).values()))
    assert (refused.score, refused.grade) == (67, "C")


def test_https_redirect_rejects_invalid_certificate():
    data = changed(healthy(), http={
        f"http://{DOMAIN}/": {"status": 301, "headers": {"Location": f"https://{DOMAIN}/"}},
    })
    data["certificates"][DOMAIN]["trusted"] = False
    assert verdict(one(data, "web.https_redirect")) == (Status.FAIL, "web.https_redirect.bad_certificate")


def test_https_redirect_timeout_does_not_create_compliance():
    data = changed(healthy(), http={
        f"http://{DOMAIN}/": "timeout",
    })
    assert one(data, "web.https_redirect").status is Status.ERROR


def test_https_redirect_requires_reachable_https():
    data = changed(healthy(), http={
        f"http://{DOMAIN}/": {"status": 301, "headers": {"Location": f"https://{DOMAIN}/"}},
    })
    del data["http"][f"https://{DOMAIN}/"]
    assert verdict(one(data, "web.https_redirect")) == (Status.FAIL, "web.https_redirect.https_unavailable")


def test_closed_http_port_does_not_excuse_unreachable_https():
    data = healthy()
    del data["http"][f"http://{DOMAIN}/"]
    del data["http"][f"https://{DOMAIN}/"]
    assert verdict(one(data, "web.https_redirect")) == (Status.FAIL, "web.https_redirect.https_unavailable")

class BlockingNetwork(FixtureNetwork):
    """Recorded answers, with some URLs refused by the egress policy."""

    def __init__(self, data, blocked):
        super().__init__(data, NOW)
        self.blocked = blocked

    async def http_get(self, url, *, verify=False):
        if url in self.blocked:
            raise DestinationBlocked(urlsplit(url).hostname or "", ip_address("10.0.0.8"), 80, "private")
        return await super().http_get(url, verify=verify)


def test_a_refused_destination_is_not_a_closed_port():
    """Port 80 refused by the scan's own rule says nothing about the site: not evaluated, not "closed"."""
    net = BlockingNetwork(healthy(), {f"http://{DOMAIN}/"})
    result = asyncio.run(engine.scan(DOMAIN, [Registry.discover().get("web.https_redirect")], net, now=NOW))
    f = result.findings[0]
    assert f.status is Status.ERROR and f.outcome.summary == "check.error.blocked.private"


# ============================================================ other headers
@pytest.mark.parametrize(("value", "expected"), [
    ("unsafe-url", (Status.WARN, "web.referrer.unsafe")),  # 0.1.0: OK
    ("no-referrer, unsafe-url", (Status.WARN, "web.referrer.unsafe")),  # the last known value applies
    ("unsafe-url, strict-origin-when-cross-origin", (Status.OK, "web.referrer.ok")),
    ("whatever", (Status.WARN, "web.referrer.missing")),
    ("same-origin", (Status.OK, "web.referrer.ok")),
])
def test_referrer_policy_values(value, expected):
    assert verdict(one(with_headers(Referrer_Policy=value), "web.referrer")) == expected


def test_nosniff_sent_twice_still_counts():
    assert one(with_headers(X_Content_Type_Options="nosniff, nosniff"), "web.nosniff").status is Status.OK


# ============================================================== security.txt
SECURITY_TXT = f"https://{DOMAIN}/.well-known/security.txt"


@pytest.mark.parametrize(("reply", "expected"), [
    # 0.1.0: OK with any "Contact:". RFC 9116 §2.5.5: Expires is required; once passed, the file is stale.
    ({"status": 200, "body": f"Contact: mailto:s@{DOMAIN}\nExpires: 2026-01-01T00:00:00Z\n"},
     (Status.WARN, "web.security_txt.expired")),
    ({"status": 200, "body": f"Contact: mailto:s@{DOMAIN}\n"}, (Status.WARN, "web.security_txt.invalid")),
    ({"status": 200, "body": "Expires: 2027-01-01T00:00:00Z\n"}, (Status.WARN, "web.security_txt.invalid")),
    ({"status": 200, "body": f"Contact: mailto:s@{DOMAIN}\nExpires: next year\n"},
     (Status.WARN, "web.security_txt.invalid")),
    ({"status": 200, "body": "<!doctype html><html><body>Welcome</body></html>"},
     (Status.WARN, "web.security_txt.missing")),  # a site answering every address with its home page
    ({"status": 200, "body": f"# comment\nContact: mailto:s@{DOMAIN}\nExpires: 2027-01-01T00:00:00+01:00\n"},
     (Status.OK, "web.security_txt.ok")),
])
def test_security_txt_follows_rfc_9116(reply, expected):
    assert verdict(one(changed(healthy(), http={SECURITY_TXT: reply}), "web.security_txt")) == expected


def test_security_txt_behind_a_redirection():
    """0.1.0: missing, because the redirection to www was not followed."""
    moved = f"https://www.{DOMAIN}/.well-known/security.txt"
    data = changed(healthy(), http={SECURITY_TXT: {"status": 301, "headers": {"Location": moved}},
                                    moved: healthy()["http"][SECURITY_TXT]})
    assert verdict(one(data, "web.security_txt")) == (Status.OK, "web.security_txt.ok")


# ====================================================================== DNS
@pytest.mark.parametrize(("records", "expected"), [
    # 0.1.0: OK. The current certificate's authority is not allowed: its renewal will be refused.
    (['0 issue "digicert.com"'], (Status.WARN, "dns.caa.excludes_current")),
    (['0 issue ";"'], (Status.WARN, "dns.caa.excludes_current")),
    (['0 issue "letsencrypt.org; validationmethods=dns-01"'], (Status.OK, "dns.caa.present")),
    (['0 issuewild "digicert.com"'], (Status.OK, "dns.caa.present")),  # not a wildcard certificate
    (['0 iodef "mailto:security@example.org"'], (Status.OK, "dns.caa.present")),
])
def test_caa_must_allow_the_current_authority(records, expected):
    assert verdict(one(changed(healthy(), dns={f"{DOMAIN} CAA": records}), "dns.caa")) == expected


def test_caa_of_a_wildcard_certificate_reads_issuewild():
    data = changed(with_certificate(names=[f"*.{DOMAIN}", DOMAIN]),
                   dns={f"{DOMAIN} CAA": ['0 issue "letsencrypt.org"', '0 issuewild "digicert.com"']})
    assert verdict(one(data, "dns.caa")) == (Status.WARN, "dns.caa.excludes_current")


def subdomain_world():
    """shop.example.org: no zone of its own, the records of example.org apply."""
    data = healthy()
    data["dns"].update({f"{SUB} A": ["192.0.2.30"], f"{SUB} NS": [], f"{SUB} CAA": [], f"{SUB} DS": []})
    return data


def test_a_subdomain_is_judged_by_its_zone():
    """0.1.0: "DNSSEC off" and "no CAA" on any subdomain of a signed zone that has CAA records."""
    found = run(subdomain_world(), "dns.nameservers", "dns.dnssec", "dns.caa", domain=SUB)
    assert verdict(found["dns.nameservers"]) == (Status.OK, "dns.nameservers.ok")
    assert verdict(found["dns.dnssec"]) == (Status.OK, "dns.dnssec.on")
    assert verdict(found["dns.caa"]) == (Status.OK, "dns.caa.present_inherited")
    assert found["dns.dnssec"].outcome.params["zone"] == DOMAIN


def test_a_ds_record_without_keys_is_broken_dnssec():
    data = changed(healthy(), dns={f"{DOMAIN} DNSKEY": []})
    assert verdict(one(data, "dns.dnssec")) == (Status.FAIL, "dns.dnssec.broken")
