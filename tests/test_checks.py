# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The built-in checks, each run against recorded answers (no network)."""

import asyncio

import pytest

from posture_cockpit.core import engine, scoring
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import Status
from posture_cockpit.core.registry import Registry
from worlds import DOMAIN, changed, dkim_key, healthy, one, run, with_certificate


def test_a_healthy_domain_passes_everything():
    findings = run(healthy())
    not_ok = {cid: (f.status, f.outcome.summary) for cid, f in findings.items()
              if f.status.scored and f.status is not Status.OK}
    assert not_ok == {}
    assert findings["mail.mx"].status is Status.INFO
    assert scoring.score(findings.values()) == 100
    assert all(f.outcome.remedy is None for f in findings.values())


# ------------------------------------------------------------------- SPF
def test_spf_missing_proposes_a_record():
    f = one(changed(healthy(), dns={f"{DOMAIN} TXT": []}), "mail.spf")
    assert f.status is Status.FAIL and f.outcome.summary == "mail.spf.missing"
    change = f.outcome.remedy.dns[0]
    assert (change.action, change.rtype, change.name, change.value) == ("add", "TXT", "@", "v=spf1 mx ~all")


def test_spf_missing_on_a_domain_without_mail_forbids_everyone():
    data = changed(healthy(), dns={f"{DOMAIN} TXT": [], f"{DOMAIN} MX": ["0 ."]})
    assert one(data, "mail.spf").outcome.remedy.dns[0].value == "v=spf1 -all"


@pytest.mark.parametrize(("record", "status", "summary"), [
    ("v=spf1 mx +all", Status.FAIL, "mail.spf.pass_all"),
    ("v=spf1 mx all", Status.FAIL, "mail.spf.pass_all"),
    ("v=spf1 mx ?all", Status.WARN, "mail.spf.neutral"),
    ("v=spf1 mx", Status.WARN, "mail.spf.no_all"),
    ("v=spf1 redirect=_spf.example.net", Status.OK, "mail.spf.ok"),
    ("v=spf1 mx ~all", Status.OK, "mail.spf.ok"),
])
def test_spf_policies(record, status, summary):
    f = one(changed(healthy(), dns={f"{DOMAIN} TXT": [record, "google-site-verification=abc"]}), "mail.spf")
    assert (f.status, f.outcome.summary) == (status, summary)


def test_two_spf_records_fail():
    f = one(changed(healthy(), dns={f"{DOMAIN} TXT": ["v=spf1 mx -all", "v=spf1 a -all"]}), "mail.spf")
    assert f.outcome.summary == "mail.spf.multiple"


def test_spf_counts_lookups_through_includes():
    # 1 include at the top, then a chain of includes each adding a + mx lookups
    dns = {f"{DOMAIN} TXT": ["v=spf1 include:a0.example.net -all"]}
    for i in range(5):
        dns[f"a{i}.example.net TXT"] = [f"v=spf1 a mx include:a{i + 1}.example.net ~all"]
    dns["a5.example.net TXT"] = ["v=spf1 ip4:192.0.2.1 -all"]
    f = one(changed(healthy(), dns=dns), "mail.spf")
    assert f.status is Status.FAIL and f.outcome.params["count"] == 16
    assert f.outcome.evidence["lookups"] == 16


def test_spf_include_loops_do_not_hang():
    dns = {f"{DOMAIN} TXT": ["v=spf1 include:loop.example.net -all"],
           "loop.example.net TXT": [f"v=spf1 include:{DOMAIN} include:loop.example.net -all"]}
    assert one(changed(healthy(), dns=dns), "mail.spf").status is Status.OK


# ----------------------------------------------------------------- DMARC
def test_dmarc_missing_proposes_monitoring_first():
    f = one(changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": None}), "mail.dmarc")
    assert f.status is Status.FAIL
    change = f.outcome.remedy.dns[0]
    assert (change.name, change.value) == ("_dmarc", f"v=DMARC1; p=none; rua=mailto:dmarc@{DOMAIN}")


def test_dmarc_monitoring_suggests_quarantine():
    record = f"v=DMARC1; p=none; rua=mailto:d@{DOMAIN}"
    f = one(changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": [record]}), "mail.dmarc")
    assert f.status is Status.WARN
    delete, add = f.outcome.remedy.dns
    assert (delete.action, delete.value) == ("delete", record)
    assert (add.action, add.value) == ("add", f"v=DMARC1; p=quarantine; rua=mailto:d@{DOMAIN}")


@pytest.mark.parametrize(("record", "status", "summary"), [
    ("v=DMARC1; p=quarantine; pct=50", Status.OK, "mail.dmarc.enforced"),
    ("v=DMARC1; p=whatever", Status.FAIL, "mail.dmarc.invalid"),
    ("v=DMARC1;p=reject", Status.OK, "mail.dmarc.enforced"),
    ("V=DMARC1; P=Quarantine", Status.OK, "mail.dmarc.enforced"),
])
def test_dmarc_policies(record, status, summary):
    f = one(changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": [record]}), "mail.dmarc")
    assert (f.status, f.outcome.summary) == (status, summary)


# ------------------------------------------------------------------ DKIM
def test_dkim_unknown_selector_is_information_only():
    data = changed(healthy(), dns={f"selector1._domainkey.{DOMAIN} TXT": []})
    f = one(data, "mail.dkim")
    assert f.status is Status.INFO and not f.status.scored


def test_dkim_short_key():
    data = changed(healthy(), dns={f"selector1._domainkey.{DOMAIN} TXT": [f"v=DKIM1; p={dkim_key(1024)}"]})
    f = one(data, "mail.dkim")
    assert f.status is Status.WARN and f.outcome.params["bits"] == 1024


# ------------------------------------------------------- MTA-STS, TLS-RPT
def test_mta_sts_and_tls_rpt_do_not_apply_without_mail():
    found = run(changed(healthy(), dns={f"{DOMAIN} MX": []}), "mail.mta_sts", "mail.tls_rpt")
    assert {f.status for f in found.values()} == {Status.NA}


def test_mta_sts_testing_mode():
    data = changed(healthy(), http={f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt": {
        "status": 200, "body": "version: STSv1\nmode: testing\nmx: mx.example.net\nmax_age: 604800\n"}})
    f = one(data, "mail.mta_sts")
    assert f.status is Status.WARN and f.outcome.params["mode"] == "testing"


def test_mta_sts_record_without_policy_file():
    data = healthy()
    del data["http"][f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt"]
    assert one(data, "mail.mta_sts").outcome.summary == "mail.mta_sts.no_policy"


def test_tls_rpt_missing_proposes_a_record():
    f = one(changed(healthy(), dns={f"_smtp._tls.{DOMAIN} TXT": []}), "mail.tls_rpt")
    assert f.outcome.remedy.dns[0].name == "_smtp._tls"


# ------------------------------------------------------------------- TLS
@pytest.mark.parametrize(("days", "status", "summary"), [
    (-2, Status.FAIL, "tls.certificate.expired"),
    (9.5, Status.FAIL, "tls.certificate.expires_soon"),
    (15.5, Status.WARN, "tls.certificate.expires"),
    (25.5, Status.OK, "tls.certificate.ok"),
])
def test_certificate_expiry(days, status, summary):
    f = one(with_certificate(expires_in_days=days), "tls.certificate")
    assert (f.status, f.outcome.summary) == (status, summary)
    if status is not Status.OK:
        assert f.outcome.remedy.message == "tls.certificate.renew_message"


def test_untrusted_certificate():
    f = one(with_certificate(trusted=False, problem="self-signed certificate"), "tls.certificate")
    assert f.status is Status.FAIL and f.outcome.params["problem"] == "self-signed certificate"


def test_no_website_means_nothing_to_check():
    data = changed(healthy(), dns={f"{DOMAIN} A": [], f"www.{DOMAIN} A": []})
    found = run(data, "tls.certificate", "web.hsts", "web.https_redirect")
    assert {f.status for f in found.values()} == {Status.NA}


def test_unreachable_website_is_not_a_failure():
    data = healthy()
    data["certificates"] = {}
    f = one(data, "tls.certificate")
    assert f.status is Status.ERROR and f.outcome.summary == "check.error.network"


def test_obsolete_tls_versions():
    data = healthy()
    data["tls"][f"www.{DOMAIN}"]["TLSv1"] = True
    f = one(data, "tls.protocols")
    assert f.status is Status.FAIL and f.outcome.params["versions"] == "TLS 1.0"


def test_a_version_this_machine_cannot_test_is_not_evaluated():
    """0.1.0 said "only recent versions accepted" without having tried TLS 1.0: a false negative."""
    data = healthy()
    for host in data["tls"]:
        data["tls"][host]["TLSv1"] = None
    f = one(data, "tls.protocols")
    assert f.status is Status.ERROR and f.outcome.summary == "tls.protocols.untestable"
    assert f.outcome.params["versions"] == "TLS 1.0"
    data["tls"][DOMAIN]["TLSv1.1"] = True  # an obsolete version that was tested and accepted still fails
    assert one(data, "tls.protocols").status is Status.FAIL


def test_without_tls_13():
    data = healthy()
    data["tls"][DOMAIN]["TLSv1.3"] = False
    assert one(data, "tls.protocols").outcome.summary == "tls.protocols.no_tls13"


def test_weak_key():
    f = one(with_certificate(key_type="RSA", key_bits=1024), "tls.key")
    assert f.status is Status.FAIL and f.outcome.params["key"] == "RSA 1024"


# ------------------------------------------------------------------- web
def test_http_without_redirection():
    data = changed(healthy(), http={f"http://www.{DOMAIN}/": {"status": 200}})
    f = one(data, "web.https_redirect")
    assert f.status is Status.FAIL and f.outcome.params["host"] == f"www.{DOMAIN}"


def test_closed_http_port_is_fine():
    data = healthy()
    del data["http"][f"http://{DOMAIN}/"]
    del data["http"][f"http://www.{DOMAIN}/"]
    assert one(data, "web.https_redirect").status is Status.OK


def test_headers_are_read_after_redirects_inside_the_domain():
    data = changed(healthy(), http={f"https://www.{DOMAIN}/": {"status": 302, "headers": {"Location": "/fr/"}},
                                    f"https://www.{DOMAIN}/fr/": healthy()["http"][f"https://www.{DOMAIN}/"]})
    assert one(data, "web.hsts").status is Status.OK


def test_redirects_outside_the_domain_are_not_followed():
    data = changed(healthy(), http={f"https://www.{DOMAIN}/": {"status": 302,
                                                               "headers": {"Location": "https://evil.example/"}}})
    f = one(data, "web.hsts")
    assert f.status is Status.WARN  # the redirection itself has no HSTS header


@pytest.mark.parametrize(("header", "value", "check", "status"), [
    ("Strict-Transport-Security", "max-age=86400", "web.hsts", Status.WARN),
    ("Content-Security-Policy", "", "web.csp", Status.WARN),
    ("X-Content-Type-Options", "", "web.nosniff", Status.WARN),
    ("Referrer-Policy", "", "web.referrer", Status.WARN),
    ("Server", "Apache/2.4.41 (Ubuntu)", "web.server_banner", Status.WARN),
    ("Server", "Apache", "web.server_banner", Status.OK),
])
def test_headers(header, value, check, status):
    data = healthy()
    headers = data["http"][f"https://www.{DOMAIN}/"]["headers"]
    if value:
        headers[header] = value
    else:
        del headers[header]
    assert one(data, check).status is status


def test_framing_is_also_protected_by_x_frame_options():
    data = healthy()
    headers = data["http"][f"https://www.{DOMAIN}/"]["headers"]
    headers["Content-Security-Policy"] = "default-src 'self'"
    assert one(data, "web.framing").status is Status.WARN
    headers["X-Frame-Options"] = "SAMEORIGIN"
    assert one(data, "web.framing").status is Status.OK


def test_security_txt_needs_a_contact():
    data = changed(healthy(), http={f"https://{DOMAIN}/.well-known/security.txt": {"status": 200, "body": "hello"}})
    assert one(data, "web.security_txt").status is Status.WARN


# ------------------------------------------------------------------- DNS
def test_single_name_server():
    f = one(changed(healthy(), dns={f"{DOMAIN} NS": ["ns1.example.net."]}), "dns.nameservers")
    assert f.status is Status.WARN and f.outcome.params["host"] == "ns1.example.net"


def test_dnssec_off():
    f = one(changed(healthy(), dns={f"{DOMAIN} DS": []}), "dns.dnssec")
    assert f.status is Status.WARN and f.outcome.remedy.how == "dns.dnssec.how"


def test_caa_proposal_follows_the_current_certificate_issuer():
    data = changed(with_certificate(issuer="Sectigo Limited"), dns={f"{DOMAIN} CAA": []})
    f = one(data, "dns.caa")
    assert f.outcome.remedy.dns[0].value == '0 issue "sectigo.com"'


def test_dns_timeout_is_reported_as_not_checked():
    f = one(changed(healthy(), dns={f"{DOMAIN} DS": "timeout"}), "dns.dnssec")
    assert f.status is Status.ERROR


# --------------------------------------------------------------- passive
def test_checks_only_ask_the_four_passive_questions():
    """DNS queries, certificates, TLS handshakes and GET requests: nothing else."""
    net = FixtureNetwork(healthy())
    asyncio.run(engine.scan(DOMAIN, Registry.discover().checks(), net))
    assert {question.split()[0] for question in net.asked} == {"dns", "certificate", "tls", "http"}
