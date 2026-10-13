# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""DNS of the domain: name servers, DNSSEC signature, CAA records.

A name that is not a zone of its own (``shop.example.org`` inside the zone
``example.org``) is judged by its zone: its name servers and DNSSEC are those
of ``example.org``, and CAA records are looked up from the name upwards, as
certificate authorities do (RFC 8659 §3).

References: ANSSI, « Bonnes pratiques pour l'acquisition et l'exploitation de
noms de domaine »; RFC 2182 (secondary servers), RFC 4033 (DNSSEC), RFC 8659 (CAA).
"""

from __future__ import annotations

from .. import __version__
from ..core import (
    CheckContext,
    DnsChange,
    Effort,
    Extension,
    NetworkError,
    Outcome,
    Remedy,
    fail,
    load_messages,
    na,
    ok,
    warn,
)
from . import LOCALES

extension = Extension("dns", name="DNS", version=__version__,
                      description="Name servers, DNSSEC and CAA records of the domain.",
                      messages=load_messages(LOCALES, "dns"))

# Value to put in a CAA record for the certificate authorities seen most often,
# keyed by a word of the issuer's name in the certificate.
CAA_DOMAINS = {
    "let's encrypt": "letsencrypt.org",
    "sectigo": "sectigo.com",
    "zerossl": "sectigo.com",
    "digicert": "digicert.com",
    "globalsign": "globalsign.com",
    "google trust services": "pki.goog",
    "amazon": "amazon.com",
    "buypass": "buypass.com",
    "certigna": "certigna.fr",
}


def _parents(name: str) -> list[str]:
    """``a.b.example.org`` → itself, ``b.example.org``, ``example.org`` (never the top-level domain alone)."""
    labels = name.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


async def _zone(ctx: CheckContext) -> tuple[str, list[str]]:
    """The zone the domain belongs to (the closest name with NS records), and its name servers."""

    async def find() -> tuple[str, list[str]]:
        for name in _parents(ctx.domain):
            hosts = sorted(ns.lower().rstrip(".") for ns in (await ctx.net.dns(name, "NS")).records)
            if hosts:
                return name, hosts
        return ctx.domain, []

    return await ctx.shared("zone", find)


@extension.check("nameservers", category="dns", weight=4, internal=False)
async def nameservers(ctx: CheckContext) -> Outcome:
    """At least two name servers, so the domain still answers when one is down."""
    zone, hosts = await _zone(ctx)
    evidence = {"zone": zone, "nameservers": hosts}
    if not hosts:
        return na("dns.nameservers.none", evidence)
    if len(hosts) == 1:
        return warn("dns.nameservers.single", Remedy(30, Effort.DELEGATE, message="dns.nameservers.message"),
                    evidence, host=hosts[0], zone=zone)
    return ok("dns.nameservers.ok", evidence, count=len(hosts), zone=zone)


@extension.check("dnssec", category="dns", weight=4, internal=False)
async def dnssec(ctx: CheckContext) -> Outcome:
    """A DS record at the parent zone means the zone is signed; its keys (DNSKEY) must then be published."""
    zone, _ = await _zone(ctx)
    ds = list((await ctx.net.dns(zone, "DS")).records)
    if not ds:
        return warn("dns.dnssec.off", Remedy(10, Effort.EASY, how="dns.dnssec.how"), {"zone": zone}, zone=zone)
    keys = list((await ctx.net.dns(zone, "DNSKEY")).records)
    evidence = {"zone": zone, "ds": ds, "dnskey": len(keys)}
    if not keys:
        # The parent announces a signature the zone does not publish: validating resolvers reject its answers.
        return fail("dns.dnssec.broken", Remedy(30, Effort.DELEGATE, message="dns.dnssec.broken_message"),
                    evidence, zone=zone)
    return ok("dns.dnssec.on", evidence, zone=zone)


async def _certificate(ctx: CheckContext) -> tuple[str, list[str]]:
    """Issuer and names of the website's certificate; ("", []) when there is no website or it is unreachable."""
    for host in await ctx.web_hosts():
        try:
            cert = await ctx.net.certificate(host)
        except NetworkError:
            continue
        return cert.issuer, list(cert.names)
    return "", []


def _caa_entries(records: list[str]) -> list[tuple[str, str]]:
    """``'0 issue "letsencrypt.org; validationmethods=dns-01"'`` → ``[("issue", "letsencrypt.org")]``."""
    entries = []
    for record in records:
        parts = record.split(None, 2)
        if len(parts) == 3:
            value = parts[2].strip().strip('"').split(";")[0].strip().lower()
            entries.append((parts[1].lower(), value))
    return entries


def _authorized(entries: list[tuple[str, str]], ca: str, wildcard: bool) -> bool:
    """Whether CAA lets ``ca`` issue the certificate (RFC 8659 §4.2 and §4.3).

    For a wildcard certificate, "issuewild" entries apply when there are any, "issue" otherwise."""
    tag = "issuewild" if wildcard and any(t == "issuewild" for t, _ in entries) else "issue"
    allowed = [value for t, value in entries if t == tag]
    return not allowed or ca in allowed  # no entry of that kind: no restriction


@extension.check("caa", category="dns", weight=2, internal=False)
async def caa(ctx: CheckContext) -> Outcome:
    """CAA records name the only authorities allowed to issue certificates for the domain."""
    owner, records = ctx.domain, []
    for name in _parents(ctx.domain):  # the closest name with CAA records applies
        records = list((await ctx.net.dns(name, "CAA")).records)
        if records:
            owner = name
            break
    issuer, names = await _certificate(ctx)
    ca = next((domain for word, domain in CAA_DOMAINS.items() if word in issuer.lower()), "")
    evidence = {"records": records, "found_at": owner, "certificate_issuer": issuer}
    if not records:
        value = ca or "letsencrypt.org"
        remedy = Remedy(5, Effort.EASY, dns=(DnsChange("add", "CAA", "@", f'0 issue "{value}"'),), how="dns.caa.how")
        return warn("dns.caa.missing", remedy, evidence, ca=value)
    if ca and not _authorized(_caa_entries(records), ca, any(n.startswith("*.") for n in names)):
        # The authority of the current certificate is no longer allowed: its next renewal will be refused.
        return warn("dns.caa.excludes_current", Remedy(5, Effort.EASY, how="dns.caa.excludes_current.how"),
                    evidence, ca=ca, issuer=issuer)
    return ok("dns.caa.present_inherited" if owner != ctx.domain else "dns.caa.present", evidence, zone=owner)
