# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""DNS of the domain: name servers, DNSSEC signature, CAA records.

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
    info,
    load_messages,
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


@extension.check("nameservers", category="dns", weight=4, internal=False)
async def nameservers(ctx: CheckContext) -> Outcome:
    """At least two name servers, so the domain still answers when one is down."""
    hosts = sorted(ns.lower().rstrip(".") for ns in (await ctx.net.dns(ctx.domain, "NS")).records)
    evidence = {"nameservers": hosts}
    if not hosts:
        return info("dns.nameservers.none", evidence)
    if len(hosts) == 1:
        return warn("dns.nameservers.single", Remedy(30, Effort.DELEGATE, message="dns.nameservers.message"),
                    evidence, host=hosts[0])
    return ok("dns.nameservers.ok", evidence, count=len(hosts))


@extension.check("dnssec", category="dns", weight=4, internal=False)
async def dnssec(ctx: CheckContext) -> Outcome:
    """A DS record at the parent zone means the domain is signed with DNSSEC."""
    ds = (await ctx.net.dns(ctx.domain, "DS")).records
    if ds:
        return ok("dns.dnssec.on", {"ds": list(ds)})
    return warn("dns.dnssec.off", Remedy(10, Effort.EASY, how="dns.dnssec.how"))


async def _certificate_issuer(ctx: CheckContext) -> str:
    """Issuer of the website's certificate, or "" when there is no website or it is unreachable."""
    for host in await ctx.web_hosts():
        try:
            return (await ctx.net.certificate(host)).issuer
        except NetworkError:
            continue
    return ""


@extension.check("caa", category="dns", weight=2, internal=False)
async def caa(ctx: CheckContext) -> Outcome:
    """CAA records name the only authorities allowed to issue certificates for the domain."""
    records = list((await ctx.net.dns(ctx.domain, "CAA")).records)
    if records:
        return ok("dns.caa.present", {"records": records})
    issuer = await _certificate_issuer(ctx)
    ca = next((domain for word, domain in CAA_DOMAINS.items() if word in issuer.lower()), "letsencrypt.org")
    remedy = Remedy(5, Effort.EASY, dns=(DnsChange("add", "CAA", "@", f'0 issue "{ca}"'),), how="dns.caa.how")
    return warn("dns.caa.missing", remedy, {"certificate_issuer": issuer}, ca=ca)
