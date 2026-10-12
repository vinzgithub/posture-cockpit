# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""E-mail of the domain: who may send in its name (SPF, DKIM, DMARC) and how
mail reaches it (MTA-STS, TLS reports).

References: RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 8461
(MTA-STS), RFC 8460 (TLS-RPT), RFC 8301 (DKIM key sizes); ANSSI, « Recommandations
pour la mise en place d'une passerelle d'interconnexion sécurisée ».
"""

from __future__ import annotations

import base64
import binascii
import re

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

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
    info,
    load_messages,
    ok,
    warn,
)
from . import LOCALES

extension = Extension("mail", name="Messagerie", version=__version__,
                      description="SPF, DKIM, DMARC, MTA-STS and TLS reporting.",
                      messages=load_messages(LOCALES, "mail"))

SPF_LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4: more DNS lookups than this and SPF fails for everyone
# DKIM selectors cannot be listed; these are the ones mail services use most often.
DKIM_SELECTORS = ("default", "dkim", "mail", "selector1", "selector2", "google", "k1", "k2", "s1", "s2",
                  "protonmail", "protonmail2", "fm1", "fm2", "zoho", "mxvault", "smtp", "key1")


# ---------------------------------------------------------------- helpers
def _is_spf(record: str) -> bool:
    return record.lower() == "v=spf1" or record.lower().startswith("v=spf1 ")


def _tags(record: str) -> dict[str, str]:
    """``"v=DMARC1; p=none; rua=mailto:x"`` → ``{"v": "DMARC1", "p": "none", "rua": "mailto:x"}``."""
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


async def _mx_hosts(ctx: CheckContext) -> list[str]:
    async def find() -> list[str]:
        records = (await ctx.net.dns(ctx.domain, "MX")).records
        hosts = [r.split()[-1].lower().rstrip(".") for r in records]
        return [h for h in hosts if h]  # "0 ." is a null MX: the domain receives no mail

    return await ctx.shared("mx_hosts", find)


async def _spf_lookups(ctx: CheckContext, record: str, seen: set[str], depth: int = 0) -> int:
    """DNS lookups an SPF record needs, counting its includes and redirect recursively."""
    count = 0
    for term in record.split()[1:]:
        term = term.lower().lstrip("+-~?")
        mechanism = re.split(r"[:/=]", term, maxsplit=1)[0]
        if mechanism in ("a", "mx", "ptr", "exists"):
            count += 1
        elif mechanism in ("include", "redirect"):
            count += 1
            target = re.split(r"[:=]", term, maxsplit=1)[1] if re.search(r"[:=]", term) else ""
            if target and "%" not in target and target not in seen and depth < SPF_LOOKUP_LIMIT:
                seen.add(target)
                included = [r for r in await ctx.txt(target) if _is_spf(r)]
                if included:
                    count += await _spf_lookups(ctx, included[0], seen, depth + 1)
    return count


# ------------------------------------------------------------------ checks
@extension.check("mx", category="mail", weight=1)
async def mx(ctx: CheckContext) -> Outcome:
    """Where the domain's mail goes. Information only: it helps read the other checks."""
    hosts = await _mx_hosts(ctx)
    if not hosts:
        return info("mail.mx.none")
    return info("mail.mx.list", {"mx": hosts}, hosts=", ".join(hosts))


@extension.check("spf", category="mail", weight=8)
async def spf(ctx: CheckContext) -> Outcome:
    """SPF lists the servers allowed to send mail for the domain."""
    records = [r for r in await ctx.txt(ctx.domain) if _is_spf(r)]
    if not records:
        # A domain that sends no mail at all says so with "-all" only.
        value = "v=spf1 mx ~all" if await _mx_hosts(ctx) else "v=spf1 -all"
        return fail("mail.spf.missing", Remedy(10, Effort.EASY, dns=(DnsChange("add", "TXT", "@", value),),
                                               how="mail.spf.how"))
    evidence: dict[str, object] = {"records": records}
    if len(records) > 1:
        return fail("mail.spf.multiple", Remedy(15, Effort.MEDIUM, how="mail.spf.multiple.how"), evidence)
    record = records[0]
    terms = [t.lower() for t in record.split()[1:]]
    all_term = next((t for t in terms if t.lstrip("+-~?") == "all"), "")
    lookups = await _spf_lookups(ctx, record, {ctx.domain})
    evidence["lookups"] = lookups
    if lookups > SPF_LOOKUP_LIMIT:
        return fail("mail.spf.too_many_lookups", Remedy(30, Effort.DELEGATE, message="mail.spf.lookups.message"),
                    evidence, count=lookups, limit=SPF_LOOKUP_LIMIT)
    if all_term in ("all", "+all"):
        return fail("mail.spf.pass_all", Remedy(10, Effort.MEDIUM, how="mail.spf.pass_all.how"), evidence)
    if all_term == "?all":
        return warn("mail.spf.neutral", Remedy(10, Effort.MEDIUM, how="mail.spf.neutral.how"), evidence)
    if not all_term and not any(t.startswith("redirect=") for t in terms):
        return warn("mail.spf.no_all", Remedy(10, Effort.MEDIUM, how="mail.spf.neutral.how"), evidence)
    return ok("mail.spf.ok", evidence, policy=all_term or "redirect")


@extension.check("dmarc", category="mail", weight=10)
async def dmarc(ctx: CheckContext) -> Outcome:
    """DMARC tells receiving servers what to do with mail that fails SPF and DKIM."""
    name = f"_dmarc.{ctx.domain}"
    records = [r for r in await ctx.txt(name) if r.replace(" ", "").lower().startswith("v=dmarc1")]
    first_step = f"v=DMARC1; p=none; rua=mailto:dmarc@{ctx.domain}"
    if not records:
        return fail("mail.dmarc.missing", Remedy(10, Effort.EASY, how="mail.dmarc.how",
                                                 dns=(DnsChange("add", "TXT", "_dmarc", first_step),)))
    evidence: dict[str, object] = {"records": records}
    if len(records) > 1:
        return fail("mail.dmarc.multiple", Remedy(10, Effort.MEDIUM, how="mail.dmarc.multiple.how"), evidence)
    record = records[0]
    tags = _tags(record)
    policy = tags.get("p", "").lower()
    evidence["tags"] = tags
    if policy == "none":
        # Next step once the reports show that legitimate mail passes: quarantine.
        stricter = re.sub(r"p\s*=\s*none", "p=quarantine", record, count=1, flags=re.IGNORECASE)
        return warn("mail.dmarc.monitoring", Remedy(10, Effort.MEDIUM, how="mail.dmarc.monitoring.how",
                                                    dns=(DnsChange("delete", "TXT", "_dmarc", record),
                                                         DnsChange("add", "TXT", "_dmarc", stricter))),
                    evidence)
    if policy not in ("quarantine", "reject"):
        return fail("mail.dmarc.invalid", Remedy(10, Effort.EASY, how="mail.dmarc.how",
                                                 dns=(DnsChange("delete", "TXT", "_dmarc", record),
                                                      DnsChange("add", "TXT", "_dmarc", first_step))),
                    evidence)
    pct = tags.get("pct", "100")
    if pct.isdigit() and int(pct) < 100:
        return warn("mail.dmarc.partial", Remedy(5, Effort.MEDIUM, how="mail.dmarc.partial.how"), evidence,
                    policy=policy, pct=int(pct))
    return ok("mail.dmarc.enforced", evidence, policy=policy)


@extension.check("dkim", category="mail", weight=4)
async def dkim(ctx: CheckContext) -> Outcome:
    """DKIM signs outgoing mail. Its keys are only found by guessing their name (the selector)."""
    found: dict[str, int] = {}
    for selector in DKIM_SELECTORS:
        for record in await ctx.txt(f"{selector}._domainkey.{ctx.domain}"):
            key = _tags(record).get("p", "")
            if key:
                found[selector] = _rsa_bits(key)
    if not found:
        return info("mail.dkim.not_found", {"selectors_tried": list(DKIM_SELECTORS)})
    evidence = {"selectors": found}
    weakest = min(found.values())
    selectors = ", ".join(sorted(found))
    if 0 < weakest < 1024:
        return fail("mail.dkim.weak_key", Remedy(20, Effort.DELEGATE, message="mail.dkim.message"), evidence,
                    bits=weakest, selectors=selectors)
    if 0 < weakest < 2048:
        return warn("mail.dkim.short_key", Remedy(20, Effort.DELEGATE, message="mail.dkim.message"), evidence,
                    bits=weakest, selectors=selectors)
    return ok("mail.dkim.found", evidence, selectors=selectors)


def _rsa_bits(key_base64: str) -> int:
    """Size of an RSA key published in DKIM, 0 for other key types (Ed25519) or unreadable keys."""
    try:
        key = load_der_public_key(base64.b64decode(re.sub(r"\s", "", key_base64)))
    except (ValueError, binascii.Error):
        return 0
    return key.key_size if isinstance(key, rsa.RSAPublicKey) else 0


@extension.check("mta_sts", category="mail", weight=3)
async def mta_sts(ctx: CheckContext) -> Outcome:
    """MTA-STS makes the servers that deliver mail to the domain insist on encryption."""
    if not await _mx_hosts(ctx):
        return info("mail.no_inbound")
    records = [r for r in await ctx.txt(f"_mta-sts.{ctx.domain}") if r.lower().startswith("v=stsv1")]
    remedy = Remedy(30, Effort.DELEGATE, message="mail.mta_sts.message")
    if not records:
        return warn("mail.mta_sts.missing", remedy)
    url = f"https://mta-sts.{ctx.domain}/.well-known/mta-sts.txt"
    try:
        reply = await ctx.net.http_get(url)
    except NetworkError:
        return warn("mail.mta_sts.no_policy", remedy, {"url": url})
    mode = next((line.split(":", 1)[1].strip().lower() for line in reply.body.splitlines()
                 if line.lower().startswith("mode:")), "")
    evidence = {"record": records[0], "url": url, "mode": mode}
    if reply.status != 200 or not mode:
        return warn("mail.mta_sts.no_policy", remedy, evidence)
    if mode != "enforce":
        return warn("mail.mta_sts.testing", Remedy(10, Effort.DELEGATE, message="mail.mta_sts.enforce_message"),
                    evidence, mode=mode)
    return ok("mail.mta_sts.enforce", evidence)


@extension.check("tls_rpt", category="mail", weight=1)
async def tls_rpt(ctx: CheckContext) -> Outcome:
    """TLS reports tell the domain when mail could not be delivered over an encrypted connection."""
    if not await _mx_hosts(ctx):
        return info("mail.no_inbound")
    records = [r for r in await ctx.txt(f"_smtp._tls.{ctx.domain}") if r.lower().startswith("v=tlsrptv1")]
    if records:
        return ok("mail.tls_rpt.present", {"record": records[0]})
    value = f"v=TLSRPTv1; rua=mailto:tls-reports@{ctx.domain}"
    return warn("mail.tls_rpt.missing", Remedy(5, Effort.EASY, dns=(DnsChange("add", "TXT", "_smtp._tls", value),),
                                               how="mail.tls_rpt.how"))
