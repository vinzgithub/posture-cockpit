# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""E-mail of the domain: who may send in its name (SPF, DKIM, DMARC) and how
mail reaches it (MX, MTA-STS, TLS reports).

The records are read by records.py; this module decides what they are worth.
A record a receiver must ignore is as good as no record (FAIL or WARN as for
a missing one); a record with a faulty value that receivers replace by the
default still works, but the fault is reported (WARN).

References: RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 7505 (null
MX), RFC 8461 (MTA-STS), RFC 8460 (TLS-RPT), RFC 8301 and 8463 (DKIM keys);
ANSSI, « Recommandations pour la mise en place d'une passerelle
d'interconnexion sécurisée ».
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

from .. import __version__
from ..core import (
    CheckContext,
    DnsChange,
    Effort,
    Extension,
    NetworkError,
    Outcome,
    Refused,
    Remedy,
    UntrustedCertificate,
    fail,
    info,
    load_messages,
    na,
    ok,
    warn,
)
from ..core.egress import parse_address
from . import LOCALES
from .records import (
    Spf,
    is_dmarc_candidate,
    is_spf,
    mta_sts_record_ok,
    mx_matches,
    parse_dkim,
    parse_dmarc,
    parse_mta_sts_policy,
    parse_spf,
    tls_rpt_problems,
)

extension = Extension("mail", name="Mail", version=__version__,
                      description="MX, SPF, DKIM, DMARC, MTA-STS and TLS reporting.",
                      messages=load_messages(LOCALES, "mail"))

SPF_LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4: more DNS lookups than this and SPF fails for everyone
# DKIM selectors cannot be listed; these are the ones mail services use most often.
DKIM_SELECTORS = ("default", "dkim", "mail", "selector1", "selector2", "google", "k1", "k2", "s1", "s2",
                  "protonmail", "protonmail2", "fm1", "fm2", "zoho", "mxvault", "smtp", "key1")
MTA_STS_MIN_MAX_AGE = 86_400  # a policy cached for less than a day protects little (RFC 8461 §3.2: "weeks")
DMARC_TREE_WALK = 5  # parent names searched for an inherited DMARC policy


# ---------------------------------------------------------------- helpers
async def _mx_hosts(ctx: CheckContext) -> list[str]:
    """Hosts of the MX records; empty for a domain that receives no mail ("0 ." null MX, or no MX)."""
    async def find() -> list[str]:
        records = (await ctx.net.dns(ctx.domain, "MX")).records
        hosts = [r.split()[-1].lower().rstrip(".") for r in records]
        return [h for h in hosts if h]

    return await ctx.shared("mx_hosts", find)


def _tags_text(errors: tuple[tuple[str, str], ...]) -> str:
    return ", ".join(f"{name}={value}" if value else name for name, value in errors)


# --------------------------------------------------------------------- MX
@extension.check("mx", category="mail", weight=1, internal=False)
async def mx(ctx: CheckContext) -> Outcome:
    """Where the domain's mail goes. Information, unless a server cannot be reached by name."""
    records = list((await ctx.net.dns(ctx.domain, "MX")).records)
    hosts = await _mx_hosts(ctx)
    evidence: dict[str, object] = {"mx": records}
    if not hosts:
        return info("mail.mx.none", evidence)
    if len(hosts) < len(records):  # a null MX next to real ones (RFC 7505 §3: MUST NOT)
        return warn("mail.mx.null_mixed", Remedy(10, Effort.MEDIUM, how="mail.mx.null_mixed.how"), evidence)
    literal = [h for h in hosts if parse_address(h) is not None]
    if literal:  # RFC 5321 §5.1: an MX names a host, not an address
        return warn("mail.mx.address", Remedy(10, Effort.MEDIUM, how="mail.mx.address.how"), evidence,
                    hosts=", ".join(literal))
    unresolved = []
    for host in hosts:
        try:
            answers = await asyncio.gather(ctx.net.dns(host, "A"), ctx.net.dns(host, "AAAA"))
        except NetworkError:
            continue  # no answer is not proof of absence
        if not any(a.records for a in answers):
            unresolved.append(host)
    if unresolved:
        evidence["unresolved"] = unresolved
        return warn("mail.mx.unresolved", Remedy(15, Effort.DELEGATE, message="mail.mx.message"), evidence,
                    hosts=", ".join(unresolved), n=len(unresolved))
    return info("mail.mx.list", evidence, hosts=", ".join(hosts))


# -------------------------------------------------------------------- SPF
@dataclass
class _SpfTree:
    """What an SPF record pulls in through its includes and redirect."""

    lookups: int = 0
    missing: list[str] = field(default_factory=list)  # targets without exactly one SPF record: permerror
    invalid: list[str] = field(default_factory=list)  # included records with syntax errors


async def _spf_walk(ctx: CheckContext, record: Spf, seen: set[str], depth: int, tree: _SpfTree) -> None:
    tree.lookups += record.lookups
    for target in record.includes + ([record.redirect] if record.redirect else []):
        target = target.lower().rstrip(".")
        if "%" in target or target in seen or depth >= SPF_LOOKUP_LIMIT:
            continue  # macros depend on the sender; loops and depth are bounded by the lookup limit anyway
        seen.add(target)
        found = [r for r in (await ctx.net.dns(target, "TXT")).records if is_spf(r)]
        if len(found) != 1:
            tree.missing.append(target)  # RFC 7208 §5.2 and §6.1
            continue
        included = parse_spf(found[0])
        if included.errors:
            tree.invalid.append(f"{target}: {' '.join(included.errors)}")
        await _spf_walk(ctx, included, seen, depth + 1, tree)


@extension.check("spf", category="mail", weight=8, internal=False)
async def spf(ctx: CheckContext) -> Outcome:
    """SPF lists the servers allowed to send mail for the domain."""
    records = [r for r in await ctx.txt(ctx.domain) if is_spf(r)]
    if not records:
        # A domain that sends no mail at all says so with "-all" only.
        value = "v=spf1 mx ~all" if await _mx_hosts(ctx) else "v=spf1 -all"
        return fail("mail.spf.missing", Remedy(10, Effort.EASY, dns=(DnsChange("add", "TXT", "@", value),),
                                               how="mail.spf.how"))
    evidence: dict[str, object] = {"records": records}
    if len(records) > 1:
        return fail("mail.spf.multiple", Remedy(15, Effort.MEDIUM, how="mail.spf.multiple.how"), evidence)
    record = parse_spf(records[0])
    if record.errors:
        evidence["errors"] = list(record.errors)
        return fail("mail.spf.syntax", Remedy(10, Effort.MEDIUM, how="mail.spf.syntax.how"), evidence,
                    terms=" ".join(record.errors))
    tree = _SpfTree()
    await _spf_walk(ctx, record, {ctx.domain}, 0, tree)
    evidence["lookups"] = tree.lookups
    if tree.missing or tree.invalid:
        evidence.update(missing=tree.missing, invalid=tree.invalid)
        return fail("mail.spf.broken_include", Remedy(15, Effort.MEDIUM, how="mail.spf.broken_include.how"),
                    evidence, targets=", ".join(tree.missing + [i.split(":")[0] for i in tree.invalid]))
    if tree.lookups > SPF_LOOKUP_LIMIT:
        return fail("mail.spf.too_many_lookups", Remedy(30, Effort.DELEGATE, message="mail.spf.lookups.message"),
                    evidence, count=tree.lookups, limit=SPF_LOOKUP_LIMIT)
    qualifier = record.all_qualifier
    if qualifier == "+":
        return fail("mail.spf.pass_all", Remedy(10, Effort.MEDIUM, how="mail.spf.pass_all.how"), evidence)
    if qualifier == "?":
        return warn("mail.spf.neutral", Remedy(10, Effort.MEDIUM, how="mail.spf.neutral.how"), evidence)
    if qualifier is None and record.redirect is None:
        return warn("mail.spf.no_all", Remedy(10, Effort.MEDIUM, how="mail.spf.neutral.how"), evidence)
    if record.uses_ptr:  # RFC 7208 §5.5: "SHOULD NOT be published"
        return warn("mail.spf.ptr", Remedy(10, Effort.MEDIUM, how="mail.spf.ptr.how"), evidence)
    return ok("mail.spf.ok", evidence, policy=f"{qualifier}all" if qualifier else "redirect")


# ------------------------------------------------------------------ DMARC
async def _dmarc_records(ctx: CheckContext) -> tuple[str, list[str]]:
    """RFC 9989 DNS Tree Walk, bounded to the DNS name's parents.

    An exact record wins. Otherwise a record with psd=n identifies an
    organizational domain, while psd=y identifies a public-suffix policy.
    With no explicit markers, the nearest ancestor is used as a conservative
    legacy-compatible fallback. Never inspect the TLD itself.
    """
    labels = ctx.domain.lower().rstrip(".").split(".")
    candidates: list[tuple[str, list[str], str]] = []
    for start in range(len(labels) - 1):
        name = ".".join(labels[start:])
        records = [r for r in await ctx.txt(f"_dmarc.{name}") if is_dmarc_candidate(r)]
        if not records:
            continue
        parsed = parse_dmarc(records[0]) if len(records) == 1 else None
        marker = parsed.psd if parsed is not None and parsed.starts_right else "u"
        candidates.append((name, records, marker))
        if start == 0:
            return name, records  # exact-domain policy, even when invalid/multiple
        if marker == "n":
            return name, records
    for name, records, marker in candidates:
        if marker != "y":
            return name, records
    for name, records, marker in candidates:
        if marker == "y":
            return name, records
    return ctx.domain, []


@extension.check("dmarc", category="mail", weight=10, internal=False)
async def dmarc(ctx: CheckContext) -> Outcome:
    """DMARC tells receiving servers what to do with mail that fails SPF and DKIM."""
    owner, candidates = await _dmarc_records(ctx)
    first_step = f"v=DMARC1; p=none; rua=mailto:dmarc@{ctx.domain}"
    add_first_step = Remedy(10, Effort.EASY, how="mail.dmarc.how", dns=(DnsChange("add", "TXT", "_dmarc", first_step),))
    if not candidates:
        return fail("mail.dmarc.missing", add_first_step)
    evidence: dict[str, object] = {"records": candidates, "found_at": f"_dmarc.{owner}"}
    inherited = owner != ctx.domain
    valid = [r for r in candidates if parse_dmarc(r).starts_right]
    if not valid:
        # RFC 7489 §6.6.3: a record that does not start with "v=DMARC1" is discarded.
        return fail("mail.dmarc.malformed", Remedy(10, Effort.EASY, how="mail.dmarc.malformed.how"), evidence,
                    name=f"_dmarc.{owner}")
    if len(valid) > 1:
        return fail("mail.dmarc.multiple", Remedy(10, Effort.MEDIUM, how="mail.dmarc.multiple.how"), evidence,
                    name=f"_dmarc.{owner}")
    record = parse_dmarc(valid[0])
    evidence["tags"] = record.tags
    policy = record.subdomain_policy if inherited else record.policy
    if inherited and record.psd == "y":
        policy = record.tags.get("sp", record.tags.get("p", "none")).lower()
    params: dict[str, str | int] = {"policy": policy or "", "parent": owner}
    if policy is None:
        evidence["errors"] = [list(e) for e in record.errors]
        return fail("mail.dmarc.invalid", Remedy(10, Effort.EASY, how="mail.dmarc.how", dns=() if inherited else (
            DnsChange("delete", "TXT", "_dmarc", valid[0]), DnsChange("add", "TXT", "_dmarc", first_step))),
            evidence, name=f"_dmarc.{owner}")
    if policy == "none":
        if inherited:
            return warn("mail.dmarc.monitoring_inherited", Remedy(10, Effort.MEDIUM, how="mail.dmarc.monitoring.how"),
                        evidence, **params)
        # Next step once the reports show that legitimate mail passes: quarantine.
        stricter = re.sub(r"(?<![a-z])p\s*=\s*none", "p=quarantine", valid[0], count=1, flags=re.IGNORECASE)
        return warn("mail.dmarc.monitoring", Remedy(10, Effort.MEDIUM, how="mail.dmarc.monitoring.how",
                                                    dns=(DnsChange("delete", "TXT", "_dmarc", valid[0]),
                                                         DnsChange("add", "TXT", "_dmarc", stricter))),
                    evidence)
    if record.errors:
        evidence["errors"] = [list(e) for e in record.errors]
        return warn("mail.dmarc.syntax", Remedy(5, Effort.EASY, how="mail.dmarc.syntax.how"), evidence,
                    tags=_tags_text(record.errors), name=f"_dmarc.{owner}", **params)
    if record.pct < 100:
        return warn("mail.dmarc.partial", Remedy(5, Effort.MEDIUM, how="mail.dmarc.partial.how"), evidence,
                    pct=record.pct, **params)
    if not inherited and record.subdomain_policy == "none":
        return warn("mail.dmarc.subdomains_open", Remedy(5, Effort.MEDIUM, how="mail.dmarc.subdomains_open.how"),
                    evidence, **params)
    return ok("mail.dmarc.enforced_inherited" if inherited else "mail.dmarc.enforced", evidence, **params)


# ------------------------------------------------------------------- DKIM
@extension.check("dkim", category="mail", weight=4, internal=False)
async def dkim(ctx: CheckContext) -> Outcome:
    """DKIM signs outgoing mail. Its keys are only found by guessing their name (the selector)."""
    answers = await asyncio.gather(*(ctx.txt(f"{s}._domainkey.{ctx.domain}") for s in DKIM_SELECTORS))
    keys = {}
    for selector, records in zip(DKIM_SELECTORS, answers, strict=True):
        key = next((k for k in map(parse_dkim, records) if k is not None), None)
        if key is not None:
            keys[selector] = key
    evidence = {"selectors": {s: "revoked" if k.revoked else f"{k.key_type} {k.bits}" if k.readable else "unreadable"
                              for s, k in keys.items()}}
    usable = {s: k for s, k in keys.items() if k.readable}
    broken = sorted(s for s, k in keys.items() if not k.readable and not k.revoked)
    if not usable and not broken:
        # Not found under the usual names, or withdrawn: nothing can be concluded either way.
        return info("mail.dkim.not_found", {"selectors_tried": list(DKIM_SELECTORS), **evidence})
    rsa_sizes = {s: k.bits for s, k in usable.items() if k.key_type == "rsa"}
    weakest = min(rsa_sizes.values(), default=0)
    weak_selectors = ", ".join(sorted(s for s, bits in rsa_sizes.items() if bits == weakest))
    remedy = Remedy(20, Effort.DELEGATE, message="mail.dkim.message")
    if rsa_sizes and weakest < 1024:  # RFC 8301 §3.2: verifiers must not accept them
        return fail("mail.dkim.weak_key", remedy, evidence, bits=weakest, selectors=weak_selectors)
    if broken:
        return warn("mail.dkim.unreadable", Remedy(20, Effort.DELEGATE, message="mail.dkim.unreadable.message"),
                    evidence, selectors=", ".join(broken))
    if rsa_sizes and weakest < 2048:
        return warn("mail.dkim.short_key", remedy, evidence, bits=weakest, selectors=weak_selectors)
    return ok("mail.dkim.found", evidence, selectors=", ".join(sorted(usable)))


# ---------------------------------------------------------------- MTA-STS
@extension.check("mta_sts", category="mail", weight=3, internal=False)
async def mta_sts(ctx: CheckContext) -> Outcome:
    """MTA-STS makes the servers that deliver mail to the domain insist on encryption."""
    mx_hosts = await _mx_hosts(ctx)
    if not mx_hosts:
        return na("mail.no_inbound")
    records = [r for r in await ctx.txt(f"_mta-sts.{ctx.domain}") if r.lower().startswith("v=stsv1")]
    remedy = Remedy(30, Effort.DELEGATE, message="mail.mta_sts.message")
    if not records:
        return warn("mail.mta_sts.missing", remedy)
    evidence: dict[str, object] = {"records": records}
    if len(records) > 1 or not mta_sts_record_ok(records[0]):
        return warn("mail.mta_sts.bad_record", remedy, evidence)  # §3.1: senders then ignore MTA-STS
    host = f"mta-sts.{ctx.domain}"
    url = f"https://{host}/.well-known/mta-sts.txt"
    evidence["url"] = url
    if not any([(await ctx.net.dns(host, "A")).records, (await ctx.net.dns(host, "AAAA")).records]):
        return warn("mail.mta_sts.no_policy", remedy, evidence)
    try:
        # §3.3: the policy only counts when served over HTTPS with a valid certificate, without redirect.
        reply = await ctx.net.http_get(url, verify=True)
    except UntrustedCertificate as e:
        evidence["certificate"] = e.problem
        return warn("mail.mta_sts.bad_certificate", remedy, evidence, problem=e.problem)
    except Refused:
        return warn("mail.mta_sts.no_policy", remedy, evidence)  # nothing serves the policy (a timeout says less)
    evidence["status"] = reply.status
    if reply.status != 200:
        return warn("mail.mta_sts.no_policy", remedy, evidence)
    policy = parse_mta_sts_policy(reply.body)
    evidence.update(mode=policy.mode, mx_patterns=list(policy.mx), max_age=policy.max_age)
    if policy.errors:
        return warn("mail.mta_sts.bad_policy", remedy, evidence, fields=", ".join(policy.errors))
    if policy.mode == "none":
        return warn("mail.mta_sts.disabled", remedy, evidence)
    uncovered = [h for h in mx_hosts if not any(mx_matches(p, h) for p in policy.mx)]
    if uncovered:
        evidence["uncovered"] = uncovered
        # In "enforce" mode, senders refuse to deliver to a server the policy does not list.
        outcome = fail if policy.mode == "enforce" else warn
        return outcome("mail.mta_sts.mx_mismatch", Remedy(15, Effort.DELEGATE, message="mail.mta_sts.mx_message"),
                       evidence, hosts=", ".join(uncovered), n=len(uncovered), mode=policy.mode)
    if policy.mode == "testing":
        return warn("mail.mta_sts.testing", Remedy(10, Effort.DELEGATE, message="mail.mta_sts.enforce_message"),
                    evidence, mode=policy.mode)
    if policy.max_age is not None and policy.max_age < MTA_STS_MIN_MAX_AGE:
        return warn("mail.mta_sts.short_max_age", Remedy(5, Effort.DELEGATE, message="mail.mta_sts.max_age_message"),
                    evidence, seconds=policy.max_age)
    return ok("mail.mta_sts.enforce", evidence)


# ---------------------------------------------------------------- TLS-RPT
@extension.check("tls_rpt", category="mail", weight=1, internal=False)
async def tls_rpt(ctx: CheckContext) -> Outcome:
    """TLS reports tell the domain when mail could not be delivered over an encrypted connection."""
    if not await _mx_hosts(ctx):
        return na("mail.no_inbound")
    records = [r for r in await ctx.txt(f"_smtp._tls.{ctx.domain}") if r.lower().startswith("v=tlsrptv1")]
    value = f"v=TLSRPTv1; rua=mailto:tls-reports@{ctx.domain}"
    if not records:
        return warn("mail.tls_rpt.missing", Remedy(5, Effort.EASY, dns=(DnsChange("add", "TXT", "_smtp._tls", value),),
                                                   how="mail.tls_rpt.how"))
    problems = ["several records"] if len(records) > 1 else tls_rpt_problems(records[0])
    if problems:  # RFC 8460 §3: senders then send no report at all
        return warn("mail.tls_rpt.invalid", Remedy(5, Effort.EASY, how="mail.tls_rpt.invalid.how"),
                    {"records": records, "problems": problems}, problems=", ".join(problems))
    return ok("mail.tls_rpt.present", {"record": records[0]})
