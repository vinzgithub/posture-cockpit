# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""E-mail of the domain: who may send in its name (SPF, DKIM, DMARC) and how
mail reaches it (MX, MTA-STS, TLS reports).

The records are read by records.py; this module decides what they are worth.
A record a receiver must ignore is as good as no record (FAIL or WARN as for
a missing one); a record with a faulty value that receivers replace by the
default still works, but the fault is reported (WARN).

Version 0.7: mail.smtp_starttls tests STARTTLS and the certificates of the MX
on port 25, from this instance, when the instance turns the probe on
(smtp_measure.py observes, smtp_verdict.py decides). It reads the MTA-STS
policy with mail.mta_sts: one reading per scan (``_mta_sts_reading``), whose
results mail.mta_sts turns into the same findings as before.

References: RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 7505 (null
MX), RFC 8461 (MTA-STS), RFC 8460 (TLS-RPT), RFC 3207 (STARTTLS), RFC 8301 and
8463 (DKIM keys);
ANSSI, « Recommandations pour la mise en place d'une passerelle
d'interconnexion sécurisée ».
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

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
from ..core.network import mx_record
from . import LOCALES
from .records import (
    Dmarc,
    MtaStsPolicy,
    Spf,
    is_dmarc_candidate,
    is_spf,
    mta_sts_record_ok,
    mx_matches,
    parse_dkim,
    parse_dmarc,
    parse_mta_sts_policy,
    parse_spf,
    tags,
    tls_rpt_problems,
)

if TYPE_CHECKING:
    from .smtp_measure import ProbeResult
    from .smtp_verdict import PolicyView

log = logging.getLogger(__name__)

extension = Extension("mail", name="Mail", version=__version__,
                      description="MX, SPF, DKIM, DMARC, MTA-STS and TLS reporting.",
                      messages=load_messages(LOCALES, "mail"))

SPF_LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4: more DNS lookups than this and SPF fails for everyone
# DKIM selectors cannot be listed; these are the ones mail services use most often.
DKIM_SELECTORS = ("default", "dkim", "mail", "selector1", "selector2", "google", "k1", "k2", "s1", "s2",
                  "protonmail", "protonmail2", "fm1", "fm2", "zoho", "mxvault", "smtp", "key1")
_DKIM_SELECTOR_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?", re.IGNORECASE)
MAX_DKIM_SELECTORS = 30


def dkim_selectors(custom: str | None = None) -> tuple[str, ...]:
    """Common names plus administrator-provided DNS selectors, bounded per scan.

    ``custom``: the value of POSTURE_COCKPIT_DKIM_SELECTORS, read from the environment when None.
    An invalid value raises ValueError; Config.from_env checks it when the instance starts."""
    values = list(DKIM_SELECTORS)
    if custom is None:
        custom = os.environ.get("POSTURE_COCKPIT_DKIM_SELECTORS", "")
    if custom:
        for raw in custom.split(","):
            selector = raw.strip().lower()
            if not _DKIM_SELECTOR_PATTERN.fullmatch(selector):
                raise ValueError(f"Invalid DKIM selector: {selector!r}")
            if selector not in values:
                values.append(selector)
    if len(values) > MAX_DKIM_SELECTORS:
        raise ValueError("Too many DKIM selectors (max 30)")
    return tuple(values)


MTA_STS_MIN_MAX_AGE = 86_400  # a policy cached for less than a day protects little (RFC 8461 §3.2: "weeks")


# ---------------------------------------------------------------- helpers
async def _mx_records(ctx: CheckContext) -> list[tuple[int | None, str]]:
    """(preference, host) of each MX record, in the order the DNS gave them, read once per scan.

    The host in lower case without the root's dot, ``""`` for the null MX "0 ." (RFC 7505), duplicates
    kept (:func:`~posture_cockpit.core.network.mx_record`). Version 0.7: the SMTP probe reads the MX
    here too, so that it probes exactly the servers the mail checks judge. Callers must not change
    the list: it is shared."""
    async def find() -> list[tuple[int | None, str]]:
        return [mx_record(r) for r in (await ctx.net.dns(ctx.domain, "MX")).records]

    return await ctx.shared("mx_records", find)


async def _mx_hosts(ctx: CheckContext) -> list[str]:
    """Hosts of the MX records; empty for a domain that receives no mail ("0 ." null MX, or no MX).

    In the DNS order, duplicates kept, as before version 0.7 (tests/test_v070_mail_mx_records.py)."""
    return [host for _, host in await _mx_records(ctx) if host]


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
async def _dmarc_records(ctx: CheckContext) -> tuple[str, list[str], list[str]]:
    """RFC 9989 §4.10: at most eight DNS queries, including the exact domain.

    Exact records have priority. Ancestor discovery retains the highest
    organizational record (fewest labels), stopping at psd=n or psd=y.
    PSD policies are selected only in the absence of an organizational record.
    """
    labels = ctx.domain.lower().rstrip(".").split(".")
    own = ctx.domain.lower().rstrip(".")
    own_records = [r for r in await ctx.txt(f"_dmarc.{own}") if is_dmarc_candidate(r)]
    valid_own = [r for r in own_records if parse_dmarc(r).starts_right]
    if len(valid_own) == 1:
        return own, valid_own, []
    # Multiple or malformed local policies are unusable for DMARC discovery.
    # Search for a valid organizational/PSD policy instead. Retain the broken
    # local records for an actionable diagnosis when nothing is inherited.
    # The initial query counts toward the eight-query bound.
    first_parent = max(1, len(labels) - 7)
    discovered: list[tuple[str, list[str]]] = []
    for start in range(first_parent, len(labels)):
        name = ".".join(labels[start:])
        records = [r for r in await ctx.txt(f"_dmarc.{name}") if is_dmarc_candidate(r)]
        valid = [r for r in records if parse_dmarc(r).starts_right]
        if len(valid) != 1:
            continue  # Multiple/invalid records cannot establish an inherited policy.
        record = parse_dmarc(valid[0])
        if record.psd == "n":
            return name, valid, own_records if len(valid_own) > 1 else []
        if record.psd == "y":
            # RFC 9989: the organizational domain is exactly one label below
            # the PSD. A policy at any deeper intermediate name does not
            # supersede the PSD policy unless it is the organizational domain.
            organizational = ".".join(labels[start - 1:])
            selected = next((item for item in discovered if item[0] == organizational), (name, valid))
            return *selected, own_records if len(valid_own) > 1 else []
        discovered.append((name, valid))
    if discovered:
        return *discovered[-1], own_records if len(valid_own) > 1 else []
    return own, own_records, []


@extension.check("dmarc", category="mail", weight=10, internal=False)
async def dmarc(ctx: CheckContext) -> Outcome:
    """DMARC tells receiving servers what to do with mail that fails SPF and DKIM."""
    owner, candidates, ignored_local = await _dmarc_records(ctx)
    first_step = f"v=DMARC1; p=none; rua=mailto:dmarc@{ctx.domain}"
    add_first_step = Remedy(10, Effort.EASY, how="mail.dmarc.how", dns=(DnsChange("add", "TXT", "_dmarc", first_step),))
    if not candidates:
        return fail("mail.dmarc.missing", add_first_step)
    evidence: dict[str, object] = {"records": candidates, "found_at": f"_dmarc.{owner}"}
    inherited = owner != ctx.domain
    if ignored_local:
        evidence["ignored_local_records"] = ignored_local
        evidence["ignored_local_at"] = f"_dmarc.{ctx.domain}"
    valid = [r for r in candidates if parse_dmarc(r).starts_right]
    if not valid:
        # RFC 9989 §4.10: a record that does not start with "v=DMARC1" is discarded.
        return fail("mail.dmarc.malformed", Remedy(10, Effort.EASY, how="mail.dmarc.malformed.how"), evidence,
                    name=f"_dmarc.{owner}")
    if len(valid) > 1:
        return fail("mail.dmarc.multiple", Remedy(10, Effort.MEDIUM, how="mail.dmarc.multiple.how"), evidence,
                    name=f"_dmarc.{owner}")
    record = parse_dmarc(valid[0])
    evidence["tags"] = record.tags
    # RFC 9989 §4.10.1: np applies only to an NXDOMAIN (not NODATA).
    # A TXT query for _dmarc.DOMAIN does not establish whether DOMAIN exists.
    policy = record.policy
    if inherited:
        policy = record.subdomain_policy
        if record.non_existent_policy is not None:
            try:
                exists = (await ctx.net.dns(ctx.domain, "A")).exists
            except NetworkError:
                evidence["existence"] = "unknown"
                return warn("mail.dmarc.existence_unknown", Remedy(5, Effort.DELEGATE), evidence,
                            parent=owner)
            evidence["existence"] = "existing" if exists else "nxdomain"
            if not exists:
                policy = record.non_existent_policy
    params: dict[str, str | int] = {"policy": policy or "", "parent": owner}
    if record.errors:
        evidence["errors"] = [list(e) for e in record.errors]
    # One check, one verdict, chosen in this order: invalid policy, t=y, p=none, faulty values,
    # pct, sp=none, local records ignored. Each other anomaly of the record is kept as a note,
    # shown after the verdict on every page and report (i18n.finding_summary): none disappears
    # behind the verdict. Notes are translation keys with their parameters, never sentences.
    enforced = policy in ("quarantine", "reject")
    # An invalid policy (p, sp, np) is named by the verdict itself: the note lists the other faulty values.
    policy_errors = tuple(e for e in record.errors if e[0] in {"p", "sp", "np"})
    invalid_policy = policy is None or record.policy is None or bool(policy_errors)
    repeated = _repeated_tags(valid[0])
    # The values the syntax note lists: not those the verdict names, not the repeated tags (their own note).
    other_errors = tuple(e for e in record.errors if e not in policy_errors and e[0] not in repeated)
    anomalies: dict[str, tuple[str, dict[str, str | int]]] = {}
    if other_errors:
        anomalies["syntax"] = ("mail.dmarc.note.syntax", {"name": f"_dmarc.{owner}", "tags": _tags_text(other_errors)})
    if repeated:
        # RFC 9989 §4.7: DMARC records follow the tag-value syntax of DKIM, where a repeated tag makes
        # the whole tag-list invalid (RFC 6376 §3.2). How receivers treat it varies: said, not scored
        # differently in 0.3.2 (a study is planned for 0.4).
        anomalies["repeated"] = ("mail.dmarc.note.repeated", {"name": f"_dmarc.{owner}", "tags": ", ".join(repeated)})
    if enforced and record.pct < 100:  # pct only limits an enforced policy (RFC 7489 §6.6.4)
        anomalies["partial"] = ("mail.dmarc.note.partial_reject" if policy == "reject" else "mail.dmarc.note.partial",
                                {"pct": record.pct})
    if enforced and not inherited and record.subdomain_policy == "none":
        anomalies["subdomains_open"] = ("mail.dmarc.note.subdomains_open", {})
    if ignored_local:
        anomalies["multiple_local"] = ("mail.dmarc.note.multiple_local",
                                       {"name": f"_dmarc.{ctx.domain}", "parent": owner})

    def noted(shown: str) -> dict[str, object]:
        """The evidence, with the anomalies other than ``shown`` (the one the verdict describes) as notes."""
        notes = [{"key": key, "params": values} for name, (key, values) in anomalies.items() if name != shown]
        if notes:
            evidence["notes"] = notes
        return evidence

    if invalid_policy:
        # RFC 9989 §4.10.1: invalid p/sp/np disables enforcement even when
        # p=reject looks usable. A valid rua allows reporting-only treatment.
        policy_tags = _tags_text(policy_errors) or "p"
        if record.rua:
            return warn("mail.dmarc.invalid_monitoring", Remedy(10, Effort.EASY), noted("invalid"),
                        name=f"_dmarc.{owner}", tags=policy_tags)
        return fail("mail.dmarc.invalid", Remedy(10, Effort.EASY, how="mail.dmarc.how", dns=() if inherited else (
            DnsChange("delete", "TXT", "_dmarc", valid[0]), DnsChange("add", "TXT", "_dmarc", first_step))),
            noted("invalid"), name=f"_dmarc.{owner}", tags=policy_tags)
    if record.testing and policy != "none":
        # t=y requests one level less enforcement (reject -> quarantine;
        # quarantine -> none), not full protection at the declared level.
        # RFC 9989 §4.7. Receivers that still follow RFC 7489 do not know t=y and apply the declared
        # policy (limited by pct, kept as a note): the effective level is the RFC 9989 one.
        effective = "quarantine" if policy == "reject" else "none"
        evidence["effective_policy"] = effective
        return warn("mail.dmarc.testing", Remedy(5, Effort.MEDIUM, how="mail.dmarc.testing.how"), noted("testing"),
                    policy=policy or "", effective=effective, parent=owner)
    if policy == "none":
        if inherited:
            # The parent may not be the owner's to change (a public suffix such as gouv.fr): the step that
            # is always in the owner's hands is a policy of the domain's own, with its own reports.
            return warn("mail.dmarc.monitoring_inherited",
                        Remedy(10, Effort.EASY, how="mail.dmarc.monitoring_inherited.how",
                               dns=(DnsChange("add", "TXT", "_dmarc", first_step),)),
                        noted("monitoring"), **params)
        # Next step once the reports show that legitimate mail passes: quarantine. Decided on the record
        # that would be published, not on the current one.
        stricter = stricter_dmarc(valid[0], record)
        if stricter is None:
            # No report address that can be kept (none valid, or a repeated rua): nothing can show that
            # legitimate mail passes, so no stricter record is offered, and no address is chosen or made up.
            return warn("mail.dmarc.monitoring_no_reports",
                        Remedy(10, Effort.MEDIUM, how="mail.dmarc.monitoring_no_reports.how"),
                        noted("monitoring"), name=f"_dmarc.{owner}", **params)
        return warn("mail.dmarc.monitoring", Remedy(10, Effort.MEDIUM, how="mail.dmarc.monitoring.how",
                                                    dns=(DnsChange("delete", "TXT", "_dmarc", valid[0]),
                                                         DnsChange("add", "TXT", "_dmarc", stricter))),
                    noted("monitoring"))
    if record.errors:
        return warn("mail.dmarc.syntax", Remedy(5, Effort.EASY, how="mail.dmarc.syntax.how"), noted("syntax"),
                    tags=_tags_text(record.errors), name=f"_dmarc.{owner}", **params)
    if record.pct < 100:
        # Historic in RFC 9989, still applied by receivers that follow RFC 7489 (§6.6.4): only this
        # share of the failing mail is selected for the policy. For p=reject, the rest SHOULD be
        # quarantined; for p=quarantine, it goes through the receiver's usual filtering.
        return warn("mail.dmarc.partial_reject" if policy == "reject" else "mail.dmarc.partial",
                    Remedy(5, Effort.MEDIUM, how="mail.dmarc.partial.how"), noted("partial"),
                    pct=record.pct, **params)
    if not inherited and record.subdomain_policy == "none":
        return warn("mail.dmarc.subdomains_open", Remedy(5, Effort.MEDIUM, how="mail.dmarc.subdomains_open.how"),
                    noted("subdomains_open"), **params)
    if ignored_local:
        return warn("mail.dmarc.multiple_inherited", Remedy(5, Effort.MEDIUM, how="mail.dmarc.multiple.how"),
                    noted("multiple_local"), parent=owner, policy=policy or "", name=f"_dmarc.{ctx.domain}")
    return ok("mail.dmarc.enforced_inherited" if inherited else "mail.dmarc.enforced", evidence, **params)


def stricter_dmarc(text: str, record: Dmarc) -> str | None:
    """The record to publish after ``text`` (p=none): a full quarantine, rebuilt from the valid tags.

    - v=DMARC1 and p=quarantine come first;
    - t and pct are never kept: t=y would turn the quarantine into none (RFC 9989 §4.7), pct below
      100 would limit it (RFC 7489 §6.6.4), and t=n or pct=100 are the defaults;
    - a repeated tag is left out entirely: no choice is made between two values;
    - a tag with a faulty value is left out; rua and ruf keep their valid addresses;
    - sp, np and the other valid tags are kept as written.

    None when no report address would remain: the step relies on reports to check the real mail."""
    faulty = {name for name, _value in record.errors}
    repeated = set(_repeated_tags(text))
    parts = ["v=DMARC1", "p=quarantine"]
    for name, value in tags(text):
        if name in ("v", "p", "t", "pct") or name in repeated:
            continue
        if name in ("rua", "ruf"):
            good = [uri for uri in (u.strip() for u in value.split(",")) if uri and (name, uri) not in record.errors]
            if good:
                parts.append(f"{name}={','.join(good)}")
        elif name not in faulty:
            parts.append(f"{name}={value}")
    return "; ".join(parts) if any(part.startswith("rua=") for part in parts) else None


def _repeated_tags(text: str) -> list[str]:
    """Tag names that appear more than once in a record, in order."""
    names = [name for name, _value in tags(text)]
    return [name for i, name in enumerate(names) if names.count(name) > 1 and name not in names[:i]]


# ------------------------------------------------------------------- DKIM
@extension.check("dkim", category="mail", weight=4, internal=False)
async def dkim(ctx: CheckContext) -> Outcome:
    """DKIM signs outgoing mail. Its keys are only found by guessing their name (the selector)."""
    selectors = dkim_selectors()
    answers = await asyncio.gather(*(ctx.txt(f"{s}._domainkey.{ctx.domain}") for s in selectors))
    keys = {}
    for selector, records in zip(selectors, answers, strict=True):
        key = next((k for k in map(parse_dkim, records) if k is not None), None)
        if key is not None:
            keys[selector] = key
    evidence = {"selectors": {s: "revoked" if k.revoked else f"{k.key_type} {k.bits}" if k.readable else "unreadable"
                              for s, k in keys.items()}}
    usable = {s: k for s, k in keys.items() if k.readable}
    broken = sorted(s for s, k in keys.items() if not k.readable and not k.revoked)
    if not usable and not broken:
        # Not found under the usual names, or withdrawn: nothing can be concluded either way.
        return info("mail.dkim.not_found", {"selectors_tried": list(selectors), **evidence})
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
@dataclass(frozen=True)
class MtaStsReading:
    """What the scan read of the domain's MTA-STS policy (RFC 8461), once for every check (version 0.7).

    ``stage`` says where the reading stopped: "missing" (no TXT record names the protocol),
    "bad_record" (§3.1), "no_address" (mta-sts.<domain> has no address), "untrusted" (§3.3: the
    certificate of the policy host is refused), "refused" (nothing serves it), "status" (an answer
    other than 200), "read" (the policy was parsed, maybe with faulty fields). A question that fails
    raises, as it did before the reading was shared: each check keeps its own way to say it."""

    stage: str
    all_records: tuple[str, ...] = ()  # every TXT record of _mta-sts.<domain>
    records: tuple[str, ...] = ()      # those naming the protocol ("v=sts…")
    ignored: tuple[str, ...] = ()      # the others, when some name it
    url: str = ""
    certificate: str = ""              # why the HTTPS certificate was refused
    status: int | None = None
    policy: MtaStsPolicy | None = None


async def _mta_sts_reading(ctx: CheckContext) -> MtaStsReading:
    """The reading of the policy, shared by mail.mta_sts and mail.smtp_starttls (``ctx.shared``): the
    same questions, in the same order, as mail.mta_sts asked them alone until 0.6.1."""

    async def read() -> MtaStsReading:
        all_records = tuple(await ctx.txt(f"_mta-sts.{ctx.domain}"))
        # A TXT that does not name the protocol is not an MTA-STS record; one that does (v=STSv1,
        # v=stsv1, v=STSv2...) must not vanish when senders cannot use it.
        records = tuple(r for r in all_records if r[:5].lower() == "v=sts")
        if not records:
            return MtaStsReading("missing", all_records)
        ignored = tuple(r for r in all_records if r not in records) if len(records) < len(all_records) else ()
        # §3.1: among several TXT records, those that do not begin with "v=STSv1;" are discarded;
        # exactly one valid record must remain, otherwise senders ignore MTA-STS.
        kept = all_records if len(all_records) == 1 else [r for r in all_records if r.startswith("v=STSv1;")]
        if len(kept) != 1 or not mta_sts_record_ok(kept[0]):
            return MtaStsReading("bad_record", all_records, records, ignored)
        host = f"mta-sts.{ctx.domain}"
        url = f"https://{host}/.well-known/mta-sts.txt"
        if not any([(await ctx.net.dns(host, "A")).records, (await ctx.net.dns(host, "AAAA")).records]):
            return MtaStsReading("no_address", all_records, records, ignored, url)
        try:
            # §3.3: the policy only counts when served over HTTPS with a valid certificate, without redirect.
            reply = await ctx.net.http_get(url, verify=True)
        except UntrustedCertificate as e:
            return MtaStsReading("untrusted", all_records, records, ignored, url, certificate=e.problem)
        except Refused:
            return MtaStsReading("refused", all_records, records, ignored, url)  # a timeout says less: it raises
        if reply.status != 200:
            return MtaStsReading("status", all_records, records, ignored, url, status=reply.status)
        return MtaStsReading("read", all_records, records, ignored, url, status=reply.status,
                             policy=parse_mta_sts_policy(reply.body))

    return await ctx.shared("mta_sts_reading", read)


@extension.check("mta_sts", category="mail", weight=3, internal=False)
async def mta_sts(ctx: CheckContext) -> Outcome:
    """MTA-STS makes the servers that deliver mail to the domain insist on encryption."""
    mx_hosts = await _mx_hosts(ctx)
    if not mx_hosts:
        return na("mail.no_inbound")
    reading = await _mta_sts_reading(ctx)
    remedy = Remedy(30, Effort.DELEGATE, message="mail.mta_sts.message")
    if reading.stage == "missing":
        all_records = list(reading.all_records)
        return warn("mail.mta_sts.missing", remedy, {"ignored": all_records} if all_records else None)
    evidence: dict[str, object] = {"records": list(reading.records)}
    if reading.ignored:
        evidence["ignored"] = list(reading.ignored)
    if reading.stage == "bad_record":
        return warn("mail.mta_sts.bad_record", remedy, evidence)
    evidence["url"] = reading.url
    if reading.stage == "no_address":
        return warn("mail.mta_sts.no_policy", remedy, evidence)
    if reading.stage == "untrusted":
        evidence["certificate"] = reading.certificate
        return warn("mail.mta_sts.bad_certificate", remedy, evidence, problem=reading.certificate)
    if reading.stage == "refused":
        return warn("mail.mta_sts.no_policy", remedy, evidence)  # nothing serves the policy
    evidence["status"] = reading.status
    if reading.stage == "status":
        return warn("mail.mta_sts.no_policy", remedy, evidence)
    policy = reading.policy
    assert policy is not None  # stage "read"
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


# ---------------------------------------------------------------- STARTTLS of the MX (version 0.7)
@extension.check("smtp_starttls", category="mail", weight=5, internal=False)
async def smtp_starttls(ctx: CheckContext) -> Outcome:
    """STARTTLS and the certificates of the MX on port 25, observed from this instance (version 0.7).

    The probe is off unless the instance turns it on (A1a): then the check is NA (F05.01) and asks
    nothing, not even the MX. Registered internal=False: the engine gives NA in an internal perimeter
    before calling it (S05). On, the probe observes (smtp_measure.py), the policy is read with
    mail.mta_sts, and smtp_verdict.decide() alone gives the verdict (matrix F05)."""
    # Imported here: smtp_measure reads the MX with _mx_records, from this module.
    from . import smtp_measure, smtp_verdict

    if not ctx.smtp.enabled:
        return smtp_verdict.decide(None, None, ctx.now)
    # One deadline for the probe and for the policy (P1): min(12 s, CHECK_TIMEOUT − 2 s) from now. The
    # probe returns by it with what it observed; the policy is awaited until it too, never until the
    # engine stops the check, which would throw away every observation (check.error.timeout).
    deadline = asyncio.get_running_loop().time() + smtp_measure.deadline_seconds(ctx.check_timeout)
    probe = await smtp_measure.result(ctx)
    policy = await _policy_for_smtp(ctx, probe, deadline) if probe.mx else None
    return smtp_verdict.decide(probe, policy, ctx.now)


async def _policy_for_smtp(ctx: CheckContext, probe: ProbeResult, deadline: float) -> PolicyView:
    """The shared reading of the policy, as F05.04 and F06 read it; unreadable when it fails or when
    the deadline comes first. Waiting stops only this check: the reading goes on for mail.mta_sts
    (``ctx.shared`` shields it)."""
    from . import smtp_verdict

    names = [m.name for m in probe.mx]
    try:
        async with asyncio.timeout_at(deadline):
            reading = await _mta_sts_reading(ctx)
    except TimeoutError:
        return smtp_verdict.policy_view("unreadable", None, names, detail="deadline")
    except NetworkError as e:
        return smtp_verdict.policy_view("unreadable", None, names, detail=e.__class__.__name__)
    except Exception as e:  # a bug in the reading must not throw away the SMTP observations
        log.exception("MTA-STS reading failed on %s", ctx.domain)
        return smtp_verdict.policy_view("unreadable", None, names, detail=f"bug: {e.__class__.__name__}")
    return smtp_verdict.policy_view(reading.stage, reading.policy, names)


# ---------------------------------------------------------------- TLS-RPT
@extension.check("tls_rpt", category="mail", weight=1, internal=False)
async def tls_rpt(ctx: CheckContext) -> Outcome:
    """TLS reports tell the domain when mail could not be delivered over an encrypted connection."""
    if not await _mx_hosts(ctx):
        return na("mail.no_inbound")
    all_records = await ctx.txt(f"_smtp._tls.{ctx.domain}")
    # A TXT that does not name the protocol is not a TLS-RPT record; one that does (v=TLSRPTv1,
    # v=tlsrptv1...) is reported when senders cannot use it, not taken for absence.
    attempts = [r for r in all_records if r[:8].lower() == "v=tlsrpt"]
    value = f"v=TLSRPTv1; rua=mailto:tls-reports@{ctx.domain}"
    if not attempts:
        return warn("mail.tls_rpt.missing", Remedy(5, Effort.EASY, dns=(DnsChange("add", "TXT", "_smtp._tls", value),),
                                                   how="mail.tls_rpt.how"), {"records": all_records})
    # RFC 8460 §3: among several TXT records, those that do not begin with "v=TLSRPTv1;" are
    # discarded; exactly one valid record must remain, otherwise senders send no report at all.
    kept = all_records if len(all_records) == 1 else [r for r in all_records if r.startswith("v=TLSRPTv1;")]
    if len(kept) > 1:
        problems = ["several records"]
    elif kept:
        problems = tls_rpt_problems(kept[0])
    else:
        problems = (tls_rpt_problems(attempts[0]) if len(attempts) == 1 else []) or ["v"]
    if problems:
        return warn("mail.tls_rpt.invalid", Remedy(5, Effort.EASY, how="mail.tls_rpt.invalid.how"),
                    {"records": all_records, "policies": attempts, "problems": problems}, problems=", ".join(problems))
    return ok("mail.tls_rpt.present", {"record": kept[0]})
