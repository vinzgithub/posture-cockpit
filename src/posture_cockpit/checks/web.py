# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The website's answers: redirection to HTTPS and the protection headers browsers obey.

Version 0.4: everything starts from the HTTPS probe (:mod:`..core.https_probe`),
which looks at every published address of the domain and of ``www``. The root
check, ``https_redirect``, keeps three results apart: whether HTTPS answers on
each address (D), what ``http://`` answers on each address (P), and the other
site a redirection may lead to (X, noted, never contacted). The certificate is
judged by ``tls.certificate`` alone.

The page checks read the home page of each address that answered (the
certificate is not verified there: an invalid one must not hide the headers),
following at most a few HTTPS redirects inside the domain, and keep the worst
verdict, address named: a fault on one address is never hidden by another. Each
header is judged on what browsers actually do with it, not only on its
presence: a Content-Security-Policy that does not restrict scripts, or
``frame-ancestors *``, protects nothing.

References: ANSSI, « Recommandations pour la sécurisation des sites web »;
RFC 6797 (HSTS), RFC 7034 (X-Frame-Options), W3C CSP Level 3 (frame-ancestors
replaces X-Frame-Options when both are sent), W3C Referrer Policy, RFC 9116
(security.txt).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from ipaddress import ip_address
from typing import Any
from urllib.parse import urljoin, urlsplit

from .. import __version__
from ..core import (
    CheckContext,
    Effort,
    Extension,
    HttpReply,
    NetworkError,
    Outcome,
    Refused,
    Remedy,
    Signal,
    Status,
    fail,
    load_messages,
    na,
    not_evaluated,
    ok,
    warn,
)
from ..core import https_probe as probe_
from ..core.egress import DestinationBlocked
from ..core.https_probe import CONCLUSIVE, AddressResult, HostResult, Kind, ProbeResult
from ..core.network import Certificate
from . import LOCALES

# Version 0.4: the verdicts each HTTPS check can give (the scoring caps use the lowest non-critical one).
ROOT_VERDICTS = frozenset({Status.OK, Status.FAIL})
PAGE_VERDICTS = frozenset({Status.OK, Status.WARN})  # a missing or weak header is never critical

extension = Extension("web", name="Website", version=__version__,
                      description="HTTPS redirection, HSTS, CSP and the other protection headers, security.txt.",
                      messages=load_messages(LOCALES, "web"))

HSTS_MIN_SECONDS = 180 * 24 * 3600  # six months
MAX_REDIRECTS = 4
# CSP sources that allow any origin (or any page) to provide the resource.
OPEN_SOURCES = frozenset({"*", "http:", "https:", "data:", "blob:", "filesystem:"})
REFERRER_POLICIES = frozenset({"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
                               "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"})


def _delegate(check: str, minutes: int = 15) -> Remedy:
    return Remedy(minutes, Effort.DELEGATE, message=f"web.{check}.message")


def _same_site(ctx: CheckContext, url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host == ctx.domain or host.endswith("." + ctx.domain)


def _addresses(results: Iterable[AddressResult]) -> str:
    return ", ".join(a.address for a in results)


# ------------------------------------------------------------- redirection (P)
@dataclass
class _Redirection:
    """What ``http://host/`` answers on each address, and the worst of it."""

    value: str = "unknown"  # "https" (same site), "external", "closed", "missing" or "unknown"
    chains: dict[str, str] = field(default_factory=dict)  # address -> what was seen
    external: list[str] = field(default_factory=list)  # other sites redirected to: noted, never contacted
    to_same_host: bool = False  # http:// redirects to HTTPS of the same host: HTTPS is announced (S1)
    blocked: DestinationBlocked | None = None


_P_RANK = {"missing": 0, "https": 1, "external": 1, "closed": 1}


async def _follow_http(ctx: CheckContext, host: str, url: str, reply: HttpReply) -> tuple[str, list[str], str]:
    """Where ``http://host/`` leads, as in 0.3.2: same-site HTTP redirects are followed (by URL, MAX_REDIRECTS
    at most), never another site. Returns the value, the steps, and the HTTPS target reached."""
    steps: list[str] = []
    seen: set[str] = set()
    for _ in range(MAX_REDIRECTS + 1):
        if url in seen:
            return "missing", [*steps, f"loop {url}"], ""
        seen.add(url)
        steps.append(f"{reply.status} {url}")
        location = reply.header("location")
        if not (300 <= reply.status < 400 and location):
            return "missing", steps, ""
        next_url = urljoin(url, location)
        scheme = urlsplit(next_url).scheme
        if scheme == "https":
            return ("https" if _same_site(ctx, next_url) else "external"), [*steps, next_url], next_url
        if scheme != "http" or not _same_site(ctx, next_url):
            return "missing", [*steps, next_url], ""
        url = next_url
        try:
            reply = await ctx.net.http_get(url)
        except Refused:
            return "missing", [*steps, f"{url} closed"], ""
        except NetworkError:
            return "unknown", [*steps, f"{url} no answer"], ""
    return "missing", steps, ""


async def _redirection(ctx: CheckContext, host: HostResult) -> _Redirection:
    result = _Redirection()
    worst = None
    for a in host.addresses:
        port80 = a.port80
        if port80 is None:
            continue
        url = f"http://{host.name}/"
        if port80.result == "closed":
            value, steps = "closed", [f"{url} closed"]
        elif port80.result == "reply" and port80.reply is not None:
            first = urljoin(url, port80.reply.header("location"))
            if 300 <= port80.reply.status < 400 and urlsplit(first).scheme == "https" \
                    and (urlsplit(first).hostname or "").lower() == host.name:
                result.to_same_host = True
            value, steps, target = await _follow_http(ctx, host.name, url, port80.reply)
            if value == "external":
                result.external.append(target)
        else:
            result.blocked = result.blocked or port80.blocked
            result.chains[a.address] = f"{url} {port80.result}"
            continue
        result.chains[a.address] = " → ".join(steps)
        if value == "unknown":
            continue
        if worst is None or _P_RANK[value] < _P_RANK[worst]:
            worst = value
    result.value = worst or "unknown"
    return result


# ------------------------------------------------------- attribution, announce
def _attribution(ctx: CheckContext, probe: ProbeResult, refused: list[AddressResult]) -> dict[str, Any]:
    """Prudent attribution (specification 0.4, section 7): no effect on the status or the score.

    "destination" when, in this scan, a TLS negotiation succeeded from here, in the same address
    family, with another host of the audited domain; "undetermined" otherwise."""
    names = {a.host for a in refused}
    families = {a.family for a in refused}
    successes = {(a.host, a.address) for a in probe.negotiating}
    successes |= {(h, a) for h, a in ctx.net.negotiated()
                  if h == ctx.domain or h.endswith("." + ctx.domain)}
    others = sorted((h, a) for h, a in successes if h not in names and ip_address(a).version in families)
    if not others:
        return {"level": "undetermined", "elements": []}
    same_address = {a.address for a in refused} & {a for _, a in others}
    return {"level": "destination", "scope": "name" if same_address else "destination",
            "elements": [f"{h} ({a})" for h, a in others]}


def _announced(host: HostResult, redirection: _Redirection, ctx: CheckContext) -> dict[str, Any]:
    """S1/S2 announce HTTPS; DNS, previous availability and preload are hints only."""
    signals = (["redirect"] if redirection.to_same_host else [])
    from ..core.https_history import announced

    history = announced(host.name, ctx.history, ctx.now)
    if history.get("hsts"):
        signals.append("hsts_history")
    hints = (["https_record"] if host.hints else [])
    if history.get("last_available"):
        hints.append("https_history")
    if history.get("preload"):
        hints.append("preload")
    level = "announced" if signals else "hints" if hints else "not_announced"
    return {"level": level, "signals": signals, "hints": hints, "history": history}


# ------------------------------------------------------------------ the root
@extension.check("https_redirect", category="web", weight=8, provides="https", verdicts=ROOT_VERDICTS)
async def https_redirect(ctx: CheckContext) -> Outcome:
    """HTTPS on every published address, and http:// sent to it (specification 0.4, section 4).

    Critical as soon as one published address refuses HTTPS, or speaks only an old TLS version,
    or when http:// serves the site in clear. Not evaluated when nothing conclusive was obtained
    (a timeout, an address this machine cannot test, the probe's deadline): never a failure by
    default. Compliant when every host that has an address answers HTTPS and http:// leads to it,
    to another site, or is closed. The certificate is not judged here."""
    probe = await probe_.result(ctx)
    if probe.absent:
        return na("web.no_website")
    hosts = [h for h in probe.hosts if h.addresses or not h.discovery_complete]
    redirections = {h.name: await _redirection(ctx, h) for h in hosts}
    causes: list[tuple[str, dict[str, Any]]] = []
    unknown: list[tuple[str, dict[str, Any], str]] = []
    notes: list[dict[str, Any]] = []
    refused_hosts: list[HostResult] = []
    for host in hosts:
        p = redirections[host.name]
        refusal = _refusal_cause(host, p)
        if refusal is not None:
            causes.append(refusal)
            refused_hosts.append(host)
        if p.value == "missing":
            causes.append(("web.https_redirect.missing", {"host": host.name}))
        if refusal is None and p.value != "missing":
            pending = _not_conclusive(host, p, probe)
            if pending is not None:
                unknown.append(pending)
        for target in p.external:
            notes.append({"key": "web.https_redirect.note.external", "params": {"host": host.name, "target": target}})
    notes += _address_notes(probe)
    evidence: dict[str, Any] = {
        "https_history": {h.name: {
            "available": any(a.kind in {Kind.AVAILABLE, Kind.TLS_ONLY} for a in h.addresses),
            "hsts": [a.page.header("strict-transport-security") for a in h.addresses
                     if a.page is not None and a.certificate is not None and a.certificate.trusted
                     and a.kind is Kind.AVAILABLE and a.page.header("strict-transport-security")],
        } for h in probe.hosts},
        "observation": probe.evidence(),
        "redirection": {h.name: {"value": redirections[h.name].value, **redirections[h.name].chains} for h in hosts},
        "addresses": probe.exhaustivity(),
    }
    if any(a.certificate is not None and not a.certificate.trusted for a in probe.negotiating):
        notes.append({"key": "web.https_redirect.note.certificate", "params": {}})
    if causes:
        key, params = causes[0]
        extra = [{"key": k, "params": v} for k, v in causes[1:]]
        remedy = _delegate("https_redirect")
        if refused_hosts:
            refused = [a for h in refused_hosts for a in h.of(Kind.REFUSED)]
            attribution = _attribution(ctx, probe, refused) if refused else {"level": "undetermined", "elements": []}
            first = refused_hosts[0]
            announced = _announced(first, redirections[first.name], ctx)
            evidence["attribution"], evidence["announced"] = attribution, announced
            extra += _attribution_notes(first, refused, attribution, announced)
            remedy = _refusal_remedy(key, attribution, announced)
        signals = (frozenset({Signal.HTTPS_OBSOLETE_ONLY}) if probe.obsolete_only else
                   frozenset({Signal.HTTPS_UNDETERMINED}) if probe.undetermined else frozenset())
        evidence["notes"] = extra + notes + _exhaustivity_notes(probe)
        return replace(fail(key, remedy, evidence, **params), signals=signals)
    if unknown:
        key, params, cause = unknown[0]
        evidence["cause"] = cause
        evidence["notes"] = notes + _exhaustivity_notes(probe)
        return not_evaluated(key, evidence, **params)
    evidence["notes"] = notes + _exhaustivity_notes(probe)
    if not evidence["notes"]:
        del evidence["notes"]
    return ok("web.https_redirect.ok", evidence)


def _refusal_cause(host: HostResult, p: _Redirection) -> tuple[str, dict[str, Any]] | None:
    """The critical cause a refusal or an old TLS version on this host gives, or None."""
    refused, obsolete, available = host.of(Kind.REFUSED), host.of(Kind.OBSOLETE), host.of(Kind.AVAILABLE)
    if not refused and not obsolete:
        return None
    if available:
        if refused:
            return "web.https_redirect.refused_partial", {"host": host.name, "addresses": _addresses(refused)}
        return "web.https_redirect.obsolete_partial", {"host": host.name, "addresses": _addresses(obsolete)}
    inconclusive = [a for a in host.addresses if a.kind not in CONCLUSIVE]
    if not host.complete:
        key = "refused_undetermined" if refused else "obsolete_undetermined"
        if not inconclusive:  # every address found was tested: what is missing is an address question
            key += "_discovery"
        return f"web.https_redirect.{key}", {
            "host": host.name, "tested": len(refused) + len(obsolete), "addresses": _addresses(refused + obsolete),
            "published": len(host.addresses), "untested": len(inconclusive)}
    if obsolete:
        versions = sorted({a.version for a in obsolete}, reverse=True)
        return "web.https_redirect.obsolete", {
            "host": host.name, "addresses": _addresses(obsolete),
            "versions": ", ".join(v.replace("TLSv1.1", "TLS 1.1").replace("TLSv1", "TLS 1.0") for v in versions)}
    if all(a.port80 is not None and a.port80.result == "closed" for a in refused):
        return "web.https_redirect.no_service", {"host": host.name, "addresses": _addresses(refused)}
    if p.value == "external":
        return "web.https_redirect.external", {"host": host.name}
    return "web.https_redirect.refused", {"host": host.name, "addresses": _addresses(refused)}


def _not_conclusive(host: HostResult, p: _Redirection, probe: ProbeResult) -> tuple[str, dict[str, Any], str] | None:
    """Why this host, without any failure observed, cannot be judged; None when it can."""
    if not host.of(Kind.AVAILABLE):
        pending = [a for a in host.addresses if a.kind not in CONCLUSIVE]
        causes = {a.cause for a in pending}
        if not host.addresses:
            return "web.https_redirect.unknown", {"host": host.name}, "network"
        if "budget" in causes:
            return "web.https_redirect.budget", {"host": host.name, "seconds": round(probe.deadline)}, "budget"
        if causes == {"policy"}:
            blocked = next(a.blocked for a in pending if a.blocked is not None)
            return f"check.error.blocked.{blocked.reason}", {
                "host": blocked.host, "address": str(blocked.address), "port": blocked.port}, "policy"
        if "network" in causes:
            return "web.https_redirect.unknown", {"host": host.name}, "network"
        if any(a.reason == "legacy" for a in pending):
            return "web.https_redirect.legacy_untestable", {"host": host.name}, "tool"
        return "web.https_redirect.untestable", {"host": host.name, "addresses": _addresses(pending)}, "tool"
    if p.value == "unknown":
        if p.blocked is not None:
            return f"check.error.blocked.{p.blocked.reason}", {
                "host": p.blocked.host, "address": str(p.blocked.address), "port": p.blocked.port}, "policy"
        return "web.https_redirect.http_unknown", {"host": host.name}, "network"
    return None


def _address_notes(probe: ProbeResult) -> list[dict[str, Any]]:
    unstable = [a for a in probe.addresses if a.instability]
    refused_default = [a for a in probe.addresses if a.default_refused]
    notes = []
    if unstable:
        notes.append({"key": "web.https_redirect.note.instability", "params": {
            "addresses": ", ".join(a.label for a in unstable)}})
    if refused_default:
        notes.append({"key": "web.https_redirect.note.default_offer", "params": {
            "addresses": ", ".join(a.label for a in refused_default)}})
    return notes


def _exhaustivity_notes(probe: ProbeResult) -> list[dict[str, Any]]:
    """The addresses that gave nothing conclusive, said every time (the fourth indicator)."""
    counts = probe.exhaustivity()
    if probe.complete:
        return []
    notes: list[dict[str, Any]] = [{"key": "web.https_redirect.note.exhaustivity", "params": {
        "discovered": counts["discovered"], "attempted": counts["attempted"], "conclusive": counts["conclusive"]}}]
    for reason, params in probe.missing():
        notes.append({"key": f"web.https_redirect.note.{reason}", "params": params})
    return notes


def _attribution_notes(host: HostResult, refused: list[AddressResult], attribution: dict[str, Any],
                       announced: dict[str, Any]) -> list[dict[str, Any]]:
    notes: list[dict[str, Any]] = []
    if refused:
        if attribution["level"] == "destination":
            notes.append({"key": f"web.https_redirect.attribution.{attribution['scope']}", "params": {
                "host": host.name, "address": refused[0].address, "other": ", ".join(attribution["elements"])}})
        else:
            notes.append({"key": "web.https_redirect.attribution.undetermined", "params": {"host": host.name}})
    if announced["level"] == "announced":
        for signal in announced["signals"]:
            notes.append({"key": "web.https_redirect.announced." + signal, "params": {"host": host.name}})
    for hint in announced["hints"]:
        key = "hints" if hint == "https_record" else hint
        notes.append({"key": "web.https_redirect.announced." + key, "params": {"host": host.name}})
    return notes


def _refusal_remedy(key: str, attribution: dict[str, Any], announced: dict[str, Any]) -> Remedy:
    if key.endswith(".missing"):
        return _delegate("https_redirect")
    if key.endswith(".external"):
        return _delegate("https_redirect.external")
    if "obsolete" in key:
        return _delegate("https_redirect.obsolete")
    if attribution["level"] != "destination":
        return _delegate("https_redirect.verify", 10)
    if announced["level"] == "announced":
        return _delegate("https_redirect.restore")
    return _delegate("https_redirect.refused")


# ------------------------------------------------------------------ pages
@dataclass(frozen=True)
class _Page:
    """A home page as the page checks read it: where it came from and what it was served with."""

    host: str
    address: str  # "" when read by URL (a host of the site the probe does not cover)
    reply: HttpReply
    obsolete: bool = False
    certificate: Certificate | None = None

    @property
    def url(self) -> str:
        return self.reply.url


def _covers(names: Iterable[str], host: str) -> bool:
    for name in names:
        name = name.lower().rstrip(".")
        if name == host or (name.startswith("*.") and host.count(".") == name.count(".")
                            and host.endswith(name[1:])):
            return True
    return False


async def _read_at(ctx: CheckContext, probe: ProbeResult, url: str, depth: int,
                   pages: dict[tuple[str, str], _Page], start: tuple[AddressResult | None, HttpReply]) -> None:
    """Follows HTTPS redirects inside the domain from ``start`` and records the pages reached."""
    origin, reply = start
    location = reply.header("location")
    if depth < MAX_REDIRECTS and 300 <= reply.status < 400 and location:
        next_url = urljoin(url, location)
        if next_url.startswith("https://") and _same_site(ctx, next_url):
            target = (urlsplit(next_url).hostname or "").lower()
            host = next((h for h in probe.hosts if h.name == target), None)
            if host is None:  # another host of the site: read by URL, as in 0.3.2
                await _read_at(ctx, probe, next_url, depth + 1, pages, (None, await ctx.net.http_get(next_url)))
                return
            readable = host.of(Kind.AVAILABLE, Kind.OBSOLETE)
            if not readable:
                raise NetworkError(f"{next_url}: no address of {target} answers HTTPS")
            for a in readable:
                if next_url == f"https://{target}/" and a.page is not None:
                    following = a.page
                else:
                    following = await ctx.net.http_at(next_url, a.address, offer=a.offer or "default")
                await _read_at(ctx, probe, next_url, depth + 1, pages, (a, following))
            return
    host_name = (urlsplit(reply.url).hostname or "").lower()
    address = origin.address if origin is not None else ""
    pages.setdefault((host_name, address or reply.url), _Page(
        host_name, address, reply, obsolete=origin is not None and origin.kind is Kind.OBSOLETE,
        certificate=origin.certificate if origin is not None else None))


async def _pages(ctx: CheckContext) -> list[_Page]:
    """The home page of every address that answered, after redirects inside the domain.

    Two addresses that end on the same page (same host, same address) count once. Raises when a
    page that should be read cannot be (the checks are then "not evaluated", never judged)."""

    async def fetch() -> list[_Page]:
        probe = await probe_.result(ctx)
        pages: dict[tuple[str, str], _Page] = {}
        for a in probe.pages:
            assert a.page is not None
            await _read_at(ctx, probe, f"https://{a.host}/", 0, pages, (a, a.page))
        return list(pages.values())

    return await ctx.shared("pages", fetch)


def _host(page: _Page, pages: list[_Page]) -> str:
    """The page's host, with its address when the host was read on several."""
    several = sum(p.host == page.host for p in pages) > 1
    return f"{page.host} ({page.address})" if several and page.address else page.host


def _where(page: _Page, pages: list[_Page]) -> str:
    """A key for the page in the expert view: its URL, with the address when the URL was read on several."""
    several = sum(p.url == page.url for p in pages) > 1
    return f"{page.url} ({page.address})" if several and page.address else page.url


def _page_notes(pages: list[_Page]) -> list[dict[str, Any]]:
    """What the reading of the pages calls for, without effect on the verdict (section 4)."""
    notes: list[dict[str, Any]] = []
    obsolete = [p for p in pages if p.obsolete]
    if obsolete:
        notes.append({"key": "web.note.obsolete_page", "params": {
            "addresses": ", ".join(f"{p.host} ({p.address})" for p in obsolete)}})
    for p in pages:
        if p.certificate is not None and not _covers(p.certificate.names, p.host):
            notes.append({"key": "web.note.name_mismatch", "params": {"host": p.host}})
            break
    return notes


def _with_notes(outcome: Outcome, notes: list[dict[str, Any]]) -> Outcome:
    if not notes:
        return outcome
    return replace(outcome, evidence={**outcome.evidence, "notes": notes})


async def _measured_pages(ctx: CheckContext) -> list[_Page] | None:
    """The pages, or None when there is no website."""
    probe = await probe_.result(ctx)
    if probe.absent:
        return None
    pages = await _pages(ctx)
    if not pages:
        raise NetworkError("no home page could be read")
    return pages


def _csp_policies(page: HttpReply) -> list[dict[str, list[str]]]:
    """The enforced CSP policies of a page (Report-Only ones enforce nothing), as directive → sources.

    Several policies may arrive (several headers, or commas): browsers enforce all of them."""
    policies = []
    for text in page.header("content-security-policy").split(","):
        directives: dict[str, list[str]] = {}
        for part in text.split(";"):
            words = part.split()
            if words and words[0].lower() not in directives:  # the first occurrence wins
                directives[words[0].lower()] = [w.lower() for w in words[1:]]
        if directives:
            policies.append(directives)
    return policies


def _hsts_max_age(header: str) -> int | None:
    """The max-age of an HSTS header, None when absent or invalid. With several headers,
    browsers only use the first (RFC 6797 §8.1)."""
    for directive in header.split(",")[0].split(";"):
        name, _, value = directive.strip().partition("=")
        if name.strip().lower() == "max-age":
            value = value.strip().strip('"')
            return int(value) if value.isdigit() else None
    return None


@extension.check("hsts", category="web", weight=6, requires="https",
                 verdicts=PAGE_VERDICTS)
async def hsts(ctx: CheckContext) -> Outcome:
    """HSTS makes browsers remember to use HTTPS only, even if a link says http://."""
    pages = await _measured_pages(ctx)
    if pages is None:
        return na("web.no_website")
    notes = _page_notes(pages)
    ignored = [p for p in pages if p.certificate is not None and not p.certificate.trusted
               and p.reply.header("strict-transport-security")]
    if ignored:  # RFC 6797 §8.1: a browser ignores HSTS received over a connection with an error
        notes.append({"key": "web.hsts.note.invalid_certificate", "params": {"host": _host(ignored[0], pages)}})
    for page in pages:
        header = page.reply.header("strict-transport-security")
        evidence = {"url": page.url, "address": page.address, "header": header}
        host = _host(page, pages)
        verdict: Outcome | None = None
        if not header:
            verdict = warn("web.hsts.missing", _delegate("hsts"), evidence, host=host)
        elif (max_age := _hsts_max_age(header)) is None:
            verdict = warn("web.hsts.invalid", _delegate("hsts"), evidence, host=host)
        elif max_age == 0:  # RFC 6797 §6.1.1: tells browsers to forget the site's HSTS
            verdict = warn("web.hsts.disabled", _delegate("hsts"), evidence, host=host)
        elif max_age < HSTS_MIN_SECONDS:
            verdict = warn("web.hsts.short", _delegate("hsts"), evidence, host=host, days=max_age // 86400)
        if verdict is not None:
            return _with_notes(verdict, notes)
    return _with_notes(ok("web.hsts.ok", {"headers": {_where(p, pages): p.reply.header("strict-transport-security")
                                                     for p in pages}}), notes)


# -------------------------------------------------------------------- CSP
def _script_weakness(page: HttpReply) -> str | None:
    """Why the page's CSP does not restrict scripts ("missing", "no_script", "unsafe_inline",
    "open"), or None when one of its policies does."""
    policies = _csp_policies(page)
    if not policies:
        return "missing"
    weaknesses = []
    for policy in policies:
        sources = policy.get("script-src", policy.get("default-src"))
        if sources is None:
            weaknesses.append("no_script")
        elif any(s in OPEN_SOURCES for s in sources):
            weaknesses.append("open")
        elif "'unsafe-inline'" in sources and not any(
                s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or s == "'strict-dynamic'"
                for s in sources):
            weaknesses.append("unsafe_inline")  # nonces, hashes or strict-dynamic make browsers ignore it
        else:
            return None  # this policy restricts scripts, and browsers enforce every policy
    return weaknesses[0]


@extension.check("csp", category="web", weight=4, requires="https",
                 verdicts=PAGE_VERDICTS)
async def csp(ctx: CheckContext) -> Outcome:
    """A Content-Security-Policy that limits where scripts may come from."""
    pages = await _measured_pages(ctx)
    if pages is None:
        return na("web.no_website")
    notes = _page_notes(pages)
    evidence = {_where(p, pages): p.reply.header("content-security-policy") for p in pages}
    for page in pages:
        weakness = _script_weakness(page.reply)
        if weakness is not None:
            return _with_notes(warn(f"web.csp.{weakness}", _delegate("csp"), evidence, host=_host(page, pages)), notes)
    return _with_notes(ok("web.csp.ok", evidence), notes)


# --------------------------------------------------------------- framing
def _framing(page: HttpReply) -> str:
    """"protected", "permissive" (frame-ancestors open to any site), "obsolete" (ALLOW-FROM)
    or "missing".

    When a CSP has frame-ancestors, browsers ignore X-Frame-Options: the CSP alone decides."""
    with_directive = [p["frame-ancestors"] for p in _csp_policies(page) if "frame-ancestors" in p]
    if with_directive:
        # No source at all means 'none'. Any enforced policy that restricts framing protects.
        restricting = [s for s in with_directive if not any(source in OPEN_SOURCES for source in s)]
        return "protected" if restricting else "permissive"
    values = {v.strip().lower() for v in page.header("x-frame-options").split(",") if v.strip()}
    if values and values <= {"deny", "sameorigin"}:
        return "protected"
    if any(v.startswith("allow-from") for v in values):
        return "obsolete"  # no longer understood by current browsers
    return "missing"


@extension.check("framing", category="web", weight=3, requires="https",
                 verdicts=PAGE_VERDICTS)
async def framing(ctx: CheckContext) -> Outcome:
    """Other sites must not be able to show the site in a frame (clickjacking)."""
    pages = await _measured_pages(ctx)
    if pages is None:
        return na("web.no_website")
    notes = _page_notes(pages)
    evidence = {_where(p, pages): {"x-frame-options": p.reply.header("x-frame-options"),
                                   "content-security-policy": p.reply.header("content-security-policy")}
                for p in pages}
    for page in pages:
        state = _framing(page.reply)
        if state != "protected":
            return _with_notes(warn(f"web.framing.{state}", _delegate("framing"), evidence,
                                    host=_host(page, pages)), notes)
    return _with_notes(ok("web.framing.ok", evidence), notes)


# ------------------------------------------------------- the other headers
@extension.check("nosniff", category="web", weight=2, requires="https",
                 verdicts=PAGE_VERDICTS)
async def nosniff(ctx: CheckContext) -> Outcome:
    """X-Content-Type-Options: nosniff, so the browser does not guess file types."""
    pages = await _measured_pages(ctx)
    if pages is None:
        return na("web.no_website")
    notes = _page_notes(pages)
    evidence = {_where(p, pages): p.reply.header("x-content-type-options") for p in pages}
    for page in pages:
        if page.reply.header("x-content-type-options").split(",")[0].strip().lower() != "nosniff":
            return _with_notes(warn("web.nosniff.missing", _delegate("nosniff"), evidence,
                                    host=_host(page, pages)), notes)
    return _with_notes(ok("web.nosniff.ok", evidence), notes)


def _referrer_policy(page: HttpReply) -> str | None:
    """The policy browsers apply: the last value they know (W3C Referrer Policy §11.1)."""
    known = [v.strip().lower() for v in page.header("referrer-policy").split(",")
             if v.strip().lower() in REFERRER_POLICIES]
    return known[-1] if known else None


@extension.check("referrer", category="web", weight=1, requires="https",
                 verdicts=PAGE_VERDICTS)
async def referrer(ctx: CheckContext) -> Outcome:
    """Referrer-Policy limits the address sent to the sites a visitor goes to next."""
    pages = await _measured_pages(ctx)
    if pages is None:
        return na("web.no_website")
    notes = _page_notes(pages)
    evidence = {_where(p, pages): p.reply.header("referrer-policy") for p in pages}
    for page in pages:
        policy = _referrer_policy(page.reply)
        if policy is None:
            return _with_notes(warn("web.referrer.missing", _delegate("referrer"), evidence,
                                    host=_host(page, pages)), notes)
        if policy == "unsafe-url":  # the full address, query string included, to every site, even over HTTP
            return _with_notes(warn("web.referrer.unsafe", _delegate("referrer"), evidence,
                                    host=_host(page, pages)), notes)
    return _with_notes(ok("web.referrer.ok", evidence), notes)


@extension.check("server_banner", category="web", weight=2, requires="https",
                 verdicts=PAGE_VERDICTS)
async def server_banner(ctx: CheckContext) -> Outcome:
    """Software versions in the headers tell attackers which known flaws to try."""
    pages = await _measured_pages(ctx)
    if pages is None:
        return na("web.no_website")
    notes = _page_notes(pages)
    for page in pages:
        for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            value = page.reply.header(header)
            if re.search(r"\d+\.\d+", value):
                return _with_notes(warn("web.server_banner.version", _delegate("server_banner", 10),
                                        {"url": page.url, "address": page.address, header: value},
                                        header=header, value=value), notes)
    return _with_notes(ok("web.server_banner.ok"), notes)


# ----------------------------------------------------------- security.txt
def _security_txt_fields(body: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for line in body.splitlines():
        if line.lstrip().startswith("#"):
            continue
        name, sep, value = line.partition(":")
        if sep and name.strip() and " " not in name.strip():
            fields.setdefault(name.strip().lower(), []).append(value.strip())
    return fields


def _expiry(value: str) -> datetime | None:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else None  # RFC 9116 §2.5.5: a date with its time zone


@extension.check("security_txt", category="web", weight=1, internal=False, requires="https",
                 verdicts=PAGE_VERDICTS)
async def security_txt(ctx: CheckContext) -> Outcome:
    """security.txt tells whoever finds a flaw how to report it (RFC 9116).

    Read on the first web host that answers over HTTPS (the domain, else ``www``), on each of
    its addresses that answered; the worst verdict counts."""
    probe = await probe_.result(ctx)
    if probe.absent:
        return na("web.no_website")
    host = next((h for h in probe.hosts if h.of(Kind.AVAILABLE, Kind.OBSOLETE)), None)
    if host is None:
        raise NetworkError("no address answers HTTPS")
    url = f"https://{host.name}/.well-known/security.txt"
    pages: dict[tuple[str, str], _Page] = {}
    for a in host.of(Kind.AVAILABLE, Kind.OBSOLETE):
        reply = await ctx.net.http_at(url, a.address, offer=a.offer or "default")
        found: dict[tuple[str, str], _Page] = {}
        await _read_at(ctx, probe, url, 0, found, (a, reply))
        pages.update(found)
    read = list(pages.values())
    notes = _page_notes(read)
    if any(p.certificate is not None and not p.certificate.trusted for p in read):
        notes.append({"key": "web.security_txt.note.unverifiable", "params": {"host": host.name}})
    verdicts = [_security_txt_verdict(ctx, page.reply, url) for page in read]
    worst = next((v for v in verdicts if v.status is Status.WARN), verdicts[0])
    if len(read) > 1:
        worst = replace(worst, evidence={**worst.evidence, "addresses": [p.address for p in read]})
    return _with_notes(worst, notes)


def _security_txt_verdict(ctx: CheckContext, reply: HttpReply, url: str) -> Outcome:
    evidence = {"url": reply.url, "status": reply.status}
    remedy = _delegate("security_txt", 10)
    # A site answering every address with its home page is not publishing a security.txt.
    if reply.status != 200 or "<html" in reply.body[:2000].lower():
        return warn("web.security_txt.missing", remedy, evidence, url=url)
    fields = _security_txt_fields(reply.body)
    expires = fields.get("expires", [])
    problems = [name for name, ok_ in (("Contact", bool(fields.get("contact"))),
                                       ("Expires", len(expires) == 1 and _expiry(expires[0]) is not None)) if not ok_]
    if problems:  # §2.5.3 and §2.5.5: both are required, Expires exactly once
        return warn("web.security_txt.invalid", remedy, evidence, url=url, fields=", ".join(problems))
    expiry = _expiry(expires[0])
    assert expiry is not None
    if expiry < ctx.now:
        return warn("web.security_txt.expired", remedy, evidence, url=url, expires_on=expiry.date().isoformat())
    return ok("web.security_txt.ok", evidence)
