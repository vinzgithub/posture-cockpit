# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The website's answers: redirection to HTTPS and the protection headers browsers obey.

Only the home page is read (plus security.txt), following at most a few
redirects inside the domain. Each header is judged on what browsers actually
do with it, not only on its presence: a Content-Security-Policy that does not
restrict scripts, or ``frame-ancestors *``, protects nothing.

References: ANSSI, « Recommandations pour la sécurisation des sites web »;
RFC 6797 (HSTS), RFC 7034 (X-Frame-Options), W3C CSP Level 3 (frame-ancestors
replaces X-Frame-Options when both are sent), W3C Referrer Policy, RFC 9116
(security.txt).
"""

from __future__ import annotations

import re
from datetime import datetime
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
    UntrustedCertificate,
    fail,
    load_messages,
    na,
    ok,
    warn,
)
from ..core.egress import DestinationBlocked
from . import LOCALES

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


def _host(page: HttpReply) -> str:
    return urlsplit(page.url).hostname or ""


async def _follow(ctx: CheckContext, url: str) -> HttpReply:
    """GET ``url``, then follow HTTPS redirects inside the domain, MAX_REDIRECTS at most."""
    reply = await ctx.net.http_get(url)
    for _ in range(MAX_REDIRECTS):
        location = reply.header("location")
        if not (300 <= reply.status < 400 and location):
            break
        url = urljoin(url, location)
        if not url.startswith("https://") or not _same_site(ctx, url):
            break
        reply = await ctx.net.http_get(url)
    return reply


async def _pages(ctx: CheckContext) -> list[HttpReply]:
    """The home page of each web host over HTTPS, after redirects inside the domain.

    Two hosts that end on the same page count once. Raises the error of the
    first host when none answers (so the checks are "not evaluated", with the
    reason, rather than wrongly judged)."""

    async def fetch() -> list[HttpReply]:
        pages: dict[str, HttpReply] = {}
        errors: list[NetworkError] = []
        for host in await ctx.web_hosts():
            try:
                reply = await _follow(ctx, f"https://{host}/")
            except NetworkError as e:
                errors.append(e)
                continue
            pages.setdefault(_host(reply) or host, reply)
        if errors and not pages:
            raise next((e for e in errors if isinstance(e, DestinationBlocked)), errors[0])
        return list(pages.values())

    return await ctx.shared("pages", fetch)


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


# ------------------------------------------------------------------ HTTPS
@extension.check("https_redirect", category="web", weight=8)
async def https_redirect(ctx: CheckContext) -> Outcome:
    """Credit HTTPS only after a reachable, certificate-verified same-site endpoint.

    An external HTTPS destination is not evidence that the audited domain
    supports HTTPS. Timeouts and blocked egress never earn a positive verdict.
    """
    hosts = await ctx.web_hosts()
    if not hosts:
        return na("web.no_website")
    evidence: dict[str, str] = {}

    async def verify_https(host: str, target: str, steps: list[str]) -> Outcome | None:
        evidence[host] = " → ".join([*steps, target])
        if not _same_site(ctx, target):
            # A third-party redirect may be a legitimate business choice, but
            # it must not certify the audited site's own HTTPS deployment.
            return fail("web.https_redirect.external", _delegate("https_redirect.external"), evidence, host=host)
        try:
            # Follow no redirects here: one valid HTTPS response on our own
            # hostname proves reachability and certificate validity.
            await ctx.net.http_get(target, verify=True)
        except DestinationBlocked:
            raise
        except UntrustedCertificate:
            return fail("web.https_redirect.bad_certificate", _delegate("https_redirect"), evidence, host=host)
        except Refused:
            return fail("web.https_redirect.https_unavailable", _delegate("https_redirect"), evidence, host=host)
        # Other NetworkError subclasses (timeouts, DNS, etc.) remain ERROR:
        # the probe has no evidence and must not invent a server failure.
        return None

    for host in hosts:
        url = f"http://{host}/"
        steps: list[str] = []
        try:
            reply = await ctx.net.http_get(url)
        except DestinationBlocked:
            raise
        except Refused:
            # A closed HTTP port is safe only if HTTPS actually works.
            verdict = await verify_https(host, f"https://{host}/", [f"{url} closed"])
            if verdict is not None:
                return verdict
            continue
        # A timeout, unlike connection refusal, is not evidence of a
        # closed HTTP port; let the engine report this as not evaluated.
        seen: set[str] = set()
        for _ in range(MAX_REDIRECTS + 1):
            if url in seen:
                evidence[host] = " → ".join([*steps, f"loop {url}"])
                return fail("web.https_redirect.missing", _delegate("https_redirect"), evidence, host=host)
            seen.add(url)
            steps.append(f"{reply.status} {url}")
            location = reply.header("location")
            if not (300 <= reply.status < 400 and location):
                evidence[host] = " → ".join(steps)
                return fail("web.https_redirect.missing", _delegate("https_redirect"), evidence, host=host)
            next_url = urljoin(url, location)
            scheme = urlsplit(next_url).scheme
            if scheme == "https":
                verdict = await verify_https(host, next_url, steps)
                if verdict is not None:
                    return verdict
                break
            if scheme != "http" or not _same_site(ctx, next_url):
                evidence[host] = " → ".join([*steps, next_url])
                return fail("web.https_redirect.missing", _delegate("https_redirect"), evidence, host=host)
            url = next_url
            try:
                reply = await ctx.net.http_get(url)
            except DestinationBlocked:
                raise
            except Refused:
                evidence[host] = " → ".join([*steps, f"{url} closed"])
                return fail("web.https_redirect.missing", _delegate("https_redirect"), evidence, host=host)
        else:
            evidence[host] = " → ".join(steps)
            return fail("web.https_redirect.missing", _delegate("https_redirect"), evidence, host=host)
    return ok("web.https_redirect.ok", evidence)


def _hsts_max_age(header: str) -> int | None:
    """The max-age of an HSTS header, None when absent or invalid. With several headers,
    browsers only use the first (RFC 6797 §8.1)."""
    for directive in header.split(",")[0].split(";"):
        name, _, value = directive.strip().partition("=")
        if name.strip().lower() == "max-age":
            value = value.strip().strip('"')
            return int(value) if value.isdigit() else None
    return None


@extension.check("hsts", category="web", weight=6)
async def hsts(ctx: CheckContext) -> Outcome:
    """HSTS makes browsers remember to use HTTPS only, even if a link says http://."""
    pages = await _pages(ctx)
    if not pages:
        return na("web.no_website")
    for page in pages:
        header = page.header("strict-transport-security")
        evidence = {"url": page.url, "header": header}
        if not header:
            return warn("web.hsts.missing", _delegate("hsts"), evidence, host=_host(page))
        max_age = _hsts_max_age(header)
        if max_age is None:
            return warn("web.hsts.invalid", _delegate("hsts"), evidence, host=_host(page))
        if max_age == 0:  # RFC 6797 §6.1.1: tells browsers to forget the site's HSTS
            return warn("web.hsts.disabled", _delegate("hsts"), evidence, host=_host(page))
        if max_age < HSTS_MIN_SECONDS:
            return warn("web.hsts.short", _delegate("hsts"), evidence, host=_host(page), days=max_age // 86400)
    return ok("web.hsts.ok", {"headers": {p.url: p.header("strict-transport-security") for p in pages}})


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


@extension.check("csp", category="web", weight=4)
async def csp(ctx: CheckContext) -> Outcome:
    """A Content-Security-Policy that limits where scripts may come from."""
    pages = await _pages(ctx)
    if not pages:
        return na("web.no_website")
    evidence = {p.url: p.header("content-security-policy") for p in pages}
    for page in pages:
        weakness = _script_weakness(page)
        if weakness is not None:
            return warn(f"web.csp.{weakness}", _delegate("csp"), evidence, host=_host(page))
    return ok("web.csp.ok", evidence)


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


@extension.check("framing", category="web", weight=3)
async def framing(ctx: CheckContext) -> Outcome:
    """Other sites must not be able to show the site in a frame (clickjacking)."""
    pages = await _pages(ctx)
    if not pages:
        return na("web.no_website")
    evidence = {p.url: {"x-frame-options": p.header("x-frame-options"),
                        "content-security-policy": p.header("content-security-policy")} for p in pages}
    for page in pages:
        state = _framing(page)
        if state != "protected":
            return warn(f"web.framing.{state}", _delegate("framing"), evidence, host=_host(page))
    return ok("web.framing.ok", evidence)


# ------------------------------------------------------- the other headers
@extension.check("nosniff", category="web", weight=2)
async def nosniff(ctx: CheckContext) -> Outcome:
    """X-Content-Type-Options: nosniff, so the browser does not guess file types."""
    pages = await _pages(ctx)
    if not pages:
        return na("web.no_website")
    evidence = {p.url: p.header("x-content-type-options") for p in pages}
    for page in pages:
        if page.header("x-content-type-options").split(",")[0].strip().lower() != "nosniff":
            return warn("web.nosniff.missing", _delegate("nosniff"), evidence, host=_host(page))
    return ok("web.nosniff.ok", evidence)


def _referrer_policy(page: HttpReply) -> str | None:
    """The policy browsers apply: the last value they know (W3C Referrer Policy §11.1)."""
    known = [v.strip().lower() for v in page.header("referrer-policy").split(",")
             if v.strip().lower() in REFERRER_POLICIES]
    return known[-1] if known else None


@extension.check("referrer", category="web", weight=1)
async def referrer(ctx: CheckContext) -> Outcome:
    """Referrer-Policy limits the address sent to the sites a visitor goes to next."""
    pages = await _pages(ctx)
    if not pages:
        return na("web.no_website")
    evidence = {p.url: p.header("referrer-policy") for p in pages}
    for page in pages:
        policy = _referrer_policy(page)
        if policy is None:
            return warn("web.referrer.missing", _delegate("referrer"), evidence, host=_host(page))
        if policy == "unsafe-url":  # the full address, query string included, to every site, even over HTTP
            return warn("web.referrer.unsafe", _delegate("referrer"), evidence, host=_host(page))
    return ok("web.referrer.ok", evidence)


@extension.check("server_banner", category="web", weight=2)
async def server_banner(ctx: CheckContext) -> Outcome:
    """Software versions in the headers tell attackers which known flaws to try."""
    pages = await _pages(ctx)
    if not pages:
        return na("web.no_website")
    for page in pages:
        for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            value = page.header(header)
            if re.search(r"\d+\.\d+", value):
                return warn("web.server_banner.version", _delegate("server_banner", 10),
                            {"url": page.url, header: value}, header=header, value=value)
    return ok("web.server_banner.ok")


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


@extension.check("security_txt", category="web", weight=1, internal=False)
async def security_txt(ctx: CheckContext) -> Outcome:
    """security.txt tells whoever finds a flaw how to report it (RFC 9116)."""
    hosts = await ctx.web_hosts()
    if not hosts:
        return na("web.no_website")
    reply, url, failure = None, "", None
    for host in hosts:  # the first web host that answers over HTTPS
        url = f"https://{host}/.well-known/security.txt"
        try:
            reply = await _follow(ctx, url)
            break
        except DestinationBlocked:
            raise
        except NetworkError as e:
            failure = e
    if reply is None:
        assert failure is not None
        raise failure
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
