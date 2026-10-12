# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The website's answers: redirection to HTTPS and the protection headers browsers obey.

Only the home page is read (plus security.txt), following at most a few
redirects inside the domain.

References: ANSSI, « Recommandations pour la sécurisation des sites web »;
RFC 6797 (HSTS), RFC 7034 (X-Frame-Options), RFC 9116 (security.txt).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit

from .. import __version__
from ..core import (
    CheckContext,
    Effort,
    Extension,
    HttpReply,
    NetworkError,
    Outcome,
    Remedy,
    fail,
    info,
    load_messages,
    ok,
    warn,
)
from ..core.extension import CheckFunction
from . import LOCALES

extension = Extension("web", name="Site web", version=__version__,
                      description="HTTPS redirection, HSTS, CSP and the other protection headers, security.txt.",
                      messages=load_messages(LOCALES, "web"))

HSTS_MIN_SECONDS = 180 * 24 * 3600  # six months
MAX_REDIRECTS = 4


def _delegate(check: str, minutes: int = 15) -> Remedy:
    return Remedy(minutes, Effort.DELEGATE, message=f"web.{check}.message")


def _same_site(ctx: CheckContext, url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host == ctx.domain or host.endswith("." + ctx.domain)


async def _pages(ctx: CheckContext) -> list[HttpReply]:
    """The home page of each web host over HTTPS, after redirects inside the domain.

    Two hosts that end on the same page count once."""

    async def fetch() -> list[HttpReply]:
        pages: dict[str, HttpReply] = {}
        for host in await ctx.web_hosts():
            url = f"https://{host}/"
            try:
                reply = await ctx.net.http_get(url)
                for _ in range(MAX_REDIRECTS):
                    location = reply.header("location")
                    if not (300 <= reply.status < 400 and location):
                        break
                    url = urljoin(url, location)
                    if not url.startswith("https://") or not _same_site(ctx, url):
                        break
                    reply = await ctx.net.http_get(url)
            except NetworkError:
                continue
            pages.setdefault(urlsplit(reply.url).hostname or host, reply)
        if await ctx.web_hosts() and not pages:
            raise NetworkError("no web host answered over HTTPS")
        return list(pages.values())

    return await ctx.shared("pages", fetch)


@extension.check("https_redirect", category="web", weight=8)
async def https_redirect(ctx: CheckContext) -> Outcome:
    """A visitor who types the address without https:// must be sent to the encrypted site."""
    hosts = await ctx.web_hosts()
    if not hosts:
        return info("web.no_website")
    evidence: dict[str, str] = {}
    for host in hosts:
        try:
            reply = await ctx.net.http_get(f"http://{host}/")
        except NetworkError:
            evidence[host] = "closed"  # nothing served without encryption: fine
            continue
        location = reply.header("location")
        if 300 <= reply.status < 400 and location.startswith("https://"):
            evidence[host] = f"{reply.status} → {location}"
            continue
        evidence[host] = f"{reply.status} {location}".strip()
        return fail("web.https_redirect.missing", _delegate("https_redirect"), evidence, host=host)
    return ok("web.https_redirect.ok", evidence)


@extension.check("hsts", category="web", weight=6)
async def hsts(ctx: CheckContext) -> Outcome:
    """HSTS makes browsers remember to use HTTPS only, even if a link says http://."""
    pages = await _pages(ctx)
    if not pages:
        return info("web.no_website")
    for page in pages:
        header = page.header("strict-transport-security")
        match = re.search(r"max-age\s*=\s*\"?(\d+)", header, re.IGNORECASE)
        host = urlsplit(page.url).hostname or ""
        evidence = {"url": page.url, "header": header}
        if not match:
            return warn("web.hsts.missing", _delegate("hsts"), evidence, host=host)
        if int(match.group(1)) < HSTS_MIN_SECONDS:
            return warn("web.hsts.short", _delegate("hsts"), evidence, host=host, days=int(match.group(1)) // 86400)
    return ok("web.hsts.ok", {"headers": {p.url: p.header("strict-transport-security") for p in pages}})


def _header_check(name: str, header: str, accept: Callable[[HttpReply], bool]) -> CheckFunction:
    """Declares a check that passes when ``accept(page)`` is true on every page."""

    async def run(ctx: CheckContext) -> Outcome:
        pages = await _pages(ctx)
        if not pages:
            return info("web.no_website")
        evidence = {p.url: p.header(header) for p in pages}
        for page in pages:
            if not accept(page):
                return warn(f"web.{name}.missing", _delegate(name), evidence, host=urlsplit(page.url).hostname or "")
        return ok(f"web.{name}.ok", evidence)

    run.__doc__ = f"Header {header} on the home page."
    return run


def _frame_protected(page: HttpReply) -> bool:
    xfo = page.header("x-frame-options").lower()
    return xfo in ("deny", "sameorigin") or "frame-ancestors" in page.header("content-security-policy").lower()


extension.check("csp", category="web", weight=4)(
    _header_check("csp", "content-security-policy", lambda p: bool(p.header("content-security-policy"))))
extension.check("framing", category="web", weight=3)(
    _header_check("framing", "x-frame-options", _frame_protected))
extension.check("nosniff", category="web", weight=2)(
    _header_check("nosniff", "x-content-type-options",
                  lambda p: p.header("x-content-type-options").lower() == "nosniff"))
extension.check("referrer", category="web", weight=1)(
    _header_check("referrer", "referrer-policy", lambda p: bool(p.header("referrer-policy"))))


@extension.check("server_banner", category="web", weight=2)
async def server_banner(ctx: CheckContext) -> Outcome:
    """Software versions in the headers tell attackers which known flaws to try."""
    pages = await _pages(ctx)
    if not pages:
        return info("web.no_website")
    for page in pages:
        for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            value = page.header(header)
            if re.search(r"\d+\.\d+", value):
                return warn("web.server_banner.version", _delegate("server_banner", 10),
                            {"url": page.url, header: value}, header=header, value=value)
    return ok("web.server_banner.ok")


@extension.check("security_txt", category="web", weight=1)
async def security_txt(ctx: CheckContext) -> Outcome:
    """security.txt tells whoever finds a flaw how to report it (RFC 9116)."""
    hosts = await ctx.web_hosts()
    if not hosts:
        return info("web.no_website")
    url = f"https://{hosts[0]}/.well-known/security.txt"
    try:
        reply = await ctx.net.http_get(url)
    except NetworkError:
        reply = None
    if reply and reply.status == 200 and re.search(r"^contact:", reply.body, re.IGNORECASE | re.MULTILINE):
        return ok("web.security_txt.ok", {"url": url})
    return warn("web.security_txt.missing", _delegate("security_txt", 10), {"url": url}, url=url)
