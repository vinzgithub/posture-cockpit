# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""HTTPS of the website: certificate, TLS versions, key strength.

The website is the domain itself and ``www``, whichever have an address.

References: ANSSI, « Recommandations de sécurité relatives à TLS » and « Guide
de sélection d'algorithmes cryptographiques »; RFC 8996 (end of TLS 1.0 and 1.1).
"""

from __future__ import annotations

import asyncio

from .. import __version__
from ..core import (
    Certificate,
    CheckContext,
    Effort,
    Extension,
    NetworkError,
    Outcome,
    Remedy,
    fail,
    load_messages,
    na,
    not_evaluated,
    ok,
    warn,
)
from ..core.egress import DestinationBlocked
from . import LOCALES

extension = Extension("tls", name="TLS", version=__version__,
                      description="Certificate validity and expiry, TLS versions, key strength.",
                      messages=load_messages(LOCALES, "tls"))

# Days before expiry. Certificates renewed automatically are replaced well before
# these limits (Let's Encrypt: 30 days before), so reaching them means renewal failed.
EXPIRY_CRITICAL_DAYS = 10
EXPIRY_WARNING_DAYS = 20
MIN_RSA_BITS = 2048
TLS_NAMES = {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1", "TLSv1.2": "TLS 1.2", "TLSv1.3": "TLS 1.3"}
MIN_EC_BITS = 256


async def _certificates(ctx: CheckContext) -> dict[str, Certificate]:
    """Certificate of each web host. Raises NetworkError when none answers on port 443."""

    async def fetch() -> dict[str, Certificate]:
        hosts = await ctx.web_hosts()
        results = await asyncio.gather(*(ctx.net.certificate(h) for h in hosts), return_exceptions=True)
        certs = {h: r for h, r in zip(hosts, results, strict=True) if isinstance(r, Certificate)}
        errors = [r for r in results if isinstance(r, BaseException)]
        if hosts and not certs:
            # Say why nothing could be read; a refused destination says it best.
            first = next((e for e in errors if isinstance(e, DestinationBlocked)), errors[0])
            raise first if isinstance(first, NetworkError) else NetworkError(str(first))
        return certs

    return await ctx.shared("certificates", fetch)


def _days_left(ctx: CheckContext, cert: Certificate) -> int:
    return (cert.not_after - ctx.now).days


@extension.check("certificate", category="tls", weight=10)
async def certificate(ctx: CheckContext) -> Outcome:
    """The certificate must be trusted by browsers and must not be about to expire."""
    certs = await _certificates(ctx)
    if not certs:
        return na("tls.no_website")
    evidence = {host: {"issuer": c.issuer, "expires": c.not_after.date().isoformat(), "names": list(c.names),
                       "trusted": c.trusted, "problem": c.problem} for host, c in certs.items()}
    # The host whose certificate expires first decides.
    host, cert = min(certs.items(), key=lambda item: item[1].not_after)
    days = _days_left(ctx, cert)
    params: dict[str, str | int] = {"host": host, "days": max(days, 0), "issuer": cert.issuer,
                                    "expires_on": cert.not_after.date().isoformat()}
    renew = Remedy(5, Effort.DELEGATE, message="tls.certificate.renew_message")
    if days < 0:
        return fail("tls.certificate.expired", renew, evidence, **params)
    untrusted = next(((h, c) for h, c in certs.items() if not c.trusted), None)
    if untrusted:
        h, c = untrusted
        return fail("tls.certificate.untrusted", Remedy(15, Effort.DELEGATE, message="tls.certificate.fix_message"),
                    evidence, host=h, problem=c.problem)
    if days <= EXPIRY_CRITICAL_DAYS:
        return fail("tls.certificate.expires_soon", renew, evidence, **params)
    if days <= EXPIRY_WARNING_DAYS:
        return warn("tls.certificate.expires", renew, evidence, **params)
    return ok("tls.certificate.ok", evidence, **params)


@extension.check("protocols", category="tls", weight=5)
async def protocols(ctx: CheckContext) -> Outcome:
    """TLS 1.0 and 1.1 are obsolete; TLS 1.3 is preferred, TLS 1.2 accepted."""
    hosts = list(await _certificates(ctx))
    if not hosts:
        return na("tls.no_website")
    support: dict[str, dict[str, bool | None]] = {}
    for host in hosts:
        versions = ("TLSv1", "TLSv1.1", "TLSv1.3")
        answers = await asyncio.gather(*(ctx.net.accepts_tls(host, v) for v in versions))
        support[host] = dict(zip(versions, answers, strict=True))
    evidence = {"accepted": support}
    obsolete = sorted({v for answers in support.values() for v, accepted in answers.items()
                       if v in ("TLSv1", "TLSv1.1") and accepted})
    if obsolete:
        return fail("tls.protocols.obsolete", Remedy(15, Effort.DELEGATE, message="tls.protocols.message"),
                    evidence, versions=", ".join(TLS_NAMES[v] for v in obsolete))
    untested = sorted({v for answers in support.values() for v, accepted in answers.items()
                       if v in ("TLSv1", "TLSv1.1") and accepted is None})
    if untested:
        # This machine's TLS library cannot speak these versions: saying "not accepted" would be a guess.
        return not_evaluated("tls.protocols.untestable", evidence, versions=", ".join(TLS_NAMES[v] for v in untested))
    if not all(answers.get("TLSv1.3") for answers in support.values()):
        return warn("tls.protocols.no_tls13", Remedy(15, Effort.DELEGATE, message="tls.protocols.tls13_message"),
                    evidence)
    return ok("tls.protocols.ok", evidence)


@extension.check("key", category="tls", weight=3)
async def key(ctx: CheckContext) -> Outcome:
    """The certificate's key must be long enough: RSA 2048 bits, or an elliptic curve of 256 bits."""
    certs = await _certificates(ctx)
    if not certs:
        return na("tls.no_website")
    evidence = {host: f"{c.key_type} {c.key_bits}" for host, c in certs.items()}
    for host, c in certs.items():
        weak = (c.key_type == "RSA" and c.key_bits < MIN_RSA_BITS) or (c.key_type == "EC" and c.key_bits < MIN_EC_BITS)
        if weak or c.key_type == "DSA":
            return fail("tls.key.weak", Remedy(15, Effort.DELEGATE, message="tls.key.message"), evidence,
                        host=host, key=f"{c.key_type} {c.key_bits}")
    first = next(iter(certs.values()))
    return ok("tls.key.ok", evidence, key=f"{first.key_type} {first.key_bits}")
