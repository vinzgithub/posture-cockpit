# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""HTTPS of the website: certificate, TLS versions, key strength.

The website is the domain itself and ``www``. Version 0.4: every address of
theirs that negotiates TLS is measured (from the HTTPS probe, see
:mod:`..core.https_probe`), and each check keeps the worst verdict of its
addresses, the address named: one address in good order never hides another.
An address that speaks only TLS 1.0 or 1.1 is measured over that version.

References: ANSSI, « Recommandations de sécurité relatives à TLS » and « Guide
de sélection d'algorithmes cryptographiques »; RFC 8996 (end of TLS 1.0 and 1.1).
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any

from .. import __version__
from ..core import (
    Certificate,
    CheckContext,
    Effort,
    Extension,
    NetworkError,
    Outcome,
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
from ..core.https_probe import AddressResult, Kind
from . import LOCALES

extension = Extension("tls", name="TLS", version=__version__,
                      description="Certificate validity and expiry, TLS versions, key strength.",
                      messages=load_messages(LOCALES, "tls"))

# Version 0.4: the verdicts each check can give (the scoring caps use the lowest non-critical one).
THREE_VERDICTS = frozenset({Status.OK, Status.WARN, Status.FAIL})
KEY_VERDICTS = frozenset({Status.OK, Status.FAIL})  # a key is long enough or it is not

# Days before expiry. Certificates renewed automatically are replaced well before
# these limits (Let's Encrypt: 30 days before), so reaching them means renewal failed.
EXPIRY_CRITICAL_DAYS = 10
EXPIRY_WARNING_DAYS = 20
MIN_RSA_BITS = 2048
TLS_NAMES = {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1", "TLSv1.2": "TLS 1.2", "TLSv1.3": "TLS 1.3"}
MIN_EC_BITS = 256


async def _measured(ctx: CheckContext) -> list[AddressResult] | None:
    """Every address that negotiates TLS, with its certificate; None when there is no website."""
    probe = await probe_.result(ctx)
    if probe.absent:
        return None
    measured = [a for a in probe.negotiating if a.certificate is not None]
    if not measured:
        raise NetworkError("no address of the website negotiates TLS")
    return measured


def _label(a: AddressResult, measured: list[AddressResult]) -> str:
    """The host, with the address when the host was measured on several."""
    return a.label if sum(m.host == a.host for m in measured) > 1 else a.host


def _days_left(ctx: CheckContext, cert: Certificate) -> int:
    return (cert.not_after - ctx.now).days


def _unauthenticated(ctx: CheckContext, cert: Certificate) -> bool:
    """A browser cannot authenticate the server: expired, not yet valid, chain or name not verified.

    "Expires soon" is not: the certificate is still valid. A certificate signed by the
    perimeter's own authority is verified as such, in an internal audit."""
    return _days_left(ctx, cert) < 0 or not cert.trusted


def _rank(ctx: CheckContext, cert: Certificate) -> int:
    """0 expired, 1 not trusted, 2 expires within 10 days, 3 within 20, 4 fine (0.3.2's order)."""
    days = _days_left(ctx, cert)
    if days < 0:
        return 0
    if not cert.trusted:
        return 1
    return 2 if days <= EXPIRY_CRITICAL_DAYS else 3 if days <= EXPIRY_WARNING_DAYS else 4


@extension.check("certificate", category="tls", weight=10, requires="https", verdicts=THREE_VERDICTS)
async def certificate(ctx: CheckContext) -> Outcome:
    """The certificate must be trusted by browsers and must not be about to expire."""
    measured = await _measured(ctx)
    if measured is None:
        return na("tls.no_website")
    certs = [(a, a.certificate) for a in measured if a.certificate is not None]
    evidence: dict[str, Any] = {_label(a, measured): {
        "address": a.address, "issuer": c.issuer, "expires": c.not_after.date().isoformat(), "names": list(c.names),
        "trusted": c.trusted, "problem": c.problem, "version": a.version} for a, c in certs}
    best = min(_rank(ctx, c) for _, c in certs)
    candidates = [(a, c) for a, c in certs if _rank(ctx, c) == best]
    # The certificate that expires first decides, as in 0.3.2; for a distrusted one, the first found.
    a, cert = candidates[0] if best == 1 else min(candidates, key=lambda item: item[1].not_after)
    host = _label(a, measured)
    days = _days_left(ctx, cert)
    params: dict[str, str | int] = {"host": host, "days": max(days, 0), "issuer": cert.issuer,
                                    "expires_on": cert.not_after.date().isoformat()}
    renew = Remedy(5, Effort.DELEGATE, message="tls.certificate.renew_message")
    obsolete = [m for m in measured if m.kind is Kind.OBSOLETE]
    if obsolete:  # verified at security level 0, as these versions require: a weak signature may pass
        evidence["notes"] = [{"key": "tls.certificate.note.seclevel", "params": {
            "addresses": ", ".join(m.label for m in obsolete)}}]
    if best == 0:
        outcome = fail("tls.certificate.expired", renew, evidence, **params)
    elif best == 1:
        outcome = fail("tls.certificate.untrusted",
                       Remedy(15, Effort.DELEGATE, message="tls.certificate.fix_message"),
                       evidence, host=host, problem=cert.problem)
    elif best == 2:
        return fail("tls.certificate.expires_soon", renew, evidence, **params)
    elif best == 3:
        return warn("tls.certificate.expires", renew, evidence, **params)
    else:
        return ok("tls.certificate.ok", evidence, **params)
    # Expired or not trusted on one address at least: the authentication cap (version 0.4).
    return replace(outcome, signals=frozenset({Signal.CERTIFICATE_UNAUTHENTICATED}))


async def _versions(ctx: CheckContext, a: AddressResult) -> dict[str, bool | None]:
    """The TLS versions one address accepts. An obsolete address: what the probe saw (TLS 1.2 and
    1.3 refused); otherwise one handshake per version, closed at once, unless the probe saw it."""
    if a.kind is Kind.OBSOLETE:
        return {"TLSv1": a.legacy.get("TLSv1"), "TLSv1.1": a.legacy.get("TLSv1.1"),
                "TLSv1.2": False, "TLSv1.3": False}
    answers: dict[str, bool | None] = {}
    asked = []
    for version in ("TLSv1", "TLSv1.1", "TLSv1.3"):
        seen = [t for t in a.attempts if t.offer == version]
        if (version == "TLSv1.3" and a.version == "TLSv1.3") or (seen and seen[-1].result == "ok"):
            answers[version] = True  # negotiated by the probe
        elif seen and seen[-1].stage == "tls" and seen[-1].result not in ("timeout", "untestable"):
            answers[version] = False  # refused during the probe's confirmation
        else:
            asked.append(version)
    results = await asyncio.gather(*(ctx.net.accepts_tls_at(a.host, a.address, v) for v in asked))
    answers.update(zip(asked, results, strict=True))
    return {v: answers[v] for v in ("TLSv1", "TLSv1.1", "TLSv1.3")}


@extension.check("protocols", category="tls", weight=5, requires="https", verdicts=THREE_VERDICTS)
async def protocols(ctx: CheckContext) -> Outcome:
    """TLS 1.0 and 1.1 are obsolete; TLS 1.3 is preferred, TLS 1.2 accepted."""
    measured = await _measured(ctx)
    if measured is None:
        return na("tls.no_website")
    support = {_label(a, measured): answers
               for a, answers in zip(measured, await asyncio.gather(*(_versions(ctx, a) for a in measured)),
                                     strict=True)}
    evidence: dict[str, Any] = {"accepted": support}
    obsolete = sorted({v for answers in support.values() for v, accepted in answers.items()
                       if v in ("TLSv1", "TLSv1.1") and accepted})
    only_old = [a for a in measured if a.kind is Kind.OBSOLETE]
    if only_old:
        evidence["notes"] = [{"key": "tls.protocols.note.no_modern", "params": {
            "addresses": ", ".join(a.label for a in only_old)}}]
    if obsolete:
        return fail("tls.protocols.obsolete", Remedy(15, Effort.DELEGATE, message="tls.protocols.message"),
                    evidence, versions=", ".join(TLS_NAMES[v] for v in obsolete))
    untested = sorted({v for answers in support.values() for v, accepted in answers.items()
                       if v in ("TLSv1", "TLSv1.1") and accepted is None})
    if untested:
        # This machine's TLS library cannot speak these versions: saying "not accepted" would be a guess.
        evidence["cause"] = "tool"
        return not_evaluated("tls.protocols.untestable", evidence, versions=", ".join(TLS_NAMES[v] for v in untested))
    if not all(answers.get("TLSv1.3") for answers in support.values()):
        return warn("tls.protocols.no_tls13", Remedy(15, Effort.DELEGATE, message="tls.protocols.tls13_message"),
                    evidence)
    return ok("tls.protocols.ok", evidence)


@extension.check("key", category="tls", weight=3, requires="https", verdicts=KEY_VERDICTS)
async def key(ctx: CheckContext) -> Outcome:
    """The certificate's key must be long enough: RSA 2048 bits, or an elliptic curve of 256 bits."""
    measured = await _measured(ctx)
    if measured is None:
        return na("tls.no_website")
    certs = [(a, a.certificate) for a in measured if a.certificate is not None]
    evidence = {_label(a, measured): f"{c.key_type} {c.key_bits}" for a, c in certs}
    for a, c in certs:
        weak = (c.key_type == "RSA" and c.key_bits < MIN_RSA_BITS) or (c.key_type == "EC" and c.key_bits < MIN_EC_BITS)
        if weak or c.key_type == "DSA":
            return fail("tls.key.weak", Remedy(15, Effort.DELEGATE, message="tls.key.message"), evidence,
                        host=_label(a, measured), key=f"{c.key_type} {c.key_bits}")
    first = certs[0][1]
    return ok("tls.key.ok", evidence, key=f"{first.key_type} {first.key_bits}")
