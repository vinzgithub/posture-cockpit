# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""TLS 1.0 and 1.1, for diagnosis only: the one place that builds a context for them (version 0.4).

These versions need old ciphers, which OpenSSL only allows at its security level 0.
A context built here is used:

- by the HTTPS probe, to tell an address that speaks only these versions from one
  that refuses HTTPS altogether, after TLS 1.2 and 1.3 were refused;
- on an address that speaks nothing newer, to read what the checks measure there:
  the certificate, the home page and ``/.well-known/security.txt``;
- by ``tls.protocols``, for its version handshakes, closed as soon as they end, on
  any address (it must find out whether an old version is still accepted).

Nothing else may use it. Requests sent over it are plain GETs without cookie,
credentials, client certificate or body, and its certificate verification
authenticates nothing: it only describes the certificate.
"""

from __future__ import annotations

import ssl
import warnings

VERSIONS = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1}


def context(minimum: str = "TLSv1", maximum: str = "TLSv1.1", *, verify: bool = False,
            trusted_ca: str = "") -> ssl.SSLContext | None:
    """A client context for TLS ``minimum`` to ``maximum`` (each "TLSv1" or "TLSv1.1"), at security level 0.

    ``verify``: check the chain and the name like a browser, with the system's authorities and the
    perimeter's own (``trusted_ca``), for the diagnosis only. None when this machine's TLS library
    cannot be set up for these versions at all."""
    try:
        if verify:
            built = ssl.create_default_context()
            if trusted_ca:
                built.load_verify_locations(cadata=trusted_ca)
        else:
            built = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            built.check_hostname = False
            built.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():  # Python warns that TLS 1.0 is deprecated: that is the point
            warnings.simplefilter("ignore", DeprecationWarning)
            built.minimum_version = VERSIONS[minimum]
            built.maximum_version = VERSIONS[maximum]
        built.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    return built
