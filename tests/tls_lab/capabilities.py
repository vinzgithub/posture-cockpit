# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""What the TLS of this interpreter can do, as a stable JSON report (version 0.8.0, PR-A).

Run in the image of the product, on AMD64 and ARM64 (CI job ``tls-lab``), it says what a prober built on
the ``ssl`` module could offer there: versions, suites of TLS ≤ 1.2 by category, DHE parameters, the APIs
that are missing (choice of the TLS 1.3 suites and of the groups, the group negotiated), and one real
handshake per version between a server and a client of the bench, on this machine only (guard.py)::

    PYTHONPATH=tests python -m tls_lab.capabilities [--out report.json]

It confirms, or not, the limits of the ``ssl`` module that study R0 (§ 1.2) listed. It changes nothing.
"""

from __future__ import annotations

import argparse
import json
import platform
import ssl
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import guard, servers, wire

LEGACY = ("TLS1.0", "TLS1.1")


def _enabled(name: str) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        ctx.set_ciphers(f"{name}:@SECLEVEL=0")
    except ssl.SSLError:
        return False
    return any(c["name"] == name for c in ctx.get_ciphers())


def _dh(name: str) -> str:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    try:
        ctx.load_dh_params(str(servers.DATA / f"{name}.pem"))
    except (ssl.SSLError, OSError) as error:
        return f"refused: {getattr(error, 'reason', None) or error}"
    return "loaded"


def _handshakes(certs: dict) -> dict[str, str]:
    out = {}
    for version in ("TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"):
        level = 0 if version in LEGACY else None
        config = servers.ServerConfig(f"only-{version}", minimum=version, maximum=version, seclevel=level)
        try:
            with servers.TlsServer(config, certs) as server:
                got = servers.handshake(server.address, servers.client_context(version, version, seclevel=level))
        except ssl.SSLError as error:
            out[version] = f"server refused: {error.reason or error}"
            continue
        out[version] = f"{got.version} {got.suite}" if got.version else f"failed: {got.error}"
    return out


def report() -> dict[str, Any]:
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    categories: dict[str, dict[str, bool]] = {}
    for suite in sorted(wire.SUITES.values(), key=lambda s: s.code):
        if suite.category != "tls13":
            categories.setdefault(suite.category, {})[suite.name] = _enabled(suite.name)
    with tempfile.TemporaryDirectory() as folder, guard.loopback_only():
        certs = servers.certificates(Path(folder))
        handshakes = _handshakes(certs)
    return {
        "python": platform.python_version(),
        "openssl": ssl.OPENSSL_VERSION,
        "machine": platform.machine(),
        "module": {name: bool(getattr(ssl, name, False))
                   for name in ("HAS_SSLv2", "HAS_SSLv3", "HAS_TLSv1", "HAS_TLSv1_1", "HAS_TLSv1_2", "HAS_TLSv1_3")},
        "api": {
            "choose TLS 1.3 suites (SSLContext.set_ciphersuites)": hasattr(client, "set_ciphersuites"),
            "choose groups (SSLContext.set_groups)": hasattr(client, "set_groups"),
            "group negotiated (SSLSocket.group)": hasattr(ssl.SSLSocket, "group"),
            "offer SSLv3": bool(getattr(ssl, "HAS_SSLv3", False)),
        },
        "suites_tls12_at_seclevel_0": categories,
        "dh_parameters_at_seclevel_0": {name: _dh(name) for name in ("dh1024", "dh2048")},
        "handshakes": handshakes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, help="write the report to this file as well")
    args = parser.parse_args(argv)
    text = json.dumps(report(), indent=2, sort_keys=True)
    sys.stdout.write(text + "\n")
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
