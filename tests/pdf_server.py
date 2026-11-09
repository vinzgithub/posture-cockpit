# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A server of its own for the tests of the PDF reports (version 0.7.0, corrective 3).

tests/test_v070_pdf_server.py starts it as a separate process, as an instance runs:

    python tests/pdf_server.py FOLDER MX_COUNT

It builds the application with recorded answers (core/fixture.py), three accounts (vincent, the
administrator, alice and bob), and scans two domains: example.org, whose MX record lists MX_COUNT
names (3,000 gives the heaviest report measured, 117 pages), and light.example, a usual one. It serves
on a free port of 127.0.0.1 and writes the port to FOLDER/port and its process id to FOLDER/pid. When
it stops (SIGTERM, at the end of its shutdown: uvicorn then ends the process by that signal), it writes to
FOLDER/modules whether WeasyPrint was ever imported in its own process: the reports are laid out in
processes of their own, never here.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "src"), str(HERE)]

import uvicorn  # noqa: E402

from helpers import PASSWORD  # noqa: E402
from posture_cockpit.config import Config  # noqa: E402
from posture_cockpit.core.fixture import FixtureNetwork  # noqa: E402
from posture_cockpit.security import hash_password  # noqa: E402
from posture_cockpit.web import first_run  # noqa: E402
from posture_cockpit.web.app import create_app  # noqa: E402
from posture_cockpit.web.scanning import scan_and_save  # noqa: E402
from smtp_reference import build  # noqa: E402
from worlds import DOMAIN, healthy  # noqa: E402

LIGHT = "light.example"
MX1 = "mx.example.net"


def worlds(mx_count: int) -> dict[str, dict]:
    """example.org with ``mx_count`` MX names besides MX1 (the measured one), and light.example."""
    names = [f"a{i}.example.org" for i in range(mx_count)]
    heavy = build([(i + 1, name) for i, name in enumerate(names)] + [(9000, MX1)], {MX1: ["192.0.2.25"]},
                  {MX1: {"192.0.2.25": "tls_verified"}}, covered=[MX1, *names[:1000]])
    return {DOMAIN: heavy, LIGHT: json.loads(json.dumps(healthy()).replace(DOMAIN, LIGHT))}


def main(folder: Path, mx_count: int) -> None:
    known = worlds(mx_count)

    def network(domain: str) -> FixtureNetwork:
        return FixtureNetwork(known.get(domain, {"dns": {f"{domain} SOA": None}}))

    app = create_app(Config(data_dir=folder / "data"), network_factory=network)
    s = app.state.services
    for name in ("vincent", "alice", "bob"):
        s.accounts.create(name, hash_password(PASSWORD), is_admin=name == "vincent")
    app.state.setup_code = None
    first_run.clear(s.db)
    vincent = s.accounts.by_name("vincent")
    for domain in (DOMAIN, LIGHT):
        asyncio.run(scan_and_save(s, domain, vincent))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))

    def modules() -> None:
        (folder / "modules").write_text(json.dumps({"weasyprint": "weasyprint" in sys.modules}))

    app.router.on_shutdown.append(modules)
    (folder / "pid").write_text(str(os.getpid()))
    (folder / "port").write_text(str(sock.getsockname()[1]))
    server.run(sockets=[sock])


if __name__ == "__main__":
    main(Path(sys.argv[1]), int(sys.argv[2]))
