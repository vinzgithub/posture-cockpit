# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Reproduce the public fictitious report with the normal report renderer, without network."""
import asyncio
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from posture_cockpit import __version__
from posture_cockpit.core import engine
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.registry import Registry
from posture_cockpit.i18n import Catalog
from posture_cockpit.report import build_pdf
from posture_cockpit.scanner import DEMO_DOMAIN, demo_data
from posture_cockpit.storage import Database, Scans

registry = Registry.discover()
catalog = Catalog(registry.messages)
# Frozen reference date: fixtures/certificates are not silently aged by the generator's clock.
now = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
result = asyncio.run(engine.scan(DEMO_DOMAIN, registry.checks(), FixtureNetwork(demo_data(DEMO_DOMAIN), now), now=now))
output = Path(__file__).resolve().parents[1] / 'docs' / 'examples'
output.mkdir(parents=True, exist_ok=True)
with TemporaryDirectory() as folder:
    db = Database(Path(folder) / 'demo.db')
    try:
        scans = Scans(db)
        did = scans.add_domain(DEMO_DOMAIN, None)
        sid = scans.save(did, result, __version__, None)
        scan = scans.get(sid)
        for language, author in [('fr', 'DÉMONSTRATION FICTIVE — candidate v0.6.1'),
                                 ('en', 'FICTIONAL DEMONSTRATION — v0.6.1 candidate')]:
            path = output / f'posture-cockpit-mission-control-demo.{language}.pdf'
            path.write_bytes(build_pdf(catalog, language, scan, author))
            print(path.name, scan.assessment().score, scan.assessment().grade)
    finally:
        db.close()
