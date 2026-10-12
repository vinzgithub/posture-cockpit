# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The objects every route needs, built once when the application starts.

Routes reach them with ``services(request)``. Tests reach them through
``app.state.services``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from ..config import Config
from ..core.registry import Registry
from ..i18n import Catalog
from ..scanner import Scanner
from ..security import LoginThrottle
from ..storage import Accounts, AuditLog, Database, InstanceSettings, Perimeters, Scans

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


@dataclass
class Services:
    config: Config
    db: Database
    accounts: Accounts
    scans: Scans
    perimeters: Perimeters
    audit: AuditLog
    settings: InstanceSettings
    registry: Registry
    catalog: Catalog
    scanner: Scanner
    throttle: LoginThrottle
    templates: Jinja2Templates


def services(request: Request) -> Services:
    return request.app.state.services
