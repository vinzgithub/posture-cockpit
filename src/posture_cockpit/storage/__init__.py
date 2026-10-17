# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Persistence in one SQLite file: the connection (database.py), its schema
(schema.py), its opening with a verified backup before any migration (upgrade.py)
and one repository per subject (accounts.py, scans.py, perimeters.py, audit.py,
settings.py)."""

from . import instance_lock
from .accounts import Accounts
from .audit import AuditLog
from .database import Database, Row, UnsupportedSchema
from .perimeters import Perimeter, PerimeterError, Perimeters
from .scans import CorruptScan, Scan, Scans
from .settings import InstanceSettings
from .upgrade import open_database

__all__ = [
           "Accounts",
           "AuditLog",
           "CorruptScan",
           "Database",
           "InstanceSettings",
           "Perimeter",
           "PerimeterError",
           "Perimeters",
           "Row",
           "Scan",
           "Scans",
           "UnsupportedSchema",
           "instance_lock",
           "open_database",
]
