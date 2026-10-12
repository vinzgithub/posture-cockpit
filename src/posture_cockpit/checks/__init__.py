# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The built-in extensions, written exactly like third-party ones.

Each module creates an ``extension`` object and declares its checks with
``@extension.check(...)``; its texts are in ``locales/<module>.<lang>.json``.
They are a good starting point for writing a new extension (docs/EXTENSIONS.md).
"""

from pathlib import Path

LOCALES = Path(__file__).parent / "locales"
