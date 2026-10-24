# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Posture Cockpit: passive security check of a domain, with a guided plan of fixes.

Package layout (details in docs/ARCHITECTURE.md):

- ``core``     the analysis engine: data model, extensions, network access, scoring;
- ``checks``   the built-in extensions (mail, TLS, web, DNS);
- ``storage``  the SQLite database: accounts and scan results;
- ``web``      the FastAPI application, its pages and their routes;
- ``report``   the PDF report;
- ``cli``      command-line tools (scan from a terminal, account rescue).
"""

__version__ = "0.6.1"
