# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""One module per area of the interface:

- auth.py     first run, sign-in with two-factor authentication, sign-out, language
- account.py  the user's settings: password, two-factor authentication, API keys
- admin.py    accounts and extensions (administrators only)
- domains.py  domain list, scans, plan of fixes, rechecks, expert view
- report.py   the PDF report
- api.py      read-only JSON for Home Assistant and monitoring tools
"""
