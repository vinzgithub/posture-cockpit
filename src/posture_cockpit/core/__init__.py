# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The analysis engine, independent of the web interface.

Extension authors only need the names exported here::

    from posture_cockpit.core import CheckContext, Extension, ok, warn, fail, info, Remedy, Effort, DnsChange
"""

from .extension import CATEGORIES, Check, CheckContext, Extension, load_messages
from .model import DnsChange, Effort, Finding, Outcome, Remedy, Status, fail, info, ok, warn
from .network import Certificate, DnsAnswer, HttpReply, Network, NetworkError

__all__ = [
    "CATEGORIES", "Certificate", "Check", "CheckContext", "DnsAnswer", "DnsChange", "Effort", "Extension",
    "Finding", "HttpReply", "Network", "NetworkError", "Outcome", "Remedy", "Status", "fail", "info",
    "load_messages", "ok", "warn",
]
