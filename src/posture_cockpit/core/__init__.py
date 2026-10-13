# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The analysis engine, independent of the web interface.

Extension authors only need the names exported here::

    from posture_cockpit.core import CheckContext, Extension, ok, warn, fail, na, info, Remedy, Effort, DnsChange
"""

from .extension import CATEGORIES, Check, CheckContext, Extension, load_messages
from .model import DnsChange, Effort, Finding, Outcome, Remedy, Status, fail, info, na, not_evaluated, ok, warn
from .network import Certificate, DnsAnswer, HttpReply, Network, NetworkError, Refused, UntrustedCertificate

__all__ = [
    "CATEGORIES", "Certificate", "Check", "CheckContext", "DnsAnswer", "DnsChange", "Effort", "Extension",
    "Finding", "HttpReply", "Network", "NetworkError", "Outcome", "Refused", "Remedy", "Status", "UntrustedCertificate",
    "fail", "info", "load_messages", "na", "not_evaluated", "ok", "warn",
]
