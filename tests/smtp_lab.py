# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The real network, aimed at fake SMTP servers on this machine, for the tests of the SMTP probe (version 0.7).

:class:`LabNetwork` is :class:`~posture_cockpit.core.network.LiveNetwork` itself, every
refusal of :meth:`~posture_cockpit.core.network.LiveNetwork.smtp_attempt` included: an MX
not published by the audited domain, an address not in this scan's DNS, the budget, the
deadline. It redefines the three methods that hold production values, and nothing else:

- ``_smtp_policy()``: the loopback range on the lab port, instead of public addresses on
  port 25 (the fake servers listen on 127.0.0.x);
- ``_smtp_port()``: the port of the fake servers, chosen by the system;
- ``_smtp_tls_context()``: the production contexts, plus the test authority
  (:class:`~local_servers.TestPki`) for the verifying one, so a certificate it signs can be
  verified here; the checks themselves are those of production.

This is the only redefinition of these methods anywhere: a test checks that nothing in
``src/`` redefines or calls them outside ``core/network.py``, and that the scanner always
builds a plain ``LiveNetwork``. There is no parameter of production to get the same effect.
"""

from __future__ import annotations

import ssl
from ipaddress import ip_network
from typing import Any

from local_servers import TestPki
from posture_cockpit.core.egress import EgressPolicy
from posture_cockpit.core.network import LiveNetwork, SmtpPurpose

LAB_RANGE = ip_network("127.0.0.0/8")


class LabNetwork(LiveNetwork):
    """LiveNetwork reaching fake SMTP servers on 127.0.0.0/8, port ``smtp_port``, trusting ``pki``."""

    def __init__(self, *args: Any, smtp_port: int, pki: TestPki | None = None, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.lab_port = smtp_port
        self.lab_pki = pki

    def _smtp_policy(self) -> EgressPolicy:
        return EgressPolicy(networks=(LAB_RANGE,), ports=frozenset({self.lab_port}), name="lab")

    def _smtp_port(self) -> int:
        return self.lab_port

    def _smtp_tls_context(self, purpose: str) -> ssl.SSLContext:
        context = super()._smtp_tls_context(purpose)
        if purpose == SmtpPurpose.VERIFY and self.lab_pki is not None:
            context.load_verify_locations(cadata=self.lab_pki.pem)
        return context
