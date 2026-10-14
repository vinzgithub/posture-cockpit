# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""SMTP parsing tests; no outbound networking."""

import pytest

from posture_cockpit.checks.smtp import parse_ehlo_reply


@pytest.mark.parametrize(("lines", "expected"), [
    (("250-mx.example.org", "250-STARTTLS", "250 SIZE 1000"), True),
    (("250-mx.example.org", "250 STARTTLS"), True),
    (("250-mx.example.org", "250 SIZE 1000"), False),
    (("220 mail.example.org ready",), False),
    (("550 STARTTLS",), False),
    (("250-mx.example.org", "250-STARTTLS"), False),
    (("250-mx.example.org", "550 STARTTLS"), False),
    ((), False),
])
def test_ehlo_starttls_advertisement(lines, expected):
    capabilities = parse_ehlo_reply(lines)
    assert capabilities.starttls_advertised is expected


def test_starttls_must_be_an_extension_keyword():
    assert not parse_ehlo_reply(("250-mx.example.org", "250 X-STARTTLS")).starttls_advertised
