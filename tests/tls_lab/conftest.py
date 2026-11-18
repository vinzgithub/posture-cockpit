# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The TLS bench (version 0.8.0, PR-A): every test of this folder runs with the loopback guard on.

The bench is part of the suite (``python -m pytest``, Python 3.11 to 3.13, and inside the image), and can
run alone: ``python -m pytest tests/tls_lab``. It needs no tool beyond the dependencies of the product;
``openssl`` on the path enables the reference tests of test_real_tls.py, skipped and counted as such
without it.
"""

import pytest

from tls_lab import guard, servers


@pytest.fixture(autouse=True)
def loopback_only():
    """Nothing leaves the machine (guard.py), in every thread, for the length of each test."""
    with guard.loopback_only():
        yield


@pytest.fixture(scope="session")
def certs(tmp_path_factory):
    return servers.certificates(tmp_path_factory.mktemp("tls-lab-certs"))
