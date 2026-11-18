# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The capability report runs anywhere the suite runs, and says what this TLS can do."""

import json

from tls_lab import capabilities


def test_the_report_is_stable_json_with_tls_12_and_13_working(capsys):
    assert capabilities.main([]) == 0
    report = json.loads(capsys.readouterr().out)
    assert set(report) == {"python", "openssl", "machine", "module", "api", "suites_tls12_at_seclevel_0",
                           "dh_parameters_at_seclevel_0", "handshakes"}
    assert report["handshakes"]["TLS1.2"].startswith("TLS1.2 ")
    assert report["handshakes"]["TLS1.3"].startswith("TLS1.3 TLS_")
    assert report["dh_parameters_at_seclevel_0"] == {"dh1024": "loaded", "dh2048": "loaded"}
    categories = report["suites_tls12_at_seclevel_0"]
    assert all(categories["aead_pfs"].values())  # what a modern prober needs is always there
    assert set(categories) == {"aead_pfs", "cbc_pfs", "dhe_aead", "dhe_cbc", "rsa_kex", "3des", "rc4", "null",
                               "export", "anon"}
