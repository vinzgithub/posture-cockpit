# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""T01/T10: complete outputs captured from the exact released v0.5.0 scorer.

The checked-in corpus was generated with seed 603 against commit
88623bccf9054b3fbbb1c360151efd27f467460f before comparison with the new scorer.
It covers observation rules, not the intentionally corrected projections.
"""
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from posture_cockpit.core import scoring
from posture_cockpit.core.model import Finding

CORPUS = json.loads((Path(__file__).parent / "data/observation-v050-mc3.json").read_text())


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: str(CORPUS["cases"].index(c)))
def test_complete_observation_assessments_are_identical_to_v050(case):
    findings = [Finding.from_stored(f["id"], f["category"], f["weight"], f["status"], f["data"])
                for f in case["findings"]]
    # JSON normalisation changes tuples to arrays; compare every Assessment field.
    actual = json.loads(json.dumps(asdict(scoring.assess(findings))))
    categories = json.loads(json.dumps({k: asdict(v) for k, v in scoring.by_category(findings).items()}))
    assert actual == case["assessment"]
    assert categories == case["categories"]
