# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Generation of the scanning and scoring rules (0.5.0).

Two scans are compared only when the same rules made them: a verdict or a score that changed
because the rules changed says nothing about the domain. :data:`GENERATION` is stored with every
scan (``scans.engine``) and every measured state (``scan_states.engine``). It changes whenever a
check gives another verdict or the scoring another score for the same observations;
tests/test_v050_generation.py fails until it does (it compares the verdicts and scores of the
test worlds with tests/data/generation-<GENERATION>.json).

Scans made before 0.5.0 carry only the version that made them. :data:`RELEASED` gives the
generation of the released versions whose rules are known to be those of a generation; any other
value (an older version, a development build) has no generation, and its scans are compared with
none. Checked on the tags (0.5.0): v0.3.1 to v0.4.0 changed the scoring and the checks; v0.4.0 to
v0.4.1 changed two sentences of translation only; "0.4.0" first appears in the commit of the tag.
A version prefix would not do: the tag 0.3.0-dev.1 declares "0.2.0" with other checks than v0.2.0.
"""

from __future__ import annotations

GENERATION = 4

RELEASED: dict[str, int] = {"0.4.0": 4, "0.4.1": 4}


def of_version(version: str | None) -> int | None:
    """The generation of the rules of a released ``version``; None when it is not known."""
    return RELEASED.get(version or "")
