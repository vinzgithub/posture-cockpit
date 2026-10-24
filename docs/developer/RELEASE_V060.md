# Posture Cockpit v0.6.0 — Mission Control release handoff

> **UNPUBLISHED RELEASE CANDIDATE** (24 October 2026). This document does not authorize merge, tagging, GHCR publication or a production upgrade.

The complete phase 1–5 implementation is preserved in `mission-control-phases1-5.patch`, against tag v0.5.0, retaining SQLite schema 5 and the old observation/scoring semantics. The phase 6 overlay updates the three version identifiers to `0.6.0`, adds a draft changelog entry and these bilingual delivery notes. Public README and installation links intentionally remain pinned to the **already published v0.5.0** until a 0.6.0 image becomes available.

Features: honest multi-remediation what-if simulations (including staged DMARC), conclusive change history, updated remediation plan after rechecks, a paginated multi-domain dashboard with ACL enforcement, event pagination and clearer scoring explanations in documents/PDF. No external notifications, embedded AI, new SMTP checks, automated remediation or global risk score.

**Work's phase 5 evidence (not independently rerun here):** 1,727 full tests passed plus two additional tests per Python runtime (3.11, 3.12, 3.13), two skips; 27 Chromium tests; Ruff/mypy and Python-level rollback to v0.5.0. T21 and T22 remain partial pending Docker-image rollback, AMD64/ARM64, CI and assistive-technology accessibility evidence.

**Independent handoff checks:** cumulative patch SHA-256 verified, 20 new files extracted, 16 Python files parsed without syntax errors and one JSON fixture decoded. Comparison of GitHub trees shows no overlap between the modified files of the phase 1–5 patch and changes on `main` since v0.5.0. This does not replace `git apply --check` against the current clone.

**Next validation gates:** apply both patches on an isolated branch based on current `main`; rerun tests and `scripts/release_tags.py`; validate Docker amd64/arm64 and image downgrade on synthetic SQLite copies; manually inspect PDF first pages and keyboard/screen-reader accessibility; obtain GitHub required checks and maintainer approval. Do not merge, publish GHCR, tag or deploy without distinct authorization.
