# Roadmap — Posture Cockpit

🇫🇷 [Version française](ROADMAP.fr.md)

> **Future ideas, not release commitments.** This roadmap is subject to testing and review. **Mission Control is not included in v0.4.1, and no release number (including v0.5.0) is assigned to it.**

## Short term — prove usefulness and reliability

- Compare findings with independent tools on diverse, authorized domains. Document false positives, false negatives, diagnostic coverage and divergences.
- Conduct usability testing with users unfamiliar with the project: understand a finding, perform a safe change, verify the outcome and read the PDF report.
- Fix observed problems before adding more checks.
- Keep measured evidence, unknown/blocked observations and hypothetical changes clearly distinct.

## Later candidate — continuous monitoring

- Opt-in scheduled scans and change detection.
- Actionable security regression and certificate-expiration alerts, with rate limits.
- A dated history of observed changes, including uncertainty and measurement limitations.

## Future release concept — interactive “Mission Control” dashboard

**Goal:** an actionable and verifiable remediation cockpit rather than a collection of score widgets.

1. **Interactive dependency graph:** explore root and dependent checks and the effects of blocked or inconclusive HTTPS/certificate observations.
2. **Security time machine:** compare two dated audits, surface before/after technical evidence, distinguish real changes from measurement changes.
3. **What-if remediation simulator:** select fixes and estimate score/coverage improvements using the real scoring model, caps and dependency logic. Show ranges for provisional gains rather than inventing exact outcomes.
4. **Verified remediation workflow:** identify what to change and where, prepare copyable settings or a provider message, recheck and compare predicted versus actually observed results.
5. **Drift dashboard:** once monitoring exists, show regressions, certificate alerts and relevant changes as prioritized actionable events.
6. **Consistent accessible UI:** desktop/mobile, keyboard and screen-reader access, bilingual FR/EN, timestamps and evidence provenance.

### Guardrails and acceptance criteria

- No intrusive probing, automatic DNS/server modifications or weakening of the current passive-scan and egress safeguards.
- Generative AI must never fabricate security findings, measurements or unexplained scores; optional explanations are distinct from observed evidence.
- Preserve blocked/undetermined states, scoring coverage, dependencies and existing v0.4.x behavior.
- Build on a dedicated branch with automated tests and a real-user acceptance process.
- Release only after testers can independently complete a correction; estimates are traceable to the engine; measured, simulated and verified states are distinguishable; partial/inconclusive cases remain correct; FR/EN and mobile are supported.

*Features, order and version allocation will depend on user feedback and technical evaluation.*
