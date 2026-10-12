# Changelog

## 0.1.0 — 2026-10

First release.

- Passive scan of a domain: 20 checks in four built-in extensions (mail, TLS, website, DNS), with references to ANSSI guides and RFCs.
- Score from 0 to 100, grade from A to F, score per area; checks that could not run do not count.
- Guided plan of fixes: priorities and improvements sorted by effect on the score, time and effort, steps for the detected DNS host (OVHcloud, Gandi, IONOS, Cloudflare, other), records ready to copy, ready-to-send messages for providers, "Check" button that reruns a single check.
- PDF report laid out like an expert's file, with a technical annex.
- Expert view with every check and the raw values found.
- Extensions: Python packages declaring a `posture_cockpit.extensions` entry point; switch per extension in the administration; complete example in `examples/`.
- Several accounts, two-factor authentication (TOTP and recovery codes), administration of accounts.
- JSON API for Home Assistant and cron: scores, and a scan on demand.
- Command line: `scan`, `extensions`, account rescue.
- French and English; light and dark themes; phone layout.
- Demo domain (`menuiserie-dupont.example`) answered from recorded data.
