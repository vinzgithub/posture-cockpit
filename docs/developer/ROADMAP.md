# Posture Cockpit — Development roadmap

🇫🇷 [Version française](ROADMAP.fr.md)

> **Planning document — 14 October 2026.** Future capabilities are **proposals**, not shipped features, release-date commitments or compliance attestations. Every release requires tests, acceptance testing and the project owner's explicit approval.

## Product direction

Evolve Posture Cockpit from a **self-hosted domain security posture auditor** into a platform for **continuous, evidence-based DNS, Web, PKI and email security posture monitoring**, serving individuals and SMBs as well as public administrations, local authorities, large enterprises, enterprise groups and security teams.

Core measurements must work without AI or a third-party cloud. Reliable observations, provenance, coverage, limits, audit history and verifiable remediation matter more than a superficially high score.

## Release sequence (proposed, no dates committed)

| Milestone | Scope | Release gate |
|---|---|---|
| **v0.2.0 — shipped** | Passive checks, FR/EN UI, authentication/2FA, API/PDF, coverage, controlled internal perimeters, SSRF/egress safeguards, Docker | Released and tested |
| **v0.3.0 — stabilization** | Finalize HTTPS redirect correctness, TLS-RPT/DKIM, cautious MTA-STS guidance and acceptance tests for previously developed historical PDFs, RFC 9989 DMARC, local time and cookies | CI, security review, eight-domain before/after comparison, backups and rollback |
| **v0.4.0 — SMTP/STARTTLS** | Finalize draft [PR #8](../../pull/8) and [PR #9](../../pull/9): explicit opt-in, restricted MX-only port 25, EHLO, STARTTLS, certificate checks and precise diagnostics | Authorized live MX plus mock-server tests, IPv4/IPv6 and per-IP evidence, no unjustified compliance |
| **v0.4.x–v0.5.0** | Measured SMTP TLS versions/ciphers; Web / Mail / Mixed profiles with deliberate scoring migration | Measurable results, historical comparability, API/PDF compatibility |
| **Later operational releases** | Scheduled scans, alerting, trends, portfolio dashboards, change tracking | Quotas, resilient jobs, de-duplication, traceable evidence |
| **v0.6+ and separate workstreams** | DANE, IPv6 visibility, reliable RPKI data, provenance-preserving import/export, secure remote agents | Separate threat review, strict network scope and regression tests |
| **Public-sector / enterprise track** | Multi-entity inventory, federation/SSO, granular RBAC, executive reports, scalability and operations | Pilots, authorization isolation, performance benchmarks, documented operations |

Previously merged [PR #4](../../pull/4), [#5](../../pull/5), [#6](../../pull/6) and [#7](../../pull/7) already deliver substantial v0.3.0 code. Draft [PR #10](../../pull/10) addresses HTTPS redirect evidence. Work on SMTP/STARTTLS is ahead of the schedule but **is not shipped**.

## Enterprise and public-sector epics (not yet delivered)

**E1 — Authorized asset portfolio.** Group explicitly authorized domains by organization, department, subsidiary, service and environment. Track owners and observation points. Never imply an inventory is complete merely because a subset has been scanned.

**E2 — Multi-tenant governance.** Separate organization administrator, entity manager, auditor and reader roles; isolate domains, historical findings, reports, APIs and exports. Evaluate OIDC/SAML SSO, centrally managed MFA and session revocation. Prove cross-tenant isolation and absence of IDOR risks.

**E3 — Continuous monitoring.** Bounded scheduled checks, change detection, certificate-expiration and posture-degradation alerts, delivery by email/webhook, acknowledgement, suppression of duplicates and scanner-failure-aware messaging.

**E4 — CISO reporting.** Executive dashboards by organization/entity, trend views, accountable remediation, documented exceptions, evidence-linked metrics and provenance-aware PDF/CSV/JSON export. SIEM/ITSM connectors may be optional extensions; never equate a posture score to regulatory certification.

**E5 — Scale and operations.** Benchmarks with **100 and 1,000 authorized domains**, concurrency and job queues, recovery, backup/restore, documented upgrades, retention, SBOM and vulnerability management. Evaluate PostgreSQL only if real measurements justify replacing SQLite.

**E6 — Remote measurement.** Optional agents following the [existing study](REMOTE_AGENT.md), outbound communication, strong authentication, locally enforced immutable egress boundaries, signed/authenticated evidence and agent-offline handling; no arbitrary remote code execution.

**E7 — Government-specific assurance.** Evaluate applicable RGAA/WCAG accessibility, GDPR, PSSI, procurement, data residency, security review, support and contractual obligations according to customer and deployment context. ANSSI/RFC references do **not** constitute ANSSI qualification, government authorization or formal compliance.

**E8 — Optional AI assistance.** Explain and summarize evidence, suggest remediation and produce executive narratives. AI **must not independently determine compliance**. Suggestions must cite deterministic checks, remain reviewable, avoid sending sensitive data without explicit consent and support a local model path. AI remains disabled by default.

## Non-negotiable architecture and quality constraints

- Strict SSRF/egress enforcement, protected internal perimeters, bounded scans and opt-in-only limited SMTP; never silently weaken security to make probes pass.
- State **verified / indirectly observed / not evaluated / not applicable** explicitly. Always present a score with its coverage and observation limitations.
- FR/EN support, responsive UI, typed modular core and backward-compatible data/API contracts.
- Enterprise and AI capabilities should be **optional**, keeping self-hosted personal/SMB deployments approachable.
- Focused PRs, green `test`/`docker` CI, threat review, isolated acceptance tests and proven rollback **before** an owner-approved merge or production release.
- Public licensing is currently [PolyForm Noncommercial 1.0.0](../../LICENSE). Commercial use, support, distribution and public procurement conditions require separate decisions.

## Evidence needed before enterprise positioning

Interview real public-sector administrators, CISOs and enterprise operators; select the 3–5 highest-value needs; conduct an explicitly authorized portfolio pilot; define and measure correctness, coverage, access isolation, throughput, upgrade and support acceptance criteria; assess alternatives and commercial licensing. Do not advertise enterprise readiness before documented results.

**Relationship to previous requirements:** this roadmap extends, and does not supersede, the consolidated v0.3.0 requirements dated 13 October 2026.
