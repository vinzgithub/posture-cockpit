# Changelog

## Unreleased

Display fixes shared by the next changes (history, PDF): local time, wording, PDF layout, cookie name. No change to the stored data, the scores or the API.

### Times

- **Local time on pages and in PDF reports.** Times were shown in UTC ("07:19" for a scan at 09:19 in Paris), and the day could be wrong between midnight and 2 a.m. Pages, the audit log and reports now use the time zone of the instance: `POSTURE_COCKPIT_TIMEZONE`, else `TZ`, else UTC. The PDF states the offset ("09:19 UTC+2"). The database, the API (`scanned_at`) and the file number of the report keep UTC. Summer and winter time are handled (tests on both changes of hour).
- New dependency `tzdata`: zone names are available even where the system has none.

### Wording

- A fix worth less than one point once rounded showed "+ points" with no number: it now says "< 1 point" (card, panel, PDF), and checking it again says the score stays where it was instead of "+0 points".
- Agreement with numbers: "1 demande une correction rapide" (was "1 demandent"), "1 est conforme", "1 point peut encore être amélioré", "+1 point", "+1 pt", "1 minute", "1 seconde", "1 contrôle réalisé"; English likewise.
- A scan that had no score at first and got one through rechecks no longer reads "Votre note est passée de 0 à 70": a missing score is never shown as 0.

### PDF report

- A heading is never left alone at the bottom of a page ("MÉTHODE" ended page 2 of the fournet.one report, its text alone on page 3). The annex now follows on the same page when there is room.

### Sessions

- `POSTURE_COCKPIT_SESSION_COOKIE` names the session cookie (default unchanged: `posture_cockpit`), so that two instances at the same address no longer sign each other out. Names browsers would refuse are rejected at start-up.

## 0.2.0 — 2026-10-13

Audit and consolidation release: security of the scanner and of the application, accuracy of the checks, reliability of the score. No new family of checks.

### Security

- **Egress rule against SSRF** (`core/egress.py`): every connection of a scan is checked after DNS resolution, on the address actually contacted, IPv4 and IPv6 (IPv4-mapped, NAT64 and 6to4 judged by the IPv4 address they lead to). Internet mode: public addresses only, ports 80 and 443. Link-local, multicast, reserved ranges and cloud metadata services are never contacted. A name is resolved once per scan (no DNS rebinding); each redirection is checked as a new request; proxy variables of the environment are ignored. A refused connection makes the check "not evaluated" with the reason.
- **Scan limits**: a deadline per network operation, at most 400 DNS queries and 80 connections per scan, work left running cancelled at the end of a scan; at most 4 scans at once and 30 per account and per hour (`POSTURE_COCKPIT_MAX_CONCURRENT_SCANS`, `POSTURE_COCKPIT_SCANS_PER_HOUR`); the API answers 429 with `Retry-After`.
- **Sign-in**: failures are also counted by account name (10 failures: 15 minutes); an unknown name costs the same password check as a known one (no account enumeration by timing).
- **Open redirect** fixed on the language switch (`/\host` was accepted).
- **Audit log**: sign-ins, password, two-factor and API key changes, administration changes, perimeters, every scan with its perimeter and origin. Read by administrators.
- **Headers**: Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, and HSTS when served over HTTPS.
- **Files**: the data folder and the database are created readable by their owner only.

### Internal networks

- **Internal perimeters**, off unless `POSTURE_COCKPIT_INTERNAL_SCANS=true`: an administrator describes the allowed networks (private ranges only), internal DNS servers, ports and internal certificate authority (added to the trusted ones, verification never turned off). Domains of a perimeter are seen, scanned and reported on by administrators only (404 for any other account, API included). Internet-only checks (mail, DNS, security.txt) are "not applicable" in an internal audit. Reports are marked "restricted distribution".
- Design study of a remote agent: `docs/developer/REMOTE_AGENT.md` (not developed).

### Score

- **"Not evaluated"** instead of 100/A when nothing, or too little, could be checked (reproduced: no check, 19 errors and 1 OK, only information all gave 100/A).
- **Coverage** (weight evaluated / weight applicable) shown with every score: plan, domain list, details, history, API, PDF, command line.
- Below 50 % coverage: no score; below 90 %: partial evaluation, grade capped at B.
- New status **"not applicable"**, distinct from "information" and from "not evaluated".
- Weights and score formula unchanged. Rules in `docs/user/SCORING.md`.

### Accuracy of the checks

One non-regression test per wrong verdict found (`tests/test_check_accuracy.py`).

- **DMARC**: `pct` outside 0-100 or not a number (e.g. `pct=101`, `pct=abc`), `rua` without `mailto:`, invalid `adkim`/`aspf`/`fo`/`ri` are reported; a record not starting with `v=DMARC1` is reported as ignored by receivers; `sp=none` under an enforced policy is reported; a subdomain follows the policy of its parent domain instead of failing.
- **SPF**: unknown mechanisms, invalid `ip4`/`ip6`, duplicated `redirect`/`exp`, includes or redirect to a name without exactly one valid SPF record are permanent errors; `ptr` is reported.
- **DKIM**: unreadable keys are no longer counted as found; revoked keys are ignored; Ed25519 and bare RSAPublicKey keys are read.
- **MX**: server names without address, IP addresses as MX and a null MX next to real ones are reported.
- **MTA-STS**: policy fetched with certificate verification (RFC 8461 §3.3); record id, policy fields and coverage of the MX servers checked (a policy that does not list the MX fails in enforce mode).
- **TLS-RPT**: record and destinations checked.
- **HTTPS redirection**: redirects over HTTP inside the domain are followed (http://www → http://domain → https:// is fine).
- **HSTS**: `max-age=0` is "disabled", an unreadable value "invalid".
- **CSP**: must restrict scripts (`script-src` or `default-src`, no `'unsafe-inline'` without nonce or hash, no open sources); Report-Only policies do not count.
- **Framing**: `frame-ancestors *` and scheme-only sources are permissive; with `frame-ancestors` present, X-Frame-Options is ignored, as browsers do; `ALLOW-FROM` is obsolete.
- **Referrer-Policy**: `unsafe-url` is reported.
- **security.txt**: `Contact` and a valid `Expires` required, expired files reported, redirects inside the domain followed, HTML pages answered for every address ignored.
- **TLS**: TLS 1.0/1.1 that this machine cannot test is "not evaluated" instead of "only recent versions accepted".
- **DNS**: a subdomain is judged by its zone (name servers, DNSSEC) and by the CAA records above it; DS without DNSKEY is broken DNSSEC; CAA no longer allowing the current certificate's authority is reported.
- "No website" and "no inbound mail" are "not applicable".

### Interface and report

- Plan: "not evaluated" state, coverage line, list of the checks not evaluated with their reason, internal perimeter tag; no points shown when there is no score.
- Details: coverage and scan history (date, score, coverage, version).
- Administration: internal perimeters, audit log.
- PDF: perimeter, coverage, checks not evaluated, time of the scan, restricted distribution for internal audits.

### For developers

- Extension API: `na()`, `not_evaluated()`, `Extension.check(..., internal=False)`, `ctx.internal`, `http_get(url, verify=True)`, exceptions `Refused`, `UntrustedCertificate`, `DestinationBlocked`.
- Mail records are parsed in `checks/records.py` (pure functions).
- Migrations may be Python functions; they run with foreign keys off and checked before commit; the database is copied to `backups/` before migrating.
- Tests: local DNS, web and TLS servers and a test CA (`tests/local_servers.py`); more than 400 tests.

### Upgrading from 0.1.0

- Migrations 2 and 3 run at start-up, after a copy of the database to `/data/backups/`. Scores of stored scans are computed again: unchanged when coverage reaches 50 %, "not evaluated" below, A capped at B below 90 %. Findings are not changed.
- **API**: `score` and `grade` can be `null`; new fields `evaluation`, `coverage`, `checks_evaluated`, `checks_applicable`, `not_evaluated`, `perimeter`. A Home Assistant sensor should use an `availability` template (see `docs/user/HOME_ASSISTANT.md`).
- New scans of the same domain may give a different score than before: the diagnosis is more accurate, not the domain different.
- Scans no longer go through `HTTP_PROXY`/`HTTPS_PROXY`.
- Behind a corporate resolver, set `POSTURE_COCKPIT_NAMESERVERS` to public resolvers (see `SECURITY.md`).

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
