# Changelog

## 0.4.1 — 2026-10-17

Maintenance release: simple installation and update with Docker Compose, consistent backups,
a protected first start. Scoring rules, checks, statuses and the API contract are unchanged;
schema 4 too, so the 0.4.0 image can still open the database (rollback without restoration).

**Installation and update**
- `compose.yaml` runs the published image `ghcr.io/vinzgithub/posture-cockpit:0.4.1` (never
  `latest`), without building: `curl -fsSLO …/v0.4.1/compose.yaml && docker compose up -d`.
  Requires Docker Compose 2.24 or later.
- Settings go in an optional `.env` next to it (`.env.example` documents them): port, listening
  address, time zone, reverse proxy, second instance, image to test. An update only replaces
  `compose.yaml`. Empty `POSTURE_COCKPIT_*` values now count as absent.
- The project name is fixed (`posture-cockpit`): the volume stays
  `posture-cockpit_posture-cockpit-data` whatever the folder, as for installations made in a
  `posture-cockpit` folder; the container keeps its name `posture-cockpit` (configurable).
- Same protections: uid 10001, read-only system, no capability, `no-new-privileges`, `/tmp` in memory.

**Image and publication**
- Pinned image contents: exact base image (`python:3.12.15-slim-trixie`), libraries from
  `docker/requirements.lock` with hashes, pinned build tools, `pip check`, numeric non-root user.
- `release.yml` publishes only when a GitHub release is published, after the whole test suite
  and the Docker recette; amd64 and arm64; SBOM and provenance (mode max). Pre-releases never
  move `X.Y` or `latest`, an older line never takes `latest` back (`scripts/release_tags.py`).
  The registry is read first (`scripts/registry_tag.py`): a version published from another commit
  is never overwritten, an interrupted publication resumes, an unreadable registry stops it; the
  exact version is pushed, then the moving tags, then every tag is read back. Pull requests
  rehearse it against a registry started in the job.
- CI: `scripts/docker-recette.sh` on the built image (new installation, protections, setup code,
  backup and restore, refusals), the whole suite inside the image, updates from the released
  v0.3.0 and v0.4.0 images and rollback to v0.4.0. Actions moved off Node.js 20.

**Backups and start-up**
- `posture-cockpit backup` writes a consistent archive (SQLite online backup, WAL included,
  plus the session key and a manifest with hashes) while the server runs; `check-backup`
  verifies one; `restore` checks the whole archive first, refuses while the database is in use,
  keeps a copy of the replaced data and removes stale journals; `info` shows version, schema and
  content. The former documented backup command archived an empty volume: replaced.
- A restoration holds the data folder alone from its first check to its last file (flock on
  `.posture-cockpit.lock`, shared by the server and the database commands): no server starts and
  no command runs meanwhile, two restorations never overlap. The former data is saved as a
  restorable backup, the files are swapped all or nothing (put back on failure), and a backup
  without session key never leaves the key of the replaced instance with the restored accounts.
- The start is refused, with what to do and without changing anything, for a database written by
  a newer version (schema above 4), an unreadable schema version or database, an empty or
  truncated session key, and a data folder the application cannot write (the message gives the
  `chown`). A session key readable by others is restricted to its owner.

**Security**
- The first (administrator) account needs a one-time setup code written to the server log at
  each start while no account exists (or `POSTURE_COCKPIT_SETUP_CODE`); only its hash is stored,
  it is consumed in the same transaction as the creation of the account (both or neither), wrong
  codes are throttled and audited. Existing instances are unaffected.
- Documented reverse proxy configuration (`POSTURE_COCKPIT_BIND=127.0.0.1`, `COOKIE_SECURE`,
  `FORWARDED_ALLOW_IPS`, Caddy and Nginx examples).

**Pages, PDF and API**
- The scoring coverage is stated once per page (it was repeated under the score) and named
  "scoring coverage" next to the "diagnostic coverage", with a one-line explanation when blocked
  checks make them differ. Address counts agree in number; the provisional-score sentence names
  its inconclusive addresses.
- HTTPS wording: dependent checks no longer repeat "Not evaluated:" after their status;
  "inconclusive address" everywhere. The wordings arbitrated in 0.4 are kept as they are
  ("Bloqué — dépend de : Redirection HTTPS (refus observé)", attribution notes that start with
  the observation).
- PDF: area comments give the verdict without its notes; what could not be measured is listed
  once per reason; zero counts are left out of the diagnosis; compact indicators; fewer awkward
  page breaks.
- API: `diagnostic_coverage` is rounded to 3 decimals like `coverage` (it was not for 0.4 scans).
  No field added or removed.

**Housekeeping**: the 0.4.0 recette files are removed (`compose.recette-v040.yaml`,
`Dockerfile.recette-tests`, `docs/user/RECETTE_V040.fr.md`); recette and release process in
`docs/developer/RELEASE.md`.

## 0.4.0 — 2026-10-16

Counter-review corrections: S4 and preload are hints only; HSTS recheck history is compacted
without losing zero-max-age events or dates. Stored data corruption is isolated per scan,
with localized pages/error PDFs and explicit API errors. Legacy API metrics use stored
scores/coverage without recalculation; legacy history rows keep their former presentation.
Provisional results name the number of inconclusive addresses in French and English.

- HTTPS is probed per published (host, address), with confirmed refusals, obsolete TLS,
  incomplete discovery and bounded deadlines distinguished. External redirects are never fetched.
- Blocked HTTPS dependents are separate from errors. Raw, reference-cap and final scores,
  diagnostic coverage, blocked counts and address completeness are retained.
- HTTPS root/dependent rechecks rerun the entire enabled family with one shared fresh probe,
  and persist all results and metrics atomically. Other checks remain independent.
- Schema 4 adds nullable columns using ALTER TABLE only. Schema 3 data and scores are not
  recalculated; automatic pre-migration backups remain enabled.
- API compatibility: `score` can now be present with `grade: null` and
  `evaluation: "undetermined"`. `grade_withheld_reason` explains this state.
  New score/cap/coverage/address fields are additive. Consumers must not infer a grade from a score.
- Pages, history and PDF show diagnostic indicators, blocked rows, cap reasons and provisional gains.
  Non-comparable history scores are hollow markers, without a comparative delta.
- HSTS announcements use only authenticated modern-TLS observations; max-age=0 clears the
  stored signal, absence does not, expiry is capped at one year, includeSubDomains is scoped.
  Historical announcements affect advice only, never status or score.
- Includes the pending 0.3.2 recette corrections listed below.


## 0.3.2 — unreleased

Corrections from the audit of 0.3.1. No database migration, no configuration change required, stored scans and their scores are not recalculated. The verdicts below may move the score of the next scan: the diagnosis became more accurate, the domain did not change (see [SCORING](docs/user/SCORING.md#7-what-changed-in-03x-and-why)).

### Security

- **Session of a deleted account** (present since 0.1.0): SQLite gives the id of a deleted account to the next account created, which started with the default session epoch. A browser of the deleted account still carrying that epoch (signed in with its temporary password and never changed, within the 7 days of the cookie) was taken for the new account, could choose its password and, if it was an administrator, administer. Each account now gets a session epoch of its own when it is created, in the same transaction.

### Interface

- **"Copier" buttons on a page in plain HTTP** (`http://192.168.x.x:8080`): `navigator.clipboard` only exists on HTTPS and `localhost`, so they did nothing and said nothing. They now fall back to the browser's copy command; if that fails too, the value is selected and a message says how to copy it by hand. Two quick clicks no longer leave "Copié ✓" on the button.
- The language switch comes back to the task shown and to the history page, instead of the first task.
- On a phone, or a window where the steps sit beside the score card, the four steps go two by two without a connecting line leading nowhere.
- The first step counts the checks evaluated ("19 contrôles évalués", as the coverage), not every check including the informational ones ("20 contrôles"). Scores unchanged.
- PDF: a gain such as "(+1 pt)" is no longer cut at the end of a line.

### Checks

- **DMARC `pct`** is read again. 0.3.0 ignored it because RFC 9989 made it historic, so `pct=0` was reported as an enforced policy; receivers that still follow RFC 7489 apply it. A value below 100 is now "to improve" (`mail.dmarc.partial` or `mail.dmarc.partial_reject`, advice: remove `pct`), and a value that is not 1 to 3 digits up to 100 is a syntax warning, as in 0.2.0.
- **DMARC inherited from a parent in monitoring (`p=none`)**: the advice no longer says that no local record is needed. The parent (a public suffix such as `gouv.fr`) may not be the owner's to change: the remedy publishes a policy of the domain's own.
- **DMARC, one verdict and notes**: the verdict is chosen in a fixed order (invalid policy, `t=y`, `p=none`, faulty values, `pct`, `sp=none`, local records ignored); the other anomalies of the record are shown after it as notes on every page and report (0.3.1 hid `pct=abc` behind `p=none` and `pct=101` behind `t=y`). Notes are stored as translation keys in the evidence of the finding; they change neither the status nor the score.
- **DMARC under `p=none`**: the record offered for `p=quarantine` is a full quarantine rebuilt from the valid tags: no faulty value (0.3.1 copied `pct=abc` or `rua=d@x.org` into it), no `t` or `pct` (`t=y` would make it none, `pct` below 100 would limit it), no repeated tag; `sp` and `np` are kept as written. The decision is taken on that record: when no report address would remain (none valid, or a repeated `rua`), the new verdict "monitoring without reports" offers no record, and no address is chosen or made up: reports first. The advice asks to check that reports arrive and are read, recalls that an address on another domain needs its authorization (`_report._dmarc`), and that without `sp` the quarantine also applies to the subdomains.
- **DMARC, invalid policy**: the verdict names the faulty policy value (`p`, `sp` or `np`; it always said "p"), and the other faulty values stay visible in a note.
- **DMARC, repeated tags**: a note says that the syntax of DMARC records forbids them (RFC 6376 §3.2) and that some receivers may ignore the whole record. Status and score unchanged in 0.3.2.
- **DMARC wording**: `pct` after RFC 7489 §6.6.4 (with `p=reject`, the other failing mail should be quarantined, new verdict text `mail.dmarc.partial_reject`; with `p=quarantine`, usual filtering), historic in RFC 9989; `t=y` gives the RFC 9989 level and says that RFC 7489 receivers ignore it.
- **HTTP redirect to another site**: 0.3.0 failed every such redirect, even when the audited host also answers over HTTPS (`example.org` → `https://www.example.com`). `https://host/` itself is now requested, with certificate verification and without following redirects (the other site is never fetched): a valid answer is compliant, a refused connection fails (`web.https_redirect.external`, reworded), an untrusted certificate fails, a timeout is not evaluated.
- **MTA-STS record** read as RFC 8461 §3.1 writes it: extension fields allowed before or after the `id`, spaces around `;`, one final `;`; `v=STSv1` and `id=` are case-sensitive, a second `id` is refused; among several TXT, those not beginning with `v=STSv1;` are discarded; a TXT that does not name the protocol means "missing", not "invalid record".
- **TLS-RPT record** read as RFC 8460 §3 writes it: spaces allowed after `v=TLSRPTv1` (`v=TLSRPTv1 ; rua=…` was reported as missing); the discard rule applies only among several TXT; a record naming the protocol in another case or version is reported as invalid instead of missing.

### History

- A scan or page number that is not one (`abc`, `0`, a number SQLite cannot hold) gives the 404 page: 0.3.1 answered 500 for a huge number and a JSON 422 for text.
- The list shows the number of each scan, how many checks it evaluated, where it was measured from (Internet or the perimeter) and which one is the latest; "1 analyse conservée" agrees with its number.
- A stored scan says whether it is the latest, with a link to the current plan of fixes.
- The historical PDF says when it was generated, in the time zone of the instance; its file name uses the local day of the scan; the `report.internal` audit entry names the scan.

### Configuration

- An invalid `POSTURE_COCKPIT_DKIM_SELECTORS` stops the start, naming the variable; 0.3.1 started, then reported an internal error for DKIM on every scan.

### Code and tests

- The checks of the technical page and of a stored scan come from one template; the two history style blocks are merged.
- Timeouts: a real HTTP reply that does not come in time (read, write or pool timeout) is now reported as a timeout ("Délai dépassé…"), like a connection that times out; 0.3.1 reported it as a plain network error. The recorded timeouts of the tests raise the same error.
- Synthetic DMARC scenarios (`tests/test_dmarc_scenarios.py`) back the table of SCORING §7.
- Browser tests (`tests/browser`, Playwright and Chromium) in their own CI job: copy buttons on a page in plain HTTP and in a secure context, the API key copied without a trace, the language switch, the steps at every width from 320 to 1300 px in French and English.

### Planned for 0.4

- DMARC records with a repeated tag: whether the parser should treat the whole record as invalid (RFC 6376 §3.2, referred to by RFC 9989 §4.7), how receivers actually behave, the status to give, its effect on the score, and the regression tests.

## 0.3.1 — 2026-10-15

Network diagnostics. No database migration or configuration change.

- A check that could not be evaluated now says why: connection timed out, reset, refused, or TLS handshake failed, in French and English, on the pages and in the PDF. Scores and coverage are unchanged.

## 0.3.0 — 2026-10-14

Scan history, DMARC after RFC 9989, more accurate mail and HTTPS checks, and display fixes. No database migration.

### Scan history

- A paginated list of the stored scans of a domain, the read-only details of each, and the PDF report of any stored scan, labelled as historical with the versions that made the scan and the PDF. Same access rules as the domain (internal domains for administrators only).
- DNS findings stored by earlier versions are worded without placeholders. On phones, the history is shown as cards.

### Checks

- **DMARC** follows RFC 9989: DNS tree walk of at most eight queries, `psd=y/n`, `np` for non-existent subdomains, `t=y` testing mode, an omitted `p` read as `none`. (`pct` was ignored: read again in 0.3.2.)
- **MTA-STS**: absent, invalid and multiple TXT records are told apart; the `mx` patterns of the policy file are checked.
- **TLS-RPT**: the record is parsed after RFC 8460; an invalid record is reported instead of passing for an absent one.
- **DKIM**: a key found in the DNS no longer claims that outgoing mail is signed. `POSTURE_COCKPIT_DKIM_SELECTORS` adds selectors to look for (30 at most in all).
- **HTTPS redirect**: credited only after a certificate-verified answer from the domain's own host; a redirect to another site is reported (refined in 0.3.2).

### PDF report

- With partial coverage, the projection after the fixes is worded as an estimate; a category without a score keeps its critical findings in the report.

### Display fixes

Local time, wording, PDF layout, cookie name. No change to the stored data, the scores or the API.

#### Times

- **Local time on pages and in PDF reports.** Times were shown in UTC ("07:19" for a scan at 09:19 in Paris), and the day could be wrong between midnight and 2 a.m. Pages, the audit log and reports now use the time zone of the instance: `POSTURE_COCKPIT_TIMEZONE`, else `TZ`, else UTC. The PDF states the offset ("09:19 UTC+2"). The database, the API (`scanned_at`) and the file number of the report keep UTC. Summer and winter time are handled (tests on both changes of hour).
- New dependency `tzdata`: zone names are available even where the system has none.

#### Wording

- A fix worth less than one point once rounded showed "+ points" with no number: it now says "< 1 point" (card, panel, PDF), and checking it again says the score stays where it was instead of "+0 points".
- Agreement with numbers: "1 demande une correction rapide" (was "1 demandent"), "1 est conforme", "1 point peut encore être amélioré", "+1 point", "+1 pt", "1 minute", "1 seconde", "1 contrôle réalisé"; English likewise.
- A scan that had no score at first and got one through rechecks no longer reads "Votre note est passée de 0 à 70": a missing score is never shown as 0.

#### PDF layout

- A heading is never left alone at the bottom of a page ("MÉTHODE" ended page 2 of the fournet.one report, its text alone on page 3). The annex now follows on the same page when there is room.

#### Sessions

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
