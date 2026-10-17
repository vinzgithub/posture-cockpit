# Posture Cockpit architecture

🇫🇷 [Version française](ARCHITECTURE.fr.md)

This document is the map of the code: where things are, how a scan flows, and how to make the usual changes without breaking anything.

## 1. Overview

```
 browser ─► web/ (FastAPI, pages)
              │
              ├─► scanner.py ─► core/engine.py ─► checks/*.py (extensions)
              │                                     │
              │                                     ▼
              │                               core/network.py  (DNS, TLS, HTTP — passive)
              │                                     │  every connection goes through
              │                                     ▼
              │                               core/egress.py   (where a scan may connect)
              │
              ├─► storage/  (SQLite: accounts, domains, perimeters, scans, audit log)
              └─► report/   (PDF)
```

**Golden rule: dependencies go one way.** `web` uses `scanner`, `storage` and `report`; all of them use `core`; `core` never imports `web` or `storage`. The engine can be read, tested or reused without a web server (the command line does exactly that).

## 2. Folders

| Path | Role |
|---|---|
| `src/posture_cockpit/core/` | The engine, independent of the web |
| `core/model.py` | `Status`, `Outcome`, `Finding`, `Remedy`, `DnsChange`: the data that flows everywhere |
| `core/extension.py` | The extension API: `Extension`, the `@extension.check` decorator, `CheckContext` |
| `core/registry.py` | Finds extensions (built-in + entry points); a broken extension is reported, never fatal |
| `core/network.py` | The four questions a check may ask (`dns`, `certificate`, `accepts_tls`, `http_get`) and their real implementation, `LiveNetwork` (cache, limits, deadlines per scan) |
| `core/egress.py` | **The single rule for outgoing connections**: address zones (public, internal, forbidden), `EgressPolicy`, `DestinationBlocked` |
| `core/errors.py` | `NetworkError` and `Refused` (nothing listens: a definite answer, unlike a timeout) |
| `core/fixture.py` | `FixtureNetwork`: the same questions, answered from recorded data (tests, demo) |
| `core/engine.py` | Runs checks concurrently, each with its own time limit; normalizes domain names; preflight |
| `core/scoring.py` | Coverage, score, grade (or "not evaluated"), assessment per area, plan of fixes |
| `core/generation.py` | The generation of the scanning and scoring rules (`GENERATION`) and the exact versions it covers; two scans are compared only within one generation |
| `core/providers.py` | Known DNS hosts and their detection |
| `checks/` | The built-in extensions (`mail`, `tls`, `web`, `dns`) and their texts in `checks/locales/` |
| `checks/records.py` | Parsing of SPF, DMARC, DKIM, MTA-STS and TLS-RPT records against their RFCs (pure functions) |
| `scanner.py` | Chooses the network (real or demo) with the rule of the perimeter, leaves out disabled extensions, reruns a single check |
| `storage/` | One SQLite connection (`database.py`), the schema (`schema.py`), its opening with a verified backup before any migration (`upgrade.py`), backups (`backup.py`), one repository per subject (`accounts.py`, `scans.py`, `perimeters.py`, `audit.py`, `settings.py`) |
| `web/app.py` | Builds the application: services, security headers, session, routes, error pages |
| `web/deps.py` | What routes share: signed-in user, access rules, CSRF-checked forms, rendering |
| `web/credentials.py` | Password and code checks used by several pages, and the sign-in throttles |
| `web/scanning.py`, `web/limits.py` | Start a scan (limits, audit log, perimeter) and the limits themselves |
| `web/views.py` | Turns a scan into what the plan page shows (texts, gains, steps) |
| `web/routes/` | One module per area: `auth`, `account`, `admin`, `perimeters`, `domains`, `report`, `api` |
| `web/templates/`, `web/static/` | Jinja templates, one stylesheet, one small script, the fonts |
| `report/` | The PDF report: context, template, style and fonts |
| `locales/` | Texts of the interface and the report (`fr.json`, `en.json`) |
| `demo/` | Recorded answers of the demo domain |
| `cli.py` | `posture-cockpit scan`, `extensions`, account rescue tools, `backup`, `check-backup`, `restore`, `info` |

## 3. How a scan flows

1. **`POST /domains`** (`web/routes/domains.py`) receives what the user typed. (A domain of an internal perimeter is added from its page in the administration, `web/routes/perimeters.py`.)
2. `engine.normalize_domain` turns it into a clean name (`https://www.Example.com/contact` → `example.com`).
3. `scanner.preflight` checks that the DNS answers something for that name. Otherwise: "does not exist" or "the DNS returns nothing", and nothing is saved.
4. `scanning.scan_and_save` takes a slot of the **scan limiter** (concurrent scans, scans per account and per hour).
5. `scanner.scan` takes the checks of the enabled extensions and a **fresh network** (its cache only serves this scan) built with the **rule of the perimeter**: the Internet (public addresses, ports 80 and 443), or an internal perimeter (its networks, DNS servers, ports and CA).
6. `engine.scan` runs **all checks at once**. Each receives a `CheckContext` (domain, network, time, internal or not) and returns an `Outcome`. Checks made for the Internet only are "not applicable" in an internal scan. A check that times out, raises a network error, hits the egress rule or crashes becomes an `Outcome` with status `ERROR` ("not evaluated", with the reason): the others carry on. Work left running is cancelled at the end.
7. `Scans.save` stores, in one transaction, the scan (with how it was started, `via`: web, api, schedule, and the generation of its rules, `engine`), its `Finding`s, its assessment (score, grade, coverage, perimeter, metrics) and its first measured state (`scan_states`); the scan is written to the audit log.
8. The plan page (`GET /domains/<name>`) calls `views.plan_view`, which produces ready-worded objects for the `plan.html` template.
9. **"Check"** (`POST /domains/<name>/verify/<check>`) reruns that single check. The result is saved as a *recheck* of the same scan: the original scan does not change (the order of the plan stays stable), the current score takes the recheck into account, and a state is added to the timeline of the scan in the same transaction.

## 4. Data model

- **`Outcome`**: what a check returns. A status (`ok`, `warn`, `fail`, `na`, `info`, `error`), a **text key** (never a sentence), parameters for that text, the raw values found (`evidence`) and, when something must change, a **`Remedy`**.
- **`Remedy`**: estimated time, effort (`easy`, `medium`, `delegate`) and the shape of the fix: **`DnsChange`s** (add or delete a record), a **message** to send, or an explanation (`how`).
- **`Finding`**: an `Outcome` with the identity of its check (`mail.dmarc`), its category and its weight. This is what the database stores (as JSON) and what pages show.

**Statuses**: `ok`, `warn` and `fail` are *evaluated*; `error` ("not evaluated": timeout, unreachable, destination refused, bug) is *applicable but not evaluated*; `na` (does not apply: no website, no inbound mail, internal audit) and `info` are left out.

**Assessment** (`core/scoring.py`, rules written at the top of the module and explained to users in [`docs/user/SCORING.md`](../user/SCORING.md)): the **coverage** is the weight evaluated over the weight applicable; the **score** is the share of the evaluated weight earned (`ok` the full weight, `warn` half, `fail` nothing). Below 50 % coverage there is no score ("not evaluated"); below 90 % the grade cannot be better than B. `Scan.assessment()` is the only function the pages, the API, the PDF and the history use. **Plan**: `fail`s first (priorities), then `warn`s (improvements), each sorted by effect on the score, then by speed. Displayed gains are cumulative so they add up exactly.

## 5. Database

One SQLite file in the data folder, in WAL mode, readable by its owner only. Tables: `users`, `totp`, `recovery_codes`, `api_tokens`, `perimeters`, `domains` (with `perimeter_id`), `scans` (score, grade, coverage, perimeter, metrics, `via`, `engine`), `findings`, `rechecks`, `scan_states`, `schedules`, `schedule_runs`, `events`, `audit_log`, `meta`.

**Migrations**: `storage/schema.py` holds a list of SQL scripts or Python functions. The database remembers how many it applied (`meta.schema_version`) and applies the next ones at start-up, each in a transaction, with foreign keys switched off and checked (`PRAGMA foreign_key_check`) before the commit, as SQLite documents for rebuilding a table. Before migrating a database that holds data, a copy is written to `backups/`. To change the schema, **append a migration to the list**; never edit one that has been released. A database whose schema is newer than the list (written by a later release) is refused at start-up, untouched (`UnsupportedSchema`). `storage/backup.py` makes and restores consistent backups (`posture-cockpit backup`, `restore`).

**Backup before migrating** (0.5.0): the server and the account commands open the database with `storage/upgrade.py`, `open_database()`. Before migrating a database that holds data, it checks the free space (twice the database), writes a complete backup archive (database and session key) to `backups/posture-cockpit-before-schema<N>-<time>.tar.gz`, reads it back (`backup.check`) and compares its schema, accounts, domains, scans and session key with the data folder; on any failure it stops before migrating, deletes the archive that failed and leaves the database unchanged. The archive is recorded in `meta.upgrade_backup` and shown by `posture-cockpit info`. Each migration runs in `BEGIN IMMEDIATE` and reads the version again inside it: of two processes starting together on one data folder, one migrates, the other finds it done.

| Version | Migration |
|---|---|
| 1 (0.1.0) | Initial schema |
| 2 (0.2.0) | `perimeters`, `domains.perimeter_id`, `audit_log` |
| 3 (0.2.0) | `scans` rebuilt (score and grade nullable, `coverage`, `perimeter`), scores of stored scans recomputed |
| 4 (0.4.0) | Metrics of `scans` (raw score, cap, final score, diagnostic coverage, blocked checks, addresses, reasons), added empty: nothing recomputed |
| 5 (0.5.0) | `scans.via`, `scans.engine`, `scan_states`, `schedules`, `schedule_runs`, `events`, `users.events_seen_at`; one state per existing scan made of its stored values, nothing recomputed; the images 0.4.x refuse this schema |

**Timeline of measured states** (`scan_states`, 0.5.0). The values stored in `scans` are overwritten by each recheck; each moment is also kept as a state: one `scan` state when the scan is saved, one `recheck` state after each recheck, in the transaction of the change. A state holds its date, the generation of the rules, score, grade, coverage, evaluation, the metrics and the status of every check. Rows are only ever added (a trigger refuses any `UPDATE`; no code deletes one; they go with their scan). Scans made before 0.5.0 got a single state made of their stored values: `scan` when never rechecked, otherwise `legacy`, dated from the last recheck — the values before that recheck were overwritten, so no state is made up for them. The generation (`core/generation.py`) changes whenever the rules would give another verdict or score for the same observations (`tests/test_v050_generation.py` fails until it does); a recheck of a scan judged by other rules has no generation.

**Transactions.** One connection serves the whole process and its lock lets the same thread in again — and every asyncio task runs on that thread. So `transaction()` remembers the thread and the task that opened it, and any use of the connection by another one while it is open raises `TransactionOwnerError`, reads included; another thread waits for the lock. The rule: **no `await` inside `with db.transaction():`** (`tests/test_v050_contract.py` checks the code for it).

## 6. Texts and languages

No sentence is written in Python code: only keys.

- Interface and report: `locales/fr.json` and `locales/en.json`.
- Checks: `checks/locales/<extension>.<lang>.json` (each extension brings its texts).

For a check `mail.dmarc`, the expected keys are:

| Key | Role |
|---|---|
| `mail.dmarc.title` | Short name of the check |
| `mail.dmarc.why` | Why it matters, in one or two sentences |
| `mail.dmarc.action` | What to do (task title) |
| `mail.dmarc.ref` | References (ANSSI, RFC), shown in the report annex |
| `<summary key>` | One per possible result (`mail.dmarc.missing`, `mail.dmarc.enforced`…) |
| `<summary key>.action` | Optional: a more precise action for that result |
| `how` and `message` keys | The explanation of the fix, the ready-to-send message |

Parameters: `{name}`. A parameter whose name ends with `_on` is an ISO date, written in the reader's language. A number can agree with its noun: `{days:day|days}`. `tests/test_texts.py` checks that every key exists in both languages.

## 7. Interface security

- **Session**: signed cookie (`SessionMiddleware`). It holds the user id and an "epoch": changing the password or two-factor settings changes the epoch and signs other browsers out (`deps.current_user`).
- **Access**: FastAPI dependencies (`require_user`, `require_admin`…) raise an exception that `app.py` turns into a redirect (`/setup`, `/login`, `/account/password`, `/admin/confirm`).
- **CSRF**: every form goes through the `checked_form` dependency, which refuses a missing or wrong token.
- **Sign-in**: password, then TOTP code when enabled (two steps, 5 minutes at most). Password and code failures share the same counters (`LoginThrottle`): by address (5 failures, 5 minutes) and by account name (10 failures, 15 minutes). An unknown name costs the same scrypt check as a known one.
- **Internal perimeters**: their domains are visible to administrators only (`deps.visible_domain`: 404 for anyone else, pages and API alike).
- **Scans**: limited at once and per account per hour (`web/limits.py`); every scan and every sensitive change is written to the audit log (`storage/audit.py`), never with a secret.
- **Network**: see `core/egress.py` and [SECURITY.md](../../SECURITY.md).
- **Headers**: strict Content Security Policy (`script-src 'self'`, `style-src 'self'`, no external resource), `nosniff`, `no-store`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, and HSTS when served over HTTPS. Consequence: **no `style="…"` and no script in templates** (a test checks it); score bars are drawn in SVG.

## 8. Common tasks

**Add a built-in check**
1. In `checks/<extension>.py`, an `async def` function decorated with `@extension.check("name", category=…, weight=…)` (add `internal=False` if it only makes sense on the Internet) that returns `ok(…)`, `warn(…)`, `fail(…)`, `na(…)`, `info(…)` or `not_evaluated(…)`.
2. Its texts in `checks/locales/<extension>.fr.json` and `.en.json` (see the table above).
3. Tests in `tests/test_checks.py` or `tests/test_check_accuracy.py`, starting from `worlds.healthy()` changed with `changed(...)`. A verdict that follows an RFC deserves a test that names the RFC section.

**Add a DNS host**: a `DnsHost` in `core/providers.py` (suffixes of its name servers) and its six `dnshost.<id>.*` texts in both `locales/` files. The test `test_every_dns_host_has_its_texts` lists the missing ones.

**Add a page**: a route in the right module of `web/routes/`, a template extending `base.html`, its texts in `locales/`. Prepared data goes in `views.py` when it needs computing.

**Add a language**: add it to `LOCALES` in `i18n.py`, create `locales/<lang>.json` and the extension files, complete `MONTHS`.

## 9. Tests

`pytest` runs more than 400 tests, **without reaching any other machine**:

- `tests/worlds.py` describes a healthy domain (`healthy()`); each test changes part of it with `changed(...)` and runs a check with `one(...)`;
- `tests/conftest.py` provides an application whose network is a dictionary (`world`) that a test can change between a scan and a recheck;
- `tests/local_servers.py` starts a DNS server, web and TLS servers and a test certificate authority on the loopback address: `tests/test_network.py` and `tests/test_egress.py` run the real network code against them (SSRF, IPv4/IPv6, redirections, DNS rebinding, internal DNS and CA, limits);
- `tests/test_check_accuracy.py` holds one non-regression test per wrong verdict found by the 0.2.0 audit;
- `tests/test_perimeters.py` and `tests/test_app_security.py` cover access rights, the audit log, sign-in protections and scan limits.

One test needs an IPv6 loopback address and is skipped on machines without one.

Since 0.4.1, `tests/test_v041_migrations.py` opens databases made by the real code of v0.3.0 and
v0.4.0 (SQL dumps in `tests/data/`, written by `tests/data/make_legacy_databases.py`), and the CI
(`.github/workflows/tests.yml`) also runs `scripts/docker-recette.sh` on the built image (new
installation, Docker protections, setup code, backup and restore, refusals, updates from the
released v0.3.0 and v0.4.0 images and rollback) and the whole suite inside the image. Release
process: [RELEASE.md](RELEASE.md).

Since 0.5.0: `tests/test_v050_contract.py` holds the answers of the API of 0.4.1 (written by the code
of the tag) that later versions must keep; `tests/data/database-v0.4.1.sql` adds two-factor
authentication, an internal perimeter, a provisional and an unscored scan;
`tests/test_v050_generation.py` the verdicts and scores of the rules of each generation. The CI
also updates the official image of v0.4.1 (pinned by its digest) and runs
`scripts/docker-recette.sh rollback`: update, then return to 0.4.1 through the backup made before
the migration, checked with the fingerprints of `scripts/data-fingerprint.py` (data restored
identical, exact list of what the return loses).

## 10. Conventions

- Every source file starts with the copyright notice and the license identifier (a test checks it).
- Code, names and comments in English; visible texts in French and English.
- A module starts with a docstring that states its role; comments explain **why**, not what the line does.
- `ruff check src tests examples`, `mypy` and `pytest` must pass before every merge (CI runs them).


### 0.4 HTTPS persistence

Migration 4 only adds nullable scan columns. It never calls scoring, rewrites findings,
or backfills prior scans. Database startup backs up an existing schema before migration.
The engine stores family metadata inside outcome JSON, so pre-0.4 findings keep their
original scoring semantics. New saves and recheck groups update every metric in the
same SQLite transaction as their findings.

Scanner.recheck_group selects the entire enabled HTTPS family when a root or dependent
is requested. A fresh network and shared probe serve the group. The web route commits
all findings together, with one timestamp. No partial family update is exposed.

The scanner receives a local history snapshot. The HTTPS root records authenticated
modern-TLS HSTS headers per host and last availability. Before replacing a root recheck,
the repository compacts `https_history_previous` to the last interpretable HSTS header
(including zero max-age) and the last availability per host, each with its original date.
The compact trail is bounded by the host count, independent of the number of rechecks. This is essential: a subsequent missing header must not resurrect
a policy erased by an earlier recheck. `https_history` replays scan and recheck events
chronologically without contacting the network or changing scores. An ancestor policy
only covers a child with includeSubDomains. Preload is never treated as list membership.

Validation uses fixture networks and loopback servers only. In execution environments
that intercept custom local names, `POSTURE_TEST_LOOPBACK_TRANSPORT=1` enables a
loopback-only test proxy. It serves the actual app and preserves the browser's insecure
HTTP origin (including unavailable clipboard API); it does not stub application code.


Only S1 (redirect) and S2 (unexpired authenticated HSTS history) announce HTTPS. DNS HTTPS
records (S3), previous HTTPS availability (S4) and a preload request are hints only;
they do not change a refusal remedy to restoration. The preload list is never queried.
`Scans.https_history(now=...)` accepts a deterministic clock for tests.

Stored finding decoding rejects non-finite floors, false HTTPS roots and invalid JSON.
It raises CorruptScan at the repository boundary. Web handlers return localized HTTP 409
pages or an error PDF; the API gives scan_unreadable. Lists isolate damaged analyses.
