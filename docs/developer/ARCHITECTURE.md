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
              │
              ├─► storage/  (SQLite: accounts, domains, scans)
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
| `core/network.py` | The four questions a check may ask (`dns`, `certificate`, `accepts_tls`, `http_get`) and their real implementation, `LiveNetwork` |
| `core/fixture.py` | `FixtureNetwork`: the same questions, answered from recorded data (tests, demo) |
| `core/engine.py` | Runs checks concurrently, each with its own time limit; normalizes domain names; preflight |
| `core/scoring.py` | Score, grade, score per area, plan of fixes |
| `core/providers.py` | Known DNS hosts and their detection |
| `checks/` | The built-in extensions (`mail`, `tls`, `web`, `dns`) and their texts in `checks/locales/` |
| `scanner.py` | Chooses the network (real or demo), leaves out disabled extensions, reruns a single check |
| `storage/` | One SQLite connection (`database.py`), the schema (`schema.py`), one repository per subject (`accounts.py`, `scans.py`, `settings.py`) |
| `web/app.py` | Builds the application: services, security headers, session, routes, error pages |
| `web/deps.py` | What routes share: signed-in user, access rules, CSRF-checked forms, rendering |
| `web/credentials.py` | Password and code checks used by several pages |
| `web/views.py` | Turns a scan into what the plan page shows (texts, gains, steps) |
| `web/routes/` | One module per area: `auth`, `account`, `admin`, `domains`, `report`, `api` |
| `web/templates/`, `web/static/` | Jinja templates, one stylesheet, one small script, the fonts |
| `report/` | The PDF report: context, template, style and fonts |
| `locales/` | Texts of the interface and the report (`fr.json`, `en.json`) |
| `demo/` | Recorded answers of the demo domain |
| `cli.py` | `posture-cockpit scan`, `extensions`, account rescue tools |

## 3. How a scan flows

1. **`POST /domains`** (`web/routes/domains.py`) receives what the user typed.
2. `engine.normalize_domain` turns it into a clean name (`https://www.Example.com/contact` → `example.com`).
3. `scanner.preflight` checks that the DNS answers something for that name. Otherwise: "does not exist" or "the DNS returns nothing", and nothing is saved.
4. `scanner.scan` takes the checks of the enabled extensions and a **fresh network** (its cache only serves this scan).
5. `engine.scan` runs **all checks at once**. Each receives a `CheckContext` (domain, network, time) and returns an `Outcome`. A check that times out, raises a network error or crashes becomes an `Outcome` with status `ERROR`: the others carry on.
6. `Scans.save` stores the scan and its `Finding`s (the score is computed then).
7. The plan page (`GET /domains/<name>`) calls `views.plan_view`, which produces ready-worded objects for the `plan.html` template.
8. **"Check"** (`POST /domains/<name>/verify/<check>`) reruns that single check. The result is saved as a *recheck* of the same scan: the original scan does not change (the order of the plan stays stable), the current score takes the recheck into account.

## 4. Data model

- **`Outcome`**: what a check returns. A status (`ok`, `warn`, `fail`, `info`, `error`), a **text key** (never a sentence), parameters for that text, the raw values found (`evidence`) and, when something must change, a **`Remedy`**.
- **`Remedy`**: estimated time, effort (`easy`, `medium`, `delegate`) and the shape of the fix: **`DnsChange`s** (add or delete a record), a **message** to send, or an explanation (`how`).
- **`Finding`**: an `Outcome` with the identity of its check (`mail.dmarc`), its category and its weight. This is what the database stores (as JSON) and what pages show.

**Score** (`core/scoring.py`): the share of the weight earned. `ok` earns the full weight, `warn` half, `fail` nothing; `info` and `error` are left out. **Plan**: `fail`s first (priorities), then `warn`s (improvements), each sorted by effect on the score, then by speed. Displayed gains are cumulative so they add up exactly.

## 5. Database

One SQLite file in the data folder, in WAL mode. Tables: `users`, `totp`, `recovery_codes`, `api_tokens`, `domains`, `scans`, `findings`, `rechecks`, `meta`.

**Migrations**: `storage/schema.py` holds a list of scripts. The database remembers how many it applied (`meta.schema_version`) and applies the next ones at start-up, each in a transaction. To change the schema, **append a script to the list**; never edit one that has been released.

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
- **Sign-in**: password, then TOTP code when enabled (two steps, 5 minutes at most). Password and code failures share the same counter (`LoginThrottle`).
- **Headers**: strict Content Security Policy (`script-src 'self'`, `style-src 'self'`, no external resource), `nosniff`, `no-store`. Consequence: **no `style="…"` and no script in templates** (a test checks it); score bars are drawn in SVG.

## 8. Common tasks

**Add a built-in check**
1. In `checks/<extension>.py`, an `async def` function decorated with `@extension.check("name", category=…, weight=…)` that returns `ok(…)`, `warn(…)`, `fail(…)` or `info(…)`.
2. Its texts in `checks/locales/<extension>.fr.json` and `.en.json` (see the table above).
3. Tests in `tests/test_checks.py`, starting from `worlds.healthy()` changed with `changed(...)`.

**Add a DNS host**: a `DnsHost` in `core/providers.py` (suffixes of its name servers) and its six `dnshost.<id>.*` texts in both `locales/` files. The test `test_every_dns_host_has_its_texts` lists the missing ones.

**Add a page**: a route in the right module of `web/routes/`, a template extending `base.html`, its texts in `locales/`. Prepared data goes in `views.py` when it needs computing.

**Add a language**: add it to `LOCALES` in `i18n.py`, create `locales/<lang>.json` and the extension files, complete `MONTHS`.

## 9. Tests

`pytest` runs more than 130 tests, **without any network access**:

- `tests/worlds.py` describes a healthy domain (`healthy()`); each test changes part of it with `changed(...)` and runs a check with `one(...)`;
- `tests/conftest.py` provides an application whose network is a dictionary (`world`) that a test can change between a scan and a recheck;
- `tests/test_network.py` tests the real network code against TLS and HTTP servers started on the machine for the occasion.

## 10. Conventions

- Every source file starts with the copyright notice and the license identifier (a test checks it).
- Code, names and comments in English; visible texts in French and English.
- A module starts with a docstring that states its role; comments explain **why**, not what the line does.
- `ruff check src tests examples`, `mypy` and `pytest` must pass before every merge (CI runs them).
