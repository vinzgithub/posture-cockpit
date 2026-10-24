# Installation

🇫🇷 [Version française](INSTALLATION.fr.md)

## With Docker (recommended)

**Fresh installations only:** these commands create a new **v0.6.1** instance. If you already have data from v0.4.1 or earlier, follow [Updating](#updating), make a verified backup outside the Docker volume and disable the scheduler before upgrading. v0.6.1 retains SQLite schema 5; changing the image alone does not downgrade a database.

You need Docker Engine and **Docker Compose 2.24 or later** (`docker compose version`). Nothing to build, no Git: the official image is published on `ghcr.io/vinzgithub/posture-cockpit`, for amd64 and arm64 processors.

```bash
mkdir posture-cockpit && cd posture-cockpit
curl -fsSLO https://raw.githubusercontent.com/vinzgithub/posture-cockpit/v0.6.1/compose.yaml
docker compose up -d
```

The [`compose.yaml`](../../compose.yaml) file names an exact version of the image (`0.6.1`), never `latest`: an installation never changes version on its own. It keeps the protections: unprivileged user (uid 10001), read-only system, no Linux capability, `no-new-privileges`, `/tmp` in memory. The data goes to the volume `posture-cockpit_posture-cockpit-data`, whatever the installation folder.

### First start: the setup code

While no account exists, creating the administrator account asks for a **setup code**, written to the server log (it changes at each restart while no account exists):

```bash
docker compose logs posture-cockpit
# … Setup code / code d'initialisation : 7KQM-3XHA-PZ2W
```

Open `http://<server>:8080/setup`, enter the code, then create the account. Ticking **"Check the demo domain"** adds a fictitious domain to discover the tool without scanning anything real. Without the code, someone who reached the page before you cannot become administrator. Instances that already have accounts never see a code.

For an automated installation, `POSTURE_COCKPIT_SETUP_CODE` sets the code (at least 12 letters or digits); it is then never written to the log.

### Check

```bash
curl http://localhost:8080/healthz                       # {"status":"ok","version":"0.6.1"}
docker compose exec posture-cockpit posture-cockpit info  # version, schema, accounts, scans
```

### Settings: the `.env` file

Do not edit `compose.yaml`: an update replaces it. Settings go in an optional `.env` file next to it; the [`.env.example`](../../.env.example) template describes them all, commented out:

```bash
curl -fsSL https://raw.githubusercontent.com/vinzgithub/posture-cockpit/v0.6.1/.env.example -o .env
nano .env                 # uncomment the lines you need
docker compose up -d      # applies the changes
```

The most common:

| `.env` line | Effect |
|---|---|
| `POSTURE_COCKPIT_PORT=8081` | Port of the server (8080 by default) |
| `POSTURE_COCKPIT_BIND=127.0.0.1` | Listen on this address only (all by default); `127.0.0.1` behind a reverse proxy on the same server |
| `TZ=Europe/Paris` | Time zone of the pages and PDF reports (`Europe/Paris` by default) |
| `POSTURE_COCKPIT_COOKIE_SECURE=true` | Served over HTTPS by a reverse proxy (below) |
| `POSTURE_COCKPIT_NAMESERVERS=9.9.9.9,1.1.1.1` | DNS resolvers to use |

An empty line (`NAME=`) keeps the default. Every setting of the application (`POSTURE_COCKPIT_*` variables, below) can go in this file too.

> Note: a port published by Docker bypasses the host's firewall (Docker's iptables rules). To expose Posture Cockpit to the reverse proxy of the same server only, use `POSTURE_COCKPIT_BIND=127.0.0.1`.

## Network access needed

The server must be able to reach the Internet:

- **DNS** (port 53 UDP and TCP) to its resolvers, or those of `POSTURE_COCKPIT_NAMESERVERS`;
- **HTTPS and HTTP** (ports 443 and 80) to the domains scanned.

A filtering resolver (ad blocker, corporate DNS) may return empty answers: Posture Cockpit then refuses the scan rather than reporting missing records by mistake. Give it public resolvers, for instance `POSTURE_COCKPIT_NAMESERVERS=9.9.9.9,1.1.1.1` in the `.env`.

**Installed in a company network**, also set `POSTURE_COCKPIT_NAMESERVERS` to public resolvers: otherwise the internal resolver answers the "Internet" scans, and a user could read records of your internal zones there. Internal sites are audited in an **internal perimeter** (below), for administrators only.

Scans do **not** go through an HTTP proxy: the `HTTP_PROXY` and `HTTPS_PROXY` variables are ignored, because a proxy would connect in Posture Cockpit's place, out of reach of its egress rule. The server must therefore reach ports 80 and 443 directly.

**Egress rule.** In Internet mode, Posture Cockpit only connects to public addresses, on ports 80 and 443. A domain that points to a private address (10.x, 192.168.x, ::1…) is not contacted: the checks concerned are "not evaluated", with the reason. Link-local, multicast and reserved addresses and the cloud metadata services (169.254.169.254…) are never contacted, whatever the mode. Details in [SECURITY.md](../../SECURITY.md).

## Settings

With Docker, these settings go in the `.env` file (`NAME=value`, see above).

| Variable | Default | Role |
|---|---|---|
| `POSTURE_COCKPIT_DATA_DIR` | `/data` (image) | Folder of the SQLite database and the session key |
| `POSTURE_COCKPIT_NAMESERVERS` | the system's | DNS resolvers, comma-separated |
| `POSTURE_COCKPIT_DKIM_SELECTORS` | empty | Additional DKIM selectors (comma-separated labels, without domain suffix). Usual selectors remain checked; 30 selectors maximum overall. An invalid value stops the start, with its reason. |
| `POSTURE_COCKPIT_CHECK_TIMEOUT` | `15` | Seconds allowed to each check |
| `POSTURE_COCKPIT_COOKIE_SECURE` | `false` | `true` when the application is served over HTTPS |
| `POSTURE_COCKPIT_DEFAULT_LOCALE` | `fr` | Language of the pages before sign-in |
| `POSTURE_COCKPIT_SESSION_MAX_AGE` | `604800` | Session length in seconds (7 days) |
| `POSTURE_COCKPIT_FRAME_ANCESTORS` | `'self'` | Sites allowed to show the application in a frame (Home Assistant) |
| `POSTURE_COCKPIT_INTERNAL_SCANS` | `false` | `true` to let administrators create internal perimeters |
| `POSTURE_COCKPIT_MAX_CONCURRENT_SCANS` | `4` | Scans running at the same time on the instance |
| `POSTURE_COCKPIT_SCANS_PER_HOUR` | `30` | Scans per account and per hour (checking one fix again does not count) |
| `POSTURE_COCKPIT_TIMEZONE` | `TZ`, else UTC | Time zone of pages and PDF reports (IANA name, e.g. `Europe/Paris`). The database and the API stay in UTC |
| `POSTURE_COCKPIT_SESSION_COOKIE` | `posture_cockpit` | Name of the session cookie: change it for a second instance at the same address (below) |
| `FORWARDED_ALLOW_IPS` | – | Address of the reverse proxy, so the attempt limit counts the real client address |
| `POSTURE_COCKPIT_SETUP_CODE` | random | Code of the first account (at least 12 letters or digits) instead of the random code written to the log |
| `POSTURE_COCKPIT_PORT` | `8080` | Docker Compose: port of the server |
| `POSTURE_COCKPIT_BIND` | all | Docker Compose: listening address of the server |
| `POSTURE_COCKPIT_IMAGE` | the image of the version | Docker Compose: image to run (test of a locally built image) |
| `POSTURE_COCKPIT_CONTAINER` | `posture-cockpit` | Docker Compose: container name (second instance) |
| `COMPOSE_PROJECT_NAME` | `posture-cockpit` | Docker Compose: project name, prefix of the volume (second instance) |

### Times shown

Times are stored and returned by the API in UTC (`2026-10-13T07:19:05+00:00`). Pages and PDF reports show them in the time zone of the instance: `POSTURE_COCKPIT_TIMEZONE`, else the `TZ` variable of the container (the one in the example above), else UTC. The PDF states the offset ("09:19 UTC+2"). An unknown zone name in `POSTURE_COCKPIT_TIMEZONE` stops the start; a POSIX-style `TZ` (`CET-1CEST,…`) is ignored, with a warning in the log.

## Audits of internal networks

To audit sites of your private network (intranet, internal applications over HTTPS):

1. install Posture Cockpit **inside** that network, or on a machine that reaches it;
2. start it with `POSTURE_COCKPIT_INTERNAL_SCANS=true` in the `.env`;
3. in **Administration → Internal perimeters**, an administrator creates a perimeter: the allowed networks (CIDR, inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 or fc00::/7), the internal DNS servers, the ports (443 and 80 by default) and, if needed, the internal certificate authority in PEM;
4. from the perimeter's page, they add the internal domains and scan them.

Only administrators see these domains, their scans and their reports (marked "Restricted distribution"). Certificate verification is never turned off: the internal CA is added to the trusted authorities. Every internal scan is written to the audit log. The checks made for the Internet (mail, public DNS, security.txt) are "not applicable" in an internal audit.

The loopback address (127.0.0.0/8, ::1) is never opened: Posture Cockpit does not scan itself.

To audit several networks from a single instance, an agent architecture is studied in [REMOTE_AGENT.md](../developer/REMOTE_AGENT.md).

## Behind a reverse proxy (HTTPS)

Serve Posture Cockpit over HTTPS (Caddy, Nginx, Traefik, HAProxy…). In the `.env`:

```bash
POSTURE_COCKPIT_COOKIE_SECURE=true   # session cookie over HTTPS only, and an HSTS header
POSTURE_COCKPIT_BIND=127.0.0.1       # when the proxy runs on the same server
FORWARDED_ALLOW_IPS=127.0.0.1        # the address of the proxy: its X-Forwarded-* headers are trusted
```

`FORWARDED_ALLOW_IPS` must be the address the proxy connects from, as the container sees it (for a proxy in another container, its address on the Docker network); otherwise the limits on sign-in attempts would count the proxy instead of the visitors. Examples:

```text
# Caddyfile
cockpit.example.org {
    reverse_proxy 127.0.0.1:8080
}
```

```nginx
server {
    listen 443 ssl;
    server_name cockpit.example.org;
    # ssl_certificate … ; ssl_certificate_key … ;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Backup

Everything is in the `/data` volume: the database `posture_cockpit.db`, the session key `.secret_key` and the `backups/` folder. The `backup` command makes a **consistent** copy while the application runs: it goes through SQLite's backup API, which takes the WAL journal into account, and adds the session key and a checkable manifest.

```bash
umask 077   # the backup holds the accounts: readable by you only
docker compose exec -T posture-cockpit posture-cockpit backup --output - > posture-cockpit-$(date +%F).tar.gz
```

Without `--output`, the archive is written to the volume, `/data/backups/posture-cockpit-<date>.tar.gz`. A backup can be checked without restoring anything:

```bash
docker compose run --rm --no-deps -T posture-cockpit posture-cockpit check-backup - < posture-cockpit-2026-10-17.tar.gz
```

Do not copy the volume with `tar` while it runs: the database file may then disagree with its journal.

## Restoring

Restoring checks the whole archive (content, hashes, integrity, schema) before touching anything, then:

- it takes the data folder for itself, from its first check to its last file (lock `/data/.posture-cockpit.lock`): it refuses to begin while the application or a command uses it, and the application refuses to start until it is over;
- it saves the replaced data as an ordinary backup, `/data/backups/posture-cockpit-before-restore-<date>.tar.gz`, restorable in turn (or copies it as it is when it is too damaged to be read);
- it replaces the files all or nothing: if one replacement fails (full disk…), the former files are put back and the message says so.

The lock holds between all the containers of one server that share the volume. On a network file system it holds only if the file server supports locks (NFSv4, NFS with lockd; not SMB/CIFS): never use the same data folder from two servers.

**On the same installation:**

```bash
docker compose stop
docker compose run --rm --no-deps -T posture-cockpit posture-cockpit restore --replace - < posture-cockpit-2026-10-17.tar.gz
docker compose up -d
```

**On a new installation** (another server, or a test instance): install it as above without starting it, then restore without `--replace` (its volume is empty) and start it. A backup of an older version is upgraded at start, like any older database. A backup made by a newer version is refused.

As the session key is restored, open sessions stay valid; accounts, two-factor authentication and API tokens are those of the backup. A backup without session key (an instance that never started) gives the replaced instance a **new** key — never its former one, which would open the restored accounts that have the same numbers — and everyone signs in again; a new installation makes its own at its first start.

## Updating

**Before the first v0.5.0 start**, add `POSTURE_COCKPIT_SCHEDULER=off` (without `#`) to your `.env`: the scheduler is **enabled by default**. Enable it only after checking schedules, domains and quotas. Export a verified backup outside the production volume before migrating.

1. Make a backup (above), and keep a copy away from the server.
2. Replace `compose.yaml` with the one of the new version, then restart:

```bash
curl -fsSLO https://raw.githubusercontent.com/vinzgithub/posture-cockpit/v0.6.1/compose.yaml   # the version you want
docker compose up -d
docker compose exec posture-cockpit posture-cockpit info
```

Docker downloads the new image and recreates the container on the same volume. At start, the database is upgraded automatically. Your `.env` is left as it is; if it sets `POSTURE_COCKPIT_IMAGE`, change it to the new version.

**When the schema changes** (0.5.0: from schema 4 to 5), the application first writes a complete backup — database and session key — to `/data/backups/posture-cockpit-before-schema5-<date>.tar.gz`. It then reads it back and compares it with the database: schema, accounts, domains, scans, session key. It needs free space of twice the database; before updating, `posture-cockpit info` says how much. If any of this fails, nothing is migrated and the application does not start: the message says why (table below), and the database is left as it was. The account commands (`reset-password`, …) do the same when they find a database to migrate. Afterwards, `info` shows that backup:

```
Backup before the last update: backups/posture-cockpit-before-schema5-20261020T081500Z.tar.gz (schema 4 to 5, 2026-10-20T08:15:00+00:00, verified)
```

Keep a copy of it away from the server too:

```bash
umask 077
docker compose exec -T posture-cockpit cat /data/backups/posture-cockpit-before-schema5-<date>.tar.gz > before-0.5.0.tar.gz
```

Once migrated to schema 5, the database can no longer be opened by 0.4.x: going back is a restoration (below).

0.4.1 keeps the schema 4 of 0.4.0: going from 0.4.0 to 0.4.1, or back from 0.4.1 to 0.4.0, does not change the database.

**Moving to 0.2.0**: the scores of stored scans are recomputed with the coverage rules (see [SCORING.md](SCORING.md)); the API may return `"score": null` for a domain that is "not evaluated" (see [HOME_ASSISTANT.md](HOME_ASSISTANT.md)).

## Rollback

**Same schema** (0.4.0 and 0.4.1, schema 4): put back the `compose.yaml` of the previous version and restart.

```bash
curl -fsSLO https://raw.githubusercontent.com/vinzgithub/posture-cockpit/v0.4.0/compose.yaml
docker compose up -d
```

**From 0.5.0 to 0.4.1** (schema 5 to 4): the image of 0.4.1 refuses the migrated database (`uses schema 5; this version of Posture Cockpit handles schema 4 at most`) and changes nothing. Restore the backup made before the update, with the image of 0.4.1:

```bash
docker compose stop
curl -fsSLO https://raw.githubusercontent.com/vinzgithub/posture-cockpit/v0.4.1/compose.yaml   # and POSTURE_COCKPIT_IMAGE in .env, if set
docker compose run --rm --no-deps posture-cockpit ls /data/backups                    # the name of posture-cockpit-before-schema5-<date>.tar.gz
docker compose run --rm --no-deps -T posture-cockpit posture-cockpit check-backup /data/backups/posture-cockpit-before-schema5-<date>.tar.gz
docker compose run --rm --no-deps -T posture-cockpit posture-cockpit restore --replace /data/backups/posture-cockpit-before-schema5-<date>.tar.gz
docker compose up -d
docker compose exec posture-cockpit posture-cockpit info                              # schema 4 (up to date)
```

The copy kept away from the server is restored the same way, from the standard input (`restore --replace - < before-0.5.0.tar.gz`). The restoration first saves the data of 0.5.0 to `/data/backups/posture-cockpit-before-restore-<date>.tar.gz`: nothing done since the update is destroyed, and the image of 0.5.0 can restore that archive to take up the update again where it was left.

**From 0.5.0 to 0.4.0 or earlier**: these versions do not refuse a newer schema and would run on it, with errors. Never start them on the migrated database. 0.4.0 has no `restore` command: restore the backup with the image of 0.5.0 (the commands above, with the `compose.yaml` of 0.5.0), then put back the `compose.yaml` of 0.4.0 and start.

**What the return loses: everything done after the backup.** The data comes back as it was at the moment of the update:

- scans and rechecks made since, domains added or deleted, perimeters and settings changed;
- accounts created since disappear; accounts deleted since come back, with their former rights; a role given or removed since is undone;
- **passwords** changed or reset since: the former one works again;
- **two-factor authentication** enabled since is off again; disabled since, it is on again with its former secret and recovery codes; recovery codes used or renewed since come back;
- **API keys** created since disappear; **revoked since, they work again**;
- the sign-outs forced since (password change, two-factor change) are undone: sessions they ended become valid again, since the session key is that of the backup;
- the audit entries since.

**Re-apply the security changes made since the update.** The audit log of the data saved by the restoration (`posture-cockpit-before-restore-<date>.tar.gz`) lists them: restore that archive into a test instance (section below, never over your installation) and read Administration → Audit log. Then, on the restored installation: revoke again the API keys revoked since, change again the passwords changed since (above all one changed because it had leaked), disable or enable two-factor authentication again, delete again the accounts deleted since, check the role of each account. If a session that was ended since must not come back, make a new session key — every browser is signed out:

```bash
docker compose stop
docker compose run --rm --no-deps posture-cockpit rm /data/.secret_key
docker compose up -d   # a new key is made at start
```

## From an older `compose.yaml`

Installations made with the `compose.yaml` of 0.4.0 or earlier keep their data when they move to the new file:

- **Volume.** The new file sets the project name to `posture-cockpit`: the volume stays `posture-cockpit_posture-cockpit-data`, the one of an installation made in a `posture-cockpit` folder. If your folder had another name, check with `docker volume ls` and put its prefix in the `.env`: `COMPOSE_PROJECT_NAME=<prefix>`.
- **Settings.** Move your `environment:` lines to the `.env` (same name, `NAME=value`, without quotes) and your port to `POSTURE_COCKPIT_PORT`.
- **Image.** A locally built image is kept with `POSTURE_COCKPIT_IMAGE=<name:tag>`; otherwise the official image is downloaded.
- **Container name.** It stays `posture-cockpit`; `docker compose exec posture-cockpit …` commands work in every case.

## A test instance on the same server

A separate folder with its own `.env`: separate project, container, port and cookie, hence a separate volume. A browser sends the cookies of an address to all its ports: without a cookie name of its own, the two instances would sign each other out.

```bash
COMPOSE_PROJECT_NAME=posture-cockpit-test
POSTURE_COCKPIT_CONTAINER=posture-cockpit-test
POSTURE_COCKPIT_PORT=8089
POSTURE_COCKPIT_SESSION_COOKIE=posture_cockpit_test
#POSTURE_COCKPIT_IMAGE=posture-cockpit:local   # an image built from the repository: docker build -t posture-cockpit:local .
```

Letters, digits, `_` and `-` only for the cookie; the `__Host-` and `__Secure-` prefixes need `POSTURE_COCKPIT_COOKIE_SECURE=true`. Renaming the cookie of an existing instance signs its users out once. To stop it and erase everything: `docker compose down -v`, **in the test folder only**.

## When the start fails

The application refuses to start, saying what to do (`docker compose logs posture-cockpit`), rather than putting the data at risk:

| Message | Cause and fix |
|---|---|
| `The data folder /data cannot be written … chown -R 10001:10001 <folder>` | A folder of the host mounted on `/data` belongs to root. Use the named volume of `compose.yaml`, or give the folder to user 10001. |
| `The database … uses schema N; this version … handles schema M at most` | The database comes from a newer version. Run that one again, or restore a backup made before. Nothing was changed. |
| `The session key … is empty or damaged` | Restore `.secret_key` from a backup, or delete it: a new key is created and every browser is signed out. |
| `The database … cannot be opened` | The database file is damaged: restore a backup. |
| `Not enough free space in /data to back up the database before updating it` | The backup made before a migration needs twice the size of the database. Free some space (old archives of `/data/backups/`, kept elsewhere first), then start again. Nothing was changed. |
| `The backup before the update could not be written` or `… failed its verification` | The backup made before a migration could not be written or read back identical. Nothing was migrated; the archive that failed was deleted. Check the disk (`df`, `docker system df`), then start again. |

## Without Docker

Python 3.11 or later, and the Pango libraries for the PDF report (Debian/Ubuntu: `apt install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0`):

```bash
python -m venv /opt/posture-cockpit
/opt/posture-cockpit/bin/pip install posture-cockpit   # or: pip install . from the repository
POSTURE_COCKPIT_DATA_DIR=/var/lib/posture-cockpit \
  /opt/posture-cockpit/bin/uvicorn --factory posture_cockpit.web.app:create_app --host 0.0.0.0 --port 8080
```

Without Pango, everything works except the PDF report, which shows a message.

## Rescue

```bash
docker compose exec posture-cockpit posture-cockpit reset-password <username>
docker compose exec posture-cockpit posture-cockpit disable-totp <username>   # lost phone and recovery codes
docker compose exec posture-cockpit posture-cockpit make-admin <username>
```

### Returning between schema-5 versions (v0.5.0, v0.6.0 and v0.6.1)

Before changing images: verify a backup outside the volume, disable scheduling and stop the instance cleanly. Schema 5 is unchanged: a pinned official older image can reuse the current volume without restoring an earlier backup. Data created after the upgrade must remain available. v0.5.0 shows its older projections, including DMARC, while observed scores remain unchanged. Test on an isolated copy; never run two instances concurrently on that volume. Returning to schema 4 still requires a separate restore procedure.
