# Installation

🇫🇷 [Version française](INSTALLATION.fr.md)

## With Docker (recommended)

```yaml
# compose.yaml
services:
  posture-cockpit:
    image: ghcr.io/vinzgithub/posture-cockpit:latest
    container_name: posture-cockpit
    restart: unless-stopped
    ports:
      - "8080:8080"          # "8081:8080" if port 8080 is already taken
    volumes:
      - posture-cockpit-data:/data
    environment:
      TZ: Europe/Paris
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
volumes:
  posture-cockpit-data:
```

```bash
docker compose up -d
curl http://localhost:8080/healthz     # {"status":"ok","version":"…"}
```

Open `http://<server>:8080` and create the administrator account. The **"Check the demo domain"** box adds a fictitious domain to discover the tool without scanning anything real.

The repository's [`compose.yaml`](../../compose.yaml) holds the same, with the optional settings in comments.

## Network access needed

The server must be able to reach the Internet:

- **DNS** (port 53 UDP and TCP) to its resolvers, or those of `POSTURE_COCKPIT_NAMESERVERS`;
- **HTTPS and HTTP** (ports 443 and 80) to the domains scanned.

A filtering resolver (ad blocker, corporate DNS) may return empty answers: Posture Cockpit then refuses the scan rather than reporting missing records by mistake. Give it public resolvers, for instance `POSTURE_COCKPIT_NAMESERVERS: "9.9.9.9,1.1.1.1"`.

**Installed in a company network**, also set `POSTURE_COCKPIT_NAMESERVERS` to public resolvers: otherwise the internal resolver answers the "Internet" scans, and a user could read records of your internal zones there. Internal sites are audited in an **internal perimeter** (below), for administrators only.

Scans do **not** go through an HTTP proxy: the `HTTP_PROXY` and `HTTPS_PROXY` variables are ignored, because a proxy would connect in Posture Cockpit's place, out of reach of its egress rule. The server must therefore reach ports 80 and 443 directly.

**Egress rule.** In Internet mode, Posture Cockpit only connects to public addresses, on ports 80 and 443. A domain that points to a private address (10.x, 192.168.x, ::1…) is not contacted: the checks concerned are "not evaluated", with the reason. Link-local, multicast and reserved addresses and the cloud metadata services (169.254.169.254…) are never contacted, whatever the mode. Details in [SECURITY.md](../../SECURITY.md).

## Settings

| Variable | Default | Role |
|---|---|---|
| `POSTURE_COCKPIT_DATA_DIR` | `/data` (image) | Folder of the SQLite database and the session key |
| `POSTURE_COCKPIT_NAMESERVERS` | the system's | DNS resolvers, comma-separated |
| `POSTURE_COCKPIT_CHECK_TIMEOUT` | `15` | Seconds allowed to each check |
| `POSTURE_COCKPIT_COOKIE_SECURE` | `false` | `true` when the application is served over HTTPS |
| `POSTURE_COCKPIT_DEFAULT_LOCALE` | `fr` | Language of the pages before sign-in |
| `POSTURE_COCKPIT_SESSION_MAX_AGE` | `604800` | Session length in seconds (7 days) |
| `POSTURE_COCKPIT_FRAME_ANCESTORS` | `'self'` | Sites allowed to show the application in a frame (Home Assistant) |
| `POSTURE_COCKPIT_INTERNAL_SCANS` | `false` | `true` to let administrators create internal perimeters |
| `POSTURE_COCKPIT_MAX_CONCURRENT_SCANS` | `4` | Scans running at the same time on the instance |
| `POSTURE_COCKPIT_SCANS_PER_HOUR` | `30` | Scans per account and per hour (checking one fix again does not count) |
| `FORWARDED_ALLOW_IPS` | – | Address of the reverse proxy, so the attempt limit counts the real client address |

## Audits of internal networks

To audit sites of your private network (intranet, internal applications over HTTPS):

1. install Posture Cockpit **inside** that network, or on a machine that reaches it;
2. start it with `POSTURE_COCKPIT_INTERNAL_SCANS: "true"`;
3. in **Administration → Internal perimeters**, an administrator creates a perimeter: the allowed networks (CIDR, inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 or fc00::/7), the internal DNS servers, the ports (443 and 80 by default) and, if needed, the internal certificate authority in PEM;
4. from the perimeter's page, they add the internal domains and scan them.

Only administrators see these domains, their scans and their reports (marked "Restricted distribution"). Certificate verification is never turned off: the internal CA is added to the trusted authorities. Every internal scan is written to the audit log. The checks made for the Internet (mail, public DNS, security.txt) are "not applicable" in an internal audit.

The loopback address (127.0.0.0/8, ::1) is never opened: Posture Cockpit does not scan itself.

To audit several networks from a single instance, an agent architecture is studied in [REMOTE_AGENT.md](../developer/REMOTE_AGENT.md).

## Behind a reverse proxy (HTTPS)

Serve Posture Cockpit over HTTPS (Caddy, Nginx, Traefik, HAProxy…), then:

```yaml
    environment:
      POSTURE_COCKPIT_COOKIE_SECURE: "true"
      FORWARDED_ALLOW_IPS: "10.0.0.2"        # the proxy's address
```

## Backup

Everything is in the `/data` volume: the `posture_cockpit.db` database, the `.secret_key` session key and the `backups/` folder (copies made before each schema upgrade).

```bash
docker run --rm -v posture-cockpit-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/posture-cockpit-$(date +%F).tgz -C /data .
```

## Updating

```bash
docker compose pull
docker compose up -d
```

The database is upgraded automatically at start-up (migrations); a copy of the database from before is first written to `/data/backups/`. Still, back up before a major update.

**Upgrading to 0.2.0**: the scores of stored scans are computed again with the coverage rules (see [SCORING.md](SCORING.md)); the API may return `"score": null` for a domain "not evaluated" (see [HOME_ASSISTANT.md](HOME_ASSISTANT.md)).

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
docker exec -it posture-cockpit posture-cockpit reset-password <username>
docker exec -it posture-cockpit posture-cockpit disable-totp <username>   # lost phone and recovery codes
docker exec -it posture-cockpit posture-cockpit make-admin <username>
```
