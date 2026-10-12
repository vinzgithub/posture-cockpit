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
| `FORWARDED_ALLOW_IPS` | – | Address of the reverse proxy, so the attempt limit counts the real client address |

## Behind a reverse proxy (HTTPS)

Serve Posture Cockpit over HTTPS (Caddy, Nginx, Traefik, HAProxy…), then:

```yaml
    environment:
      POSTURE_COCKPIT_COOKIE_SECURE: "true"
      FORWARDED_ALLOW_IPS: "10.0.0.2"        # the proxy's address
```

## Backup

Everything is in the `/data` volume: the `posture_cockpit.db` database and the `.secret_key` session key.

```bash
docker run --rm -v posture-cockpit-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/posture-cockpit-$(date +%F).tgz -C /data .
```

## Updating

```bash
docker compose pull
docker compose up -d
```

The database is upgraded automatically at start-up (migrations). Back up before a major update.

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
