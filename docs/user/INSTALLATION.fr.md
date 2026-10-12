# Installation

🇬🇧 [English version](INSTALLATION.md)

## Avec Docker (recommandé)

```yaml
# compose.yaml
services:
  posture-cockpit:
    image: ghcr.io/vinzgithub/posture-cockpit:latest
    container_name: posture-cockpit
    restart: unless-stopped
    ports:
      - "8080:8080"          # "8081:8080" si le port 8080 est déjà pris
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

Ouvrez `http://<serveur>:8080`, créez le compte administrateur. La case **« Analyser le domaine de démonstration »** ajoute un domaine fictif pour découvrir l'outil sans rien analyser de réel.

Le fichier [`compose.yaml`](../../compose.yaml) du dépôt contient la même chose, avec les réglages facultatifs en commentaire.

## Accès réseau nécessaire

Le serveur doit pouvoir sortir vers Internet :

- **DNS** (port 53 UDP et TCP) vers ses résolveurs, ou ceux de `POSTURE_COCKPIT_NAMESERVERS` ;
- **HTTPS et HTTP** (ports 443 et 80) vers les domaines analysés.

Un résolveur qui filtre (bloqueur de publicités, DNS d'entreprise) peut renvoyer des réponses vides : Posture Cockpit refuse alors l'analyse plutôt que de signaler à tort des enregistrements manquants. Donnez-lui des résolveurs publics, par exemple `POSTURE_COCKPIT_NAMESERVERS: "9.9.9.9,1.1.1.1"`.

## Réglages

| Variable | Par défaut | Rôle |
|---|---|---|
| `POSTURE_COCKPIT_DATA_DIR` | `/data` (image) | Dossier de la base SQLite et de la clé de session |
| `POSTURE_COCKPIT_NAMESERVERS` | ceux du système | Résolveurs DNS, séparés par des virgules |
| `POSTURE_COCKPIT_CHECK_TIMEOUT` | `15` | Secondes accordées à chaque contrôle |
| `POSTURE_COCKPIT_COOKIE_SECURE` | `false` | `true` quand l'application est servie en HTTPS |
| `POSTURE_COCKPIT_DEFAULT_LOCALE` | `fr` | Langue des pages avant la connexion |
| `POSTURE_COCKPIT_SESSION_MAX_AGE` | `604800` | Durée de la session, en secondes (7 jours) |
| `POSTURE_COCKPIT_FRAME_ANCESTORS` | `'self'` | Sites autorisés à afficher l'application dans un cadre (Home Assistant) |
| `FORWARDED_ALLOW_IPS` | – | Adresse du proxy inverse, pour que les essais limités comptent la vraie adresse du client |

## Derrière un proxy inverse (HTTPS)

Servez Posture Cockpit en HTTPS (Caddy, Nginx, Traefik, HAProxy…), puis :

```yaml
    environment:
      POSTURE_COCKPIT_COOKIE_SECURE: "true"
      FORWARDED_ALLOW_IPS: "10.0.0.2"        # l'adresse du proxy
```

## Sauvegarde

Tout est dans le volume `/data` : la base `posture_cockpit.db` et la clé de session `.secret_key`.

```bash
docker run --rm -v posture-cockpit-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/posture-cockpit-$(date +%F).tgz -C /data .
```

## Mise à jour

```bash
docker compose pull
docker compose up -d
```

La base est mise à niveau automatiquement au démarrage (migrations). Faites une sauvegarde avant une mise à jour majeure.

## Sans Docker

Python 3.11 ou plus récent, et les bibliothèques Pango pour le rapport PDF (Debian/Ubuntu : `apt install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0`) :

```bash
python -m venv /opt/posture-cockpit
/opt/posture-cockpit/bin/pip install posture-cockpit   # ou : pip install . depuis le dépôt
POSTURE_COCKPIT_DATA_DIR=/var/lib/posture-cockpit \
  /opt/posture-cockpit/bin/uvicorn --factory posture_cockpit.web.app:create_app --host 0.0.0.0 --port 8080
```

Sans Pango, tout fonctionne sauf le rapport PDF, qui affiche un message.

## Secours

```bash
docker exec -it posture-cockpit posture-cockpit reset-password <identifiant>
docker exec -it posture-cockpit posture-cockpit disable-totp <identifiant>   # téléphone et codes de secours perdus
docker exec -it posture-cockpit posture-cockpit make-admin <identifiant>
```
