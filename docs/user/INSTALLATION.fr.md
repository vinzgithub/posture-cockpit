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

**Installé dans un réseau d'entreprise**, réglez aussi `POSTURE_COCKPIT_NAMESERVERS` sur des résolveurs publics : sinon le résolveur interne répond aux analyses « Internet », et un utilisateur pourrait y lire des enregistrements de vos zones internes. Les sites internes s'auditent dans un **périmètre interne** (ci-dessous), réservé aux administrateurs.

Les analyses ne passent **pas** par un proxy HTTP : les variables `HTTP_PROXY` et `HTTPS_PROXY` sont ignorées, car un proxy se connecterait à la place de Posture Cockpit, hors de portée de sa règle de sortie. Le serveur doit donc joindre directement les ports 80 et 443.

**Règle de sortie.** En mode Internet, Posture Cockpit ne se connecte qu'à des adresses publiques, sur les ports 80 et 443. Un domaine qui pointe vers une adresse privée (10.x, 192.168.x, ::1…) n'est pas contacté : les contrôles concernés sont « non évalués », avec la raison. Les adresses lien-local, multidiffusion, réservées et les services de métadonnées des clouds (169.254.169.254…) ne sont jamais contactés, quel que soit le mode. Détails dans [SECURITY.md](../../SECURITY.md).

## Réglages

| Variable | Par défaut | Rôle |
|---|---|---|
| `POSTURE_COCKPIT_DATA_DIR` | `/data` (image) | Dossier de la base SQLite et de la clé de session |
| `POSTURE_COCKPIT_NAMESERVERS` | ceux du système | Résolveurs DNS, séparés par des virgules |
| `POSTURE_COCKPIT_DKIM_SELECTORS` | vide | Sélecteurs DKIM supplémentaires (séparés par des virgules, sans nom de domaine). Les sélecteurs usuels restent vérifiés ; limite totale : 30 sélecteurs. |
| `POSTURE_COCKPIT_CHECK_TIMEOUT` | `15` | Secondes accordées à chaque contrôle |
| `POSTURE_COCKPIT_COOKIE_SECURE` | `false` | `true` quand l'application est servie en HTTPS |
| `POSTURE_COCKPIT_DEFAULT_LOCALE` | `fr` | Langue des pages avant la connexion |
| `POSTURE_COCKPIT_SESSION_MAX_AGE` | `604800` | Durée de la session, en secondes (7 jours) |
| `POSTURE_COCKPIT_FRAME_ANCESTORS` | `'self'` | Sites autorisés à afficher l'application dans un cadre (Home Assistant) |
| `POSTURE_COCKPIT_INTERNAL_SCANS` | `false` | `true` pour permettre aux administrateurs de créer des périmètres internes |
| `POSTURE_COCKPIT_MAX_CONCURRENT_SCANS` | `4` | Analyses simultanées sur l'instance |
| `POSTURE_COCKPIT_SCANS_PER_HOUR` | `30` | Analyses par compte et par heure (une revérification n'en consomme pas) |
| `POSTURE_COCKPIT_TIMEZONE` | `TZ`, sinon UTC | Fuseau des pages et des rapports PDF (nom IANA, par exemple `Europe/Paris`). La base et l'API restent en UTC |
| `POSTURE_COCKPIT_SESSION_COOKIE` | `posture_cockpit` | Nom du cookie de session : à changer pour une deuxième instance à la même adresse (ci-dessous) |
| `FORWARDED_ALLOW_IPS` | – | Adresse du proxy inverse, pour que les essais limités comptent la vraie adresse du client |

### Heures affichées

Les heures sont enregistrées et transmises par l'API en UTC (`2026-10-13T07:19:05+00:00`). Les pages et les rapports PDF les affichent dans le fuseau de l'instance : `POSTURE_COCKPIT_TIMEZONE`, sinon la variable `TZ` du conteneur (celle de l'exemple ci-dessus), sinon UTC. Le PDF indique le décalage (« 09:19 UTC+2 »). Un nom de fuseau inconnu dans `POSTURE_COCKPIT_TIMEZONE` empêche le démarrage ; une variable `TZ` au format POSIX (`CET-1CEST,…`) est ignorée, avec un avertissement dans le journal.

### Deux instances à la même adresse

Un navigateur envoie les cookies d'une adresse à tous ses ports : une instance de test sur `192.168.2.15:8081` et l'instance en service sur `192.168.2.15:8080` se déconnectent alors l'une l'autre. Donnez un autre nom au cookie de l'instance de test :

```yaml
    environment:
      POSTURE_COCKPIT_SESSION_COOKIE: posture_cockpit_validation
```

Lettres, chiffres, `_` et `-` seulement. Les préfixes `__Host-` et `__Secure-` exigent `POSTURE_COCKPIT_COOKIE_SECURE: "true"`. Changer le nom d'une instance existante déconnecte ses utilisateurs une fois.

## Audits de réseaux internes

Pour auditer des sites de votre réseau privé (intranet, applications internes en HTTPS) :

1. installez Posture Cockpit **dans** ce réseau, ou sur une machine qui le joint ;
2. démarrez-le avec `POSTURE_COCKPIT_INTERNAL_SCANS: "true"` ;
3. dans **Administration → Périmètres internes**, un administrateur crée un périmètre : les réseaux autorisés (CIDR, dans 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 ou fc00::/7), les serveurs DNS internes, les ports (443 et 80 par défaut) et, au besoin, l'autorité de certification interne au format PEM ;
4. depuis la page du périmètre, il ajoute les domaines internes et les analyse.

Seuls les administrateurs voient ces domaines, leurs analyses et leurs rapports (marqués « Diffusion restreinte »). La vérification des certificats n'est jamais désactivée : l'AC interne s'ajoute aux autorités reconnues. Chaque analyse interne est inscrite au journal d'audit. Les contrôles faits pour Internet (messagerie, DNS public, security.txt) sont « non applicables » dans un audit interne.

L'adresse de boucle locale (127.0.0.0/8, ::1) n'est jamais ouverte : Posture Cockpit ne s'analyse pas lui-même.

Pour auditer plusieurs réseaux depuis une seule instance, une architecture à agents est étudiée dans [REMOTE_AGENT.fr.md](../developer/REMOTE_AGENT.fr.md).

## Derrière un proxy inverse (HTTPS)

Servez Posture Cockpit en HTTPS (Caddy, Nginx, Traefik, HAProxy…), puis :

```yaml
    environment:
      POSTURE_COCKPIT_COOKIE_SECURE: "true"
      FORWARDED_ALLOW_IPS: "10.0.0.2"        # l'adresse du proxy
```

## Sauvegarde

Tout est dans le volume `/data` : la base `posture_cockpit.db`, la clé de session `.secret_key` et le dossier `backups/` (copies faites avant chaque mise à jour du schéma).

```bash
docker run --rm -v posture-cockpit-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/posture-cockpit-$(date +%F).tgz -C /data .
```

## Mise à jour

```bash
docker compose pull
docker compose up -d
```

La base est mise à niveau automatiquement au démarrage (migrations) ; une copie de la base d'avant est d'abord écrite dans `/data/backups/`. Faites tout de même une sauvegarde avant une mise à jour majeure.

**Passage en 0.2.0** : les notes des analyses enregistrées sont recalculées avec les règles de couverture (voir [SCORING.fr.md](SCORING.fr.md)) ; l'API peut renvoyer `"score": null` pour un domaine « non évalué » (voir [HOME_ASSISTANT.fr.md](HOME_ASSISTANT.fr.md)).

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
