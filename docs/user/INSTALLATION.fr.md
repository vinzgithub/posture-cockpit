# Installation

🇬🇧 [English version](INSTALLATION.md)

## Avec Docker (recommandé)

**Nouvelle installation uniquement :** ces commandes créent une instance neuve en **v0.6.0**. Si vous avez déjà des données v0.4.1 ou antérieures, suivez la [mise à jour](#mise-à-jour), exportez une sauvegarde vérifiée hors du volume Docker et désactivez l'ordonnanceur avant la migration. La v0.6.0 conserve le schéma SQLite 5 ; revenir au schéma 4 nécessite une restauration.

Il faut Docker Engine et **Docker Compose 2.24 ou plus récent** (`docker compose version`). Rien à compiler, pas besoin de Git : l'image officielle est publiée sur `ghcr.io/vinzgithub/posture-cockpit`, pour les processeurs amd64 et arm64.

```bash
mkdir posture-cockpit && cd posture-cockpit
curl -fsSLO https://raw.githubusercontent.com/vinzgithub/posture-cockpit/v0.6.0/compose.yaml
docker compose up -d
```

Le fichier [`compose.yaml`](../../compose.yaml) désigne une version précise de l'image (`0.6.0`), jamais `latest` : une installation ne change pas de version toute seule. Il garde les protections : utilisateur sans privilèges (uid 10001), système en lecture seule, aucune capacité Linux, `no-new-privileges`, `/tmp` en mémoire. Les données vont dans le volume `posture-cockpit_posture-cockpit-data`, quel que soit le dossier d'installation.

### Premier démarrage : le code d'initialisation

Tant qu'aucun compte n'existe, la création du compte administrateur demande un **code d'initialisation**, écrit dans le journal du serveur (il change à chaque redémarrage tant qu'aucun compte n'existe) :

```bash
docker compose logs posture-cockpit
# … Setup code / code d'initialisation : 7KQM-3XHA-PZ2W
```

Ouvrez `http://<serveur>:8080/setup`, saisissez ce code, puis créez le compte. La case **« Analyser le domaine de démonstration »** ajoute un domaine fictif pour découvrir l'outil sans rien analyser de réel. Sans ce code, une personne qui atteindrait la page avant vous ne peut pas devenir administrateur. Les instances qui ont déjà des comptes ne voient aucun code.

Pour une installation automatisée, `POSTURE_COCKPIT_SETUP_CODE` fixe le code (12 lettres ou chiffres au moins) ; il n'est alors jamais écrit dans le journal.

### Vérifier

```bash
curl http://localhost:8080/healthz                       # {"status":"ok","version":"0.6.0"}
docker compose exec posture-cockpit posture-cockpit info  # version, schéma, comptes, analyses
```

### Régler : le fichier `.env`

Ne modifiez pas `compose.yaml` : une mise à jour le remplace. Les réglages vont dans un fichier `.env` facultatif, à côté de lui ; le modèle [`.env.example`](../../.env.example) les décrit tous, en commentaire :

```bash
curl -fsSL https://raw.githubusercontent.com/vinzgithub/posture-cockpit/v0.6.0/.env.example -o .env
nano .env                 # décommentez les lignes utiles
docker compose up -d      # applique les changements
```

Les plus courants :

| Ligne du `.env` | Effet |
|---|---|
| `POSTURE_COCKPIT_PORT=8081` | Port du serveur (8080 par défaut) |
| `POSTURE_COCKPIT_BIND=127.0.0.1` | Écoute sur cette adresse seulement (toutes par défaut) ; `127.0.0.1` derrière un proxy inverse sur le même serveur |
| `TZ=Europe/Paris` | Fuseau horaire des pages et des PDF (`Europe/Paris` par défaut) |
| `POSTURE_COCKPIT_COOKIE_SECURE=true` | Servi en HTTPS par un proxy inverse (ci-dessous) |
| `POSTURE_COCKPIT_NAMESERVERS=9.9.9.9,1.1.1.1` | Résolveurs DNS à utiliser |

Une ligne laissée vide (`NOM=`) garde la valeur par défaut. Tous les réglages de l'application (variables `POSTURE_COCKPIT_*`, ci-dessous) se mettent aussi dans ce fichier.

> Attention : un port publié par Docker passe outre le pare-feu de l'hôte (règles iptables de Docker). Pour n'exposer Posture Cockpit qu'au proxy inverse du même serveur, utilisez `POSTURE_COCKPIT_BIND=127.0.0.1`.

## Accès réseau nécessaire

Le serveur doit pouvoir sortir vers Internet :

- **DNS** (port 53 UDP et TCP) vers ses résolveurs, ou ceux de `POSTURE_COCKPIT_NAMESERVERS` ;
- **HTTPS et HTTP** (ports 443 et 80) vers les domaines analysés.

Un résolveur qui filtre (bloqueur de publicités, DNS d'entreprise) peut renvoyer des réponses vides : Posture Cockpit refuse alors l'analyse plutôt que de signaler à tort des enregistrements manquants. Donnez-lui des résolveurs publics, par exemple `POSTURE_COCKPIT_NAMESERVERS=9.9.9.9,1.1.1.1` dans le `.env`.

**Installé dans un réseau d'entreprise**, réglez aussi `POSTURE_COCKPIT_NAMESERVERS` sur des résolveurs publics : sinon le résolveur interne répond aux analyses « Internet », et un utilisateur pourrait y lire des enregistrements de vos zones internes. Les sites internes s'auditent dans un **périmètre interne** (ci-dessous), réservé aux administrateurs.

Les analyses ne passent **pas** par un proxy HTTP : les variables `HTTP_PROXY` et `HTTPS_PROXY` sont ignorées, car un proxy se connecterait à la place de Posture Cockpit, hors de portée de sa règle de sortie. Le serveur doit donc joindre directement les ports 80 et 443.

**Règle de sortie.** En mode Internet, Posture Cockpit ne se connecte qu'à des adresses publiques, sur les ports 80 et 443. Un domaine qui pointe vers une adresse privée (10.x, 192.168.x, ::1…) n'est pas contacté : les contrôles concernés sont « non évalués », avec la raison. Les adresses lien-local, multidiffusion, réservées et les services de métadonnées des clouds (169.254.169.254…) ne sont jamais contactés, quel que soit le mode. Détails dans [SECURITY.md](../../SECURITY.md).

## Réglages

Avec Docker, ces réglages se mettent dans le fichier `.env` (`NOM=valeur`, voir plus haut).

| Variable | Par défaut | Rôle |
|---|---|---|
| `POSTURE_COCKPIT_DATA_DIR` | `/data` (image) | Dossier de la base SQLite et de la clé de session |
| `POSTURE_COCKPIT_NAMESERVERS` | ceux du système | Résolveurs DNS, séparés par des virgules |
| `POSTURE_COCKPIT_DKIM_SELECTORS` | vide | Sélecteurs DKIM supplémentaires (séparés par des virgules, sans nom de domaine). Les sélecteurs usuels restent vérifiés ; limite totale : 30 sélecteurs. Une valeur invalide empêche le démarrage, avec sa raison. |
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
| `POSTURE_COCKPIT_SETUP_CODE` | aléatoire | Code du premier compte (12 lettres ou chiffres au moins) au lieu du code aléatoire écrit dans le journal |
| `POSTURE_COCKPIT_PORT` | `8080` | Docker Compose : port du serveur |
| `POSTURE_COCKPIT_BIND` | toutes | Docker Compose : adresse d'écoute du serveur |
| `POSTURE_COCKPIT_IMAGE` | l'image de la version | Docker Compose : image à utiliser (test d'une image construite localement) |
| `POSTURE_COCKPIT_CONTAINER` | `posture-cockpit` | Docker Compose : nom du conteneur (seconde instance) |
| `COMPOSE_PROJECT_NAME` | `posture-cockpit` | Docker Compose : nom du projet, préfixe du volume (seconde instance) |

### Heures affichées

Les heures sont enregistrées et transmises par l'API en UTC (`2026-10-13T07:19:05+00:00`). Les pages et les rapports PDF les affichent dans le fuseau de l'instance : `POSTURE_COCKPIT_TIMEZONE`, sinon la variable `TZ` du conteneur (celle de l'exemple ci-dessus), sinon UTC. Le PDF indique le décalage (« 09:19 UTC+2 »). Un nom de fuseau inconnu dans `POSTURE_COCKPIT_TIMEZONE` empêche le démarrage ; une variable `TZ` au format POSIX (`CET-1CEST,…`) est ignorée, avec un avertissement dans le journal.

## Audits de réseaux internes

Pour auditer des sites de votre réseau privé (intranet, applications internes en HTTPS) :

1. installez Posture Cockpit **dans** ce réseau, ou sur une machine qui le joint ;
2. démarrez-le avec `POSTURE_COCKPIT_INTERNAL_SCANS=true` dans le `.env` ;
3. dans **Administration → Périmètres internes**, un administrateur crée un périmètre : les réseaux autorisés (CIDR, dans 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 ou fc00::/7), les serveurs DNS internes, les ports (443 et 80 par défaut) et, au besoin, l'autorité de certification interne au format PEM ;
4. depuis la page du périmètre, il ajoute les domaines internes et les analyse.

Seuls les administrateurs voient ces domaines, leurs analyses et leurs rapports (marqués « Diffusion restreinte »). La vérification des certificats n'est jamais désactivée : l'AC interne s'ajoute aux autorités reconnues. Chaque analyse interne est inscrite au journal d'audit. Les contrôles faits pour Internet (messagerie, DNS public, security.txt) sont « non applicables » dans un audit interne.

L'adresse de boucle locale (127.0.0.0/8, ::1) n'est jamais ouverte : Posture Cockpit ne s'analyse pas lui-même.

Pour auditer plusieurs réseaux depuis une seule instance, une architecture à agents est étudiée dans [REMOTE_AGENT.fr.md](../developer/REMOTE_AGENT.fr.md).

## Derrière un proxy inverse (HTTPS)

Servez Posture Cockpit en HTTPS (Caddy, Nginx, Traefik, HAProxy…). Dans le `.env` :

```bash
POSTURE_COCKPIT_COOKIE_SECURE=true   # cookie de session en HTTPS seulement, et en-tête HSTS
POSTURE_COCKPIT_BIND=127.0.0.1       # si le proxy tourne sur le même serveur
FORWARDED_ALLOW_IPS=127.0.0.1        # l'adresse vue du proxy : ses en-têtes X-Forwarded-* sont crus
```

`FORWARDED_ALLOW_IPS` doit être l'adresse d'où le proxy se connecte, telle que le conteneur la voit (pour un proxy dans un autre conteneur, son adresse sur le réseau Docker) ; sinon les essais de connexion limités compteraient l'adresse du proxy au lieu de celle des visiteurs. Exemples :

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

## Sauvegarde

Tout est dans le volume `/data` : la base `posture_cockpit.db`, la clé de session `.secret_key` et le dossier `backups/`. La commande `backup` en fait une copie **cohérente**, application en marche : elle passe par l'API de sauvegarde de SQLite, qui tient compte du journal WAL, et ajoute la clé de session et un manifeste vérifiable.

```bash
umask 077   # la sauvegarde contient les comptes : lisible par vous seul
docker compose exec -T posture-cockpit posture-cockpit backup --output - > posture-cockpit-$(date +%F).tar.gz
```

Sans `--output`, l'archive est écrite dans le volume, `/data/backups/posture-cockpit-<date>.tar.gz`. Une sauvegarde se vérifie sans rien restaurer :

```bash
docker compose run --rm --no-deps -T posture-cockpit posture-cockpit check-backup - < posture-cockpit-2026-10-17.tar.gz
```

Ne copiez pas le volume à chaud avec `tar` : le fichier de la base peut alors être incohérent avec son journal.

## Restauration

La restauration vérifie toute l'archive (contenu, empreintes, intégrité, schéma) avant de toucher à quoi que ce soit, puis :

- elle prend le dossier de données pour elle seule, du premier contrôle au dernier fichier (verrou `/data/.posture-cockpit.lock`) : elle refuse de commencer si l'application ou une commande l'utilise, et l'application refuse de démarrer tant qu'elle n'est pas finie ;
- elle enregistre les données remplacées comme une sauvegarde ordinaire, `/data/backups/posture-cockpit-before-restore-<date>.tar.gz`, restaurable à son tour (ou les copie telles quelles si elles sont trop abîmées pour être lues) ;
- elle remplace les fichiers tout ou rien : si un remplacement échoue (disque plein…), les anciens fichiers sont remis en place et le message le dit.

Le verrou vaut entre tous les conteneurs d'un même serveur qui partagent le volume. Sur un système de fichiers réseau, il ne vaut que si le serveur de fichiers gère les verrous (NFSv4, NFS avec lockd ; pas SMB/CIFS) : n'utilisez jamais le même dossier de données depuis deux serveurs.

**Sur la même installation :**

```bash
docker compose stop
docker compose run --rm --no-deps -T posture-cockpit posture-cockpit restore --replace - < posture-cockpit-2026-10-17.tar.gz
docker compose up -d
```

**Sur une nouvelle installation** (autre serveur, ou instance de test) : installez-la comme ci-dessus sans la démarrer, puis restaurez sans `--replace` (son volume est vide) et démarrez. Une sauvegarde d'une version plus ancienne est mise à niveau au démarrage, comme toute base ancienne. Une sauvegarde faite par une version plus récente est refusée.

La clé de session étant restaurée, les sessions ouvertes restent valides ; les comptes, la double authentification et les jetons d'API sont ceux de la sauvegarde. Une sauvegarde sans clé de session (instance jamais démarrée) donne une **nouvelle** clé à l'instance remplacée — jamais l'ancienne, qui ouvrirait les comptes restaurés portant les mêmes numéros — et chacun se reconnecte ; une nouvelle installation crée la sienne au premier démarrage.

## Mise à jour

**Avant le premier démarrage en v0.5.0**, ajouter `POSTURE_COCKPIT_SCHEDULER=off` (sans `#`) à votre fichier `.env` : l'ordonnanceur est **activé par défaut**. Ne l'activer qu'après contrôle des horaires, domaines et quotas. La sauvegarde vérifiée doit être exportée hors du volume de production avant migration.

1. Faites une sauvegarde (ci-dessus) et gardez-en une copie hors du serveur.
2. Remplacez `compose.yaml` par celui de la nouvelle version, puis redémarrez :

```bash
curl -fsSLO https://raw.githubusercontent.com/vinzgithub/posture-cockpit/v0.6.0/compose.yaml   # la version voulue
docker compose up -d
docker compose exec posture-cockpit posture-cockpit info
```

Docker télécharge la nouvelle image et recrée le conteneur sur le même volume. Au démarrage, la base est mise à niveau automatiquement. Votre `.env` n'est pas touché ; s'il fixe `POSTURE_COCKPIT_IMAGE`, passez-le à la nouvelle version.

**Quand le schéma change** (0.5.0 : du schéma 4 au 5), l'application écrit d'abord une sauvegarde complète — base et clé de session — dans `/data/backups/posture-cockpit-before-schema5-<date>.tar.gz`. Elle la relit ensuite et la compare à la base : schéma, comptes, domaines, analyses, clé de session. Il lui faut une place libre de deux fois la base ; avant la mise à jour, `posture-cockpit info` indique combien. Si l'une de ces étapes échoue, rien n'est migré et l'application ne démarre pas : le message dit pourquoi (tableau plus bas), et la base reste telle qu'elle était. Les commandes de comptes (`reset-password`, …) font de même quand elles trouvent une base à migrer. Ensuite, `info` montre cette sauvegarde :

```
Backup before the last update: backups/posture-cockpit-before-schema5-20261020T081500Z.tar.gz (schema 4 to 5, 2026-10-20T08:15:00+00:00, verified)
```

Gardez-en aussi une copie hors du serveur :

```bash
umask 077
docker compose exec -T posture-cockpit cat /data/backups/posture-cockpit-before-schema5-<date>.tar.gz > avant-0.5.0.tar.gz
```

Une fois migrée au schéma 5, la base ne peut plus être ouverte par la 0.4.x : revenir en arrière passe par une restauration (ci-dessous).

La 0.4.1 garde le schéma 4 de la 0.4.0 : passer de 0.4.0 à 0.4.1, ou revenir de 0.4.1 à 0.4.0, ne modifie pas la base.

**Passage en 0.2.0** : les notes des analyses enregistrées sont recalculées avec les règles de couverture (voir [SCORING.fr.md](SCORING.fr.md)) ; l'API peut renvoyer `"score": null` pour un domaine « non évalué » (voir [HOME_ASSISTANT.fr.md](HOME_ASSISTANT.fr.md)).

## Retour arrière

**Même schéma** (0.4.0 et 0.4.1, schéma 4) : remettez le `compose.yaml` de la version précédente et redémarrez.

```bash
curl -fsSLO https://raw.githubusercontent.com/vinzgithub/posture-cockpit/v0.4.0/compose.yaml
docker compose up -d
```

**De la 0.5.0 à la 0.4.1** (schéma 5 vers 4) : l'image de la 0.4.1 refuse la base migrée (`uses schema 5; this version of Posture Cockpit handles schema 4 at most`) et ne modifie rien. Restaurez la sauvegarde faite avant la mise à jour, avec l'image de la 0.4.1 :

```bash
docker compose stop
curl -fsSLO https://raw.githubusercontent.com/vinzgithub/posture-cockpit/v0.4.1/compose.yaml   # et POSTURE_COCKPIT_IMAGE dans .env, s'il est fixé
docker compose run --rm --no-deps posture-cockpit ls /data/backups                    # le nom de posture-cockpit-before-schema5-<date>.tar.gz
docker compose run --rm --no-deps -T posture-cockpit posture-cockpit check-backup /data/backups/posture-cockpit-before-schema5-<date>.tar.gz
docker compose run --rm --no-deps -T posture-cockpit posture-cockpit restore --replace /data/backups/posture-cockpit-before-schema5-<date>.tar.gz
docker compose up -d
docker compose exec posture-cockpit posture-cockpit info                              # schema 4 (up to date)
```

La copie gardée hors du serveur se restaure de la même façon, par l'entrée standard (`restore --replace - < avant-0.5.0.tar.gz`). La restauration enregistre d'abord les données de la 0.5.0 dans `/data/backups/posture-cockpit-before-restore-<date>.tar.gz` : rien de ce qui a été fait depuis la mise à jour n'est détruit, et l'image de la 0.5.0 peut restaurer cette archive pour reprendre la mise à jour là où elle en était.

**De la 0.5.0 à la 0.4.0 ou avant** : ces versions ne refusent pas un schéma plus récent et tourneraient dessus, avec des erreurs. Ne les démarrez jamais sur la base migrée. La 0.4.0 n'a pas de commande `restore` : restaurez la sauvegarde avec l'image de la 0.5.0 (les commandes ci-dessus, avec le `compose.yaml` de la 0.5.0), puis remettez le `compose.yaml` de la 0.4.0 et démarrez.

**Ce que le retour perd : tout ce qui a été fait après la sauvegarde.** Les données reviennent telles qu'elles étaient au moment de la mise à jour :

- les analyses et revérifications faites depuis, les domaines ajoutés ou supprimés, les périmètres et réglages modifiés ;
- les comptes créés depuis disparaissent ; les comptes supprimés depuis reviennent, avec leurs droits d'alors ; un rôle donné ou retiré depuis est annulé ;
- les **mots de passe** changés ou réinitialisés depuis : l'ancien fonctionne de nouveau ;
- la **double authentification** activée depuis est de nouveau désactivée ; désactivée depuis, elle est de nouveau active, avec son ancien secret et ses codes de secours ; les codes de secours utilisés ou renouvelés depuis reviennent ;
- les **clés d'API** créées depuis disparaissent ; **révoquées depuis, elles fonctionnent de nouveau** ;
- les déconnexions forcées depuis (changement de mot de passe, de double authentification) sont annulées : les sessions qu'elles avaient fermées redeviennent valides, puisque la clé de session est celle de la sauvegarde ;
- les entrées du journal d'audit depuis.

**Réappliquez les changements de sécurité faits depuis la mise à jour.** Le journal d'audit des données enregistrées par la restauration (`posture-cockpit-before-restore-<date>.tar.gz`) les liste : restaurez cette archive dans une instance de test (section plus bas, jamais par-dessus votre installation) et lisez Administration → Journal d'audit. Puis, sur l'installation restaurée : révoquez de nouveau les clés d'API révoquées depuis, changez de nouveau les mots de passe changés depuis (surtout un mot de passe changé parce qu'il avait fuité), désactivez ou réactivez la double authentification, supprimez de nouveau les comptes supprimés depuis, vérifiez le rôle de chaque compte. Si une session fermée depuis ne doit pas revenir, créez une nouvelle clé de session — tous les navigateurs sont déconnectés :

```bash
docker compose stop
docker compose run --rm --no-deps posture-cockpit rm /data/.secret_key
docker compose up -d   # une nouvelle clé est créée au démarrage
```

## Depuis un ancien `compose.yaml`

Les installations faites avec le `compose.yaml` de la 0.4.0 ou d'avant gardent leurs données en passant au nouveau fichier :

- **Volume.** Le nouveau fichier fixe le nom du projet à `posture-cockpit` : le volume reste `posture-cockpit_posture-cockpit-data`, celui d'une installation faite dans un dossier `posture-cockpit`. Si votre dossier avait un autre nom, vérifiez avec `docker volume ls` et mettez son préfixe dans le `.env` : `COMPOSE_PROJECT_NAME=<préfixe>`.
- **Réglages.** Reportez vos lignes `environment:` dans le `.env` (même nom, `NOM=valeur`, sans guillemets) et votre port dans `POSTURE_COCKPIT_PORT`.
- **Image.** Une image construite localement se garde avec `POSTURE_COCKPIT_IMAGE=<nom:étiquette>` ; sinon l'image officielle est téléchargée.
- **Nom du conteneur.** Il reste `posture-cockpit` ; les commandes `docker compose exec posture-cockpit …` fonctionnent dans tous les cas.

## Une instance de test sur le même serveur

Un dossier à part, avec son propre `.env` : projet, conteneur, port et cookie distincts, donc un volume distinct. Un navigateur envoie les cookies d'une adresse à tous ses ports : sans nom de cookie propre, les deux instances se déconnecteraient l'une l'autre.

```bash
COMPOSE_PROJECT_NAME=posture-cockpit-test
POSTURE_COCKPIT_CONTAINER=posture-cockpit-test
POSTURE_COCKPIT_PORT=8089
POSTURE_COCKPIT_SESSION_COOKIE=posture_cockpit_test
#POSTURE_COCKPIT_IMAGE=posture-cockpit:local   # une image construite depuis le dépôt : docker build -t posture-cockpit:local .
```

Lettres, chiffres, `_` et `-` seulement pour le cookie ; les préfixes `__Host-` et `__Secure-` exigent `POSTURE_COCKPIT_COOKIE_SECURE=true`. Changer le nom du cookie d'une instance existante déconnecte ses utilisateurs une fois. Pour l'arrêter et tout effacer : `docker compose down -v`, **dans le dossier de test uniquement**.

## Quand le démarrage échoue

L'application refuse de démarrer, en disant quoi faire (`docker compose logs posture-cockpit`), plutôt que de risquer les données :

| Message | Cause et solution |
|---|---|
| `The data folder /data cannot be written … chown -R 10001:10001 <folder>` | Un dossier de l'hôte monté sur `/data` appartient à root. Utilisez le volume nommé de `compose.yaml`, ou donnez le dossier à l'utilisateur 10001. |
| `The database … uses schema N; this version … handles schema M at most` | La base vient d'une version plus récente. Relancez celle-ci, ou restaurez une sauvegarde faite avant. Rien n'a été modifié. |
| `The session key … is empty or damaged` | Restaurez `.secret_key` depuis une sauvegarde, ou supprimez-le : une nouvelle clé est créée et tous les navigateurs sont déconnectés. |
| `The database … cannot be opened` | Le fichier de la base est endommagé : restaurez une sauvegarde. |
| `Not enough free space in /data to back up the database before updating it` | La sauvegarde faite avant une migration demande deux fois la taille de la base. Libérez de la place (anciennes archives de `/data/backups/`, copiées ailleurs d'abord), puis redémarrez. Rien n'a été modifié. |
| `The backup before the update could not be written` ou `… failed its verification` | La sauvegarde faite avant une migration n'a pas pu être écrite, ou relue identique. Rien n'a été migré ; l'archive en échec a été supprimée. Vérifiez le disque (`df`, `docker system df`), puis redémarrez. |

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
docker compose exec posture-cockpit posture-cockpit reset-password <identifiant>
docker compose exec posture-cockpit posture-cockpit disable-totp <identifiant>   # téléphone et codes de secours perdus
docker compose exec posture-cockpit posture-cockpit make-admin <identifiant>
```

### Retour entre versions au schéma 5 (v0.5.0, v0.6.0 et candidate v0.6.1)

Avant tout changement d’image : sauvegarde vérifiée hors du volume, ordonnanceur désactivé, arrêt propre de l’instance. Le schéma 5 reste identique : le retour à une image officielle épinglée peut réutiliser le volume courant sans restaurer une ancienne sauvegarde. Les données créées après la mise à niveau doivent être conservées. La v0.5.0 retrouve ses anciennes projections, notamment DMARC, sans changer les notes observées. Tester ce retour sur copie isolée ; ne jamais démarrer simultanément deux instances sur le volume. Le retour au schéma 4 reste une autre procédure exigeant une restauration. Aucun tag/image v0.6.1 n’est annoncé comme publié par ce guide.
