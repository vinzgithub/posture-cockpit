# Architecture de Posture Cockpit

🇬🇧 [English version](ARCHITECTURE.md)

Ce document est la carte du code : où se trouve quoi, comment une analyse circule, et comment faire les modifications courantes sans rien casser.

## 1. Vue d'ensemble

```
 navigateur ─► web/ (FastAPI, pages)
                 │
                 ├─► scanner.py ─► core/engine.py ─► checks/*.py (extensions)
                 │                                     │
                 │                                     ▼
                 │                               core/network.py  (DNS, TLS, HTTP — passif)
                 │                                     │  chaque connexion passe par
                 │                                     ▼
                 │                               core/egress.py   (où une analyse peut se connecter)
                 │
                 ├─► storage/  (SQLite : comptes, domaines, périmètres, analyses, journal d'audit)
                 └─► report/   (PDF)
```

**Règle d'or : les dépendances vont dans un seul sens.** `web` utilise `scanner`, `storage` et `report` ; tous utilisent `core` ; `core` n'importe jamais `web` ni `storage`. On peut donc lire, tester ou réutiliser le moteur sans serveur web (c'est ce que fait la ligne de commande).

## 2. Les dossiers

| Chemin | Rôle |
|---|---|
| `src/posture_cockpit/core/` | Le moteur, indépendant du web |
| `core/model.py` | `Status`, `Outcome`, `Finding`, `Remedy`, `DnsChange` : les données qui circulent partout |
| `core/extension.py` | L'API des extensions : `Extension`, le décorateur `@extension.check`, `CheckContext` |
| `core/registry.py` | Trouve les extensions (intégrées + points d'entrée) ; une extension cassée est signalée, jamais fatale |
| `core/network.py` | Les quatre questions qu'un contrôle peut poser (`dns`, `certificate`, `accepts_tls`, `http_get`) et leur réalisation réelle `LiveNetwork` (cache, limites et délais par analyse) |
| `core/egress.py` | **La règle unique des connexions sortantes** : zones d'adresses (publique, interne, interdite), `EgressPolicy`, `DestinationBlocked` |
| `core/errors.py` | `NetworkError` et `Refused` (rien n'écoute : une réponse nette, contrairement à un délai dépassé) |
| `core/fixture.py` | `FixtureNetwork` : les mêmes questions, répondues par des données enregistrées (tests, démo) |
| `core/engine.py` | Lance les contrôles en parallèle avec un délai chacun ; normalise les noms de domaine ; vérification préalable |
| `core/scoring.py` | Couverture, note, lettre (ou « non évalué »), évaluation par domaine, plan de corrections |
| `core/providers.py` | Hébergeurs DNS connus et leur détection |
| `checks/` | Les extensions intégrées (`mail`, `tls`, `web`, `dns`) et leurs textes dans `checks/locales/` |
| `checks/records.py` | Lecture des enregistrements SPF, DMARC, DKIM, MTA-STS et TLS-RPT selon leurs RFC (fonctions pures) |
| `scanner.py` | Choisit le réseau (réel ou démo) avec la règle du périmètre, retire les extensions désactivées, relance un contrôle seul |
| `storage/` | Une connexion SQLite (`database.py`), le schéma (`schema.py`), un dépôt par sujet (`accounts.py`, `scans.py`, `perimeters.py`, `audit.py`, `settings.py`) |
| `web/app.py` | Fabrique l'application : services, en-têtes de sécurité, session, routes, pages d'erreur |
| `web/deps.py` | Ce que les routes partagent : utilisateur connecté, droits, formulaire vérifié (CSRF), rendu |
| `web/credentials.py` | Vérifications de mots de passe et de codes, communes à plusieurs pages, et les compteurs d'échecs |
| `web/scanning.py`, `web/limits.py` | Lancer une analyse (limites, journal d'audit, périmètre) et les limites elles-mêmes |
| `web/views.py` | Transforme une analyse en ce qu'affiche la page du plan (textes, gains, étapes) |
| `web/routes/` | Un module par zone : `auth`, `account`, `admin`, `perimeters`, `domains`, `report`, `api` |
| `web/templates/`, `web/static/` | Gabarits Jinja, une feuille de style, un petit script, les polices |
| `report/` | Le rapport PDF : contexte, gabarit, style et polices |
| `locales/` | Les textes de l'interface et du rapport (`fr.json`, `en.json`) |
| `demo/` | Les réponses enregistrées du domaine de démonstration |
| `cli.py` | `posture-cockpit scan`, `extensions`, outils de secours des comptes |

## 3. Le parcours d'une analyse

1. **`POST /domains`** (`web/routes/domains.py`) reçoit ce que l'utilisateur a tapé. (Un domaine de périmètre interne s'ajoute depuis la page du périmètre, dans l'administration : `web/routes/perimeters.py`.)
2. `engine.normalize_domain` en fait un nom propre (`https://www.Exemple.fr/contact` → `exemple.fr`).
3. `scanner.preflight` vérifie que le DNS répond quelque chose pour ce nom. Sinon : « n'existe pas » ou « le DNS ne renvoie rien », et rien n'est enregistré.
4. `scanning.scan_and_save` prend une place auprès du **limiteur d'analyses** (analyses simultanées, analyses par compte et par heure).
5. `scanner.scan` prend les contrôles des extensions actives et un **réseau neuf** (son cache ne sert qu'à cette analyse) construit avec la **règle du périmètre** : Internet (adresses publiques, ports 80 et 443), ou un périmètre interne (ses réseaux, serveurs DNS, ports et AC).
6. `engine.scan` lance **tous les contrôles en même temps**. Chacun reçoit un `CheckContext` (domaine, réseau, heure, interne ou non) et renvoie un `Outcome`. Les contrôles faits pour Internet seulement sont « non applicables » dans une analyse interne. Un contrôle qui dépasse son délai, lève une erreur réseau, se heurte à la règle de sortie ou plante devient un `Outcome` d'état `ERROR` (« non évalué », avec la raison) : les autres continuent. Le travail encore en cours est annulé à la fin.
7. `Scans.save` enregistre l'analyse, ses `Finding` et son évaluation (note, lettre, couverture, périmètre) ; l'analyse est inscrite au journal d'audit.
8. La page du plan (`GET /domains/<nom>`) appelle `views.plan_view`, qui produit des objets déjà rédigés pour le gabarit `plan.html`.
9. **« Vérifier »** (`POST /domains/<nom>/verify/<contrôle>`) relance ce seul contrôle. Le résultat est enregistré comme une *revérification* de la même analyse : l'analyse d'origine ne change pas (l'ordre du plan reste stable), la note courante tient compte de la revérification.

## 4. Le modèle de données

- **`Outcome`** : ce que renvoie un contrôle. Un état (`ok`, `warn`, `fail`, `na`, `info`, `error`), une **clé de texte** (jamais une phrase), des paramètres pour ce texte, les valeurs brutes relevées (`evidence`) et, si quelque chose doit changer, un **`Remedy`**.
- **`Remedy`** : le temps estimé, l'effort (`easy`, `medium`, `delegate`) et la forme de la correction : des **`DnsChange`** (ajouter ou supprimer un enregistrement), un **message** à envoyer, ou une explication (`how`).
- **`Finding`** : un `Outcome` avec l'identité du contrôle (`mail.dmarc`), sa catégorie et son poids. C'est ce que la base enregistre (en JSON) et ce que les pages affichent.

**Les états** : `ok`, `warn` et `fail` sont *évalués* ; `error` (« non évalué » : délai dépassé, serveur injoignable, destination refusée, bogue) est *applicable mais non évalué* ; `na` (ne s'applique pas : pas de site web, pas de courrier entrant, audit interne) et `info` sont écartés.

**L'évaluation** (`core/scoring.py`, règles écrites en tête du module et expliquées aux utilisateurs dans [`docs/user/SCORING.fr.md`](../user/SCORING.fr.md)) : la **couverture** est le poids évalué divisé par le poids applicable ; la **note** est la part gagnée du poids évalué (`ok` tout le poids, `warn` la moitié, `fail` rien). Sous 50 % de couverture, pas de note (« non évalué ») ; sous 90 %, la lettre ne peut pas dépasser B. `Scan.assessment()` est la seule fonction qu'utilisent les pages, l'API, le PDF et l'historique. **Le plan** : les `fail` d'abord (priorités), puis les `warn` (améliorations), chacun classé par effet sur la note puis par rapidité. Les gains affichés sont cumulés, pour que leur somme tombe juste.

## 5. La base de données

Un seul fichier SQLite dans le dossier de données, en mode WAL, lisible par son seul propriétaire. Tables : `users`, `totp`, `recovery_codes`, `api_tokens`, `perimeters`, `domains` (avec `perimeter_id`), `scans` (note, lettre, couverture, périmètre), `findings`, `rechecks`, `audit_log`, `meta`.

**Migrations** : `storage/schema.py` contient une liste de scripts SQL ou de fonctions Python. La base retient combien elle en a appliqué (`meta.schema_version`) et applique les suivantes au démarrage, chacune dans une transaction, clés étrangères désactivées puis vérifiées (`PRAGMA foreign_key_check`) avant validation, comme SQLite le prescrit pour reconstruire une table. Avant de migrer une base qui contient des données, une copie est écrite dans `backups/`. Pour changer le schéma, **ajoutez une migration à la fin de la liste** ; ne modifiez jamais une migration déjà publiée. Une base dont le schéma dépasse la liste (écrite par une version plus récente) est refusée au démarrage, sans être modifiée (`UnsupportedSchema`). `storage/backup.py` fait et restaure des sauvegardes cohérentes (`posture-cockpit backup`, `restore`).

| Version | Migration |
|---|---|
| 1 (0.1.0) | Schéma initial |
| 2 (0.2.0) | `perimeters`, `domains.perimeter_id`, `audit_log` |
| 3 (0.2.0) | `scans` reconstruite (note et lettre facultatives, `coverage`, `perimeter`), notes des analyses enregistrées recalculées |

## 6. Textes et langues

Aucune phrase n'est écrite dans le code Python : seulement des clés.

- Interface et rapport : `locales/fr.json` et `locales/en.json`.
- Contrôles : `checks/locales/<extension>.<langue>.json` (chaque extension apporte ses textes).

Pour un contrôle `mail.dmarc`, les clés attendues sont :

| Clé | Rôle |
|---|---|
| `mail.dmarc.title` | Nom court du contrôle |
| `mail.dmarc.why` | Pourquoi c'est important, en une ou deux phrases |
| `mail.dmarc.action` | Ce qu'il faut faire, à l'infinitif (titre de la tâche) |
| `mail.dmarc.ref` | Références (ANSSI, RFC), affichées dans l'annexe du rapport |
| `<clé du constat>` | Une par résultat possible (`mail.dmarc.missing`, `mail.dmarc.enforced`…) |
| `<clé du constat>.action` | Facultatif : une action plus précise pour ce constat |
| clés `how` et `message` | L'explication de la correction, le message prêt à envoyer |

Paramètres : `{nom}`. Un paramètre dont le nom finit par `_on` est une date ISO, écrite dans la langue du lecteur. Un nombre peut s'accorder avec son nom : `{days:jour|jours}`. Le test `tests/test_texts.py` vérifie que chaque clé existe dans les deux langues.

## 7. Sécurité de l'interface

- **Session** : cookie signé (`SessionMiddleware`). Il contient l'identifiant de l'utilisateur et une « époque » : changer de mot de passe ou de double authentification change l'époque et déconnecte les autres navigateurs (`deps.current_user`).
- **Droits** : des dépendances FastAPI (`require_user`, `require_admin`…) lèvent une exception que `app.py` transforme en redirection (`/setup`, `/login`, `/account/password`, `/admin/confirm`).
- **CSRF** : tout formulaire passe par la dépendance `checked_form`, qui refuse un jeton absent ou faux.
- **Connexion** : mot de passe, puis code TOTP si activé (deux étapes, 5 minutes maximum). Les échecs de mot de passe et de code partagent les mêmes compteurs (`LoginThrottle`) : par adresse (5 échecs, 5 minutes) et par nom de compte (10 échecs, 15 minutes). Un nom inconnu coûte la même vérification scrypt qu'un nom connu.
- **Périmètres internes** : leurs domaines ne sont visibles que des administrateurs (`deps.visible_domain` : 404 pour les autres, pages et API comprises).
- **Analyses** : limitées en simultané et par compte et par heure (`web/limits.py`) ; chaque analyse et chaque changement sensible est inscrit au journal d'audit (`storage/audit.py`), jamais avec un secret.
- **Réseau** : voir `core/egress.py` et [SECURITY.md](../../SECURITY.md).
- **En-têtes** : politique de sécurité du contenu stricte (`script-src 'self'`, `style-src 'self'`, aucune ressource extérieure), `nosniff`, `no-store`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, et HSTS quand l'application est servie en HTTPS. Conséquence : **pas de `style="…"` ni de script dans les gabarits** (un test le vérifie) ; les barres de score sont dessinées en SVG.

## 8. Tâches courantes

**Ajouter un contrôle intégré**
1. Dans `checks/<extension>.py`, une fonction `async def` décorée par `@extension.check("nom", category=…, weight=…)` (ajoutez `internal=False` s'il n'a de sens que sur Internet) qui renvoie `ok(…)`, `warn(…)`, `fail(…)`, `na(…)`, `info(…)` ou `not_evaluated(…)`.
2. Ses textes dans `checks/locales/<extension>.fr.json` et `.en.json` (voir le tableau ci-dessus).
3. Des tests dans `tests/test_checks.py` ou `tests/test_check_accuracy.py`, à partir de `worlds.healthy()` modifié par `changed(...)`. Un verdict qui suit une RFC mérite un test qui cite la section.

**Ajouter un hébergeur DNS** : un `DnsHost` dans `core/providers.py` (suffixes de ses serveurs de noms) et ses six textes `dnshost.<id>.*` dans les deux fichiers de `locales/`. Le test `test_every_dns_host_has_its_texts` rappelle ceux qui manquent.

**Ajouter une page** : une route dans le module de `web/routes/` qui convient, un gabarit qui étend `base.html`, ses textes dans `locales/`. Les données préparées vont dans `views.py` si elles demandent un calcul.

**Ajouter une langue** : l'ajouter à `LOCALES` dans `i18n.py`, créer `locales/<langue>.json` et les fichiers des extensions, compléter `MONTHS`.

## 9. Les tests

`pytest` lance plus de 400 tests, **sans joindre aucune autre machine** :

- `tests/worlds.py` décrit un domaine sain (`healthy()`) ; chaque test en modifie une partie avec `changed(...)` et lance un contrôle avec `one(...)` ;
- `tests/conftest.py` fournit une application dont le réseau est un dictionnaire (`world`) que le test peut modifier entre une analyse et une revérification ;
- `tests/local_servers.py` démarre un serveur DNS, des serveurs web et TLS et une autorité de certification de test sur l'adresse de boucle locale : `tests/test_network.py` et `tests/test_egress.py` y confrontent le vrai code réseau (SSRF, IPv4/IPv6, redirections, DNS rebinding, DNS et AC internes, limites) ;
- `tests/test_check_accuracy.py` contient un test de non-régression par verdict erroné trouvé lors de l'audit de la 0.2.0 ;
- `tests/test_perimeters.py` et `tests/test_app_security.py` couvrent les droits, le journal d'audit, les protections de la connexion et les limites d'analyse.

Un test demande une adresse de boucle locale IPv6 : il est sauté sur les machines qui n'en ont pas.

Depuis la 0.4.1, `tests/test_v041_migrations.py` ouvre des bases faites par le vrai code des v0.3.0
et v0.4.0 (exports SQL de `tests/data/`, écrits par `tests/data/make_legacy_databases.py`), et la CI
(`.github/workflows/tests.yml`) passe aussi `scripts/docker-recette.sh` sur l'image construite
(installation neuve, protections Docker, code d'initialisation, sauvegarde et restauration, refus,
mises à jour depuis les images v0.3.0 et v0.4.0 et retour arrière) et toute la suite dans l'image.
Publication : [RELEASE.fr.md](RELEASE.fr.md).

## 10. Conventions

- Chaque fichier source commence par l'avis de copyright et l'identifiant de licence (un test le vérifie).
- Code, noms et commentaires en anglais ; textes visibles en français et en anglais.
- Un module commence par une docstring qui dit son rôle ; les commentaires expliquent **pourquoi**, pas ce que fait la ligne.
- `ruff check src tests examples`, `mypy` et `pytest` doivent passer avant chaque fusion (la CI les lance).
