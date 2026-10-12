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
                 │
                 ├─► storage/  (SQLite : comptes, domaines, analyses)
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
| `core/network.py` | Les quatre questions qu'un contrôle peut poser (`dns`, `certificate`, `accepts_tls`, `http_get`) et leur réalisation réelle `LiveNetwork` |
| `core/fixture.py` | `FixtureNetwork` : les mêmes questions, répondues par des données enregistrées (tests, démo) |
| `core/engine.py` | Lance les contrôles en parallèle avec un délai chacun ; normalise les noms de domaine ; vérification préalable |
| `core/scoring.py` | Note, lettre, note par domaine, plan de corrections |
| `core/providers.py` | Hébergeurs DNS connus et leur détection |
| `checks/` | Les extensions intégrées (`mail`, `tls`, `web`, `dns`) et leurs textes dans `checks/locales/` |
| `scanner.py` | Choisit le réseau (réel ou démo), retire les extensions désactivées, relance un contrôle seul |
| `storage/` | Une connexion SQLite (`database.py`), le schéma (`schema.py`), un dépôt par sujet (`accounts.py`, `scans.py`, `settings.py`) |
| `web/app.py` | Fabrique l'application : services, en-têtes de sécurité, session, routes, pages d'erreur |
| `web/deps.py` | Ce que les routes partagent : utilisateur connecté, droits, formulaire vérifié (CSRF), rendu |
| `web/credentials.py` | Vérifications de mots de passe et de codes, communes à plusieurs pages |
| `web/views.py` | Transforme une analyse en ce qu'affiche la page du plan (textes, gains, étapes) |
| `web/routes/` | Un module par zone : `auth`, `account`, `admin`, `domains`, `report`, `api` |
| `web/templates/`, `web/static/` | Gabarits Jinja, une feuille de style, un petit script, les polices |
| `report/` | Le rapport PDF : contexte, gabarit, style et polices |
| `locales/` | Les textes de l'interface et du rapport (`fr.json`, `en.json`) |
| `demo/` | Les réponses enregistrées du domaine de démonstration |
| `cli.py` | `posture-cockpit scan`, `extensions`, outils de secours des comptes |

## 3. Le parcours d'une analyse

1. **`POST /domains`** (`web/routes/domains.py`) reçoit ce que l'utilisateur a tapé.
2. `engine.normalize_domain` en fait un nom propre (`https://www.Exemple.fr/contact` → `exemple.fr`).
3. `scanner.preflight` vérifie que le DNS répond quelque chose pour ce nom. Sinon : « n'existe pas » ou « le DNS ne renvoie rien », et rien n'est enregistré.
4. `scanner.scan` prend les contrôles des extensions actives et un **réseau neuf** (son cache ne sert qu'à cette analyse).
5. `engine.scan` lance **tous les contrôles en même temps**. Chacun reçoit un `CheckContext` (domaine, réseau, heure) et renvoie un `Outcome`. Un contrôle qui dépasse son délai, lève une erreur réseau ou plante devient un `Outcome` d'état `ERROR` : les autres continuent.
6. `Scans.save` enregistre l'analyse et ses `Finding` (la note est calculée à ce moment).
7. La page du plan (`GET /domains/<nom>`) appelle `views.plan_view`, qui produit des objets déjà rédigés pour le gabarit `plan.html`.
8. **« Vérifier »** (`POST /domains/<nom>/verify/<contrôle>`) relance ce seul contrôle. Le résultat est enregistré comme une *revérification* de la même analyse : l'analyse d'origine ne change pas (l'ordre du plan reste stable), la note courante tient compte de la revérification.

## 4. Le modèle de données

- **`Outcome`** : ce que renvoie un contrôle. Un état (`ok`, `warn`, `fail`, `info`, `error`), une **clé de texte** (jamais une phrase), des paramètres pour ce texte, les valeurs brutes relevées (`evidence`) et, si quelque chose doit changer, un **`Remedy`**.
- **`Remedy`** : le temps estimé, l'effort (`easy`, `medium`, `delegate`) et la forme de la correction : des **`DnsChange`** (ajouter ou supprimer un enregistrement), un **message** à envoyer, ou une explication (`how`).
- **`Finding`** : un `Outcome` avec l'identité du contrôle (`mail.dmarc`), sa catégorie et son poids. C'est ce que la base enregistre (en JSON) et ce que les pages affichent.

**La note** (`core/scoring.py`) : part du poids gagnée. `ok` gagne tout le poids, `warn` la moitié, `fail` rien ; `info` et `error` sont exclus du calcul. **Le plan** : les `fail` d'abord (priorités), puis les `warn` (améliorations), chacun classé par effet sur la note puis par rapidité. Les gains affichés sont cumulés, pour que leur somme tombe juste.

## 5. La base de données

Un seul fichier SQLite dans le dossier de données, en mode WAL. Tables : `users`, `totp`, `recovery_codes`, `api_tokens`, `domains`, `scans`, `findings`, `rechecks`, `meta`.

**Migrations** : `storage/schema.py` contient une liste de scripts. La base retient combien elle en a appliqué (`meta.schema_version`) et applique les suivants au démarrage, chacun dans une transaction. Pour changer le schéma, **ajoutez un script à la fin de la liste** ; ne modifiez jamais un script déjà publié.

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
- **Connexion** : mot de passe, puis code TOTP si activé (deux étapes, 5 minutes maximum). Les échecs de mot de passe et de code partagent le même compteur (`LoginThrottle`).
- **En-têtes** : politique de sécurité du contenu stricte (`script-src 'self'`, `style-src 'self'`, aucune ressource extérieure), `nosniff`, `no-store`. Conséquence : **pas de `style="…"` ni de script dans les gabarits** (un test le vérifie) ; les barres de score sont dessinées en SVG.

## 8. Tâches courantes

**Ajouter un contrôle intégré**
1. Dans `checks/<extension>.py`, une fonction `async def` décorée par `@extension.check("nom", category=…, weight=…)` qui renvoie `ok(…)`, `warn(…)`, `fail(…)` ou `info(…)`.
2. Ses textes dans `checks/locales/<extension>.fr.json` et `.en.json` (voir le tableau ci-dessus).
3. Des tests dans `tests/test_checks.py`, à partir de `worlds.healthy()` modifié par `changed(...)`.

**Ajouter un hébergeur DNS** : un `DnsHost` dans `core/providers.py` (suffixes de ses serveurs de noms) et ses six textes `dnshost.<id>.*` dans les deux fichiers de `locales/`. Le test `test_every_dns_host_has_its_texts` rappelle ceux qui manquent.

**Ajouter une page** : une route dans le module de `web/routes/` qui convient, un gabarit qui étend `base.html`, ses textes dans `locales/`. Les données préparées vont dans `views.py` si elles demandent un calcul.

**Ajouter une langue** : l'ajouter à `LOCALES` dans `i18n.py`, créer `locales/<langue>.json` et les fichiers des extensions, compléter `MONTHS`.

## 9. Les tests

`pytest` lance plus de 130 tests, **sans aucun accès réseau** :

- `tests/worlds.py` décrit un domaine sain (`healthy()`) ; chaque test en modifie une partie avec `changed(...)` et lance un contrôle avec `one(...)` ;
- `tests/conftest.py` fournit une application dont le réseau est un dictionnaire (`world`) que le test peut modifier entre une analyse et une revérification ;
- `tests/test_network.py` teste le vrai code réseau contre des serveurs TLS et HTTP démarrés sur la machine pour l'occasion.

## 10. Conventions

- Chaque fichier source commence par l'avis de copyright et l'identifiant de licence (un test le vérifie).
- Code, noms et commentaires en anglais ; textes visibles en français et en anglais.
- Un module commence par une docstring qui dit son rôle ; les commentaires expliquent **pourquoi**, pas ce que fait la ligne.
- `ruff check src tests examples`, `mypy` et `pytest` doivent passer avant chaque fusion (la CI les lance).
