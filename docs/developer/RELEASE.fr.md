# Recette et publication

🇬🇧 [English version](RELEASE.md)

## Ce que la CI vérifie à chaque envoi

`.github/workflows/tests.yml` :

| Tâche | Contenu |
|---|---|
| `test (3.11)`, `test (3.12)`, `test (3.13)` | Ruff, mypy, toute la suite (dont les bases faites par v0.3.0 et v0.4.0) |
| `browser` | Les pages dans Chromium, sur un ordinateur et des téléphones |
| `docker` | L'image, la recette de `scripts/docker-recette.sh install`, puis toute la suite **dans l'image** (bibliothèques et OpenSSL qu'elle embarque) |
| `upgrade (v0.3.0)`, `upgrade (v0.4.0)` | Une instance faite par l'image publiée de ces versions (reconstruite depuis leur tag), mise à jour vers l'image du dépôt, puis retour à v0.4.0 ; et une installation disposée comme la production (le `compose.yaml` de la version, dans un dossier `posture-cockpit`), passée au nouveau `compose.yaml` sur le même volume |

Les vérifications réussies de la recette sont listées dans les annotations de l'exécution.

## Recette sur un serveur Docker isolé

Sur un serveur de test (jamais celui de la production), avec Docker Compose 2.24 ou plus récent :

```bash
git clone -b <branche ou tag> https://github.com/vinzgithub/posture-cockpit.git posture-cockpit-recette
cd posture-cockpit-recette
docker build -t posture-cockpit:recette .
scripts/docker-recette.sh install posture-cockpit:recette
```

Le script démarre ses propres instances (projets `pc-recette-*`, ports 18080 à 18083 sur 127.0.0.1, volumes à part) et les supprime à la fin ; il ne touche à aucune installation existante. Pour une mise à jour depuis une version publiée :

```bash
git worktree add ../v0.4.0 v0.4.0 && docker build -t posture-cockpit:v0.4.0 ../v0.4.0
scripts/docker-recette.sh upgrade posture-cockpit:v0.4.0 posture-cockpit:recette
```

Pour une recette manuelle dans le navigateur, un dossier à part avec le `compose.yaml` du dépôt et ce `.env` (voir [INSTALLATION.fr.md](../user/INSTALLATION.fr.md#une-instance-de-test-sur-le-même-serveur)) :

```bash
COMPOSE_PROJECT_NAME=posture-cockpit-recette
POSTURE_COCKPIT_CONTAINER=posture-cockpit-recette
POSTURE_COCKPIT_PORT=8089
POSTURE_COCKPIT_SESSION_COOKIE=posture_cockpit_recette
POSTURE_COCKPIT_IMAGE=posture-cockpit:recette
```

À la fin : `docker compose down -v` **dans ce dossier uniquement**.

## Publier une version

1. Sur une branche : la version dans `pyproject.toml`, `src/posture_cockpit/__init__.py` et l'image de `compose.yaml` (`0.4.2`), le titre du `CHANGELOG.md` (`## 0.4.2 — <date>`), et les liens d'installation des README et de `INSTALLATION` (`v0.4.2`). Si les dépendances changent, régénérer `docker/requirements.lock` (commande en tête du fichier). `tests/test_v041_distribution.py` vérifie que tout concorde.
2. PR vers `main` : la CI ci-dessus, plus l'exécution à blanc de `release.yml` (les deux architectures construites, rien de publié).
3. Après la fusion : créer le tag `v0.4.2` et **publier la release GitHub**. C'est cet acte qui déclenche `release.yml` : toute la suite, la recette Docker, la construction amd64 et arm64, puis la publication sur `ghcr.io/vinzgithub/posture-cockpit` avec SBOM et provenance. Le digest est noté dans le résumé de l'exécution.

Étiquettes publiées (`scripts/release_tags.py`) :

| Release | Étiquettes |
|---|---|
| `v0.4.2` (version finale, la plus récente) | `0.4.2`, `0.4`, `latest` |
| `v0.3.3` (correctif d'une branche plus ancienne) | `0.3.3`, `0.3` — jamais `latest` |
| `v0.4.2-rc.1`, case « pre-release » cochée | `0.4.2-rc.1` seulement — ni `0.4` ni `latest` |

La publication se fait en trois temps, chacun vérifié (`scripts/registry_tag.py`) :

1. **État de la version dans le registre.** Absente : on publie. Publiée depuis le même commit : une publication interrompue reprend sans reconstruire. Publiée depuis un autre commit, ou depuis un commit inconnu : **refus**, une version publiée n'est jamais écrasée. Un registre illisible (authentification refusée, erreur, délai) arrête tout : rien n'est deviné.
2. **Envoi des deux architectures sous la version exacte seulement.**
3. **Étiquettes mobiles** (`X.Y`, `latest`) pointées sur ce même digest, puis **relecture de chaque étiquette** et comparaison des digests.

Un échec entre 2 et 3 laisse la version exacte publiée et les étiquettes mobiles où elles étaient : relancer le job (« Re-run failed jobs ») reprend à l'étape 3. Sur une PR, tout cela est rejoué sur un registre lancé dans le job (`localhost:5000`), y compris les refus. Le tag doit correspondre au dépôt (pour une préversion, `pyproject.toml` dit `0.4.2rc1` et `compose.yaml` garde la version finale `0.4.2` ; on teste la préversion avec `POSTURE_COCKPIT_IMAGE=ghcr.io/vinzgithub/posture-cockpit:0.4.2-rc.1`).

**Une seule fois** : après la première publication, rendre le paquet public (GitHub → Packages → posture-cockpit → Package settings → Change visibility → Public), pour que l'installation n'ait besoin d'aucun compte. Ce choix est **irréversible** : un paquet public ne peut pas redevenir privé.
