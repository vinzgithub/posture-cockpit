# Recette and release

🇫🇷 [Version française](RELEASE.fr.md)

## What the CI checks at each push

`.github/workflows/tests.yml`:

| Job | Content |
|---|---|
| `test (3.11)`, `test (3.12)`, `test (3.13)` | Ruff, mypy, the whole suite (including databases made by v0.3.0 and v0.4.0) |
| `browser` | The pages in Chromium, on a desktop and on phones |
| `docker` | The image, the recette of `scripts/docker-recette.sh install`, then the whole suite **inside the image** (the libraries and OpenSSL it ships) |
| `upgrade (v0.3.0)`, `upgrade (v0.4.0)` | An instance made by the released image of these versions (rebuilt from their tag), updated to the image of the repository, then back to v0.4.0; and an installation laid out like the production (the `compose.yaml` of that version, in a `posture-cockpit` folder), moved to the new `compose.yaml` on the same volume |

The checks the recette passed are listed in the annotations of the run.

## Recette on an isolated Docker server

On a test server (never the production one), with Docker Compose 2.24 or later:

```bash
git clone -b <branch or tag> https://github.com/vinzgithub/posture-cockpit.git posture-cockpit-recette
cd posture-cockpit-recette
docker build -t posture-cockpit:recette .
scripts/docker-recette.sh install posture-cockpit:recette
```

The script starts its own instances (projects `pc-recette-*`, ports 18080 to 18083 on 127.0.0.1, separate volumes) and removes them at the end; it touches no existing installation. For an update from a released version:

```bash
git worktree add ../v0.4.0 v0.4.0 && docker build -t posture-cockpit:v0.4.0 ../v0.4.0
scripts/docker-recette.sh upgrade posture-cockpit:v0.4.0 posture-cockpit:recette
```

For a manual recette in the browser, a separate folder with the `compose.yaml` of the repository and this `.env` (see [INSTALLATION.md](../user/INSTALLATION.md#a-test-instance-on-the-same-server)):

```bash
COMPOSE_PROJECT_NAME=posture-cockpit-recette
POSTURE_COCKPIT_CONTAINER=posture-cockpit-recette
POSTURE_COCKPIT_PORT=8089
POSTURE_COCKPIT_SESSION_COOKIE=posture_cockpit_recette
POSTURE_COCKPIT_IMAGE=posture-cockpit:recette
```

At the end: `docker compose down -v` **in that folder only**.

## Releasing a version

1. On a branch: the version in `pyproject.toml`, `src/posture_cockpit/__init__.py` and the image of `compose.yaml` (`0.4.2`), the heading of `CHANGELOG.md` (`## 0.4.2 — <date>`), and the installation links of the READMEs and `INSTALLATION` (`v0.4.2`). When dependencies change, regenerate `docker/requirements.lock` (command at the top of the file). `tests/test_v041_distribution.py` checks that everything agrees.
2. Pull request to `main`: the CI above, plus the dry run of `release.yml` (both architectures built, nothing published).
3. After the merge: create the tag `v0.4.2` and **publish the GitHub release**. That act triggers `release.yml`: the whole suite, the Docker recette, the amd64 and arm64 builds, then publication on `ghcr.io/vinzgithub/posture-cockpit` with SBOM and provenance. The digest is written in the summary of the run.

Tags published (`scripts/release_tags.py`):

| Release | Tags |
|---|---|
| `v0.4.2` (final version, the latest) | `0.4.2`, `0.4`, `latest` |
| `v0.3.3` (a fix of an older line) | `0.3.3`, `0.3` — never `latest` |
| `v0.4.2-rc.1`, "pre-release" box ticked | `0.4.2-rc.1` only — neither `0.4` nor `latest` |

Publication happens in three steps, each checked (`scripts/registry_tag.py`):

1. **State of the version in the registry.** Absent: publish. Published from the same commit: an interrupted publication resumes without rebuilding. Published from another commit, or from an unknown one: **refused**, a published version is never overwritten. A registry that cannot be read (authentication refused, error, timeout) stops everything: nothing is guessed.
2. **Both architectures pushed under the exact version only.**
3. **Moving tags** (`X.Y`, `latest`) pointed at that digest, then **every tag read back** and the digests compared.

A failure between 2 and 3 leaves the exact version published and the moving tags where they were: re-running the job ("Re-run failed jobs") resumes at step 3. On a pull request, all of it is rehearsed against a registry started in the job (`localhost:5000`), refusals included. The tag must match the repository (for a pre-release, `pyproject.toml` says `0.4.2rc1` and `compose.yaml` keeps the final version `0.4.2`; the pre-release is tested with `POSTURE_COCKPIT_IMAGE=ghcr.io/vinzgithub/posture-cockpit:0.4.2-rc.1`).

**Once**: after the first publication, make the package public (GitHub → Packages → posture-cockpit → Package settings → Change visibility → Public), so that installing needs no account. This choice is **irreversible**: a public package cannot become private again.
