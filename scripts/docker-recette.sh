#!/usr/bin/env bash
# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Recette of a Posture Cockpit image with the compose.yaml of this repository, on a real Docker.
# Used by the CI (tests.yml, release.yml); also runs on any test server with Docker Compose 2.24+.
# Every instance it starts has its own project, port, container, cookie and volume, and is
# removed at the end: it never touches an existing installation.
#
#   scripts/docker-recette.sh install IMAGE [VERSION]   new installation, security, setup code,
#                                                       backup, restore, refusals
#   scripts/docker-recette.sh upgrade OLD_IMAGE IMAGE   data made by OLD_IMAGE, then IMAGE: the
#                                                       verified backup made before a migration, then
#                                                       OLD_IMAGE again on the same schema, or its
#                                                       refusal of the newer one
#   scripts/docker-recette.sh rollback OLD_IMAGE IMAGE [--data ARCHIVE]
#                                                       update to IMAGE then return to OLD_IMAGE through
#                                                       the backup made before the migration, checked
#                                                       with fingerprints (scripts/data-fingerprint.py):
#                                                       data, accounts, rights, session key, sign-in with
#                                                       two-factor authentication, API key, and the exact
#                                                       list of what the return loses. Synthetic data, or
#                                                       a backup ARCHIVE of an instance (a copy of real
#                                                       data: only fingerprints and counts are printed)
#   scripts/docker-recette.sh layout OLD_TAG OLD_IMAGE IMAGE
#                                                       an installation made like the production: the
#                                                       compose.yaml of OLD_TAG in a folder named
#                                                       posture-cockpit, then the new compose.yaml there.
#                                                       Uses the default names: refuses to run where
#                                                       a container or volume of that name exists.
#   scripts/docker-recette.sh quick IMAGE [VERSION]     start, health, PDF libraries (another architecture)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
PASSWORD="correct horse 42"
PROJECTS=()
PASSED=()
STEP=""

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; STEP=$*; }
ok() { printf '   ok: %s\n' "$*"; PASSED+=("$*"); }
fail() { printf '::error::%s: %s\n' "${STEP:-recette}" "$*" >&2; exit 1; }

cleanup() {
  local status=$?
  for project in "${PROJECTS[@]}"; do
    if [ "$status" -ne 0 ]; then
      echo "---- logs of $project"; compose "$project" logs --no-color --tail 80 2>/dev/null || true
    fi
    compose "$project" down -v --remove-orphans >/dev/null 2>&1 || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

# An instance: a folder with the compose.yaml of the repository and its own .env.
instance() {  # instance NAME PORT IMAGE
  local dir="$WORK/$1"
  mkdir -p "$dir"
  cp "$ROOT/compose.yaml" "$dir/compose.yaml"
  cat > "$dir/.env" <<EOF
COMPOSE_PROJECT_NAME=$1
POSTURE_COCKPIT_CONTAINER=$1
POSTURE_COCKPIT_PORT=$2
POSTURE_COCKPIT_BIND=127.0.0.1
POSTURE_COCKPIT_IMAGE=$3
POSTURE_COCKPIT_SESSION_COOKIE=${1//-/_}
POSTURE_COCKPIT_SCHEDULER=off
TZ=Europe/Paris
EOF
  PROJECTS+=("$1")
}

compose() { local name=$1; shift; docker compose --project-directory "$WORK/$name" "$@"; }
set_image() { sed -i "s|^POSTURE_COCKPIT_IMAGE=.*|POSTURE_COCKPIT_IMAGE=$2|" "$WORK/$1/.env"; }
port_of() { sed -n 's/^POSTURE_COCKPIT_PORT=//p' "$WORK/$1/.env"; }
url() { echo "http://127.0.0.1:$(port_of "$1")$2"; }

wait_ready() {  # wait_ready NAME [SECONDS]
  local deadline=$((SECONDS + ${2:-120}))
  until curl -fsS -o /dev/null "$(url "$1" /healthz)" 2>/dev/null; do
    [ $SECONDS -lt $deadline ] || fail "$1 did not answer /healthz"
    sleep 2
  done
  ok "$1 answers /healthz"
}

start() { compose "$1" up -d --quiet-pull >/dev/null 2>&1 || { compose "$1" up -d; fail "cannot start $1"; }; wait_ready "$1" "${2:-120}"; }

csrf() {  # csrf NAME PATH  -> token of the page, with the cookies of $WORK/NAME/cookies
  curl -fsS -c "$WORK/$1/cookies" -b "$WORK/$1/cookies" "$(url "$1" "$2")" \
    | sed -n 's/.*<meta name="csrf" content="\([^"]*\)".*/\1/p' | head -1
}

post() {  # post NAME PATH FIELD=VALUE...  -> HTTP status
  local name=$1 path=$2; shift 2
  local args=()
  for field in "$@"; do args+=(--data-urlencode "$field"); done
  curl -sS -o "$WORK/$name/last.html" -w '%{http_code}' -c "$WORK/$name/cookies" -b "$WORK/$name/cookies" \
    "${args[@]}" "$(url "$name" "$path")"
}

setup_code_of() { compose "$1" logs --no-color posture-cockpit 2>&1 | sed -n 's/.*code d.initialisation : \([A-Z0-9-]*\).*/\1/p' | tail -1; }

create_admin() {  # create_admin NAME [CODE] [DEMO]
  local token status fields=()
  token=$(csrf "$1" /setup)
  [ -n "$token" ] || fail "no CSRF token on /setup"
  [ -n "${2:-}" ] && fields+=("setup_code=$2")
  [ -n "${3:-}" ] && fields+=("demo=on")
  status=$(post "$1" /setup "csrf=$token" username=vincent "password=$PASSWORD" "password2=$PASSWORD" lang=fr "${fields[@]}")
  [ "$status" = 303 ] || fail "creating the first account on $1 answered $status"
  ok "first account created on $1"
}

log_in() {
  local token status
  rm -f "$WORK/$1/cookies"
  token=$(csrf "$1" /login)
  status=$(post "$1" /login "csrf=$token" username=vincent "password=$PASSWORD")
  [ "$status" = 303 ] || fail "signing in on $1 answered $status"
  [ "$(curl -sS -o /dev/null -w '%{http_code}' -b "$WORK/$1/cookies" "$(url "$1" /domains)")" = 200 ] \
    || fail "/domains is not reachable after signing in on $1"
  ok "sign-in works on $1"
}

in_container() { compose "$1" exec -T posture-cockpit "${@:2}"; }
# Output of a command first, then the search: grep -q could close the pipe early (pipefail).
expect_output() {  # expect_output PATTERN COMMAND...
  local pattern=$1 out
  shift
  out=$("$@" 2>&1) || fail "$* failed: $out"
  grep -q -- "$pattern" <<< "$out" || fail "expected '$pattern' from $*, got: $out"
}
key_hash() { in_container "$1" sha256sum /data/.secret_key | cut -d' ' -f1; }
schema_of_image() { docker run --rm --entrypoint python "$1" -c 'from posture_cockpit.storage.schema import MIGRATIONS; print(len(MIGRATIONS))'; }
version_of_image() { docker run --rm --entrypoint python "$1" -c 'import posture_cockpit; print(posture_cockpit.__version__)'; }
# 0.4.1 and later refuse a database of a newer schema; 0.4.0 and earlier would run on it.
refuses_newer_schema() { docker run --rm --entrypoint python "$1" -c 'from posture_cockpit.storage.database import UnsupportedSchema' >/dev/null 2>&1; }
in_backups() {  # in_backups NAME PREFIX -> the newest file of /data/backups starting with PREFIX
  compose "$1" run --rm --no-deps -T posture-cockpit sh -c "ls /data/backups" 2>/dev/null | grep "^$2" | sort | tail -1
}
expect_version() {
  local found
  found=$(curl -fsS "$(url "$1" /healthz)" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
  [ "$found" = "$2" ] || fail "$1 reports version '$found', expected '$2'"
  ok "$1 runs version $2"
}

image_checks() {  # image_checks IMAGE
  say "Image $1"
  [ "$(docker image inspect -f '{{.Config.User}}' "$1")" = "10001:10001" ] || fail "the image does not run as 10001:10001"
  docker image inspect -f '{{json .Config.Healthcheck}}' "$1" | grep -q healthz || fail "no health check"
  ok "runs as 10001:10001, with a health check"
}

install_recette() {  # install_recette IMAGE VERSION
  local image=$1 version=$2 fresh=pc-recette-fresh copy=pc-recette-restore code status schema
  image_checks "$image"
  schema=$(schema_of_image "$image")

  say "New installation (compose.yaml of the repository, optional .env)"
  instance "$fresh" 18080 "$image"
  compose "$fresh" config --quiet || fail "compose.yaml is not valid"
  start "$fresh"
  expect_version "$fresh" "$version"
  [ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.Config.User}}' "$fresh")" \
    = "true [ALL] [no-new-privileges:true] 10001:10001" ] || fail "Docker protections are missing: $(docker inspect -f '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}}' "$fresh")"
  [ "$(in_container "$fresh" sh -c 'grep CapEff /proc/1/status' | awk '{print $2}')" = 0000000000000000 ] || fail "the process keeps capabilities"
  in_container "$fresh" sh -c 'touch /usr/local/x 2>/dev/null' && fail "the system is writable"
  ok "read-only system, no capability, no-new-privileges, uid 10001"
  [ "$(in_container "$fresh" stat -c '%u %a' /data)" = "10001 700" ] || fail "/data: $(in_container "$fresh" stat -c '%u %a' /data)"
  [ "$(in_container "$fresh" stat -c '%a' /data/.secret_key /data/posture_cockpit.db | sort -u)" = 600 ] || fail "key or database readable by others"
  ok "/data belongs to 10001 (700), key and database 600"
  [ "$(docker volume inspect -f '{{.Name}}' "${fresh}_posture-cockpit-data")" = "${fresh}_posture-cockpit-data" ] || fail "volume name"
  ok "volume ${fresh}_posture-cockpit-data"

  say "First account protected by the setup code"
  code=$(setup_code_of "$fresh")
  [ -n "$code" ] || fail "no setup code in the log"
  ok "setup code found in docker compose logs"
  status=$(post "$fresh" /setup "csrf=$(csrf "$fresh" /setup)" username=intrus "password=$PASSWORD" "password2=$PASSWORD" lang=fr)
  [ "$status" = 403 ] || fail "/setup without the code answered $status"
  status=$(post "$fresh" /setup "csrf=$(csrf "$fresh" /setup)" setup_code=AAAA-BBBB-CCCC username=intrus "password=$PASSWORD" "password2=$PASSWORD" lang=fr)
  [ "$status" = 403 ] || fail "/setup with a wrong code answered $status"
  ok "refused without the code and with a wrong code"
  create_admin "$fresh" "$code" demo
  [ "$(curl -sS -o /dev/null -w '%{http_code}' "$(url "$fresh" /setup)")" = 303 ] || fail "/setup is still open"
  log_in "$fresh"
  status=$(curl -sS -o "$WORK/report.pdf" -w '%{http_code}' -b "$WORK/$fresh/cookies" "$(url "$fresh" /domains/menuiserie-dupont.example/report.pdf)")
  if [ "$status" != 200 ] || [ "$(head -c 5 "$WORK/report.pdf")" != "%PDF-" ]; then fail "PDF report: $status"; fi
  ok "PDF report generated in the image"
  expect_output "schema $schema (up to date), 1 account(s), 1 domain(s), 1 scan(s)" in_container "$fresh" posture-cockpit info
  ok "posture-cockpit info"

  say "Backup while the server runs, restore into an isolated instance"
  in_container "$fresh" posture-cockpit backup --output - > "$WORK/backup.tar.gz"
  [ "$(tar -tzf "$WORK/backup.tar.gz" | tr '\n' ' ')" = "manifest.json posture_cockpit.db .secret_key " ] || fail "content of the backup"
  in_container "$fresh" posture-cockpit backup >/dev/null 2>&1 || fail "backup into /data/backups"
  ok "backup to the standard output and into /data/backups"
  instance "$copy" 18081 "$image"
  expect_output "complete and readable" compose "$copy" run --rm --no-deps -T posture-cockpit posture-cockpit check-backup - < "$WORK/backup.tar.gz"
  expect_output "Backup restored" compose "$copy" run --rm --no-deps -T posture-cockpit posture-cockpit restore - < "$WORK/backup.tar.gz"
  start "$copy"
  [ "$(key_hash "$copy")" = "$(key_hash "$fresh")" ] || fail "the session key was not restored"
  [ "$(curl -sS -o /dev/null -w '%{http_code}' "$(url "$copy" /setup)")" = 303 ] || fail "the restored instance asks for a setup"
  log_in "$copy"
  ok "accounts, scans and session key restored"
  if in_container "$copy" posture-cockpit restore --replace - < "$WORK/backup.tar.gz" > "$WORK/out.txt" 2>&1; then fail "restore accepted while the server runs"; fi
  grep -q "stop Posture Cockpit first" "$WORK/out.txt" || fail "message: $(cat "$WORK/out.txt")"
  ok "restore refused while the server uses the database"
  if compose "$copy" run --rm --no-deps -T posture-cockpit posture-cockpit restore --replace - < "$WORK/backup.tar.gz" > "$WORK/out.txt" 2>&1; then
    fail "restore accepted from a second container while the server runs"
  fi
  grep -q "stop Posture Cockpit first" "$WORK/out.txt" || fail "message: $(cat "$WORK/out.txt")"
  ok "restore refused from a second container sharing the volume (lock of the data folder)"
  compose "$copy" stop >/dev/null 2>&1
  expect_output "former data is kept" compose "$copy" run --rm --no-deps -T posture-cockpit posture-cockpit restore --replace - < "$WORK/backup.tar.gz"
  start "$copy"
  log_in "$copy"
  ok "restore --replace on a stopped instance keeps a copy of the former data"

  say "Refusals at start-up"
  compose "$copy" stop >/dev/null 2>&1
  compose "$copy" run --rm --no-deps -T posture-cockpit python -c \
    "import sqlite3; c = sqlite3.connect('/data/posture_cockpit.db'); c.execute(\"UPDATE meta SET value='99' WHERE key='schema_version'\"); c.commit()"
  if compose "$copy" run --rm --no-deps -T posture-cockpit > "$WORK/out.txt" 2>&1; then fail "started on schema 99"; fi
  grep -q "uses schema 99; this version of Posture Cockpit handles schema $schema" "$WORK/out.txt" || fail "message: $(tail -5 "$WORK/out.txt")"
  ok "a newer schema is refused with its explanation"
  mkdir -p "$WORK/host-folder"
  chmod 0755 "$WORK/host-folder"
  if docker run --rm --read-only --tmpfs /tmp -v "$WORK/host-folder:/data" "$image" > "$WORK/out.txt" 2>&1; then
    fail "started on a folder it cannot write"
  fi
  grep -q "chown -R 10001:10001" "$WORK/out.txt" || fail "message: $(tail -5 "$WORK/out.txt")"
  ok "a host folder it cannot write is refused with the chown to run"
}

# A real HTTP scan of the fictitious domain; the scanner uses its built-in fixture.
schema5_scan() {
  local name=$1 status
  status=$(post "$name" "/domains/menuiserie-dupont.example/scan" "csrf=$(csrf "$name" /domains/menuiserie-dupont.example)")
  [ "$status" = 303 ] || fail "schema-5 demonstration scan answered $status"
}

upgrade_recette() {  # upgrade_recette OLD_IMAGE IMAGE
  local old=$1 image=$2 name=pc-recette-upgrade version key old_schema schema archive
  version=$(version_of_image "$image")
  old_schema=$(schema_of_image "$old")
  schema=$(schema_of_image "$image")
  say "Data made by $old (schema $old_schema)"
  instance "$name" 18082 "$old"
  start "$name"
  create_admin "$name" "$(setup_code_of "$name")" demo  # 0.4.1 and later ask for the setup code
  log_in "$name"
  key=$(key_hash "$name")
  if [ "$old_schema" = "$schema" ]; then
    in_container "$name" posture-cockpit backup --output - > "$WORK/before-schema5.tar.gz"
    expect_output "complete and readable" in_container "$name" posture-cockpit check-backup - < "$WORK/before-schema5.tar.gz"
    ok "manual backup verified outside the data volume; rollback will not restore it"
  fi

  say "Update to $image (same volume, schema $schema)"
  compose "$name" stop >/dev/null 2>&1
  set_image "$name" "$image"
  start "$name"
  expect_version "$name" "$version"
  expect_output "schema $schema (up to date), 1 account(s), 1 domain(s), 1 scan(s)" in_container "$name" posture-cockpit info
  [ "$(key_hash "$name")" = "$key" ] || fail "the session key changed"
  [ "$(curl -sS -o /dev/null -w '%{http_code}' "$(url "$name" /setup)")" = 303 ] || fail "an updated instance asks for a setup code"
  log_in "$name"
  [ "$(curl -sS -o /dev/null -w '%{http_code}' -b "$WORK/$name/cookies" "$(url "$name" /domains/menuiserie-dupont.example)")" = 200 ] || fail "scan page"
  ok "accounts, scans and key kept; no setup code for an existing instance"
  if [ "$old_schema" -lt "$schema" ]; then
    archive=$(in_container "$name" sh -c 'ls /data/backups' | grep "^posture-cockpit-before-schema$schema-" | tail -1)
    [ -n "$archive" ] || fail "no backup posture-cockpit-before-schema$schema-* in /data/backups"
    expect_output "Backup before the last update: backups/$archive (schema $old_schema to $schema" in_container "$name" posture-cockpit info
    expect_output "Backup complete and readable: schema $old_schema" in_container "$name" posture-cockpit check-backup "/data/backups/$archive"
    ok "verified backup made before the migration: $archive (schema $old_schema), shown by info"
  fi

  if [ "$old_schema" = "$schema" ]; then
    schema5_scan "$name"
    # This is the candidate's real persisted JSON, not a synthetic omitted-key fixture.
    in_container "$name" python - <<'PY_EXPECT'
import json
from posture_cockpit.config import Config
from posture_cockpit.storage import Database
db = Database(Config.from_env().db_path)
rows = db.all("SELECT outcome FROM findings WHERE scan_id=(SELECT MAX(id) FROM scans)")
remedies = [json.loads(row["outcome"])["remedy"] for row in rows if "remedy" in json.loads(row["outcome"])]
assert remedies and all("expect" in remedy for remedy in remedies)
assert db.value("SELECT COUNT(*) FROM scans") == 2
db.close()
PY_EXPECT
    ok "candidate wrote explicit expectations during a real demonstration scan"
  fi

  say "Rollback to $old"
  compose "$name" stop >/dev/null 2>&1
  set_image "$name" "$old"
  if [ "$old_schema" = "$schema" ]; then
    start "$name"
    log_in "$name"
    ok "$old runs again on the same data (schema $schema unchanged by $version)"
    schema5_scan "$name"
    expect_output "schema $schema (up to date), 1 account(s), 1 domain(s), 3 scan(s)" in_container "$name" posture-cockpit info
    compose "$name" stop >/dev/null 2>&1
    set_image "$name" "$image"
    start "$name"
    expect_version "$name" "$version"
    log_in "$name"
    expect_output "schema $schema (up to date), 1 account(s), 1 domain(s), 3 scan(s)" in_container "$name" posture-cockpit info
    [ "$(key_hash "$name")" = "$key" ] || fail "the session key changed during schema-5 roundtrip"
    in_container "$name" python - <<'PY_INTEGRITY'
from posture_cockpit.config import Config
from posture_cockpit.storage import Database, Scans
db = Database(Config.from_env().db_path)
assert db.value("PRAGMA integrity_check") == "ok"
for row in db.all("SELECT id FROM scans"):
    scan = Scans(db).get(row["id"])
    scan.assessment()
    from posture_cockpit.core.scoring import plan
    plan(scan.current())
assert db.value("SELECT COUNT(*) FROM scans") == 3
print("schema-5 roundtrip: integrity_check=ok; all three scans readable; no restore")
db.close()
PY_INTEGRITY
    ok "candidate reads its data and the old image's new scan; integrity_check=ok"
  elif refuses_newer_schema "$old"; then
    if compose "$name" run --rm --no-deps -T posture-cockpit > "$WORK/out.txt" 2>&1; then fail "$old started on schema $schema"; fi
    grep -q "uses schema $schema; this version of Posture Cockpit handles schema $old_schema" "$WORK/out.txt" \
      || fail "message: $(tail -5 "$WORK/out.txt")"
    ok "$old refuses schema $schema and changes nothing: its rollback goes through the backup (mode rollback)"
  else
    ok "not started: $old would not refuse schema $schema; its rollback goes through the backup (see INSTALLATION.md)"
  fi
}

layout_recette() {  # layout_recette OLD_TAG OLD_IMAGE IMAGE: the default names of a real installation
  local tag=$1 old=$2 image=$3 name=posture-cockpit version key volume=posture-cockpit_posture-cockpit-data
  if docker container inspect posture-cockpit >/dev/null 2>&1 || docker volume inspect "$volume" >/dev/null 2>&1; then
    fail "a container or volume named posture-cockpit exists here: this recette uses those names, run it elsewhere"
  fi
  version=$(docker run --rm --entrypoint python "$image" -c 'import posture_cockpit; print(posture_cockpit.__version__)')
  say "Installation made with the compose.yaml of $tag, in a folder named posture-cockpit"
  mkdir -p "$WORK/$name"
  PROJECTS+=("$name")
  if git -C "$ROOT" show "$tag:compose.yaml" | grep -q POSTURE_COCKPIT_IMAGE; then
    # 0.4.1 and later: the compose.yaml of the release as it is, the settings in .env
    git -C "$ROOT" show "$tag:compose.yaml" > "$WORK/$name/compose.yaml"
    printf 'POSTURE_COCKPIT_IMAGE=%s\nPOSTURE_COCKPIT_PORT=18084\nPOSTURE_COCKPIT_BIND=127.0.0.1\n' "$old" > "$WORK/$name/.env"
  else
    git -C "$ROOT" show "$tag:compose.yaml" \
      | sed -e "s|^\(    image:\).*|\1 $old|" -e 's|"8080:8080"|"127.0.0.1:18084:8080"|' > "$WORK/$name/compose.yaml"
    grep -q "127.0.0.1:18084:8080" "$WORK/$name/compose.yaml" || fail "the compose.yaml of $tag has an unexpected port line"
    echo "POSTURE_COCKPIT_PORT=18084" > "$WORK/$name/.env"  # read by url(); the old file ignores it
  fi
  start "$name"
  create_admin "$name" "$(setup_code_of "$name")" demo  # 0.4.1 and later ask for the setup code
  key=$(key_hash "$name")
  [ "$(docker volume ls -q | grep '^posture-cockpit_')" = "$volume" ] || fail "volume: $(docker volume ls -q)"
  ok "data in the volume $volume, container posture-cockpit"

  say "The new compose.yaml in the same folder, settings in .env"
  compose "$name" down >/dev/null 2>&1   # the volume stays
  cp "$ROOT/compose.yaml" "$WORK/$name/compose.yaml"
  printf 'POSTURE_COCKPIT_IMAGE=%s\nPOSTURE_COCKPIT_PORT=18084\nPOSTURE_COCKPIT_BIND=127.0.0.1\n' "$image" > "$WORK/$name/.env"
  start "$name"
  expect_version "$name" "$version"
  [ "$(docker volume ls -q | grep '^posture-cockpit_')" = "$volume" ] || fail "a second volume appeared: $(docker volume ls -q)"
  docker container inspect posture-cockpit >/dev/null 2>&1 || fail "the container is no longer named posture-cockpit"
  [ "$(key_hash "$name")" = "$key" ] || fail "the session key changed"
  log_in "$name"
  expect_output "1 account(s), 1 domain(s), 1 scan(s)" in_container "$name" posture-cockpit info
  ok "same volume, same container name, same key, same data with the new compose.yaml"

  if [ "$tag" = v0.4.0 ]; then
    say "Back to the compose.yaml and image of $tag"
    compose "$name" down >/dev/null 2>&1
    if [ "$(schema_of_image "$old")" != "$(schema_of_image "$image")" ]; then
      # $tag has no restore command: the new image restores the backup made before the migration.
      archive=$(in_backups "$name" posture-cockpit-before-schema)
      [ -n "$archive" ] || fail "no backup made before the migration"
      expect_output "Backup restored" compose "$name" run --rm --no-deps -T posture-cockpit posture-cockpit restore --replace "/data/backups/$archive"
      ok "backup made before the migration restored ($archive)"
    fi
    git -C "$ROOT" show "$tag:compose.yaml" \
      | sed -e "s|^\(    image:\).*|\1 $old|" -e 's|"8080:8080"|"127.0.0.1:18084:8080"|' > "$WORK/$name/compose.yaml"
    echo "POSTURE_COCKPIT_PORT=18084" > "$WORK/$name/.env"
    start "$name"
    log_in "$name"
    [ "$(key_hash "$name")" = "$key" ] || fail "the session key changed"
    ok "$tag runs again on the volume left by $version, with the same session key"
  fi
}

# ---------------------------------------------------------------- rollback (0.5.0)
TOTP_SECRET=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
TOTP_SECRET_2=KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU
API_KEY=recette-api-key-made-before-the-update-0123456789
DEMO=menuiserie-dupont.example
LAST_STEP=0

# Data that 0.5.0 must carry over, written with the code of the old image (its own Accounts, Perimeters).
SEED_BEFORE='
import sys
from posture_cockpit.config import Config
from posture_cockpit.security import hash_password, token_hash
from posture_cockpit.storage import Accounts, Database, Perimeters, Scans
from posture_cockpit.storage.perimeters import parse_form
admin_name, password, secret, key, new_admin = sys.argv[1:6]
db = Database(Config.from_env().db_path)
accounts = Accounts(db)
if new_admin == "yes":
    accounts.create(admin_name, hash_password(password), is_admin=True, lang="fr")
admin = accounts.by_name(admin_name)["id"]
accounts.create("recette-lecteur", hash_password(password), lang="en")
accounts.start_totp_setup(admin, secret)
accounts.enable_totp(admin, 0, [token_hash(f"recette-recovery-{n}") for n in range(8)])
accounts.add_token(admin, "recette", token_hash(key))
Perimeters(db).create(parse_form("recette-siege", "10.20.0.0/16", "10.20.0.53", "443", ""), admin)
Scans(db).add_domain("menuiserie-dupont.example", admin)
db.close()
'
# Activity after the update, which the return to the old version loses (written by the new image).
ACTIVITY_AFTER='
import sys
from posture_cockpit.config import Config
from posture_cockpit.security import hash_password, token_hash
from posture_cockpit.storage import Accounts, open_database
admin_name, password, secret = sys.argv[1:4]
db = open_database(Config.from_env())
accounts = Accounts(db)
accounts.create("recette-apres-maj", hash_password(password), lang="fr")
reader = accounts.by_name("recette-lecteur")["id"]
accounts.set_password(reader, hash_password(password + " changed"))
accounts.new_session_epoch(reader)
accounts.start_totp_setup(reader, secret)
accounts.enable_totp(reader, 0, [token_hash(f"recette-after-{n}") for n in range(8)])
admin = accounts.by_name(admin_name)["id"]
for token in accounts.tokens(admin):
    if token["name"] == "recette":
        accounts.revoke_token(admin, token["id"])
db.close()
'

sign_in() {  # sign_in NAME USER PASSWORD [TOTP_SECRET]: the password, then the code of the second factor
  local token status code step
  rm -f "$WORK/$1/cookies"
  token=$(csrf "$1" /login)
  status=$(post "$1" /login "csrf=$token" "username=$2" "password=$3")
  [ "$status" = 303 ] || fail "signing in as $2 on $1 answered $status"
  if [ -n "${4:-}" ]; then
    step=$(( $(date +%s) / 30 ))
    if [ "$step" -le "$LAST_STEP" ]; then  # a code is accepted once: wait for the next one
      sleep $(( 31 - $(date +%s) % 30 ))
    fi
    code=$(in_container "$1" python -c "from posture_cockpit.security import totp_at, totp_step; print(totp_at('$4', totp_step()))")
    LAST_STEP=$(( $(date +%s) / 30 ))
    token=$(csrf "$1" /login/code)
    status=$(post "$1" /login/code "csrf=$token" "code=$code")
    [ "$status" = 303 ] || fail "the two-factor code of $2 was refused on $1 ($status)"
  fi
  [ "$(curl -sS -o /dev/null -w '%{http_code}' -b "$WORK/$1/cookies" "$(url "$1" /domains)")" = 200 ] \
    || fail "/domains is not reachable after signing in as $2 on $1"
}

api_status() { curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $2" "$(url "$1" /api/v1/domains)"; }
admin_status() { curl -sS -o /dev/null -w '%{http_code}' -b "$WORK/$1/cookies" "$(url "$1" /admin)"; }

fingerprint() {  # fingerprint NAME LABEL [PATH]: of the stopped instance, read only, without network
  docker run --rm -i --network none --user 0 -v "${1}_posture-cockpit-data:/data:ro" -v "$WORK/salt:/salt:ro" \
    --entrypoint python3 "$FINGERPRINT_IMAGE" - --salt-file /salt/salt "${3:-/data}" \
    < "$ROOT/scripts/data-fingerprint.py" > "$WORK/fp/$2.json" || fail "fingerprint $2"
  echo "   fingerprint $2: $(sed -n 's/^ "fingerprint": "\(.*\)",$/\1/p' "$WORK/fp/$2.json")"
}

compare() {  # compare FIRST SECOND [ARGS...]: prints the report; returns the status of the comparison
  local status=0
  docker run --rm -i --network none -v "$WORK/fp:/fp:ro" --entrypoint python3 "$FINGERPRINT_IMAGE" - \
    compare "/fp/$1.json" "/fp/$2.json" "${@:3}" < "$ROOT/scripts/data-fingerprint.py" > "$WORK/fp/$1-$2.txt" || status=$?
  sed 's/^/     /' "$WORK/fp/$1-$2.txt"
  return $status
}

expect_loss() {  # expect_loss PATTERN WHAT: a line of the comparison of E3 with E2
  grep -Eq -- "$1" "$WORK/fp/E3-E2.txt" || fail "the losses do not show $2"
  ok "loss listed: $2"
}

rollback_recette() {  # rollback_recette OLD_IMAGE IMAGE [ARCHIVE]
  local old=$1 image=$2 data=${3:-} name=pc-recette-rollback version old_version old_schema schema
  local admin=vincent new_admin=no archive kept status
  FINGERPRINT_IMAGE=$image
  version=$(version_of_image "$image")
  old_version=$(version_of_image "$old")
  old_schema=$(schema_of_image "$old")
  schema=$(schema_of_image "$image")
  [ "$old_schema" -lt "$schema" ] || fail "$old has schema $old_schema: nothing to roll back to"
  refuses_newer_schema "$old" || fail "$old does not refuse a newer schema: this recette is meant for 0.4.1 and later"
  mkdir -p "$WORK/fp" "$WORK/salt"
  head -c 32 /dev/urandom > "$WORK/salt/salt"
  chmod 0644 "$WORK/salt/salt"  # read by the root of the container; $WORK itself is private

  say "E0: data made by $old ($old_version, schema $old_schema)"
  instance "$name" 18085 "$old"
  if [ -n "$data" ]; then
    expect_output "Backup restored" compose "$name" run --rm --no-deps -T posture-cockpit posture-cockpit restore - < "$data"
    ok "the archive given is restored into an isolated instance (its own project and volume)"
    admin=recette-admin new_admin=yes
    start "$name"
  else
    start "$name"
    create_admin "$name" "$(setup_code_of "$name")" demo  # 0.4.1 and later ask for the setup code
    log_in "$name"
    status=$(post "$name" "/domains/$DEMO/verify/mail.dmarc" "csrf=$(csrf "$name" "/domains/$DEMO")")
    [ "$status" = 303 ] || fail "the recheck of the demonstration domain answered $status"
    ok "demonstration domain scanned and rechecked"
  fi
  in_container "$name" python - "$admin" "$PASSWORD" "$TOTP_SECRET" "$API_KEY" "$new_admin" <<< "$SEED_BEFORE" \
    || fail "the data of the recette could not be added"
  ok "second account, two-factor authentication with recovery codes, API key, internal perimeter"
  sign_in "$name" "$admin" "$PASSWORD" "$TOTP_SECRET"
  [ "$(api_status "$name" "$API_KEY")" = 200 ] || fail "API key refused"
  ok "sign-in with the password and a two-factor code; API key accepted"
  in_container "$name" posture-cockpit info | sed 's/^/     /'
  compose "$name" stop >/dev/null 2>&1
  fingerprint "$name" E0

  say "E1: update to $image ($version, schema $schema)"
  set_image "$name" "$image"
  start "$name"
  expect_version "$name" "$version"
  in_container "$name" posture-cockpit info > "$WORK/info.txt"
  sed 's/^/     /' "$WORK/info.txt"
  grep -q "schema $schema (up to date)" "$WORK/info.txt" || fail "not migrated to schema $schema"
  archive=$(sed -n "s|^Backup before the last update: backups/\(posture-cockpit-before-schema$schema-[^ ]*\) .*|\1|p" "$WORK/info.txt")
  [ -n "$archive" ] || fail "info does not show the backup made before the migration"
  in_container "$name" posture-cockpit check-backup "/data/backups/$archive" > "$WORK/out.txt" 2>&1 || fail "check-backup: $(cat "$WORK/out.txt")"
  sed 's/^/     /' "$WORK/out.txt"
  grep -q "Backup complete and readable: schema $old_schema" "$WORK/out.txt" || fail "the backup is not of schema $old_schema"
  ok "verified backup before the migration: $archive"
  compose "$name" stop >/dev/null 2>&1  # before any sign-in: E1 is the migration alone
  fingerprint "$name" E1
  fingerprint "$name" archive "/data/backups/$archive"
  compare E0 archive || fail "the backup made before the migration differs from E0"
  grep -q "^identical: yes" "$WORK/fp/E0-archive.txt" || fail "the backup made before the migration is not E0"
  ok "the backup made before the migration holds E0, exactly"
  compare E0 E1 --except meta.value || fail "the migration removed or changed data of E0"
  ok "E1 keeps every table, column, row and value of E0 (the migration only adds)"
  start "$name"
  sign_in "$name" "$admin" "$PASSWORD" "$TOTP_SECRET"
  [ "$(api_status "$name" "$API_KEY")" = 200 ] || fail "API key refused after the update"
  ok "same accounts, two-factor authentication and API key after the update"

  say "E3: activity after the update, which the return loses"
  [ "$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $API_KEY" "$(url "$name" "/api/v1/domains/$DEMO/scan")")" = 200 ] \
    || fail "scan by the API"
  in_container "$name" python - "$admin" "$PASSWORD" "$TOTP_SECRET_2" <<< "$ACTIVITY_AFTER" || fail "activity after the update"
  [ "$(api_status "$name" "$API_KEY")" = 401 ] || fail "the revoked key still works"
  ok "a scan by the API, an account created, a password changed, two-factor enabled, the API key revoked"
  compose "$name" stop >/dev/null 2>&1
  fingerprint "$name" E3

  say "E2: return to $old through the backup made before the migration"
  set_image "$name" "$old"
  if compose "$name" run --rm --no-deps -T posture-cockpit > "$WORK/out.txt" 2>&1; then fail "$old started on schema $schema"; fi
  grep -q "uses schema $schema; this version of Posture Cockpit handles schema $old_schema" "$WORK/out.txt" \
    || fail "message: $(tail -5 "$WORK/out.txt")"
  ok "$old refuses schema $schema, with its explanation"
  compose "$name" run --rm --no-deps -T posture-cockpit posture-cockpit check-backup "/data/backups/$archive" > "$WORK/out.txt" 2>&1 \
    || fail "check-backup by $old: $(cat "$WORK/out.txt")"
  sed 's/^/     /' "$WORK/out.txt"
  compose "$name" run --rm --no-deps -T posture-cockpit posture-cockpit restore --replace "/data/backups/$archive" > "$WORK/out.txt" 2>&1 \
    || fail "restore by $old: $(cat "$WORK/out.txt")"
  sed 's/^/     /' "$WORK/out.txt"
  kept=$(sed -n 's|^The former data is kept in /data/backups/\(.*\)\.$|\1|p' "$WORK/out.txt")
  [ -n "$kept" ] || fail "the restoration did not keep the former data"
  fingerprint "$name" E2
  compare E0 E2 || fail "E2 differs from E0"
  grep -q "^identical: yes" "$WORK/fp/E0-E2.txt" || fail "E2 is not E0"
  ok "E2 = E0 before any sign-in: integrity, accounts, domains, scans, rights, session key"
  start "$name"
  expect_version "$name" "$old_version"
  in_container "$name" posture-cockpit info | sed 's/^/     /'
  sign_in "$name" "$admin" "$PASSWORD" "$TOTP_SECRET"
  [ "$(admin_status "$name")" != 403 ] || fail "$admin lost the administrator role"
  ok "sign-in of $admin with the password and a two-factor code; administrator role kept"
  sign_in "$name" recette-lecteur "$PASSWORD"
  [ "$(admin_status "$name")" = 403 ] || fail "recette-lecteur became an administrator"
  ok "recette-lecteur signs in with the password of before the update, without two-factor (losses)"
  [ "$(api_status "$name" "$API_KEY")" = 200 ] || fail "the API key of before the update is refused"
  ok "the API key revoked after the update works again (loss: the revocation)"

  say "Losses: what was done after the backup (E3, kept in $kept) and is not in E2"
  fingerprint "$name" kept "/data/backups/$kept"
  compare E3 kept >/dev/null || fail "the data kept by the restoration differs from E3"
  grep -q "^identical: yes" "$WORK/fp/E3-kept.txt" || fail "the data kept by the restoration is not E3"
  ok "the restoration kept E3 exactly in $kept"
  compare E3 E2 || true
  if [ -z "$data" ]; then
    expect_loss '^scans: rows [0-9]+ -> [0-9]+; REMOVED rows 1:' "the scan made after the update"
    expect_loss '^users: .*REMOVED rows 1: .*; CHANGED rows \[[0-9]+\] \(pw_hash\)' "the account created and the password changed"
    expect_loss '^totp: .*REMOVED rows 1:' "the two-factor authentication enabled"
    expect_loss '^recovery_codes: .*REMOVED rows 8:' "its recovery codes"
    expect_loss '^api_tokens: .*added rows 1:' "the revocation of the API key"
    expect_loss '^meta: .*REMOVED rows .*\["session_epoch:[0-9]+"\]' "the session epoch of the new account"
    expect_loss '^scan_states: REMOVED' "the states of schema $schema"
  fi

  say "Round trip: the data kept by the restoration, restored by $image, is E3 again"
  compose "$name" stop >/dev/null 2>&1
  set_image "$name" "$image"
  expect_output "Backup restored" compose "$name" run --rm --no-deps -T posture-cockpit posture-cockpit restore --replace "/data/backups/$kept"
  fingerprint "$name" E4
  compare E3 E4 >/dev/null || fail "E4 differs from E3"
  grep -q "^identical: yes" "$WORK/fp/E3-E4.txt" || fail "E4 is not E3"
  start "$name"
  sign_in "$name" "$admin" "$PASSWORD" "$TOTP_SECRET"
  ok "E4 = E3: the update can be made again from where it was left"
}

quick_recette() {  # quick_recette IMAGE VERSION: another architecture, under emulation
  local image=$1 version=$2 name=pc-recette-quick
  image_checks "$image"
  instance "$name" 18083 "$image"
  start "$name" 300
  expect_version "$name" "$version"
  in_container "$name" python -c "import weasyprint; assert weasyprint.HTML(string='<p>ok</p>').write_pdf().startswith(b'%PDF')"
  ok "PDF libraries work"
}

command=${1:-}
case "$command" in
  install) install_recette "$2" "${3:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/pyproject.toml")}" ;;
  upgrade) upgrade_recette "$2" "$3" ;;
  layout) layout_recette "$2" "$3" "$4" ;;
  rollback)
    if [ "${4:-}" = --data ]; then
      [ -f "${5:-}" ] || { echo "rollback OLD_IMAGE IMAGE --data ARCHIVE: no archive ${5:-}" >&2; exit 2; }
      rollback_recette "$2" "$3" "$5"
    else
      rollback_recette "$2" "$3"
    fi ;;
  quick) quick_recette "$2" "${3:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/pyproject.toml")}" ;;
  *) sed -n '2,29p' "$0"; exit 2 ;;
esac
say "Recette $command: everything passed"
if [ -n "${GITHUB_ACTIONS:-}" ]; then  # an annotation of the run: the checks that passed
  summary=$(printf -- '- %s%%0A' "${PASSED[@]}")
  echo "::notice title=docker-recette ${command} (${#PASSED[@]} checks passed)::${summary}"
fi
