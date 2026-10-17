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
#   scripts/docker-recette.sh upgrade OLD_IMAGE IMAGE   data made by OLD_IMAGE, then IMAGE, then
#                                                       back to OLD_IMAGE when it has schema 4
#   scripts/docker-recette.sh quick IMAGE [VERSION]     start, health, PDF libraries (another architecture)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
PASSWORD="correct horse 42"
PROJECTS=()
STEP=""

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; STEP=$*; }
ok() { printf '   ok: %s\n' "$*"; }
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
  local image=$1 version=$2 fresh=pc-recette-fresh copy=pc-recette-restore code status
  image_checks "$image"

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
  expect_output "schema 4 (up to date), 1 account(s), 1 domain(s), 1 scan(s)" in_container "$fresh" posture-cockpit info
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
  grep -q "uses schema 99; this version of Posture Cockpit handles schema 4" "$WORK/out.txt" || fail "message: $(tail -5 "$WORK/out.txt")"
  ok "a newer schema is refused with its explanation"
  mkdir -p "$WORK/host-folder"
  chmod 0755 "$WORK/host-folder"
  if docker run --rm --read-only --tmpfs /tmp -v "$WORK/host-folder:/data" "$image" > "$WORK/out.txt" 2>&1; then
    fail "started on a folder it cannot write"
  fi
  grep -q "chown -R 10001:10001" "$WORK/out.txt" || fail "message: $(tail -5 "$WORK/out.txt")"
  ok "a host folder it cannot write is refused with the chown to run"
}

upgrade_recette() {  # upgrade_recette OLD_IMAGE IMAGE
  local old=$1 image=$2 name=pc-recette-upgrade version key
  version=$(docker run --rm --entrypoint python "$image" -c 'import posture_cockpit; print(posture_cockpit.__version__)')
  say "Data made by $old"
  instance "$name" 18082 "$old"
  start "$name"
  create_admin "$name" "" demo
  log_in "$name"
  key=$(key_hash "$name")

  say "Update to $image (same volume)"
  compose "$name" stop >/dev/null 2>&1
  set_image "$name" "$image"
  start "$name"
  expect_version "$name" "$version"
  expect_output "schema 4 (up to date), 1 account(s), 1 domain(s), 1 scan(s)" in_container "$name" posture-cockpit info
  [ "$(key_hash "$name")" = "$key" ] || fail "the session key changed"
  [ "$(curl -sS -o /dev/null -w '%{http_code}' "$(url "$name" /setup)")" = 303 ] || fail "an updated instance asks for a setup code"
  log_in "$name"
  [ "$(curl -sS -o /dev/null -w '%{http_code}' -b "$WORK/$name/cookies" "$(url "$name" /domains/menuiserie-dupont.example)")" = 200 ] || fail "scan page"
  ok "accounts, scans and key kept; no setup code for an existing instance"
  in_container "$name" sh -c 'ls /data/backups' > "$WORK/out.txt" 2>&1 || true
  if grep -q schema3 "$WORK/out.txt"; then ok "copy of the schema 3 database kept in /data/backups"; fi

  say "Rollback to $old"
  compose "$name" stop >/dev/null 2>&1
  set_image "$name" "$old"
  if grep -q schema3 "$WORK/out.txt"; then
    ok "skipped: $old uses schema 3, its rollback goes through a restoration (see INSTALLATION.md)"
  else
    start "$name"
    log_in "$name"
    ok "$old runs again on the same data (schema 4 unchanged by $version)"
  fi
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
  quick) quick_recette "$2" "${3:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/pyproject.toml")}" ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
say "Recette $command: everything passed"
