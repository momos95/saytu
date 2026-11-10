#!/usr/bin/env bash
# Restores a backup made by scripts/backup.sh. IRREVERSIBLE: the current application and Keycloak
# databases are replaced.
#   scripts/restore.sh <backup-directory> --yes
# The .env of the installation must hold the same SAYTU_MASTER_KEY as when the backup was made (copy it
# from env.backup if needed), otherwise the stored Git tokens cannot be decrypted (re-enter them).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

src="${1:-}"
if [[ -z "$src" || ! -f "$src/saytu.dump" || ! -f "$src/keycloak.dump" ]]; then
  echo "usage: scripts/restore.sh <backup-directory> --yes   (directory with saytu.dump and keycloak.dump)" >&2
  exit 2
fi
if [[ "${2:-}" != "--yes" ]]; then
  echo "This replaces the current databases with $src. Run again with --yes to confirm." >&2
  exit 2
fi
if [[ -f "$src/manifest.txt" ]]; then
  echo "== checking the dumps"
  if ! (cd "$src" && grep -E '^[0-9a-f]{64}  ' manifest.txt | sha256sum -c -); then
    echo "backup altered or incomplete: nothing restored" >&2
    exit 1
  fi
fi

echo "== stopping the services that use the databases"
docker compose stop web worker api keycloak
docker compose up -d postgres
for _ in $(seq 1 30); do
  docker compose exec -T postgres sh -c 'pg_isready -U "$POSTGRES_USER"' >/dev/null 2>&1 && break
  sleep 2
done

recreate() { # $1 database, $2 owner
  docker compose exec -T postgres sh -c "psql -U \"\$POSTGRES_USER\" -d postgres -v ON_ERROR_STOP=1 -q \
    -c 'DROP DATABASE IF EXISTS \"$1\" WITH (FORCE)' \
    -c 'CREATE DATABASE \"$1\" OWNER \"$2\" ENCODING ''UTF8'' TEMPLATE template0'"
}

echo "== application database"
app_db="$(docker compose exec -T postgres sh -c 'printf %s "$POSTGRES_DB"')"
app_user="$(docker compose exec -T postgres sh -c 'printf %s "$POSTGRES_USER"')"
recreate "$app_db" "$app_user"
docker compose exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --exit-on-error' \
  < "$src/saytu.dump"

echo "== Keycloak database"
docker compose up -d keycloak-db-init >/dev/null 2>&1 || true   # makes sure the keycloak role exists
recreate keycloak keycloak
docker compose exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d keycloak --no-owner --role=keycloak --exit-on-error' \
  < "$src/keycloak.dump"

echo "== restarting"
docker compose up -d
echo "restored from $src; the API applies newer migrations at start-up (docker compose logs api)"
