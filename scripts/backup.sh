#!/usr/bin/env bash
# Backs up a SAYTU installation: application database (findings, scores, settings, encrypted Git tokens),
# Keycloak database (users, roles, TOTP) and, with --with-env, the .env file holding SAYTU_MASTER_KEY.
#   scripts/backup.sh [--with-env] [backup-directory]      (default: ./backups/saytu-YYYYmmdd-HHMMSS)
# Without SAYTU_MASTER_KEY, the Git tokens of a restored database cannot be decrypted: keep .env (or at least
# the key) in a safe place, separately from the dumps.
# Restore: scripts/restore.sh <backup-directory>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

with_env=false
if [[ "${1:-}" == "--with-env" ]]; then with_env=true; shift; fi
dest="${1:-backups/saytu-$(date +%Y%m%d-%H%M%S)}"

if ! docker compose ps --status running --services 2>/dev/null | grep -qx postgres; then
  echo "postgres is not running: start it with 'docker compose up -d postgres'" >&2
  exit 1
fi
umask 077
mkdir -p "$dest"

echo "== application database"
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" --format=custom --no-owner "$POSTGRES_DB"' \
  > "$dest/saytu.dump"
echo "== Keycloak database"
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" --format=custom --no-owner keycloak' \
  > "$dest/keycloak.dump"
if $with_env; then
  cp .env "$dest/env.backup"
  echo "== .env copied (contains SAYTU_MASTER_KEY and passwords: protect this directory)"
fi

{
  echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "saytu_version=$(grep -E '^SAYTU_VERSION=' .env 2>/dev/null | cut -d= -f2- || true)"
  echo "schema_version=$(docker compose exec -T postgres sh -c \
    'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT max(version::int) FROM flyway_schema_history WHERE success"' \
    | tr -d '\r')"
  (cd "$dest" && sha256sum saytu.dump keycloak.dump)
} > "$dest/manifest.txt"

for f in saytu.dump keycloak.dump; do
  [[ -s "$dest/$f" ]] || { echo "empty dump: $dest/$f" >&2; exit 1; }
done
echo "backup written to $dest ($(du -sh "$dest" | cut -f1))"
