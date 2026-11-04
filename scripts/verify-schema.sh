#!/usr/bin/env bash
# Applies the Flyway migrations to a throw-away PostgreSQL cluster and runs the SQL constraint checks.
# Needs only the PostgreSQL server binaries (initdb, pg_ctl, psql); no JVM, no Docker.
#   scripts/verify-schema.sh                 # auto-detects /usr/lib/postgresql/<ver>/bin
#   PG_BIN=/usr/pgsql-16/bin scripts/verify-schema.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MIGRATIONS="$ROOT/backend/saytu-app/src/main/resources/db/migration"
CHECKS="$ROOT/backend/saytu-app/src/test/resources/db/schema-constraints-test.sql"

if [[ -z "${PG_BIN:-}" ]]; then
  PG_BIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1 || true)"
fi
[[ -x "$PG_BIN/initdb" ]] || { echo "initdb not found; set PG_BIN" >&2; exit 2; }

RUN_AS=()
if [[ "$(id -u)" == "0" ]]; then
  id postgres >/dev/null 2>&1 || { echo "running as root requires a 'postgres' user" >&2; exit 2; }
  RUN_AS=(runuser -u postgres --)
fi

WORK="$(mktemp -d)"
chmod 755 "$WORK"
[[ ${#RUN_AS[@]} -gt 0 ]] && chown postgres "$WORK"
PORT="${PG_PORT:-55432}"
cleanup() { "${RUN_AS[@]}" "$PG_BIN/pg_ctl" -D "$WORK/data" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

"${RUN_AS[@]}" "$PG_BIN/initdb" -D "$WORK/data" -U saytu --auth=trust -E UTF8 >/dev/null
"${RUN_AS[@]}" "$PG_BIN/pg_ctl" -D "$WORK/data" -o "-p $PORT -k $WORK -c listen_addresses=''" -l "$WORK/pg.log" -w start >/dev/null

PSQL=("${RUN_AS[@]}" "$PG_BIN/psql" -h "$WORK" -p "$PORT" -U saytu -d postgres -v ON_ERROR_STOP=1 -q -X)

echo "== PostgreSQL $("${PSQL[@]}" -tAc 'SHOW server_version')"
for f in $(ls "$MIGRATIONS"/V*__*.sql | sort -V); do
  echo "== applying $(basename "$f")"
  "${PSQL[@]}" -f "$f"
done
echo "== tables: $("${PSQL[@]}" -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")"
echo "== constraint checks"
OUT="$("${PSQL[@]}" -tA -f "$CHECKS")"
echo "$OUT" | sed '/^$/d;/^BEGIN$/d;/^ROLLBACK$/d;/^CREATE FUNCTION$/d;/^SET$/d;/^INSERT/d;/^UPDATE/d;/^DELETE/d'
if echo "$OUT" | grep -q FAIL; then echo "SCHEMA CHECKS FAILED" >&2; exit 1; fi
echo "== all schema checks passed"
