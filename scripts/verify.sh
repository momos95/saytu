#!/usr/bin/env bash
# Runs every available check and reports what could not run (missing tool / no network / no Docker).
#   scripts/verify.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
status=0
pass() { printf '  \e[32mPASS\e[0m %s\n' "$1"; }
fail() { printf '  \e[31mFAIL\e[0m %s\n' "$1"; status=1; }
skip() { printf '  \e[33mSKIP\e[0m %s (%s)\n' "$1" "$2"; }

echo "== Shell scripts"
for f in scripts/*.sh infra/postgres/init/*.sh frontend/nginx/*.envsh; do
  bash -n "$f" && pass "syntax $f" || fail "syntax $f"
done

echo "== Keycloak realm"
python3 -m json.tool infra/keycloak/saytu-realm.json >/dev/null && pass "realm JSON" || fail "realm JSON"

echo "== Docker Compose"
if command -v docker >/dev/null; then
  tmp="$(mktemp)"; scripts/generate-secrets.sh --stdout > "$tmp"
  docker compose --env-file "$tmp" config --quiet && pass "docker compose config" || fail "docker compose config"
  rm -f "$tmp"
else skip "docker compose config" "docker not installed"; fi

echo "== Database schema"
if ls -d /usr/lib/postgresql/*/bin >/dev/null 2>&1 || [[ -n "${PG_BIN:-}" ]]; then
  scripts/verify-schema.sh >/dev/null && pass "Flyway migrations + constraint checks" || fail "schema (run scripts/verify-schema.sh)"
else skip "schema" "PostgreSQL binaries not found, set PG_BIN"; fi

echo "== Backend"
if command -v mvn >/dev/null; then
  if docker info >/dev/null 2>&1; then goal=verify; else goal=test; fi
  mvn -q -f backend/pom.xml "$goal" && pass "mvn $goal" || fail "mvn $goal"
  [[ "$goal" == test ]] && skip "integration tests (*IT)" "Docker daemon not reachable"
else skip "backend" "maven not installed"; fi

echo "== Frontend"
if [[ -d frontend/node_modules ]]; then
  (cd frontend && npx ng build --configuration production >/dev/null) && pass "ng build" || fail "ng build"
  if [[ -n "${CHROME_BIN:-}" ]] || command -v chromium >/dev/null || command -v google-chrome >/dev/null; then
    (cd frontend && npm run -s test:ci) && pass "ng test" || fail "ng test"
  else skip "ng test" "no Chrome/Chromium, set CHROME_BIN"; fi
else skip "frontend" "run 'npm install' in frontend/ first"; fi

exit $status
