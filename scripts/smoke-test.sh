#!/usr/bin/env bash
# Post-installation / post-upgrade checks of a running SAYTU stack, from the machine running Docker Compose.
# Read-only: creates nothing, starts no audit.
#   scripts/smoke-test.sh
# Exit status 0 when every check passes; WARN lines do not fail the run.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

env_value() { # $1 name, $2 default
  local v
  v="$(grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '\r' || true)"
  printf '%s' "${v:-$2}"
}
public_url="$(env_value SAYTU_PUBLIC_URL http://localhost:8080)"; public_url="${public_url%/}"
kc_url="$(env_value SAYTU_KEYCLOAK_PUBLIC_URL http://localhost:8180)"; kc_url="${kc_url%/}"

status=0
pass() { printf '  \e[32mPASS\e[0m %s\n' "$1"; }
fail() { printf '  \e[31mFAIL\e[0m %s\n' "$1"; status=1; }
warn() { printf '  \e[33mWARN\e[0m %s\n' "$1"; }
http() { curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$@" 2>/dev/null; }

echo "== services"
for svc in postgres keycloak api worker web; do
  state="$(docker compose ps --format '{{.Health}}' "$svc" 2>/dev/null | head -1)"
  [[ "$state" == "healthy" ]] && pass "$svc healthy" || fail "$svc: '${state:-not running}' (docker compose logs $svc)"
done
kc_config="$(docker compose ps -a --format '{{.State}} {{.ExitCode}}' keycloak-config 2>/dev/null | head -1)"
[[ "$kc_config" == "exited 0" ]] && pass "keycloak-config done (user management)" \
  || warn "keycloak-config: '${kc_config:-absent}' (docker compose logs keycloak-config)"

echo "== web interface ($public_url)"
code="$(http "$public_url/")"
[[ "$code" == "200" ]] && pass "home page HTTP 200" || fail "home page HTTP $code"
headers="$(curl -sS -D - -o /dev/null --max-time 10 "$public_url/" 2>/dev/null | tr -d '\r')"
grep -qi '^content-security-policy:.*frame-ancestors' <<<"$headers" && pass "Content-Security-Policy header" \
  || fail "Content-Security-Policy header missing"
grep -qi '^x-content-type-options: nosniff' <<<"$headers" && pass "X-Content-Type-Options header" \
  || fail "X-Content-Type-Options header missing"
code="$(http "$public_url/api/v1/system/info")"
[[ "$code" == "401" ]] && pass "API refuses anonymous calls (401)" || fail "anonymous API call answered HTTP $code"
body="$(curl -sS --max-time 10 "$public_url/actuator/health" 2>/dev/null)"
[[ "$body" != *'"status"'* ]] && pass "actuator not exposed through the web server" || fail "actuator reachable from outside"

echo "== Keycloak ($kc_url)"
discovery="$(curl -sS --max-time 10 "$kc_url/realms/saytu/.well-known/openid-configuration" 2>/dev/null)"
if grep -q "\"issuer\":\"$kc_url/realms/saytu\"" <<<"$discovery"; then
  pass "OIDC discovery, issuer $kc_url/realms/saytu"
else
  fail "OIDC discovery does not answer with issuer $kc_url/realms/saytu (another program on that port? see docs/install-windows.md)"
fi

echo "== worker"
iso="$(docker compose logs --no-log-prefix worker 2>/dev/null | grep 'scanner isolation:' | tail -1)"
if [[ "$iso" == *"dedicated account yes"*"network blocked"* ]]; then
  pass "scanners isolated (dedicated account, network blocked)"
elif [[ -n "$iso" ]]; then
  warn "partial scanner isolation: ${iso##*scanner isolation: }"
else
  warn "no isolation line in the worker log (older image, or the worker has not started yet)"
fi
meta="$(docker compose exec -T worker cat /var/lib/saytu/trivy/db/metadata.json 2>/dev/null | tr -d '\r')"
if [[ -n "$meta" ]]; then
  updated="$(sed -n 's/.*"UpdatedAt":"\([^"]*\)".*/\1/p' <<<"$meta")"
  pass "Trivy vulnerability database present (UpdatedAt ${updated:-?})"
  if [[ -n "$updated" ]] && command -v date >/dev/null; then
    age=$(( ( $(date +%s) - $(date -d "$updated" +%s 2>/dev/null || date +%s) ) / 86400 ))
    (( age > 7 )) && warn "Trivy database is $age days old (docs/operations.md, offline update)"
  fi
else
  warn "no Trivy vulnerability database yet: dependencies are not checked (docs/operations.md)"
fi

echo
(( status == 0 )) && echo "all checks passed" || echo "some checks FAILED"
exit $status
