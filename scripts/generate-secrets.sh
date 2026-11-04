#!/usr/bin/env bash
# Creates .env from .env.example with strong random secrets (idempotent: refuses to overwrite).
#   scripts/generate-secrets.sh            -> writes .env
#   scripts/generate-secrets.sh --stdout   -> prints to stdout
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$ROOT/.env.example"
TARGET="$ROOT/.env"

rand() { head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | head -c "${1:-32}"; }
# Keycloak password policy: >= 12 chars with upper, lower and digit
policy_password() { printf '%sAa1' "$(rand 24)"; }

output="$(sed \
  -e "s|^POSTGRES_PASSWORD=CHANGE_ME|POSTGRES_PASSWORD=$(rand 32)|" \
  -e "s|^KEYCLOAK_DB_PASSWORD=CHANGE_ME|KEYCLOAK_DB_PASSWORD=$(rand 32)|" \
  -e "s|^KC_BOOTSTRAP_ADMIN_PASSWORD=CHANGE_ME|KC_BOOTSTRAP_ADMIN_PASSWORD=$(policy_password)|" \
  -e "s|^SAYTU_INITIAL_ADMIN_PASSWORD=CHANGE_ME|SAYTU_INITIAL_ADMIN_PASSWORD=$(policy_password)|" \
  -e "s|^SAYTU_MASTER_KEY=CHANGE_ME|SAYTU_MASTER_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n')|" \
  "$TEMPLATE")"

if grep -q '=CHANGE_ME' <<<"$output"; then
  echo "internal error: a CHANGE_ME placeholder was not replaced" >&2
  exit 1
fi

if [[ "${1:-}" == "--stdout" ]]; then
  printf '%s\n' "$output"
  exit 0
fi
if [[ -e "$TARGET" ]]; then
  echo "$TARGET already exists, not overwriting. Use --stdout to print new values." >&2
  exit 1
fi
umask 077
printf '%s\n' "$output" > "$TARGET"
echo "Created $TARGET (mode 600). Initial admin password: grep SAYTU_INITIAL_ADMIN_PASSWORD .env"
