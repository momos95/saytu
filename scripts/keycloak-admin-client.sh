#!/usr/bin/env bash
# Creates (or updates) the Keycloak client "saytu-admin-api" used by the "Utilisateurs & paramètres" page.
# Its service account may only manage the users of the saytu realm (view-users, query-users, manage-users).
# Run once from the repository root, with the stack running:   bash scripts/keycloak-admin-client.sh
# It writes SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET into .env; then: docker compose up -d api
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo ".env not found (run scripts/generate-secrets.sh first)" >&2; exit 1; }
get() { grep -E "^$1=" .env | tail -n1 | cut -d= -f2-; }
admin_user="$(get KC_BOOTSTRAP_ADMIN_USERNAME)"; admin_user="${admin_user:-kcadmin}"
admin_password="$(get KC_BOOTSTRAP_ADMIN_PASSWORD)"
secret="$(get SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET || true)"
if [ -z "$secret" ]; then
  secret="$(head -c 32 /dev/urandom | base64 | tr -d '\n/+=' | cut -c1-40)"
fi
docker compose exec -T \
  -e KC_ADMIN_USER="$admin_user" -e KC_ADMIN_PASSWORD="$admin_password" -e CLIENT_SECRET="$secret" \
  keycloak bash -s <<'IN_CONTAINER'
set -euo pipefail
kc=/opt/keycloak/bin/kcadm.sh
$kc config credentials --server http://localhost:8080 --realm master --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD" >/dev/null
id=$($kc get clients -r saytu -q clientId=saytu-admin-api --fields id --format csv --noquotes | head -n1)
if [ -z "$id" ]; then
  $kc create clients -r saytu -s clientId=saytu-admin-api -s name="SAYTU user administration" -s enabled=true \
    -s publicClient=false -s serviceAccountsEnabled=true -s standardFlowEnabled=false -s directAccessGrantsEnabled=false \
    -s implicitFlowEnabled=false -s "secret=$CLIENT_SECRET" >/dev/null
  echo "client saytu-admin-api created"
else
  $kc update "clients/$id" -r saytu -s "secret=$CLIENT_SECRET" -s enabled=true >/dev/null
  echo "client saytu-admin-api updated"
fi
$kc add-roles -r saytu --uusername service-account-saytu-admin-api --cclientid realm-management \
  --rolename view-users --rolename query-users --rolename manage-users
echo "roles view-users, query-users, manage-users granted (saytu realm only)"
IN_CONTAINER
if grep -qE '^SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET=' .env; then
  sed -i.bak -E "s|^SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET=.*|SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET=$secret|" .env && rm -f .env.bak
else
  printf '\nSAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET=%s\n' "$secret" >> .env
fi
echo "secret written to .env; now run: docker compose up -d api"
