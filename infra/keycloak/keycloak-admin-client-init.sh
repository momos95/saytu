#!/bin/bash
# One-shot job of the "keycloak-config" service, run at every "docker compose up" (idempotent):
# creates or updates the confidential client "saytu-admin-api" of the saytu realm, whose service account
# may only manage the users of that realm (view-users, query-users, manage-users), and hands its secret
# to the API through the "keycloak-admin-secret" volume (file readable by the API user only).
# Also aligns the URLs of the web client "saytu-web" on SAYTU_PUBLIC_URL: the realm file is imported only on
# the first start, so changing SAYTU_PUBLIC_URL or SAYTU_HTTP_PORT afterwards would otherwise break the login
# (redirect_uri refused by Keycloak).
# Secret: SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET when set in .env, else the one already in the volume, else a
# new random one. Uses the Keycloak bootstrap administrator (KC_BOOTSTRAP_ADMIN_* in .env).
set -euo pipefail

secret_file=/secrets/keycloak-admin-client-secret
kc=/opt/keycloak/bin/kcadm.sh
config=/tmp/kcadm.config

secret="${SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET:-}"
if [ -z "$secret" ] && [ -s "$secret_file" ]; then
  read -r secret < "$secret_file" || true
fi
if [ -z "$secret" ]; then
  if [ -z "${SRANDOM:-}" ]; then
    echo "bash >= 5.1 needed to generate a secret; set SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET in .env" >&2
    exit 1
  fi
  chars=ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789
  for ((i = 0; i < 40; i++)); do
    secret+="${chars:SRANDOM % ${#chars}:1}"
  done
fi

if ! "$kc" config credentials --config "$config" --server "${KEYCLOAK_URL:-http://keycloak:8080}" --realm master \
     --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD" > /dev/null; then
  echo "Keycloak administrator login refused: user management stays disabled." >&2
  echo "Check KC_BOOTSTRAP_ADMIN_USERNAME / KC_BOOTSTRAP_ADMIN_PASSWORD in .env (see docs/automation.md)." >&2
  exit 1
fi

out="$("$kc" get clients --config "$config" -r saytu -q clientId=saytu-admin-api --fields id --format csv --noquotes)"
read -r id <<< "$out" || true
if [ -z "${id:-}" ]; then
  "$kc" create clients --config "$config" -r saytu -s clientId=saytu-admin-api -s name="SAYTU user administration" \
    -s enabled=true -s publicClient=false -s serviceAccountsEnabled=true -s standardFlowEnabled=false \
    -s directAccessGrantsEnabled=false -s implicitFlowEnabled=false -s "secret=$secret" > /dev/null
  echo "client saytu-admin-api created"
else
  "$kc" update "clients/$id" --config "$config" -r saytu -s "secret=$secret" -s enabled=true > /dev/null
  echo "client saytu-admin-api up to date"
fi
"$kc" add-roles --config "$config" -r saytu --uusername service-account-saytu-admin-api --cclientid realm-management \
  --rolename view-users --rolename query-users --rolename manage-users

public_url="${SAYTU_PUBLIC_URL:-}"; public_url="${public_url%/}"
url_pattern='^https?://[][A-Za-z0-9.:-]+(/[A-Za-z0-9._~/-]*)?$'
if [[ "$public_url" =~ $url_pattern ]]; then
  out="$("$kc" get clients --config "$config" -r saytu -q clientId=saytu-web --fields id --format csv --noquotes)"
  read -r web_id <<< "$out" || true
  if [ -n "${web_id:-}" ]; then
    "$kc" update "clients/$web_id" --config "$config" -r saytu -s "rootUrl=$public_url" \
      -s "redirectUris=[\"$public_url/*\"]" -s "webOrigins=[\"$public_url\"]" \
      -s "attributes.\"post.logout.redirect.uris\"=$public_url/*" > /dev/null
    echo "client saytu-web: login allowed from $public_url"
  else
    echo "client saytu-web not found in the saytu realm" >&2
  fi
else
  echo "SAYTU_PUBLIC_URL '$public_url' is not an http(s) URL: client saytu-web left unchanged" >&2
fi
rm -f "$config"

umask 077
printf '%s' "$secret" > "$secret_file.tmp"
chown 10001:10001 "$secret_file.tmp"
mv -f "$secret_file.tmp" "$secret_file"
echo "user management enabled (roles view-users, query-users, manage-users of the saytu realm only)"
