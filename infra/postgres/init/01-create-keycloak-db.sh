#!/bin/sh
# Runs once, on first start of an empty PostgreSQL volume (docker-entrypoint-initdb.d).
# Creates a dedicated database and role for Keycloak so that the application role (saytu)
# has no access to identity data and vice versa.
set -eu

: "${KEYCLOAK_DB_PASSWORD:?KEYCLOAK_DB_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v kc_password="$KEYCLOAK_DB_PASSWORD" <<'SQL'
CREATE ROLE keycloak LOGIN PASSWORD :'kc_password';
CREATE DATABASE keycloak OWNER keycloak ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE keycloak FROM PUBLIC;
-- the application database is not reachable by the keycloak role
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database()) \gexec
SQL

echo "keycloak database created"
