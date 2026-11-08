# Creates (or updates) the Keycloak client "saytu-admin-api" used by the "Utilisateurs & paramètres" page.
# Its service account may only manage the users of the saytu realm (view-users, query-users, manage-users).
# Run once from the repository root, with the stack running:
#   powershell -ExecutionPolicy Bypass -File scripts\keycloak-admin-client.ps1
# It writes SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET into .env; then: docker compose up -d api
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$envFile = Join-Path $root '.env'
if (-not (Test-Path $envFile)) { throw '.env not found (run scripts\generate-secrets.ps1 first)' }
$lines = Get-Content $envFile
function Get-EnvValue([string]$key) {
    $line = $lines | Where-Object { $_ -match "^$key=" } | Select-Object -Last 1
    if ($line) { return ($line -split '=', 2)[1] } else { return '' }
}
$adminUser = Get-EnvValue 'KC_BOOTSTRAP_ADMIN_USERNAME'; if (-not $adminUser) { $adminUser = 'kcadmin' }
$adminPassword = Get-EnvValue 'KC_BOOTSTRAP_ADMIN_PASSWORD'
$secret = Get-EnvValue 'SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET'
if (-not $secret) {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $secret = ([Convert]::ToBase64String($bytes) -replace '[+/=]', '').Substring(0, 40)
}
$script = @'
set -euo pipefail
kc=/opt/keycloak/bin/kcadm.sh
$kc config credentials --server http://localhost:8080 --realm master --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD" >/dev/null
id=$($kc get clients -r saytu -q clientId=saytu-admin-api --fields id --format csv --noquotes | head -n1)
if [ -z "$id" ]; then
  $kc create clients -r saytu -s clientId=saytu-admin-api -s name="SAYTU user administration" -s enabled=true -s publicClient=false -s serviceAccountsEnabled=true -s standardFlowEnabled=false -s directAccessGrantsEnabled=false -s implicitFlowEnabled=false -s "secret=$CLIENT_SECRET" >/dev/null
  echo "client saytu-admin-api created"
else
  $kc update "clients/$id" -r saytu -s "secret=$CLIENT_SECRET" -s enabled=true >/dev/null
  echo "client saytu-admin-api updated"
fi
$kc add-roles -r saytu --uusername service-account-saytu-admin-api --cclientid realm-management --rolename view-users --rolename query-users --rolename manage-users
echo "roles view-users, query-users, manage-users granted (saytu realm only)"
'@
# LF line endings: the script runs in bash inside the container
$script = $script -replace "`r`n", "`n"
$script | docker compose exec -T -e "KC_ADMIN_USER=$adminUser" -e "KC_ADMIN_PASSWORD=$adminPassword" -e "CLIENT_SECRET=$secret" keycloak bash -s
if ($LASTEXITCODE -ne 0) { throw "kcadm failed (exit $LASTEXITCODE)" }
if ($lines | Where-Object { $_ -match '^SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET=' }) {
    $lines = $lines | ForEach-Object { if ($_ -match '^SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET=') { "SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET=$secret" } else { $_ } }
} else {
    $lines += ''; $lines += "SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET=$secret"
}
[System.IO.File]::WriteAllLines($envFile, $lines)
Write-Host 'secret written to .env; now run: docker compose up -d api'
