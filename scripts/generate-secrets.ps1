# Creates .env from .env.example with strong random secrets (Windows PowerShell 5.1+ or PowerShell 7).
#   powershell -ExecutionPolicy Bypass -File scripts\generate-secrets.ps1           -> writes .env
#   powershell -ExecutionPolicy Bypass -File scripts\generate-secrets.ps1 -Stdout   -> prints to the console
param([switch]$Stdout)
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$template = Join-Path $root '.env.example'
$target = Join-Path $root '.env'

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
function Get-RandomBytes([int]$count) { $b = New-Object byte[] $count; $rng.GetBytes($b); return ,$b }
function Get-RandomText([int]$length) {
    ([Convert]::ToBase64String((Get-RandomBytes 48)) -replace '[+/=]', '').Substring(0, $length)
}

$values = @{
    'POSTGRES_PASSWORD'           = Get-RandomText 32
    'KEYCLOAK_DB_PASSWORD'        = Get-RandomText 32
    # Keycloak password policy: upper, lower and digit
    'KC_BOOTSTRAP_ADMIN_PASSWORD' = (Get-RandomText 24) + 'Aa1'
    'SAYTU_INITIAL_ADMIN_PASSWORD' = (Get-RandomText 24) + 'Aa1'
    'SAYTU_MASTER_KEY'            = [Convert]::ToBase64String((Get-RandomBytes 32))
}

$lines = Get-Content -Path $template | ForEach-Object {
    $key = ($_ -split '=', 2)[0]
    if ($values.ContainsKey($key) -and $_ -eq "$key=CHANGE_ME") { "$key=$($values[$key])" } else { $_ }
}
if ($lines | Where-Object { $_ -match '=CHANGE_ME$' }) {
    throw 'internal error: a CHANGE_ME placeholder was not replaced'
}
$content = ($lines -join "`n") + "`n"   # LF line endings: read by Docker Compose

if ($Stdout) { Write-Output $content; exit 0 }
if (Test-Path $target) { throw "$target already exists, not overwriting. Delete it first or use -Stdout." }
# UTF-8 without BOM
[System.IO.File]::WriteAllText($target, $content, (New-Object System.Text.UTF8Encoding($false)))
Write-Output "Created $target. Initial admin password: Select-String SAYTU_INITIAL_ADMIN_PASSWORD .env"
