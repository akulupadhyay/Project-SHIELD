$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

if (-not $env:SECURE_VAULT_ROOT) {
    $env:SECURE_VAULT_ROOT = $repoRoot
}

Push-Location $repoRoot
try {
    cargo run --locked
} finally {
    Pop-Location
}
