param(
    [string]$OutputName = "SecurePortableVault-Windows.exe"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$windowsDir = Join-Path $scriptDir "windows"
$releaseExe = Join-Path $repoRoot "target\release\secure-vault.exe"
$deployExe = Join-Path $windowsDir $OutputName
$hashPath = "$deployExe.sha256"

New-Item -ItemType Directory -Force -Path $windowsDir | Out-Null

Push-Location $repoRoot
try {
    cargo build --release --locked
} finally {
    Pop-Location
}

if (-not (Test-Path -LiteralPath $releaseExe)) {
    throw "Release executable was not produced at $releaseExe"
}

Copy-Item -LiteralPath $releaseExe -Destination $deployExe -Force

$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $deployExe
"$($hash.Hash.ToLowerInvariant())  $OutputName" | Set-Content -LiteralPath $hashPath -Encoding ascii

Write-Host "Windows deployment artifact:"
Write-Host "  $deployExe"
Write-Host "SHA256:"
Write-Host "  $hashPath"
