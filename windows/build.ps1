param(
    [switch]$Bundle
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$distDir = Join-Path $scriptDir "dist"
$portableDir = Join-Path $repoRoot "dist-portable"

New-Item -ItemType Directory -Force -Path $distDir | Out-Null
New-Item -ItemType Directory -Force -Path $portableDir | Out-Null

if ($Bundle) {
    cargo install tauri-cli --version "^2" --locked
    Push-Location (Join-Path $repoRoot "src-tauri")
    try {
        cargo tauri build --bundles nsis
    } finally {
        Pop-Location
    }
}

Push-Location $repoRoot
try {
    cargo build --release --locked
} finally {
    Pop-Location
}

$releaseExe = Join-Path $repoRoot "target\release\secure-vault.exe"
$windowsExe = Join-Path $distDir "Start-Windows.exe"
$portableExe = Join-Path $portableDir "Start-Windows.exe"

Copy-Item -LiteralPath $releaseExe -Destination $windowsExe -Force
Copy-Item -LiteralPath $releaseExe -Destination $portableExe -Force

Write-Host "Windows build output staged in $distDir"
Write-Host "Portable Windows launcher refreshed at $portableExe"
