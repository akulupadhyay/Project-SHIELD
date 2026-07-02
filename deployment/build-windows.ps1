param(
    [string]$OutputName = "SecurePortableVault-Windows.exe",
    [string]$FixedRuntimePath = "",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$windowsDir = Join-Path $scriptDir "windows"
$releaseExe = Join-Path $repoRoot "target\release\secure-vault.exe"
$deployExe = Join-Path $windowsDir $OutputName
$hashPath = "$deployExe.sha256"
$deployRuntimeDir = Join-Path $windowsDir "WebView2FixedRuntime"

New-Item -ItemType Directory -Force -Path $windowsDir | Out-Null

function Find-WebView2RuntimeFolder {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $candidate = $resolved.Path

    if (Test-Path -LiteralPath (Join-Path $candidate "msedgewebview2.exe")) {
        return $candidate
    }

    $children = Get-ChildItem -LiteralPath $candidate -Directory -ErrorAction Stop | Sort-Object FullName
    foreach ($child in $children) {
        if (Test-Path -LiteralPath (Join-Path $child.FullName "msedgewebview2.exe")) {
            return $candidate
        }
    }

    throw "FixedRuntimePath must be an extracted Microsoft WebView2 Fixed Version Runtime folder, or its parent. Could not find msedgewebview2.exe under: $candidate"
}

if (-not $SkipBuild) {
    Push-Location $repoRoot
    try {
        cargo build --release --locked
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path -LiteralPath $releaseExe)) {
    throw "Release executable was not produced at $releaseExe"
}

Copy-Item -LiteralPath $releaseExe -Destination $deployExe -Force

if (-not [string]::IsNullOrWhiteSpace($FixedRuntimePath)) {
    $runtimeSource = Find-WebView2RuntimeFolder -Path $FixedRuntimePath

    if (Test-Path -LiteralPath $deployRuntimeDir) {
        Remove-Item -LiteralPath $deployRuntimeDir -Recurse -Force
    }

    New-Item -ItemType Directory -Force -Path $deployRuntimeDir | Out-Null
    Copy-Item -Path (Join-Path $runtimeSource "*") -Destination $deployRuntimeDir -Recurse -Force
}

$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $deployExe
"$($hash.Hash.ToLowerInvariant())  $OutputName" | Set-Content -LiteralPath $hashPath -Encoding ascii

Write-Host "Windows deployment artifact:"
Write-Host "  $deployExe"
Write-Host "SHA256:"
Write-Host "  $hashPath"

if (Test-Path -LiteralPath $deployRuntimeDir) {
    $runtimeExe = Get-ChildItem -LiteralPath $deployRuntimeDir -Recurse -Filter "msedgewebview2.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($runtimeExe) {
        Write-Host "Bundled WebView2 Fixed Runtime:"
        Write-Host "  $deployRuntimeDir"
    } else {
        Write-Warning "WebView2FixedRuntime folder exists, but msedgewebview2.exe was not found. The app will fall back to system WebView2."
    }
} else {
    Write-Warning "No WebView2 Fixed Runtime was bundled. For offline machines without WebView2, rerun with -FixedRuntimePath <extracted-runtime-folder>."
}
