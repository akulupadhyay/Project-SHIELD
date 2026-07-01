$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

function Write-Step {
    param([string]$Message)
    Write-Host "[secure-vault/windows] $Message"
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "Rust/cargo was not found. Install Rust stable from https://rustup.rs, reopen PowerShell, and rerun this script."
}

Write-Step "Rust is available: $(cargo --version)"
Write-Step "Checking project from $repoRoot."
cargo check --locked --manifest-path (Join-Path $repoRoot "Cargo.toml")
Write-Step "Windows setup is ready."
