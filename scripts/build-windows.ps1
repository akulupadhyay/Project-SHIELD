param(
    [switch]$Bundle
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$buildScript = Join-Path $repoRoot "windows\build.ps1"

& $buildScript -Bundle:$Bundle
