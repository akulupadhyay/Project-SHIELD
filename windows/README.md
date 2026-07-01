# Windows Build and Run

Use this folder when the project has been copied to a Windows machine.

## First-Time Setup

Install:

- Rust stable from `https://rustup.rs`
- Microsoft C++ Build Tools or Visual Studio with the Desktop C++ workload
- Microsoft Edge WebView2 Runtime

Then run:

```powershell
cd windows
.\bootstrap.ps1
```

If PowerShell blocks local scripts, run them with a process-scoped bypass:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1
```

## Run From Source

```powershell
cd windows
.\run.ps1
```

The script sets `SECURE_VAULT_ROOT` to the project root unless you already set it yourself.

## Build Release Executable

```powershell
cd windows
.\build.ps1
```

Outputs:

```text
windows\dist\Start-Windows.exe
dist-portable\Start-Windows.exe
```

## Build NSIS Installer

```powershell
cd windows
.\build.ps1 -Bundle
```

This installs `tauri-cli` if needed and attempts to produce an NSIS installer under Tauri's bundle output.
