# Secure Portable Vault Deployment

This folder is reserved for portable release artifacts.

## Current Artifact

- Windows: `windows/SecurePortableVault-Windows.exe`
- macOS: not built on this Windows workstation
- Linux: not built on this Windows workstation

## Windows Offline Behavior

`SecurePortableVault-Windows.exe` contains the Rust backend, Tauri IPC command surface, static HTML/CSS/JavaScript UI, cryptography modules, RBAC logic, audit handling, lockdown handling, and portable vault-root detection.

When copied to an external SSD/HDD and launched, it creates and uses runtime state beside the executable:

- `vault-data/`
- `signed-device-manifest.json`

Those runtime files are intentionally not bundled here. Each deployment target should initialize its own vault state on first run.

## System Runtime Note

Tauri on Windows uses Microsoft WebView2 to render the bundled UI. Windows 11 and most fully updated Windows 10 systems already include WebView2. On older locked-down machines without WebView2, a true zero-install deployment requires shipping Microsoft WebView2 Fixed Version Runtime beside the app or creating an offline installer bundle. That cannot be guaranteed as a single standalone EXE on every Windows machine because WebView2 is an operating-system webview dependency, not a Rust crate.

## Rebuild Windows Artifact

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\deployment\build-windows.ps1
```

The script builds with the hardened release profile and refreshes:

- `deployment/windows/SecurePortableVault-Windows.exe`
- `deployment/windows/SecurePortableVault-Windows.exe.sha256`

## Release Hardening

The release profile strips symbols, disables debug info, uses link-time optimization, uses one codegen unit, and aborts on panic. This provides modest resistance to casual reverse engineering. It is not a substitute for code signing, professional obfuscation, anti-tamper licensing, hardware-backed key storage, or an enterprise EDR/MDM deployment policy.
