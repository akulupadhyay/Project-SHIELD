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

## Build Machine Requirements

`build-windows.ps1` is a build script. It is not the file that end users run.

To run the script on a build machine, install:

- Windows 10 or Windows 11
- Rust stable toolchain with `cargo`
- Microsoft C++ Build Tools / Visual Studio Build Tools with the MSVC toolchain
- PowerShell 5 or later
- The dependencies already locked in `Cargo.lock`

For a completely offline build machine, the Rust crate cache must already contain every dependency in `Cargo.lock`, or the repository must be vendored before going offline. The build script does not install Rust, MSVC, or crate dependencies.

## Target Machine Requirements

For the machine that only runs the deployed app:

- Rust is not required
- Cargo is not required
- Visual Studio Build Tools are not required
- Node/Vite/TypeScript are not required
- Internet is not required if WebView2 Fixed Runtime is bundled in the deployment folder

## WebView2 Runtime Options

Tauri on Windows uses Microsoft WebView2 to render the bundled UI. Windows 11 and most fully updated Windows 10 systems already include WebView2. On older locked-down machines without WebView2, a true zero-install deployment requires shipping Microsoft WebView2 Fixed Version Runtime beside the app or creating an offline installer bundle. That cannot be guaranteed as a single standalone EXE on every Windows machine because WebView2 is an operating-system webview dependency, not a Rust crate.

Supported deployment shapes:

- `Single EXE`: works only on machines that already have WebView2 installed.
- `Single folder`: `SecurePortableVault-Windows.exe` plus `WebView2FixedRuntime/`; works on offline machines without installing WebView2.
- `Single installer EXE`: possible with a Tauri NSIS offline installer, but that installs WebView2/app components on the target machine and is not the same as a portable vault folder.

The app automatically checks for `WebView2FixedRuntime` beside the EXE. If it finds `msedgewebview2.exe` there, it uses that local fixed runtime. If not, it falls back to system WebView2.

## Rebuild Windows Artifact

From the repository root:

```powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File .\deployment\build-windows.ps1
```

The script builds with the hardened release profile and refreshes:

- `deployment/windows/SecurePortableVault-Windows.exe`
- `deployment/windows/SecurePortableVault-Windows.exe.sha256`

## Build a Fully Offline Portable Folder

Download the official Microsoft WebView2 Fixed Version Runtime for the target architecture on an internet-connected build machine. Extract the downloaded `.cab` first. Then run:

```powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File .\deployment\build-windows.ps1 -FixedRuntimePath "C:\Path\To\Extracted\Microsoft.WebView2.FixedVersionRuntime"
```

Copy the whole folder below to the external SSD/HDD:

```text
deployment/windows/
```

The folder should contain:

```text
SecurePortableVault-Windows.exe
SecurePortableVault-Windows.exe.sha256
WebView2FixedRuntime/
```

On the offline target machine, run `SecurePortableVault-Windows.exe`. The app will create `vault-data/` and `signed-device-manifest.json` next to itself on first launch.

## Release Hardening

The release profile strips symbols, disables debug info, uses link-time optimization, uses one codegen unit, and aborts on panic. This provides modest resistance to casual reverse engineering. It is not a substitute for code signing, professional obfuscation, anti-tamper licensing, hardware-backed key storage, or an enterprise EDR/MDM deployment policy.
