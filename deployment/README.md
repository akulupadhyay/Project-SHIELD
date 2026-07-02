# Secure Portable Vault Deployment

This folder is intentionally kept as a clean platform index. OS-specific scripts, notes, and artifacts live inside their own folders only:

```text
deployment/
  README.md
  windows/
  linux/
  macos/
```

## Platform Folders

- `windows/`: Windows EXE, SHA-256 hash, WebView2 fixed-runtime folder, and Windows build script.
- `linux/`: Linux AppImage build script, Linux notes, and generated Linux artifacts.
- `macos/`: macOS build script, macOS notes, and generated `.app` / `.dmg` artifacts.

This Windows workstation can generate the Windows EXE only. Linux AppImage and macOS `.app` / `.dmg` bundles are platform-native Tauri GUI builds and must be generated on Linux and macOS respectively.

## Build Commands

Windows, from the repository root:

```powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File .\deployment\windows\build.ps1
```

Linux, from the repository root on Linux:

```bash
./deployment/linux/build.sh
```

macOS, from the repository root on macOS:

```bash
./deployment/macos/build.sh
```

## Runtime State

Each deployed app creates runtime vault state beside the launched artifact:

```text
vault-data/
signed-device-manifest.json
```

Those runtime files are not bundled into source-controlled deployment artifacts. Each SSD/HDD deployment should initialize or carry its own vault state intentionally.

## Release Hardening

The release profile strips symbols, disables debug info, uses link-time optimization, uses one codegen unit, and aborts on panic. This provides modest resistance to casual reverse engineering. It is not a substitute for code signing, professional obfuscation, anti-tamper licensing, hardware-backed key storage, or enterprise deployment controls.
