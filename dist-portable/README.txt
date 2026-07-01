Secure Portable Vault portable release layout

This folder is the drive-root layout for runtime testing.

Windows:
  Start-Windows.exe

Linux and macOS builds are platform-specific and must be produced on Linux/macOS runners using:
  .github/workflows/cross-platform-release.yml

Expected final drive layout:
  Start-Windows.exe
  Start-Linux.AppImage
  Start-macOS.app
  signed-device-manifest.json
  vault-data/

Runtime storage:
  The app stores signed-device-manifest.json and vault-data beside the launched
  Windows/Linux executable, or beside the Start-macOS.app bundle on macOS.
  Set SECURE_VAULT_ROOT only when you intentionally want to override that
  executable-relative portable root.
