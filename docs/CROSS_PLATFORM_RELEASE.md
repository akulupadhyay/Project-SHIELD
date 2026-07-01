# Cross-Platform Release

This project is source-portable, but desktop executables are platform-specific.

Build outputs:

- Windows: `.exe` app plus NSIS installer from `src-tauri/target/release/bundle/nsis/`
- Linux: AppImage and Debian package from `src-tauri/target/release/bundle/`
- macOS: `.app` bundle and `.dmg` installer from `src-tauri/target/<target>/release/bundle/`

Use one executable/bundle per OS on the external drive:

```text
SecureDrive/
  Start-Windows.exe
  Start-Linux.AppImage
  Start-macOS.app
  signed-device-manifest.json
  vault-data/
```

Local builds:

```powershell
.\windows\bootstrap.ps1
.\windows\build.ps1
```

```bash
cd linux
chmod +x bootstrap.sh run.sh build.sh
./bootstrap.sh
./build.sh --bundle
```

```bash
cd macos
chmod +x bootstrap.sh run.sh build.sh
./bootstrap.sh
./build.sh --bundle aarch64-apple-darwin
./build.sh --bundle x86_64-apple-darwin
```

macOS builds require macOS/Xcode. Linux builds require WebKitGTK 4.1 system packages. For reliable releases, use the GitHub Actions workflow in `.github/workflows/cross-platform-release.yml`.

The current macOS config uses ad-hoc signing (`signingIdentity = "-"`) so test builds can launch on Apple Silicon. Production distribution still needs Developer ID signing and notarization.
