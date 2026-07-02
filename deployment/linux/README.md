# Linux Deployment

Build this folder on Linux, not Windows.

Recommended portable artifact:

```text
SecurePortableVault-Linux.AppImage
SecurePortableVault-Linux.AppImage.sha256
```

From the repository root on a Linux build machine:

```bash
./deployment/linux/build.sh
```

End users do not need Rust, Cargo, Node, Vite, or internet access to run the AppImage. They may need to mark it executable:

```bash
chmod +x SecurePortableVault-Linux.AppImage
./SecurePortableVault-Linux.AppImage
```

The vault creates runtime files beside the AppImage on first launch:

```text
vault-data/
signed-device-manifest.json
```

Build on the oldest Linux baseline you intend to support. Ubuntu 22.04 or Debian 12 are good baselines for Tauri v2 AppImage builds.
