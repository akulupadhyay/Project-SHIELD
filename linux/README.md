# Linux Build and Run

Use this folder when the project has been copied to a Linux machine.

## First-Time Setup

```bash
cd linux
chmod +x bootstrap.sh run.sh build.sh
./bootstrap.sh
```

`bootstrap.sh` installs/checks Rust and common Tauri Linux system dependencies when it can detect `apt`, `dnf`, `pacman`, or `zypper`.

If your distribution is not detected, install the equivalent of:

- Rust stable toolchain with `cargo`
- C/C++ build tools
- `pkg-config`
- OpenSSL development headers
- WebKitGTK 4.1 development headers
- Ayatana/AppIndicator development headers
- librsvg development headers
- `patchelf`
- `curl`, `wget`, `file`

## Run From Source

```bash
cd linux
./run.sh
```

The script sets `SECURE_VAULT_ROOT` to the project root unless you already set it yourself. That keeps development vault data in the copied project folder.

## Build Linux AppImage

```bash
cd linux
./build.sh
```

This delegates to the clean deployment builder and copies the AppImage to:

```text
deployment/linux/SecurePortableVault-Linux.AppImage
```

Requirements:

- Rust `1.77.2` or newer
- `cargo`
- Tauri Linux system packages listed above

If the script says Rust is too old, run `rustup update stable && rustup default stable`, then rerun `./build.sh`.
