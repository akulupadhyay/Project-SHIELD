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

## Build Release Binary

```bash
cd linux
./build.sh
```

The raw Linux binary is copied to:

```text
linux/dist/Start-Linux
```

## Build Linux Bundles

```bash
cd linux
./build.sh --bundle
```

This installs `tauri-cli` if needed and attempts to produce AppImage and Debian packages under Tauri's bundle output. Copies are staged in:

```text
linux/dist/
```

Linux GUI builds still require the host machine's WebKitGTK runtime packages.
