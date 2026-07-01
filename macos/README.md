# macOS Build and Run

Use this folder when the project has been copied to a Mac.

For a MacBook Air with an M3 chip, use the default Apple Silicon target:

```bash
aarch64-apple-darwin
```

## First-Time Setup

```bash
cd macos
chmod +x bootstrap.sh run.sh build.sh
./bootstrap.sh
```

`bootstrap.sh` checks for:

- Xcode Command Line Tools
- Rust stable toolchain with `cargo`
- The Apple Silicon Rust target on Apple Silicon Macs

If Xcode Command Line Tools are missing, macOS will open the installer prompt.

## Run From Source

```bash
cd macos
./run.sh
```

The script sets `SECURE_VAULT_ROOT` to the project root unless you already set it yourself.

## Build Release Binary

```bash
cd macos
./build.sh
```

The raw macOS binary is copied to:

```text
macos/dist/Start-macOS
```

## Build Apple Silicon Explicitly

```bash
cd macos
./build.sh aarch64-apple-darwin
```

## Build Intel macOS Explicitly

```bash
cd macos
./build.sh x86_64-apple-darwin
```

## Build `.app` and `.dmg`

```bash
cd macos
./build.sh --bundle
```

or for Apple Silicon:

```bash
cd macos
./build.sh --bundle aarch64-apple-darwin
```

The current Tauri config uses ad-hoc signing for development builds. Production distribution still needs Developer ID signing and notarization.
