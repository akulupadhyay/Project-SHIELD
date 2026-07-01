# Secure Portable SSD/HDD Vault System

Secure Portable Vault is a Rust/Tauri desktop vault for moving and storing sensitive data on an external SSD/HDD. The design goal is simple:

Anyone may possess, copy, or image the drive, but without the correct credentials and key material they should only obtain encrypted ciphertext.

This repository currently contains an MVP backend and static HTML/CSS/JavaScript Tauri UI. It does not use Vite, TypeScript, React, Vue, or a local HTTP server. Frontend-to-backend communication is through Tauri IPC commands only.

## Current Status

Implemented MVP:

- Rust/Tauri desktop app.
- Static HTML/CSS/JavaScript UI bundled inside Tauri.
- Backend-enforced User, Admin, Locked, Uninitialized, and Lockdown states.
- User and Admin passphrase initialization.
- Argon2id passphrase KDF.
- AES-256-GCM encryption.
- zstd decompression compatibility for older chunks created before ZIP wrapping.
- 16 MiB encrypted file chunks.
- BLAKE3 hashes for file and chunk integrity.
- ZIP payload wrapping for new uploads before encryption.
- Fast mode encrypted chunks named `.zip.aes256.chunk`.
- Super Secure mode encrypted chunks named `.zip.mlkem1024.aes256.chunk`.
- ML-KEM-1024 post-quantum file-key encapsulation for Super Secure uploads.
- Separate user/admin vault files.
- Encrypted file metadata.
- Per-file random file encryption keys.
- User upload, list, download, and delete-request flow.
- Admin audit log view.
- Admin recovery queue UI with recover/destroy controls.
- Admin password reset.
- Admin tamper alert view.
- Admin lockdown clear.
- Admin custody report export.
- Admin crypto-erase vault.
- Signed or unsigned development device manifest verification.
- Lockdown after 5 failed admin login attempts.
- Lockdown on signed manifest/app hash failure.

Not production-complete yet:

- Hardware-token authentication.
- managed host agent / automatic drive detection.
- true hardware-backed "only this app can access the drive" enforcement.
- write-protected review mode.
- enterprise DLP/view-only controls.
- signed production provisioning workflow.

## Where Files Are Stored

The app chooses a vault root at startup:

1. If `SECURE_VAULT_ROOT` is set, that folder is the vault root.
2. On Linux AppImage builds, the folder containing the AppImage file is the vault root.
3. On macOS `.app` bundles, the folder containing the `.app` bundle is the vault root.
4. Otherwise, the folder containing the running executable is the vault root.

The UI also displays `Storage Root` in the status panel after startup, so you can confirm the exact folder used on any PC.

Inside that vault root, protected data is stored here:

```text
vault-data/
  user.svault
  admin.svault
  chunks/
    <file_id>/
      0000000000000000.chunk
      0000000000000001.chunk
      ...
signed-device-manifest.json
```

Important storage behavior:

- `user.svault` stores encrypted user metadata, encrypted original file names, file states, and wrapped file keys.
- `admin.svault` stores encrypted audit records, recovery queue records, tamper alerts, admin credential wrapping data, and lockdown state.
- `vault-data/chunks/<file_id>/*.chunk` stores encrypted binary chunks. These are not plaintext files and do not preserve original filenames.
- New Fast uploads use chunk names like `0000000000000000.zip.aes256.chunk`.
- New Super Secure uploads use chunk names like `0000000000000000.zip.mlkem1024.aes256.chunk`.
- New uploads are internally packaged as a single-file ZIP payload first, then the ZIP payload is encrypted into chunks.
- Uploaded source files are read and encrypted into the vault. The original source file is not automatically deleted.
- Downloaded files are decrypted back to plaintext. By default, downloads go to the host user's `Downloads` folder unless a destination is provided.
- Once a file is downloaded, that plaintext copy is outside the vault security boundary.

Persistence:

- Yes, uploaded files persist after logout, app close, and reboot as long as `vault-data/` remains present.
- On login, the backend decrypts `user.svault`, lists active file records, and resolves their encrypted chunk paths.
- If `vault-data/` is deleted, moved away from the executable, or not copied to the external drive, the app will not show the previously uploaded files.

Common run locations:

```text
Running cargo run --locked from the project root:
  vault-data/
  signed-device-manifest.json

Running linux/run.sh, macos/run.sh, or windows/run.ps1:
  vault-data/
  signed-device-manifest.json

Running target/release/secure-vault from a workspace build:
  vault-data/
  signed-device-manifest.json

Running dist-portable/Start-Windows.exe:
  dist-portable/vault-data/
  dist-portable/signed-device-manifest.json

Running E:/Start-Windows.exe from an external drive:
  E:/vault-data/
  E:/signed-device-manifest.json
```

Recommended development command when you want data in the project root:

```powershell
cd "<PROJECT_ROOT>"
cargo run --locked
```

Platform-specific helper folders are also available:

```text
linux/    Linux bootstrap, run, and build scripts
macos/    macOS bootstrap, run, and build scripts
windows/  Windows bootstrap, run, and build scripts
```

Recommended external drive layout:

```text
SECURE_DRIVE/
  Start-Windows.exe
  Start-Linux.AppImage
  Start-macOS.app
  signed-device-manifest.json
  vault-data/
  README.md
```

For the final SSD/HDD product, copy the executable/bundle and the `vault-data` folder together. Do not move only the executable if you expect to keep the same vault contents.

## Encryption And Local Key Storage

The app stores encrypted key envelopes locally, not plaintext keys:

- User passphrase: never stored. It is processed with Argon2id using the salt/profile stored in `vault-data/user.svault`.
- Admin passphrase: never stored. It is processed with Argon2id using the salt/profile stored in `vault-data/admin.svault`.
- User Vault Key: randomly generated at initialization and stored only as an AES-256-GCM wrapped envelope inside `user.svault`.
- Admin Vault Key: randomly generated at initialization and stored only as an AES-256-GCM wrapped envelope inside `admin.svault`.
- Audit Key and Recovery Key: randomly generated at initialization. Wrapped copies are stored in `user.svault` and `admin.svault` so each role can perform its allowed backend actions.
- File Encryption Keys: generated per file. Fast mode stores the file key wrapped by the User Vault Key. Super Secure mode stores an ML-KEM-1024 encapsulation plus an AES-256-GCM wrapped file key derived from the PQC shared secret.
- Pending-delete files: active user key wrappers are removed or moved to recovery wrapping so Admin can recover or destroy them.
- Runtime keys: unwrapped keys exist only inside Rust backend memory during an authenticated session. `KeyMaterial` zeroizes on drop, and logout, timeout, lockdown, and crypto-erase clear active session keys.
- Ciphertext chunks: stored under `vault-data/chunks/<file_id>/` as `.zip.aes256.chunk` or `.zip.mlkem1024.aes256.chunk` files. These chunks do not contain plaintext names or plaintext file bytes.
- Manifest verification: `signed-device-manifest.json` stores the drive ID, app binary hash, and optionally an Ed25519 production public key/signature.

Unsigned development manifests:

- Development builds can run with `manifest_mode: "UNSIGNED_DEVELOPMENT"`.
- In this mode, `public_key_ed25519_b64` and `signature_ed25519_b64` are not trusted production keys; they remain absent until provisioning.
- A signed production manifest must include both Ed25519 fields. If the app binary hash or signature fails verification, startup enters Lockdown Mode.

## How To Use The App

### First Run

1. Launch the platform-specific app.
2. The UI opens in a native Tauri desktop window.
3. If no vault exists, the app shows `Initialize Vault`.
4. Enter a User passphrase and Admin passphrase. Each must be at least 12 characters.
5. The backend creates `vault-data/user.svault`, `vault-data/admin.svault`, and `signed-device-manifest.json`.

### User Mode

1. Select role `User`.
2. Enter the User passphrase.
3. The UI switches to User Mode with green theme.
4. Upload a file by entering its absolute source path.
5. Pick `Fast` or `Super Secure`.
6. Click `Upload`.
7. The UI shows a green-accent progress bar while the backend scans, ZIP-wraps, encrypts, commits metadata, and audits the upload.
8. The backend reads the file, creates an internal ZIP payload, encrypts that payload into chunks, stores ciphertext under `vault-data/chunks`, encrypts metadata, and writes an audit record.
9. Click `Download` to restore a plaintext copy to the default Downloads folder.
10. Click `Delete Request` to remove the file from the active user list and place it into the admin recovery queue.

Current UI limitation:

- Upload uses a typed path field, not a graphical file picker. Pasted Windows paths with surrounding quotes are now normalized by the backend.
- Download currently uses the default Downloads folder from the UI. The backend supports an optional destination directory.

### Admin Mode

1. Select role `Admin`.
2. Enter the Admin passphrase.
3. The UI switches to Admin Mode with blue theme.
4. Use the admin dashboard to:
   - view audit logs,
   - view recovery queue,
   - view tamper alerts,
   - clear lockdown,
   - reset the user passphrase,
   - export a custody report,
   - view the backend security/key-storage summary,
   - crypto-erase the vault.

Admin panels are hidden by default. Click a function button to open only that function's workspace. The recovery queue includes per-file `Recover` and `Destroy` actions.

### Lockdown Mode

Lockdown Mode uses a dark red theme and blocks normal user operations. Admin login is still allowed for recovery actions.

Currently implemented lockdown triggers:

- 5 failed admin login attempts.
- Signed manifest app hash mismatch.
- Signed manifest signature verification failure.
- Persistent lockdown state stored in `admin.svault`.
- Admin crypto-erase.

Partially implemented or future lockdown triggers:

- Audit hash-chain mismatch currently returns an integrity error when logs are read; it does not yet always persistently enter lockdown.
- Vault/chunk integrity errors currently fail the operation; automatic persistent lockdown on every integrity error is future work.
- Debugger, process injection, unexpected DLL/module, raw disk image detection, and forensic-tool detection are not reliable in a software-only external drive design and are future/best-effort only.

## Manual Run And Build

### Run Existing Windows Portable Build

```powershell
cd "<PROJECT_ROOT>"
.\dist-portable\Start-Windows.exe
```

To force it to use the project root vault:

```powershell
cd "<PROJECT_ROOT>"
$env:SECURE_VAULT_ROOT = "<PROJECT_ROOT>"
.\dist-portable\Start-Windows.exe
```

### Run From Source On Windows

Required:

- Rust and Cargo.
- Microsoft C++ Build Tools with `Desktop development with C++`.
- Windows SDK.
- Microsoft Edge WebView2 Runtime.

Install Rust:

```powershell
winget install --id Rustlang.Rustup
rustup default stable-msvc
```

Run:

```powershell
cd "<PROJECT_ROOT>"
cargo run --locked
```

Or use the Windows helper folder:

```powershell
cd "<PROJECT_ROOT>\windows"
.\bootstrap.ps1
.\run.ps1
```

Build release executable:

```powershell
cd "<PROJECT_ROOT>\windows"
.\build.ps1
```

Build Tauri NSIS bundle:

```powershell
cd "<PROJECT_ROOT>\windows"
.\build.ps1 -Bundle
```

### Run From Source On Linux

Recommended clean Linux flow:

```bash
cd "<PROJECT_ROOT>/linux"
chmod +x bootstrap.sh run.sh build.sh
./bootstrap.sh
./run.sh
```

Build a raw Linux release binary:

```bash
cd "<PROJECT_ROOT>/linux"
./build.sh
```

Build Linux AppImage and `.deb` bundles:

```bash
cd "<PROJECT_ROOT>/linux"
./build.sh --bundle
```

The legacy wrapper still works:

```bash
cd "<PROJECT_ROOT>"
chmod +x scripts/build-linux.sh
./scripts/build-linux.sh
```

Run an AppImage from an external drive:

```bash
chmod +x ./Start-Linux.AppImage
./Start-Linux.AppImage
```

When launched as an AppImage, the app uses the folder containing `Start-Linux.AppImage` as the vault root. Set `SECURE_VAULT_ROOT` only when you intentionally want to override that location.

### Run From Source On macOS

Required:

- macOS 10.15 or later for Tauri desktop development.
- Xcode Command Line Tools or Xcode.
- Rust and Cargo.

Recommended clean macOS flow:

```bash
cd "<PROJECT_ROOT>/macos"
chmod +x bootstrap.sh run.sh build.sh
./bootstrap.sh
./run.sh
```

Build a raw macOS release binary:

```bash
cd "<PROJECT_ROOT>/macos"
./build.sh
```

Build macOS `.app` and `.dmg` bundles:

```bash
cd "<PROJECT_ROOT>/macos"
./build.sh --bundle aarch64-apple-darwin
```

For Intel macOS:

```bash
cd "<PROJECT_ROOT>/macos"
./build.sh --bundle x86_64-apple-darwin
```

Run from an external drive:

```bash
open ./Start-macOS.app
```

When launched as a macOS app bundle, the app uses the folder containing `Start-macOS.app` as the vault root. To force another vault root during testing:

```bash
SECURE_VAULT_ROOT="/Volumes/SECURE_DRIVE" ./Start-macOS.app/Contents/MacOS/secure-vault
```

macOS production distribution requires proper Developer ID signing and notarization. The current config uses ad-hoc signing for test builds.

### Cross-Platform Release Builds

The repository includes a GitHub Actions workflow:

```text
.github/workflows/cross-platform-release.yml
```

It builds:

- Windows x64 NSIS bundle.
- Linux x64 AppImage and `.deb`.
- macOS Apple Silicon `.app` and `.dmg`.
- macOS Intel `.app` and `.dmg`.

Desktop binaries are platform-specific. A Windows `.exe` will not run natively on Linux or macOS.

## Dependencies

Runtime dependencies for users:

- Windows: the app executable and Microsoft Edge WebView2 Runtime. Windows 10/11 usually already has WebView2.
- Linux: the platform AppImage or native package, plus whatever WebKitGTK/runtime libraries the target distribution requires.
- macOS: the `.app` bundle. Unsigned or ad-hoc-signed builds may require Gatekeeper override for testing.

Development dependencies:

- Rust stable toolchain.
- Cargo.
- Tauri v2 crates and CLI.
- Windows: Microsoft C++ Build Tools, Windows SDK, WebView2.
- Linux: WebKitGTK 4.1 development packages and compiler toolchain.
- macOS: Xcode Command Line Tools or Xcode.

This project does not require Node/npm for the current static UI build.

Key Rust crates:

- `tauri`: native desktop shell and IPC.
- `tokio`: async runtime and filesystem operations.
- `argon2`: Argon2id passphrase KDF.
- `aes-gcm`: AES-256-GCM encryption.
- `zeroize`: memory zeroization for key material.
- `secrecy`: secret passphrase wrapper.
- `zstd`: compression.
- `blake3`: hashing and integrity identifiers.
- `ed25519-dalek`: manifest signature verification.
- `ml-kem`: ML-KEM-1024 post-quantum file-key encapsulation for Super Secure mode.
- `serde` / `serde_json`: structured vault metadata.
- `uuid`: session, file, and alert identifiers.

## Common Debugging Issues

### `io_error: I/O error: The filename, directory name, or volume label syntax is incorrect. (os error 123)`

Likely cause:

- A Windows path was pasted with quotes or contains invalid characters.
- `SECURE_VAULT_ROOT` was set to an invalid path.

Fix:

- Pull the latest code. The backend now trims surrounding quotes for external path inputs.
- Use absolute paths.
- In PowerShell, set the vault root like this:

```powershell
$env:SECURE_VAULT_ROOT = "<PROJECT_ROOT>"
cargo run --locked
```

### App stores data in the wrong folder

Cause:

- Portable builds store data beside the executable unless `SECURE_VAULT_ROOT` is set.
- Workspace development builds now detect `target/debug` and `target/release` and use the project root.

Fix:

```powershell
$env:SECURE_VAULT_ROOT = "E:\"
.\Start-Windows.exe
```

For `cargo run --locked` from the project root, the default dev vault is the project root.

### Blank page or `Tauri IPC is unavailable`

Cause:

- The static `index.html` was opened directly in a normal browser.
- The old Vite URL `http://127.0.0.1:5173/` is being viewed.

Fix:

- Launch the Tauri desktop app with `cargo run` or the built executable.
- Do not use a Vite dev server. The current app has no Vite runtime.

### `cargo` not found

Fix:

- Install Rust using `rustup`.
- Restart the terminal.
- Check:

```bash
cargo --version
rustc --version
```

### Windows linker or `link.exe` errors

Fix:

- Install Visual Studio Build Tools.
- Select `Desktop development with C++`.
- Install a Windows SDK.
- Run:

```powershell
rustup default stable-msvc
```

### WebView2 missing on Windows

Fix:

- Install Microsoft Edge WebView2 Runtime.
- Windows 10 version 1803 and later normally includes it, but managed or stripped images may not.

### Linux WebKitGTK errors

Fix:

- Install the Linux dependencies from the Linux section above.
- On Ubuntu/Debian, the important package is `libwebkit2gtk-4.1-dev`.

### macOS app blocked by Gatekeeper

Cause:

- Test build is not Developer ID signed/notarized.

Fix for testing:

- Right-click the app and choose Open.
- Or remove quarantine only for a local test build you trust:

```bash
xattr -dr com.apple.quarantine ./Start-macOS.app
```

Production fix:

- Sign and notarize the app with an Apple Developer ID.

### Login fails after moving files

Cause:

- The manifest, `user.svault`, `admin.svault`, or chunk directory was not copied together.

Fix:

- Copy the whole portable layout:

```text
signed-device-manifest.json
vault-data/
```

### Upload fails for a large file

Check:

- The source path points to a real file, not a directory.
- The drive has enough free space.
- The drive filesystem supports large files. Use exFAT for cross-platform portable SSD/HDD usage.
- Do not unplug the drive during upload.

Current behavior:

- Upload writes chunks to `vault-data/chunks/.staging/<file_id>` and moves them into final chunk storage when finished.
- Resume/retry of incomplete uploads is future work.

### Lockdown after admin login attempts

Cause:

- 5 failed admin login attempts trigger lockdown.

Recovery:

- Log in as Admin with the correct passphrase.
- Use `Clear Lockdown`.
- If the admin passphrase is lost, the MVP has no recovery bypass.

### Manifest/app hash lockdown

Cause:

- In production signed mode, `signed-device-manifest.json` pins the app binary hash. Replacing or rebuilding the executable changes the hash.

Fix:

- For development, use an unsigned dev manifest.
- For production, regenerate and sign a new manifest for the exact released binary.

## Feature Implementation Matrix

The feature names below come from the project planning file `context.md`.

### Feature 1 - Host Agent and Drive Detection

Status: Future work.

Current implementation:

- Manual launch is supported through `Start-Windows.exe`, Linux AppImage, macOS app, or `cargo run`.
- Manifest verification exists at startup.

Paths:

- `src-tauri/src/main.rs`
- `src-tauri/src/manifest.rs`
- `signed-device-manifest.json`

Future work:

- Windows Service with WMI/SetupAPI.
- Linux udev/systemd service.
- macOS LaunchDaemon with DiskArbitration/IOKit.
- Managed endpoint deployment.

### Feature 2 - Local Web UI / Tauri Interface

Status: Implemented for MVP.

Current implementation:

- Static HTML/CSS/JavaScript UI is bundled by Tauri.
- The frontend calls Rust with Tauri IPC only.
- UI renders Uninitialized, Locked, User, Admin, and Lockdown modes based on backend `session_check`.

Paths:

- `src-tauri/ui/index.html`
- `src-tauri/ui/style.css`
- `src-tauri/ui/app.js`
- `src-tauri/src/commands/auth.rs`
- `src-tauri/src/state.rs`
- `src-tauri/tauri.conf.json`

### Feature 3 - Authentication and Role-Based Access

Status: Implemented for MVP.

Current implementation:

- User and Admin have separate passphrases.
- Passphrases derive KEKs with Argon2id.
- User and Admin sessions have different backend permissions.
- Backend state stores active keys only after successful login and drops them on logout/session expiry/lockdown.

Paths:

- `src-tauri/src/commands/auth.rs`
- `src-tauri/src/state.rs`
- `src-tauri/src/vault.rs`
- `src-tauri/src/crypto.rs`

Future work:

- Hardware token factors.
- Rate limiting beyond admin failed-attempt lockdown.
- Two-person admin approval for destructive actions.

### Feature 4 - User Mode UI

Status: Implemented for MVP.

Current implementation:

- User Mode uses the green theme.
- User can upload, list, download, and request deletion.
- Backend verifies User role before each User command.

Paths:

- `src-tauri/ui/index.html`
- `src-tauri/ui/app.js`
- `src-tauri/ui/style.css`
- `src-tauri/src/commands/user.rs`
- `src-tauri/src/vault.rs`

### Feature 5 - User Vault Storage Model

Status: Implemented for MVP.

Current implementation:

- `user.svault` stores encrypted metadata and wrapped keys.
- File chunks are stored as ciphertext under `vault-data/chunks/<file_id>`.
- Original names, hashes, sizes, chunk counts, and upload mode are encrypted metadata.
- Only active records appear in the user list.

Paths:

- `src-tauri/src/models.rs`
- `src-tauri/src/vault.rs`
- `vault-data/user.svault`
- `vault-data/chunks/`

Future work:

- Stronger automatic lockdown on every vault integrity failure.
- Garbage collection for crypto-erased chunks.

### Feature 6 - Upload Pipeline

Status: Implemented for MVP.

Current implementation:

- Backend first scans the source file to calculate BLAKE3 and CRC32.
- Backend builds an internal single-file ZIP payload using the ZIP stored method, with ZIP64 support for large files.
- The ZIP payload is streamed into 16 MiB plaintext payload chunks.
- Each payload chunk is encrypted with AES-256-GCM using a random per-file key.
- Fast chunks use the `.zip.aes256.chunk` suffix.
- Super Secure chunks use the `.zip.mlkem1024.aes256.chunk` suffix.
- Chunks are written through a staging directory and committed after upload.
- BLAKE3 hashes are stored for encrypted-payload chunk integrity checks.
- Upload progress is emitted from the Rust backend to the UI while scanning, encrypting, committing metadata, and auditing.
- Upload is audited.

Paths:

- `src-tauri/src/vault.rs`
- `src-tauri/src/crypto.rs`
- `src-tauri/src/commands/user.rs`

Future work:

- Resume/retry for interrupted uploads.
- Graphical file picker.

### Feature 7 - Fast Mode and Super Secure / PQC Mode

Status: Partial, with ML-KEM-1024 key encapsulation now implemented for Super Secure uploads.

Current implementation:

- UI exposes `Fast` and `Super Secure`.
- Both modes package the source as an internal ZIP payload before encryption.
- Fast mode wraps the file encryption key under the User Vault Key using AES-256-GCM.
- Super Secure mode uses ML-KEM-1024 to establish a PQC shared secret, then wraps the file encryption key with AES-256-GCM under a key derived from that shared secret.
- Both modes still use AES-256-GCM for bulk payload encryption because ML-KEM/PQC KEM algorithms are designed for key encapsulation, not direct encryption of large 20-100+ GB files.

Paths:

- `src-tauri/src/models.rs`
- `src-tauri/src/vault.rs`
- `src-tauri/ui/index.html`

Future work:

- Hybrid classical + PQC wrapping with an external hardware or organisation recovery key.
- Time estimation before upload.
- Backend benchmark-based throughput prediction.

### Feature 8 - Download / Export Flow

Status: Implemented for MVP.

Current implementation:

- Backend checks User session and active file state.
- Backend unwraps the file key.
- Chunks are decrypted, decompressed if needed, hash-verified, and written to plaintext output.
- Default output directory is the user's Downloads folder.
- Download is audited.

Paths:

- `src-tauri/src/vault.rs`
- `src-tauri/src/commands/user.rs`
- `src-tauri/ui/app.js`

Future work:

- File-save dialog.
- View-only mode.
- Watermarking/DLP controls for managed endpoints.

### Feature 9 - Delete Request and Admin Recovery Queue

Status: Implemented for MVP.

Current implementation:

- User delete request changes file state to `PENDING_DELETE`.
- User FEK wrapper is removed.
- Recovery FEK wrapper is created.
- Admin recovery queue receives a record.
- Admin recovery queue shows per-file Recover and Destroy actions.
- Backend has admin recover and destroy commands.

Paths:

- `src-tauri/src/vault.rs`
- `src-tauri/src/commands/user.rs`
- `src-tauri/src/commands/admin.rs`
- `src-tauri/src/models.rs`

Future work:

- Add two-person approval for permanent destruction.

### Feature 10 - Admin Mode UI

Status: Implemented for MVP.

Current implementation:

- Admin Mode uses the blue theme.
- Admin function panels are hidden until their corresponding button is selected.
- Admin can view audit logs, recovery queue, tamper alerts, clear lockdown, reset user password, export custody report, review the Security & Keys summary, and crypto-erase.
- Recovery Queue includes per-file Recover and Destroy actions.

Paths:

- `src-tauri/ui/index.html`
- `src-tauri/ui/app.js`
- `src-tauri/ui/style.css`
- `src-tauri/src/commands/admin.rs`

Future work:

- Dedicated UI sections for host logs, operation filters, security policy editing, and two-person destruction approval.

### Feature 11 - Admin Vault

Status: Implemented for MVP.

Current implementation:

- `admin.svault` stores admin credential wrapping data, audit log, recovery queue, tamper alerts, failed admin attempt counter, and lockdown record.
- Admin passphrase derives Admin KEK, which unwraps Admin Vault Key and related recovery/audit keys.

Paths:

- `src-tauri/src/models.rs`
- `src-tauri/src/vault.rs`
- `vault-data/admin.svault`

Future work:

- Separate encrypted policy section.
- Stronger hardware-token-backed admin recovery.

### Feature 12 - Audit Logs

Status: Implemented for MVP.

Current implementation:

- Audit records are encrypted.
- Audit records are hash-chained with BLAKE3.
- Audit read verifies previous hash and record hash.
- Upload, download, delete request, admin login success, recovery, destruction, password reset, custody export, lockdown clear, and crypto-erase events are logged where applicable.

Paths:

- `src-tauri/src/audit.rs`
- `src-tauri/src/vault.rs`
- `src-tauri/src/models.rs`

Future work:

- Separate login/operation/host/tamper log views.
- Signed checkpoints.
- Persistent lockdown on hash-chain verification failure.

### Feature 13 - Host Fingerprinting

Status: Partial.

Current implementation:

- Audit details include host name, OS, architecture, and BLAKE3 hash of the username for admin login success.

Paths:

- `src-tauri/src/audit.rs`
- `src-tauri/src/vault.rs`

Future work:

- Machine GUID hash.
- MAC address hash.
- Drive connection history.
- App binary hash and agent version in every relevant log entry.

### Feature 14 - User Password Reset

Status: Implemented for MVP.

Current implementation:

- Admin can set a new user passphrase.
- Backend derives a new user KEK with Argon2id.
- Existing User Vault Key is rewrapped under the new user KEK.
- Files do not need to be decrypted or re-encrypted.
- Password reset is audited.

Paths:

- `src-tauri/src/commands/admin.rs`
- `src-tauri/src/vault.rs`
- `src-tauri/src/crypto.rs`

### Feature 15 - Lockdown Mode

Status: Partial.

Current implementation:

- Backend supports Lockdown UI mode.
- User operations are blocked in lockdown.
- Active sessions and keys are cleared when entering lockdown.
- Persistent lockdown reason is stored in `admin.svault`.
- Admin login remains available for recovery.
- Clear Lockdown exists for Admin.

Paths:

- `src-tauri/src/state.rs`
- `src-tauri/src/vault.rs`
- `src-tauri/src/commands/admin.rs`
- `src-tauri/ui/index.html`
- `src-tauri/ui/app.js`

Future work:

- Trigger lockdown on every verified vault/index/audit/chunk integrity failure.
- Add incident report export directly from Lockdown view.
- Hardware token requirement for clear/erase.

### Feature 16 - Tamper Alerts

Status: Partial.

Current implementation:

- Tamper alert model exists.
- Failed admin threshold creates a high severity tamper alert.
- Admin can view tamper alerts.
- Custody reports include tamper alerts.

Paths:

- `src-tauri/src/audit.rs`
- `src-tauri/src/models.rs`
- `src-tauri/src/vault.rs`
- `src-tauri/src/commands/admin.rs`

Future work:

- Alerts for invalid manifest, app hash mismatch, audit chain break, replay attempt, invalid IPC attempts, and write-protected mode.
- Alert clearing workflow.

### Feature 17 - Secure Deletion / Cryptographic Erase

Status: Implemented for MVP.

Current implementation:

- Every file has a random FEK.
- User delete request removes the active user FEK wrapper and moves the file to pending delete.
- Admin destroy removes all FEK wrappers for that file.
- Full vault crypto-erase destroys vault key wrappers and puts the vault into lockdown.

Paths:

- `src-tauri/src/vault.rs`
- `src-tauri/src/commands/admin.rs`
- `src-tauri/src/models.rs`

Future work:

- Background garbage collection to remove orphaned ciphertext chunks after key destruction.
- Stronger multi-party approval for destructive operations.

### Feature 18 - Write-Protector / Read-Only Mode

Status: Future work.

Current implementation:

- Not implemented.

Paths planned:

- `src-tauri/src/vault.rs`
- `src-tauri/src/state.rs`
- future read-only custody export module.

Future work:

- Detect write failures and enter Write-Protected Review Mode.
- Allow read-only audit verification.
- Export a host-side report without modifying the drive.

### Feature 19 - API Security / Burp Suite Resistance

Status: Implemented differently from the original HTTP design.

Current implementation:

- There is no local HTTP API.
- There is no axum/actix server.
- There is no Vite dev server in the runtime build.
- Frontend calls backend through Tauri IPC.
- Backend enforces RBAC and never trusts frontend state.
- CSP is strict and external URLs are disabled.

Paths:

- `src-tauri/tauri.conf.json`
- `src-tauri/capabilities/main.json`
- `src-tauri/src/commands/`
- `src-tauri/src/state.rs`

Future work:

- IPC nonce/rate-limit hardening.
- More detailed audit of denied IPC calls.

### Feature 20 - Key Hierarchy

Status: Implemented for MVP.

Current implementation:

- User passphrase derives User KEK.
- User KEK unwraps User Vault Key.
- User Vault Key unwraps File Encryption Keys.
- Admin passphrase derives Admin KEK.
- Admin KEK unwraps Admin Vault Key.
- Admin Vault Key unwraps audit/recovery paths.
- Recovery Key can rewrap file keys and user vault key for recovery workflows.

Paths:

- `src-tauri/src/vault.rs`
- `src-tauri/src/crypto.rs`
- `src-tauri/src/models.rs`

Future work:

- Optional hardware-token wrapping.
- PQC/hybrid wrapping.
- Key rotation workflows.

### Feature 21 - App and Device Integrity

Status: Partial.

Current implementation:

- `signed-device-manifest.json` contains drive ID, app binary BLAKE3 hash, policy version, and optional Ed25519 signature.
- Signed manifests enforce binary hash and signature verification.
- Unsigned development manifests are allowed and updated when the debug/release binary changes.

Paths:

- `src-tauri/src/manifest.rs`
- `src-tauri/src/main.rs`
- `signed-device-manifest.json`

Future work:

- Production provisioning tool to sign manifests.
- Secure element/TPM-backed drive identity.
- Policy version enforcement.

### Feature 22 - Production Hardware Path

Status: Future work.

Current implementation:

- Software-only encrypted vault on a commercial SSD/HDD.

Paths planned:

- future host agent.
- future secure element integration.
- future hardware bridge protocol.

Future work:

- Secure USB/NVMe bridge controller.
- Secure element or TPM-like chip.
- Hardware-backed challenge-response.
- Hardware-enforced key release policy.
- Monotonic counters and secure clock.

## Security Notes

- The frontend is not trusted. Backend commands enforce role, state, and key availability.
- Plain external drive browsing should reveal only manifest/public app files plus encrypted vault files/chunks.
- A normal commercial SSD/HDD cannot prevent raw disk imaging. The defense is encryption, not hiding.
- A software-only app cannot reliably detect every debugger, memory attack, USB analyzer, forensic image, or malicious host.
- For high-assurance deployments, pair this software with managed endpoints, hardware tokens, code signing, manifest signing, and eventually secure storage hardware.

## Important Paths

```text
src-tauri/src/main.rs                 Tauri entrypoint and startup manifest/lockdown checks
src-tauri/src/crypto.rs               Argon2id, AES-GCM, zstd, BLAKE3, zeroizing key material
src-tauri/src/state.rs                Runtime session state, RBAC, key lifetime, lockdown mode
src-tauri/src/vault.rs                Vault storage, upload, download, recovery, erase, password reset
src-tauri/src/audit.rs                Encrypted hash-chained audit logs and tamper alerts
src-tauri/src/manifest.rs             Device manifest and app hash verification
src-tauri/src/models.rs               Disk and IPC data structures
src-tauri/src/commands/auth.rs        Initialize, login, logout, session check
src-tauri/src/commands/user.rs        User file commands
src-tauri/src/commands/admin.rs       Admin audit/recovery/security commands
src-tauri/ui/index.html               Static Tauri UI
src-tauri/ui/style.css                UI styling
src-tauri/ui/app.js                   UI event handlers and Tauri IPC calls
src-tauri/tauri.conf.json             Tauri security and bundle configuration
linux/bootstrap.sh                    Linux first-time dependency/setup check
linux/run.sh                          Linux source run helper
linux/build.sh                        Linux release/bundle build helper
macos/bootstrap.sh                    macOS first-time dependency/setup check
macos/run.sh                          macOS source run helper
macos/build.sh                        macOS release/bundle build helper
windows/bootstrap.ps1                 Windows first-time dependency/setup check
windows/run.ps1                       Windows source run helper
windows/build.ps1                     Windows release/bundle build helper
scripts/build-windows.ps1             Windows bundle build
scripts/build-linux.sh                Linux bundle build
scripts/build-macos.sh                macOS bundle build
docs/CROSS_PLATFORM_RELEASE.md        Release notes
.github/workflows/cross-platform-release.yml  CI cross-platform build
```

## References

- Tauri v2 prerequisites: https://v2.tauri.app/start/prerequisites/
- Tauri v2 distribution: https://v2.tauri.app/distribute/
- Tauri GitHub Actions distribution: https://v2.tauri.app/distribute/pipelines/github/
