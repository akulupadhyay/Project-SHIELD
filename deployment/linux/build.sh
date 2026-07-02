#!/usr/bin/env bash
set -euo pipefail

MIN_RUST_VERSION="1.77.2"
TAURI_CLI_VERSION="${TAURI_CLI_VERSION:-^2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$SCRIPT_DIR"

mkdir -p "$OUT_DIR"

version_at_least() {
  local current="$1"
  local required="$2"
  [[ "$(printf '%s\n%s\n' "$required" "$current" | sort -V | head -n 1)" == "$required" ]]
}

require_command() {
  local command_name="$1"
  local install_hint="$2"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n%s\n' "$command_name" "$install_hint" >&2
    exit 1
  fi
}

require_command cargo "Install Rust with rustup, then rerun: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
require_command rustc "Install Rust with rustup, then rerun this script."

RUST_VERSION="$(rustc --version | awk '{print $2}')"
if ! version_at_least "$RUST_VERSION" "$MIN_RUST_VERSION"; then
  cat >&2 <<MSG
Rust $MIN_RUST_VERSION or newer is required by this project.
Current rustc: $RUST_VERSION

Fix:
  rustup update stable
  rustup default stable
  rustc --version

Then rerun:
  ./deployment/linux/build.sh
MSG
  exit 1
fi

if ! cargo tauri --version >/dev/null 2>&1; then
  cargo install tauri-cli --version "$TAURI_CLI_VERSION" --locked
fi

pushd "$REPO_ROOT/src-tauri" >/dev/null
cargo tauri build --bundles appimage
popd >/dev/null

APPIMAGE="$(find "$REPO_ROOT/target/release/bundle" -type f -name '*.AppImage' | sort | tail -n 1)"
if [[ -z "$APPIMAGE" || ! -f "$APPIMAGE" ]]; then
  echo "Linux AppImage was not produced under target/release/bundle" >&2
  exit 1
fi

DEST="$OUT_DIR/SecurePortableVault-Linux.AppImage"
cp "$APPIMAGE" "$DEST"
chmod +x "$DEST"

pushd "$OUT_DIR" >/dev/null
sha256sum "SecurePortableVault-Linux.AppImage" > "SecurePortableVault-Linux.AppImage.sha256"
popd >/dev/null

printf 'Linux deployment artifact:\n  %s\n' "$DEST"
printf 'SHA256:\n  %s\n' "$DEST.sha256"
