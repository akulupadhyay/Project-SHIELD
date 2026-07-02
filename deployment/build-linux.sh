#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$SCRIPT_DIR/linux"

mkdir -p "$OUT_DIR"

if ! cargo tauri --version >/dev/null 2>&1; then
  cargo install tauri-cli --version "^2" --locked
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
