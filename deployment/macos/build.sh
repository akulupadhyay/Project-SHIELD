#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$SCRIPT_DIR"
TARGET=""

case "$(uname -m)" in
  arm64|aarch64)
    TARGET="aarch64-apple-darwin"
    ;;
  x86_64)
    TARGET="x86_64-apple-darwin"
    ;;
  *)
    echo "Unsupported macOS architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

mkdir -p "$OUT_DIR"

if ! cargo tauri --version >/dev/null 2>&1; then
  cargo install tauri-cli --version "^2" --locked
fi

rustup target add "$TARGET"

pushd "$REPO_ROOT/src-tauri" >/dev/null
cargo tauri build --target "$TARGET" --bundles app,dmg
popd >/dev/null

BUNDLE_ROOT="$REPO_ROOT/target/$TARGET/release/bundle"
APP_BUNDLE="$(find "$BUNDLE_ROOT" -type d -name '*.app' -prune | sort | tail -n 1)"
DMG_FILE="$(find "$BUNDLE_ROOT" -type f -name '*.dmg' | sort | tail -n 1)"

if [[ -z "$APP_BUNDLE" || ! -d "$APP_BUNDLE" ]]; then
  echo "macOS .app bundle was not produced under $BUNDLE_ROOT" >&2
  exit 1
fi

if [[ -z "$DMG_FILE" || ! -f "$DMG_FILE" ]]; then
  echo "macOS .dmg was not produced under $BUNDLE_ROOT" >&2
  exit 1
fi

rm -rf "$OUT_DIR/Secure Portable Vault.app"
cp -R "$APP_BUNDLE" "$OUT_DIR/"
cp "$DMG_FILE" "$OUT_DIR/SecurePortableVault-macOS-$TARGET.dmg"

pushd "$OUT_DIR" >/dev/null
shasum -a 256 "SecurePortableVault-macOS-$TARGET.dmg" > "SecurePortableVault-macOS-$TARGET.dmg.sha256"
zip -qry "SecurePortableVault-macOS-$TARGET.app.zip" "Secure Portable Vault.app"
shasum -a 256 "SecurePortableVault-macOS-$TARGET.app.zip" > "SecurePortableVault-macOS-$TARGET.app.zip.sha256"
popd >/dev/null

printf 'macOS deployment artifacts staged in:\n  %s\n' "$OUT_DIR"
