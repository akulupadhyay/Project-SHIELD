#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$SCRIPT_DIR/dist"
BUNDLE=0
TARGET=""

for arg in "$@"; do
  case "$arg" in
    --bundle)
      BUNDLE=1
      ;;
    aarch64-apple-darwin|x86_64-apple-darwin)
      TARGET="$arg"
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: ./build.sh [--bundle] [aarch64-apple-darwin|x86_64-apple-darwin]" >&2
      exit 1
      ;;
  esac
done

mkdir -p "$DIST_DIR"

if [[ -n "$TARGET" ]]; then
  rustup target add "$TARGET"
fi

if [[ "$BUNDLE" == "1" ]]; then
  cargo install tauri-cli --version "^2" --locked
  cd "$REPO_ROOT/src-tauri"
  if [[ -n "$TARGET" ]]; then
    cargo tauri build --target "$TARGET" --bundles app,dmg
    BUNDLE_ROOT="$REPO_ROOT/target/$TARGET/release/bundle"
  else
    cargo tauri build --bundles app,dmg
    BUNDLE_ROOT="$REPO_ROOT/target/release/bundle"
  fi
  find "$BUNDLE_ROOT" -type d -name '*.app' -prune -exec cp -R {} "$DIST_DIR/" \;
  find "$BUNDLE_ROOT" -type f -name '*.dmg' -exec cp {} "$DIST_DIR/" \;
else
  cd "$REPO_ROOT"
  if [[ -n "$TARGET" ]]; then
    cargo build --release --locked --target "$TARGET"
    cp "$REPO_ROOT/target/$TARGET/release/secure-vault" "$DIST_DIR/Start-macOS"
  else
    cargo build --release --locked
    cp "$REPO_ROOT/target/release/secure-vault" "$DIST_DIR/Start-macOS"
  fi
  chmod +x "$DIST_DIR/Start-macOS"
fi

printf 'macOS build output staged in %s\n' "$DIST_DIR"
