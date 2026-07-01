#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$SCRIPT_DIR/dist"
BUNDLE=0

for arg in "$@"; do
  case "$arg" in
    --bundle)
      BUNDLE=1
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: ./build.sh [--bundle]" >&2
      exit 1
      ;;
  esac
done

mkdir -p "$DIST_DIR"

if [[ "$BUNDLE" == "1" ]]; then
  cargo install tauri-cli --version "^2" --locked
  cd "$REPO_ROOT/src-tauri"
  cargo tauri build --bundles appimage,deb
  find "$REPO_ROOT/target/release/bundle" -type f \( -name '*.AppImage' -o -name '*.deb' \) -exec cp {} "$DIST_DIR/" \;
else
  cd "$REPO_ROOT"
  cargo build --release --locked
  cp "$REPO_ROOT/target/release/secure-vault" "$DIST_DIR/Start-Linux"
  chmod +x "$DIST_DIR/Start-Linux"
fi

printf 'Linux build output staged in %s\n' "$DIST_DIR"
