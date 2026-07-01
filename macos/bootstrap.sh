#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log() {
  printf '[secure-vault/macos] %s\n' "$1"
}

ensure_xcode_tools() {
  if xcode-select -p >/dev/null 2>&1; then
    log "Xcode Command Line Tools are available."
    return
  fi

  log "Xcode Command Line Tools are missing. Opening Apple's installer prompt."
  xcode-select --install || true
  echo "Finish the Xcode Command Line Tools installation, then rerun this script." >&2
  exit 1
}

ensure_rust() {
  if command -v cargo >/dev/null 2>&1; then
    log "Rust is available: $(cargo --version)"
    return
  fi

  log "Rust/cargo was not found. Installing rustup stable toolchain for this user."
  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to install rustup. Install curl and rerun this script." >&2
    exit 1
  fi

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/secure-vault-rustup-init.sh
  sh /tmp/secure-vault-rustup-init.sh -y --profile minimal
  # shellcheck source=/dev/null
  source "$HOME/.cargo/env"
  log "Rust installed: $(cargo --version)"
}

ensure_macos_target() {
  local machine
  machine="$(uname -m)"
  if [[ "$machine" == "arm64" ]]; then
    rustup target add aarch64-apple-darwin
  elif [[ "$machine" == "x86_64" ]]; then
    rustup target add x86_64-apple-darwin
  fi
}

ensure_xcode_tools
ensure_rust
ensure_macos_target

log "Checking project from $REPO_ROOT."
cargo check --locked --manifest-path "$REPO_ROOT/Cargo.toml"
log "macOS setup is ready."
