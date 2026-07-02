#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MIN_RUST_VERSION="1.77.2"

log() {
  printf '[secure-vault/linux] %s\n' "$1"
}

version_at_least() {
  local current="$1"
  local required="$2"
  [[ "$(printf '%s\n%s\n' "$required" "$current" | sort -V | head -n 1)" == "$required" ]]
}

ensure_rust() {
  if command -v cargo >/dev/null 2>&1; then
    log "Rust is available: $(cargo --version)"
  else
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
  fi

  local rust_version
  rust_version="$(rustc --version | awk '{print $2}')"
  if ! version_at_least "$rust_version" "$MIN_RUST_VERSION"; then
    cat >&2 <<MSG
Rust $MIN_RUST_VERSION or newer is required by this project.
Current rustc: $rust_version

Fix:
  rustup update stable
  rustup default stable
  rustc --version

Then rerun:
  ./bootstrap.sh
MSG
    exit 1
  fi
}

install_system_dependencies() {
  if [[ "${SKIP_SYSTEM_DEPS:-0}" == "1" ]]; then
    log "Skipping system dependency install because SKIP_SYSTEM_DEPS=1."
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    log "Installing Debian/Ubuntu Tauri dependencies."
    sudo apt-get update
    sudo apt-get install -y \
      build-essential \
      curl \
      wget \
      file \
      pkg-config \
      libssl-dev \
      libwebkit2gtk-4.1-dev \
      libxdo-dev \
      libayatana-appindicator3-dev \
      librsvg2-dev \
      patchelf
    return
  fi

  if command -v dnf >/dev/null 2>&1; then
    log "Installing Fedora/RHEL Tauri dependencies."
    sudo dnf install -y \
      gcc \
      gcc-c++ \
      make \
      curl \
      wget \
      file \
      pkgconf-pkg-config \
      openssl-devel \
      webkit2gtk4.1-devel \
      libappindicator-gtk3-devel \
      librsvg2-devel \
      patchelf
    return
  fi

  if command -v pacman >/dev/null 2>&1; then
    log "Installing Arch Linux Tauri dependencies."
    sudo pacman -Syu --needed \
      base-devel \
      curl \
      wget \
      file \
      pkgconf \
      openssl \
      webkit2gtk-4.1 \
      libxdo \
      libappindicator-gtk3 \
      librsvg \
      patchelf
    return
  fi

  if command -v zypper >/dev/null 2>&1; then
    log "Installing openSUSE Tauri dependencies."
    sudo zypper install -y \
      -t pattern devel_basis
    sudo zypper install -y \
      curl \
      wget \
      file \
      pkg-config \
      libopenssl-devel \
      webkit2gtk4.1-devel \
      libayatana-appindicator3-devel \
      librsvg-devel \
      patchelf
    return
  fi

  cat >&2 <<'MSG'
Could not detect a supported package manager.
Install Rust stable, C/C++ build tools, pkg-config, OpenSSL headers,
WebKitGTK 4.1 headers, Ayatana/AppIndicator headers, librsvg headers, and patchelf.
Then rerun this script with SKIP_SYSTEM_DEPS=1.
MSG
}

ensure_rust
install_system_dependencies

log "Checking project from $REPO_ROOT."
cargo check --locked --manifest-path "$REPO_ROOT/Cargo.toml"
log "Linux setup is ready."
