#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export SECURE_VAULT_ROOT="${SECURE_VAULT_ROOT:-$REPO_ROOT}"
cd "$REPO_ROOT"
cargo run --locked
