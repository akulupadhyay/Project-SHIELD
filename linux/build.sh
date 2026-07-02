#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOYMENT_BUILD="$REPO_ROOT/deployment/linux/build.sh"

if [[ ! -x "$DEPLOYMENT_BUILD" ]]; then
  echo "Missing executable deployment builder: $DEPLOYMENT_BUILD" >&2
  echo "Run from a complete repository checkout and ensure Git preserved executable bits." >&2
  exit 1
fi

exec "$DEPLOYMENT_BUILD" "$@"
