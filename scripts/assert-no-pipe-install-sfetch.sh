#!/usr/bin/env bash
# Fail if any workflow/Makefile still pipes install-sfetch.sh to bash/sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Match common pipe-to-shell patterns for the sfetch installer.
if rg -n --glob '!scripts/assert-no-pipe-install-sfetch.sh' \
    'install-sfetch\.sh.*\|\s*(bash|sh)|curl[^|]*install-sfetch\.sh[^|]*\|' \
    Makefile .github/workflows 2>/dev/null; then
    echo "error: found pipe-to-bash/sh for install-sfetch.sh (use verified bootstrap)" >&2
    exit 1
fi
echo "[ok] no install-sfetch.sh pipe-to-shell in Makefile/.github/workflows"
