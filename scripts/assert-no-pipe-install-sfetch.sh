#!/usr/bin/env bash
# Fail if Makefile / .github / scripts still pipe install-sfetch.sh to bash/sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Exclude this assertion script; scan Makefile, workflows, and scripts/.
# Multiline: curl ... install-sfetch on one line, | bash on the next.
if rg -n --multiline --glob '!scripts/assert-no-pipe-install-sfetch.sh' \
    'install-sfetch\.sh[\s\S]{0,200}\|\s*(bash|sh)|curl[^\n|]*install-sfetch\.sh[^\n|]*\|' \
    Makefile .github scripts 2>/dev/null; then
    echo "error: found pipe-to-bash/sh for install-sfetch.sh (use verified bootstrap)" >&2
    exit 1
fi
echo "[ok] no install-sfetch.sh pipe-to-shell in Makefile/.github/scripts"
