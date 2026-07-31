#!/usr/bin/env bash
# Static coupling: workflow action SHA + version inputs match Makefile pins.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# shellcheck disable=SC1091
# Parse Makefile assignments (simple form).
get_make_var() {
    local name="$1"
    # Match := or = or ?= (escape ? for ERE)
    grep -E "^${name}[[:space:]]*(\\?=|:=|=)" Makefile | head -n1 |
        sed -E "s/^${name}[[:space:]]*(\\?=|:=|=)[[:space:]]*//" |
        tr -d '\r' | sed 's/[[:space:]]*#.*//' | tr -d '[:space:]'
}

WANT_VER="$(get_make_var SFETCH_VERSION)"
WANT_SHA="$(get_make_var SFETCH_ACTION_SHA)"
WANT_ENG_SHA="$(get_make_var SFETCH_ENGINE_SHA)"
WANT_ENG_SUM="$(get_make_var SFETCH_ENGINE_SHA256)"
WANT_GONEAT="$(get_make_var GONEAT_VERSION)"

[ -n "$WANT_VER" ] && [ -n "$WANT_SHA" ] || {
    echo "error: missing Makefile pins" >&2
    exit 1
}

# Action uses: must be exactly @SHA (four jobs)
uses_count="$(grep -cE "uses:[[:space:]]*3leaps/sfetch/\.github/actions/setup-sfetch@${WANT_SHA}" .github/workflows/ci.yml || true)"
if [ "$uses_count" -lt 4 ]; then
    echo "error: expected >=4 setup-sfetch@${WANT_SHA} uses; found ${uses_count}" >&2
    grep -n 'setup-sfetch@' .github/workflows/ci.yml || true
    exit 1
fi

# sfetch-version inputs must match pin (no floating)
if grep -nE 'sfetch-version:' .github/workflows/ci.yml | grep -v "sfetch-version: ${WANT_VER}"; then
    echo "error: sfetch-version input does not match Makefile SFETCH_VERSION=${WANT_VER}" >&2
    exit 1
fi
ver_count="$(grep -cE "sfetch-version:[[:space:]]*${WANT_VER}" .github/workflows/ci.yml || true)"
if [ "$ver_count" -lt 4 ]; then
    echo "error: expected >=4 sfetch-version: ${WANT_VER}; found ${ver_count}" >&2
    exit 1
fi

# Workflow env copies (if present) must agree
if grep -qE '^[[:space:]]*SFETCH_ACTION_SHA:' .github/workflows/ci.yml; then
    if ! grep -qE "SFETCH_ACTION_SHA:[[:space:]]*${WANT_SHA}" .github/workflows/ci.yml; then
        echo "error: workflow SFETCH_ACTION_SHA != Makefile" >&2
        exit 1
    fi
fi
if grep -qE '^[[:space:]]*SFETCH_VERSION:' .github/workflows/ci.yml; then
    if ! grep -qE "SFETCH_VERSION:[[:space:]]*${WANT_VER}" .github/workflows/ci.yml; then
        echo "error: workflow SFETCH_VERSION != Makefile" >&2
        exit 1
    fi
fi

# Engine pins used by install-sfetch-verified.sh path must be non-empty hex
if ! [[ "$WANT_ENG_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
    echo "error: SFETCH_ENGINE_SHA must be 40-char hex" >&2
    exit 1
fi
if ! [[ "$WANT_ENG_SUM" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "error: SFETCH_ENGINE_SHA256 must be 64-char hex" >&2
    exit 1
fi
# Prefer action SHA == engine SHA for this train (single reviewable commit)
if [ "$WANT_SHA" != "$WANT_ENG_SHA" ]; then
    echo "error: SFETCH_ACTION_SHA (${WANT_SHA}) != SFETCH_ENGINE_SHA (${WANT_ENG_SHA})" >&2
    exit 1
fi

# Anchor constant present (documentative; engine embeds its own)
if ! grep -qE '^SFETCH_MINISIGN_PUBKEY[[:space:]]*:?=' Makefile; then
    echo "error: SFETCH_MINISIGN_PUBKEY missing from Makefile (reviewable anchor pin)" >&2
    exit 1
fi

echo "[ok] sfetch pin coupling: ver=${WANT_VER} action/engine=${WANT_SHA} goneat=${WANT_GONEAT} uses=${uses_count}"
