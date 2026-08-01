#!/usr/bin/env bash
# Static coupling: workflow action SHA + version inputs match Makefile pins.
# Exactly four setup-sfetch uses; every ref must equal the reviewed SHA.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

get_make_var() {
    local name="$1"
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

# Every setup-sfetch use (any ref)
total_uses="$(grep -cE 'uses:[[:space:]]*3leaps/sfetch/\.github/actions/setup-sfetch@' .github/workflows/ci.yml || true)"
if [ "$total_uses" -ne 4 ]; then
    echo "error: expected exactly 4 setup-sfetch uses; found ${total_uses}" >&2
    grep -n 'setup-sfetch@' .github/workflows/ci.yml || true
    exit 1
fi

# Every use must be the reviewed SHA (reject extras with wrong/floating refs)
bad_uses="$(grep -nE 'uses:[[:space:]]*3leaps/sfetch/\.github/actions/setup-sfetch@' .github/workflows/ci.yml |
    grep -v "setup-sfetch@${WANT_SHA}" || true)"
if [ -n "$bad_uses" ]; then
    echo "error: setup-sfetch use(s) with wrong/floating ref (want @${WANT_SHA}):" >&2
    echo "$bad_uses" >&2
    exit 1
fi

correct_uses="$(grep -cE "uses:[[:space:]]*3leaps/sfetch/\.github/actions/setup-sfetch@${WANT_SHA}" .github/workflows/ci.yml || true)"
if [ "$correct_uses" -ne 4 ]; then
    echo "error: expected exactly 4 setup-sfetch@${WANT_SHA}; found ${correct_uses}" >&2
    exit 1
fi

# Every sfetch-version input must match pin
ver_lines="$(grep -nE 'sfetch-version:' .github/workflows/ci.yml || true)"
if [ -z "$ver_lines" ]; then
    echo "error: no sfetch-version inputs found" >&2
    exit 1
fi
bad_ver="$(echo "$ver_lines" | grep -v "sfetch-version: ${WANT_VER}" || true)"
if [ -n "$bad_ver" ]; then
    echo "error: sfetch-version input does not match Makefile SFETCH_VERSION=${WANT_VER}:" >&2
    echo "$bad_ver" >&2
    exit 1
fi
ver_count="$(grep -cE "sfetch-version:[[:space:]]*${WANT_VER}" .github/workflows/ci.yml || true)"
if [ "$ver_count" -ne 4 ]; then
    echo "error: expected exactly 4 sfetch-version: ${WANT_VER}; found ${ver_count}" >&2
    exit 1
fi

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

if ! [[ "$WANT_ENG_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
    echo "error: SFETCH_ENGINE_SHA must be 40-char hex" >&2
    exit 1
fi
if ! [[ "$WANT_ENG_SUM" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "error: SFETCH_ENGINE_SHA256 must be 64-char hex" >&2
    exit 1
fi
if [ "$WANT_SHA" != "$WANT_ENG_SHA" ]; then
    echo "error: SFETCH_ACTION_SHA (${WANT_SHA}) != SFETCH_ENGINE_SHA (${WANT_ENG_SHA})" >&2
    exit 1
fi

if ! grep -qE '^SFETCH_MINISIGN_PUBKEY[[:space:]]*:?=' Makefile; then
    echo "error: SFETCH_MINISIGN_PUBKEY missing from Makefile (reviewable anchor pin)" >&2
    exit 1
fi

echo "[ok] sfetch pin coupling: ver=${WANT_VER} action/engine=${WANT_SHA} goneat=${WANT_GONEAT} uses=${correct_uses}/4 exact"
