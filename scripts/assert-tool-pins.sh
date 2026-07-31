#!/usr/bin/env bash
# Exact pin assertions for sfetch / goneat (stderr-aware).
# Uses scripts/version-matches-pin.sh — rejects soft substrings like 0.4.110.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SFETCH_PIN="${1:-}"
GONEAT_PIN="${2:-}"
if [ -z "$SFETCH_PIN" ] || [ -z "$GONEAT_PIN" ]; then
    echo "usage: assert-tool-pins.sh <sfetch-pin> <goneat-pin>" >&2
    exit 2
fi

SFETCH_BIN="${SFETCH_BIN:-}"
if [ -z "$SFETCH_BIN" ]; then
    if [ -x "$ROOT/bin/sfetch" ]; then
        SFETCH_BIN="$ROOT/bin/sfetch"
    elif [ -x "$ROOT/bin/sfetch.exe" ]; then
        SFETCH_BIN="$ROOT/bin/sfetch.exe"
    else
        SFETCH_BIN="$(command -v sfetch 2>/dev/null || true)"
    fi
fi
GONEAT_BIN="${GONEAT_BIN:-}"
if [ -z "$GONEAT_BIN" ]; then
    if [ -x "$ROOT/bin/goneat" ]; then
        GONEAT_BIN="$ROOT/bin/goneat"
    elif [ -x "$ROOT/bin/goneat.exe" ]; then
        GONEAT_BIN="$ROOT/bin/goneat.exe"
    else
        GONEAT_BIN="$(command -v goneat 2>/dev/null || true)"
    fi
fi

[ -n "$SFETCH_BIN" ] && [ -x "$SFETCH_BIN" ] || {
    echo "error: sfetch binary not found (clean-runner expects install-dir/bin)" >&2
    exit 1
}
[ -n "$GONEAT_BIN" ] && [ -x "$GONEAT_BIN" ] || {
    echo "error: goneat binary not found" >&2
    exit 1
}

# Prefer repo-local tools over ambient PATH when asserting clean install.
case "$SFETCH_BIN" in
    "$ROOT/bin"/*) ;;
    *)
        echo "warning: sfetch not under $ROOT/bin ($SFETCH_BIN); clean-runner premise weak" >&2
        ;;
esac

SF_OUT="$("$SFETCH_BIN" --version 2>&1 | head -n1)"
if ! ./scripts/version-matches-pin.sh "$SF_OUT" "$SFETCH_PIN"; then
    echo "error: sfetch version mismatch (exact token)" >&2
    echo "  have: $SF_OUT" >&2
    echo "  want: $SFETCH_PIN" >&2
    exit 1
fi

GN_OUT="$("$GONEAT_BIN" version 2>&1 | head -n1)"
if ! ./scripts/version-matches-pin.sh "$GN_OUT" "$GONEAT_PIN"; then
    echo "error: goneat version mismatch (exact token)" >&2
    echo "  have: $GN_OUT" >&2
    echo "  want: $GONEAT_PIN" >&2
    exit 1
fi

echo "[ok] exact pins: sfetch=${SFETCH_PIN} goneat=${GONEAT_PIN}"
