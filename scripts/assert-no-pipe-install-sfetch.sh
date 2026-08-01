#!/usr/bin/env bash
# Fail if Makefile / .github / scripts still pipe install-sfetch.sh to bash/sh.
#
# Fail-closed on missing searcher: a missing rg must not green-path the guard
# (if-condition on exit 127 was previously treated as "no match").
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PATTERN='install-sfetch\.sh[\s\S]{0,200}\|\s*(bash|sh)|curl[^\n|]*install-sfetch\.sh[^\n|]*\|'
# POSIX-ish single-line fallback (no multiline); still catches same-line pipes.
PATTERN_POSIX='install-sfetch\.sh.*\|[[:space:]]*(bash|sh)|curl[^|]*install-sfetch\.sh[^|]*\|'

have_rg=0
have_grep=0
if command -v rg >/dev/null 2>&1; then
    have_rg=1
elif command -v grep >/dev/null 2>&1; then
    have_grep=1
else
    echo "error: ripgrep (rg) or grep required for no-pipe guard" >&2
    exit 1
fi

# Returns 0 if a violation is found, 1 if clean.
scan_for_pipe() {
    local target="$1"
    if [ "$have_rg" -eq 1 ]; then
        # Exclude this assertion script when scanning the real tree.
        if [ "$target" = "." ]; then
            rg -n --multiline --glob '!scripts/assert-no-pipe-install-sfetch.sh' \
                "$PATTERN" Makefile .github scripts 2>/dev/null
        else
            rg -n --multiline "$PATTERN" "$target" 2>/dev/null
        fi
    else
        # grep -rE: no multiline; still catches same-line constructions.
        if [ "$target" = "." ]; then
            grep -rEn --include='*' "$PATTERN_POSIX" Makefile .github scripts 2>/dev/null |
                grep -v 'scripts/assert-no-pipe-install-sfetch.sh' || true
        else
            grep -rEn "$PATTERN_POSIX" "$target" 2>/dev/null || true
        fi
        # Normalize: grep returns 1 on no match; we need found=0 exit for caller via output
        return 0
    fi
}

# --- Self-test: planted violation must fail the guard (non-vacuous) ---
self_test() {
    local t
    t="$(mktemp -d "${TMPDIR:-/tmp}/shs-nopipe-self.XXXXXX")"
    printf 'curl -fsSL https://example.invalid/install-sfetch.sh | bash\n' >"$t/evil.sh"
    local found=0
    if [ "$have_rg" -eq 1 ]; then
        if rg -n --multiline "$PATTERN" "$t" >/dev/null 2>&1; then
            found=1
        fi
    else
        if grep -rEn "$PATTERN_POSIX" "$t" >/dev/null 2>&1; then
            found=1
        fi
    fi
    rm -rf "$t"
    if [ "$found" -ne 1 ]; then
        echo "error: no-pipe guard self-test failed (planted violation not detected)" >&2
        exit 1
    fi
}

self_test

# --- Real tree scan ---
if [ "$have_rg" -eq 1 ]; then
    if rg -n --multiline --glob '!scripts/assert-no-pipe-install-sfetch.sh' \
        "$PATTERN" Makefile .github scripts 2>/dev/null; then
        echo "error: found pipe-to-bash/sh for install-sfetch.sh (use verified bootstrap)" >&2
        exit 1
    fi
else
    # shellcheck disable=SC2063
    matches="$(grep -rEn "$PATTERN_POSIX" Makefile .github scripts 2>/dev/null | grep -v 'scripts/assert-no-pipe-install-sfetch.sh' || true)"
    if [ -n "$matches" ]; then
        echo "$matches" >&2
        echo "error: found pipe-to-bash/sh for install-sfetch.sh (use verified bootstrap)" >&2
        exit 1
    fi
fi

echo "[ok] no install-sfetch.sh pipe-to-shell in Makefile/.github/scripts (searcher=$(command -v rg || command -v grep))"
