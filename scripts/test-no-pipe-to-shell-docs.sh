#!/usr/bin/env bash
# Fail if user-facing docs still recommend curl | bash / curl | sh installs.
# Pattern names like `curl | bash` without a URL are allowed; curl | shellsentry
# is allowed. Analysis fixtures live outside the scanned paths.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

# curl + URL + pipe to a shell. Does not match `curl | bash` as a pattern name
# or `curl ... | shellsentry`.
PATTERN='curl[^|[:cntrl:]]*https?://[^|[:cntrl:]]*\|[[:space:]]*(bash|sh|zsh|dash)\b'
PATTERN_POSIX='curl[^|]*https?://[^|]*[|][[:space:]]*(bash|sh|zsh|dash)([^a-zA-Z]|$)'

SCAN_PATHS=(
    README.md
    CHANGELOG.md
    RELEASE_NOTES.md
    RELEASE_CHECKLIST.md
    docs/releases
    scripts/install-shellsentry.sh
    internal/selfupdate/verify.go
)

have_rg=0
if command -v rg >/dev/null 2>&1; then
    have_rg=1
elif ! command -v grep >/dev/null 2>&1; then
    fail "ripgrep (rg) or grep required"
fi

scan() {
    local target="$1"
    if [ "$have_rg" -eq 1 ]; then
        rg -n --glob '!scripts/test-no-pipe-to-shell-docs.sh' "$PATTERN" "$target" || true
    elif [ -d "$target" ]; then
        grep -rEn --include='*' "$PATTERN_POSIX" "$target" || true
    else
        grep -nE "$PATTERN_POSIX" "$target" || true
    fi
}

found_in() {
    local out
    out="$(scan "$1")"
    [ -n "$out" ]
}

# Revert proof: restoring the v0.1.8 curl|bash upgrade line must be caught.
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-nopipe-docs.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
printf '%s\n' \
    'curl -sSfL https://github.com/3leaps/shellsentry/releases/download/v0.1.8/install-shellsentry.sh | bash -s -- --tag v0.1.8' \
    >"$scratch/reverted.md"
if found_in "$scratch/reverted.md"; then
    pass "scanner catches a reverted curl | bash install line"
else
    fail "scanner missed a reverted curl | bash install line"
fi
printf '%s\n' 'curl -fsSL https://example.com/install.sh | shellsentry' >"$scratch/analyze.md"
if found_in "$scratch/analyze.md"; then
    fail "scanner must not flag curl piped to shellsentry"
fi
printf '%s\n' '- `curl | bash` / `wget | sh` patterns' >"$scratch/name.md"
if found_in "$scratch/name.md"; then
    fail "scanner must not flag a pattern name without a URL"
fi
pass "scanner allows curl | shellsentry and pattern-name mentions"

# Live tree must be clean.
hits=""
for p in "${SCAN_PATHS[@]}"; do
    [ -e "$p" ] || fail "scan path missing: $p"
    chunk="$(scan "$p")"
    if [ -n "$chunk" ]; then
        hits="${hits}${chunk}"$'\n'
    fi
done
if [ -n "$hits" ]; then
    printf '%s' "$hits" >&2
    fail "docs must not recommend curl piped to a shell"
fi
pass "no curl | bash/sh install recipes in scanned docs"

echo "[ok] no pipe-to-shell install docs"
