#!/usr/bin/env bash
# Informational pin freshness probe — soft-fail only.
# Does NOT perform authenticity verification. Do not "harmonise" with fail-closed bootstrap.
set -euo pipefail

PIN="${1:-}"
if [ -z "$PIN" ]; then
    echo "usage: check-sfetch-pin-freshness.sh <pinned-tag>" >&2
    exit 2
fi

case "$PIN" in
    latest | LATEST)
        echo "error: freshness probe refuses floating pin 'latest'" >&2
        exit 1
        ;;
esac

if ! command -v curl >/dev/null 2>&1; then
    echo "::warning::sfetch pin freshness: curl missing; skipped"
    exit 0
fi

# Latest non-draft release tag via GitHub API (best-effort).
API="https://api.github.com/repos/3leaps/sfetch/releases/latest"
LATEST="$(curl -fsSL "$API" 2>/dev/null | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1 || true)"
if [ -z "$LATEST" ]; then
    echo "::warning::sfetch pin freshness: could not resolve latest release; pin is ${PIN}"
    exit 0
fi

if [ "$PIN" = "$LATEST" ]; then
    echo "[ok] sfetch pin ${PIN} matches latest release ${LATEST}"
    exit 0
fi

# Soft-fail: warn only (exit 0) so authenticity gates stay fail-closed elsewhere.
echo "::warning::sfetch pin ${PIN} is behind latest ${LATEST} (informational only; bootstrap remains fail-closed)"
exit 0
