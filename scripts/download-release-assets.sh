#!/usr/bin/env bash
set -euo pipefail
TAG=${1:-${SHELLSENTRY_RELEASE_TAG:?usage: download-release-assets.sh <tag> [dest_dir]}}
DEST=${2:-dist/release}
mkdir -p "$DEST"
if ! command -v gh >/dev/null 2>&1; then
    echo "gh CLI is required (https://cli.github.com)" >&2
    exit 1
fi
echo "[download] Release assets for ${TAG} into ${DEST}"
gh release download "$TAG" --dir "$DEST" --clobber --pattern 'shellsentry_*' --pattern 'SHA256SUMS*' --pattern 'SHA2-512SUMS*' --pattern 'install-shellsentry.sh'
echo "[ok] Assets downloaded"
