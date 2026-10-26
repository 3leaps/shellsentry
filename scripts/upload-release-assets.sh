#!/usr/bin/env bash
# Upload signed assets to an existing draft GitHub release. Does not publish.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
# shellcheck source=scripts/release-ci-refuse.sh
source "$root/scripts/release-ci-refuse.sh"
TAG=${1:-${SHELLSENTRY_RELEASE_TAG:?usage: upload-release-assets.sh <tag> [dir]}}
DIR=${2:-dist/release}
if ! command -v gh >/dev/null 2>&1; then
    echo "gh CLI is required" >&2
    exit 1
fi
if [ ! -d "$DIR" ]; then
    echo "directory $DIR not found" >&2
    exit 1
fi
NOTES_FILE="$DIR/release-notes-${TAG}.md"
if [ ! -f "$NOTES_FILE" ]; then
    echo "release notes file $NOTES_FILE not found" >&2
    exit 1
fi
is_draft="$(gh release view "$TAG" --json isDraft --jq .isDraft)"
if [ "$is_draft" != true ]; then
    echo "error: $TAG is not a draft; refusing to upload (promotion is release-publish)" >&2
    exit 1
fi
shopt -s nullglob
ARTIFACTS=()
for f in "$DIR"/shellsentry_* "$DIR"/SHA256SUMS "$DIR"/SHA512SUMS "$DIR"/install-shellsentry.sh; do
    [[ -f "$f" ]] && ARTIFACTS+=("$f")
done
SIGNATURES=()
for f in "$DIR"/SHA256SUMS.minisig "$DIR"/SHA256SUMS.asc "$DIR"/SHA512SUMS.minisig "$DIR"/SHA512SUMS.asc "$DIR"/*-minisign.pub "$DIR"/*-signing-key.asc; do
    [[ -f "$f" ]] && SIGNATURES+=("$f")
done
if [ ${#ARTIFACTS[@]} -eq 0 ]; then
    echo "no artifacts to upload" >&2
    exit 1
fi
echo "[upload] Binaries/checksums for ${TAG}"
gh release upload "$TAG" "${ARTIFACTS[@]}" --clobber
echo "[upload] Signatures and keys"
if [ ${#SIGNATURES[@]} -gt 0 ]; then
    gh release upload "$TAG" "${SIGNATURES[@]}" --clobber
else
    echo "[warn] No signature files found; skipping"
fi
echo "[upload] Release notes asset"
gh release upload "$TAG" "$NOTES_FILE" --clobber
echo "[notes] Updating release notes (draft preserved)"
gh release edit "$TAG" --notes-file "$NOTES_FILE" --draft=true
echo "[ok] Draft release updated"
