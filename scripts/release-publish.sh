#!/usr/bin/env bash
# Promote a draft GitHub release only after draft assets match local SHA256SUMS.
# Maintainer machine only. Never run with CI credentials.
#
# Usage: release-publish.sh vX.Y.Z [source_dir]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
# shellcheck source=scripts/release-ci-refuse.sh
source "$root/scripts/release-ci-refuse.sh"
die() {
    echo "error: $*" >&2
    exit 1
}
tag="${1:-}"
src="${2:-dist/release}"
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die 'usage: release-publish.sh vX.Y.Z [source_dir]'
[[ -d "$src" && ! -L "$src" ]] || die "source dir not found: $src"
for tool in gh jq cmp git; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool not found in PATH"
done
sums="$src/SHA256SUMS"
[[ -f "$sums" && -s "$sums" && ! -L "$sums" ]] || die 'local SHA256SUMS required'
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$src" && sha256sum -c SHA256SUMS >/dev/null) || die 'local files do not match SHA256SUMS'
else
    (cd "$src" && shasum -a 256 -c SHA256SUMS >/dev/null) || die 'local files do not match SHA256SUMS'
fi
packages=()
while read -r _ name; do
    name="${name#\*}"
    [[ -n "$name" ]] || continue
    packages+=("$name")
done <"$sums"
[[ "${#packages[@]}" -gt 0 ]] || die 'SHA256SUMS lists no files'
repo="${SHELLSENTRY_RELEASE_REPO:-3leaps/shellsentry}"
release="$(gh release view "$tag" --repo "$repo" --json isDraft,assets)" || die "no release for $tag"
[[ "$(jq -r '.isDraft' <<<"$release")" == true ]] || die "$tag is not a draft; refusing to re-promote"

fresh="$(mktemp -d "${TMPDIR:-/tmp}/shs-publish.XXXXXX")"
trap 'rm -rf "$fresh"' EXIT
gh release download "$tag" --repo "$repo" --dir "$fresh" >/dev/null || die 'could not download the draft assets'
cmp -s "$fresh/SHA256SUMS" "$sums" || die 'draft SHA256SUMS differs from the local file'
for want in "${packages[@]}"; do
    [[ -f "$fresh/$want" ]] || die "draft missing asset listed in SHA256SUMS: $want"
    cmp -s "$fresh/$want" "$src/$want" || die "draft asset differs from the verified local file: $want"
done

pre_promote="$(gh release view "$tag" --repo "$repo" --json isDraft)" || die "no release for $tag"
[[ "$(jq -r '.isDraft' <<<"$pre_promote")" == true ]] || die "$tag is not a draft immediately before promote"
gh release edit "$tag" --repo "$repo" --draft=false >/dev/null
echo "[ok] $tag published from ${#packages[@]} byte-verified SHA256SUMS asset(s)"
