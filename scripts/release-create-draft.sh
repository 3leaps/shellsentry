#!/usr/bin/env bash
# Create the draft GitHub release from locally staged packages.
# Runs on the maintainer machine only; CI holds no write authority.
# Usage: release-create-draft.sh vX.Y.Z [source_dir]
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
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
	die 'usage: release-create-draft.sh vX.Y.Z [source_dir]'
command -v gh >/dev/null 2>&1 || die 'gh (GitHub CLI) not found in PATH'
[[ -d "$src" && ! -L "$src" ]] || die "source dir not found: $src"
expected=(
	shellsentry_linux_amd64.tar.gz
	shellsentry_linux_arm64.tar.gz
	shellsentry_windows_amd64.zip
	shellsentry_windows_arm64.zip
	shellsentry_darwin_arm64.tar.gz
	install-shellsentry.sh
	SHA256SUMS
	SHA512SUMS
)
while IFS= read -r -d '' entry; do
	name="${entry##*/}"
	allowed=0
	for want in "${expected[@]}"; do
		[[ "$name" == "$want" ]] && allowed=1
	done
	[[ "$allowed" == 1 ]] || die "unexpected file in $src: $name"
	[[ -f "$entry" && ! -L "$entry" ]] || die "not a regular file: $name"
done < <(find "$src" -mindepth 1 -maxdepth 1 -print0)
for want in "${expected[@]}"; do
	[[ -f "$src/$want" && -s "$src/$want" ]] || die "missing release file: $want"
done
if gh release view "$tag" --repo 3leaps/shellsentry >/dev/null 2>&1; then
	die "a release for $tag already exists; do not replace it"
fi
notes="$root/docs/releases/${tag}.md"
[[ -f "$notes" && ! -L "$notes" && -s "$notes" ]] || die "missing release notes: docs/releases/${tag}.md"
files=()
for want in "${expected[@]}"; do
	files+=("$src/$want")
done
gh release create "$tag" --repo 3leaps/shellsentry --verify-tag --draft \
	--title "$tag" --notes-file "$notes" "${files[@]}"
echo "[ok] draft release $tag created from staged packages"
