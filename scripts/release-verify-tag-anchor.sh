#!/usr/bin/env bash
# Confirm a local tag is the origin tag GitHub reports verified, the tagged
# commit is an ancestor of origin/main, and identity files match origin/main.
# Usage: release-verify-tag-anchor.sh vX.Y.Z
set -euo pipefail
die() {
	echo "error: $*" >&2
	exit 1
}
tag="${1:-}"
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
	die 'usage: release-verify-tag-anchor.sh vX.Y.Z'
root="$(cd "$(dirname "$0")/.." && pwd -P)"
command -v gh >/dev/null 2>&1 || die 'gh (GitHub CLI) is required to confirm tag verification'
command -v python3 >/dev/null 2>&1 || die 'python3 is required to parse GitHub tag JSON'
object="$(git -C "$root" rev-parse --verify --quiet "refs/tags/$tag")" || die "tag $tag is missing"
[[ "$(git -C "$root" cat-file -t "$object")" == tag ]] || die 'annotated tag required'
commit="$(git -C "$root" rev-parse --verify --quiet "${tag}^{commit}")" || die "cannot peel tagged commit $tag"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die 'tagged commit is malformed'

remote_object="$(git -C "$root" ls-remote origin "refs/tags/$tag" | awk '{print $1}')"
[[ -n "$remote_object" && "$remote_object" == "$object" ]] ||
	die 'remote tag object differs from local tag'

tag_ref="$(gh api "repos/3leaps/shellsentry/git/ref/tags/$tag")"
python3 -c '
import json, sys
ref = json.loads(sys.argv[1])
obj = ref.get("object") or {}
if obj.get("type") != "tag" or obj.get("sha") != sys.argv[2]:
    raise SystemExit(1)
' "$tag_ref" "$object" || die 'GitHub tag ref mismatch'

tag_json="$(gh api "repos/3leaps/shellsentry/git/tags/$object")"
python3 -c '
import json, sys
payload = json.loads(sys.argv[1])
obj = payload.get("object") or {}
ver = payload.get("verification") or {}
if not (
    payload.get("tag") == sys.argv[2]
    and obj.get("type") == "commit"
    and obj.get("sha") == sys.argv[3]
    and ver.get("verified") is True
    and ver.get("reason") == "valid"
):
    raise SystemExit(1)
' "$tag_json" "$tag" "$commit" || die 'GitHub does not report a verified tag'

git -C "$root" rev-parse --verify --quiet origin/main >/dev/null ||
	die 'origin/main is missing'
git -C "$root" merge-base --is-ancestor "$commit" origin/main ||
	die 'tagged commit is not an ancestor of origin/main'

identity=(
	docs/security/release-signing-keys.asc
	docs/security/shellsentry-minisign.pub
	keys/expected-fingerprints.txt
	keys/expected-fingerprints.ndjson
)
for path in "${identity[@]}"; do
	tagged_blob="$(git -C "$root" rev-parse --verify --quiet "$commit:$path")" ||
		die "tagged commit missing $path"
	main_blob="$(git -C "$root" rev-parse --verify --quiet "origin/main:$path")" ||
		die "origin/main missing $path"
	[[ "$tagged_blob" == "$main_blob" ]] ||
		die "identity file $path on $tag differs from origin/main"
done
echo "[ok] $tag matches origin, GitHub verification, origin/main ancestry, and identity files"
