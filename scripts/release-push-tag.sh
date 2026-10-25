#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
# shellcheck source=scripts/release-ci-refuse.sh
source "$root/scripts/release-ci-refuse.sh"
# shellcheck source=scripts/release-tag-common.sh
source "$root/scripts/release-tag-common.sh"
cd "$tag_root"
tag_version
tag_origin
"$tag_root/scripts/verify-pinned-tag.sh"
"$tag_root/scripts/release-inspect-tag-ruleset.sh" "$SHELLSENTRY_RELEASE_TAG"
[[ -z "$(git ls-remote --tags origin "refs/tags/$SHELLSENTRY_RELEASE_TAG")" ]] || tag_die 'remote tag already exists'
git push origin "refs/tags/$SHELLSENTRY_RELEASE_TAG"
"$tag_root/scripts/release-verify-remote-tag.sh"
