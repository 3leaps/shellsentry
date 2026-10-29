#!/usr/bin/env bash
# Create and verify a signed annotated tag locally. Does not push.
# Signs in the operator GPG home so hardware-backed / non-exportable subkeys
# work. Does not export secret keys. Public-pin verification uses a disposable
# keyring in verify-pinned-tag.sh; this script never kills the operator agent.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
# shellcheck source=scripts/release-ci-refuse.sh
source "$root/scripts/release-ci-refuse.sh"
# shellcheck source=scripts/release-tag-common.sh
source "$root/scripts/release-tag-common.sh"
cd "$tag_root"
tag_version
tag_identity
tag_key_selector
tag_checkout
"$tag_root/scripts/release-require-native-ci.sh" "$(git rev-parse HEAD)"
[[ -z "$(git ls-remote --tags origin "refs/tags/$SHELLSENTRY_RELEASE_TAG")" ]] || tag_die 'remote tag already exists'
[[ -z "$(git show-ref --tags "refs/tags/$SHELLSENTRY_RELEASE_TAG" || true)" ]] || tag_die 'local tag already exists'
message="$(mktemp)"
trap 'rm -f "$message"' EXIT
tag_expected_message >"$message"
export GIT_COMMITTER_NAME="$SHELLSENTRY_TAGGER_NAME" GIT_COMMITTER_EMAIL="$SHELLSENTRY_TAGGER_EMAIL"
# Bind GNUPGHOME to the operator home for this signing only. Hardware-backed
# subkeys cannot be exported into a throwaway keyring.
export GNUPGHOME="$SHELLSENTRY_GPG_HOMEDIR"
# Host git may be configured for SSH signing (gpg.format=ssh). Force OpenPGP
# so the committed pin, not an SSH key, is what signs the tag.
# verbatim keeps the message bytes; the trailing newline is required so git
# does not concatenate the PGP signature onto the last line of the message.
git -c gpg.format=openpgp -c gpg.program=gpg tag -s -a --cleanup=verbatim \
	-u "$SHELLSENTRY_PGP_KEY_ID" -F "$message" "$SHELLSENTRY_RELEASE_TAG" HEAD
unset GNUPGHOME
"$tag_root/scripts/verify-pinned-tag.sh"
echo '[ok] signed tag is local only'
