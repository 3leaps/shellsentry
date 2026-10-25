#!/usr/bin/env bash
# Create and verify a signed annotated tag locally. Does not push.
# Signs in the operator GPG home so hardware-backed / non-exportable subkeys
# work. Does not export secret keys. Public-pin verification uses a disposable
# keyring in verify-pinned-tag.sh; this script never kills the operator agent.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
# shellcheck source=scripts/release-ci-refuse.sh
source "$root/scripts/release-ci-refuse.sh"
cd "$root"

die() {
    echo "error: $*" >&2
    exit 1
}

tag="${SHELLSENTRY_RELEASE_TAG:-}"
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die 'canonical SHELLSENTRY_RELEASE_TAG vX.Y.Z required'
[[ "$tag" == "v$(tr -d ' \n' <VERSION)" ]] || die "release tag must match VERSION (want v$(tr -d ' \n' <VERSION))"
[[ "${SHELLSENTRY_PGP_KEY_ID:-}" =~ ^[0-9A-F]{40}!$ ]] || die 'SHELLSENTRY_PGP_KEY_ID must be the uppercase signing subkey fingerprint with !'
[[ -n "${SHELLSENTRY_GPG_HOMEDIR:-}" && -d "$SHELLSENTRY_GPG_HOMEDIR" && ! -L "$SHELLSENTRY_GPG_HOMEDIR" ]] ||
    die 'SHELLSENTRY_GPG_HOMEDIR must be an isolated directory (not a symlink)'
case "$SHELLSENTRY_GPG_HOMEDIR" in
    "$root" | "$root"/*) die 'GPG home must be outside the repository' ;;
esac
[[ "$SHELLSENTRY_GPG_HOMEDIR" != "${HOME:-/}/.gnupg" ]] || die 'GPG home must not be the default homedir'
mode="$(stat -c '%a' "$SHELLSENTRY_GPG_HOMEDIR" 2>/dev/null || stat -f '%OLp' "$SHELLSENTRY_GPG_HOMEDIR")"
[[ "$mode" == "700" ]] || die 'GPG home must be mode 0700'
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || die 'clean checkout required'
[[ -z "$(git show-ref --tags "refs/tags/$tag" || true)" ]] || die 'local tag already exists'

uid="$(gpg --homedir "$SHELLSENTRY_GPG_HOMEDIR" --batch --with-colons --list-keys "${SHELLSENTRY_PGP_KEY_ID%!}" |
    awk -F: '$1=="uid" {print $10;exit}')"
[[ -n "$uid" ]] || die 'signing key has no uid'
name="${uid%% <*}"
email="${uid#*<}"
email="${email%>}"
export GIT_COMMITTER_NAME="$name" GIT_COMMITTER_EMAIL="$email"
# Bind GNUPGHOME to the operator home for this signing only. Hardware-backed
# subkeys cannot be exported into a throwaway keyring.
export GNUPGHOME="$SHELLSENTRY_GPG_HOMEDIR"
# verbatim keeps the message bytes; the trailing newline is required so git
# does not concatenate the PGP signature onto the last line of the message.
git -c gpg.format=openpgp -c gpg.program=gpg tag -s -a --cleanup=verbatim \
    -u "$SHELLSENTRY_PGP_KEY_ID" -m "shellsentry $tag"$'\n' "$tag" HEAD
unset GNUPGHOME
"$root/scripts/verify-pinned-tag.sh"
echo '[ok] signed tag is local only'
