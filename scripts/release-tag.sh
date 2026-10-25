#!/usr/bin/env bash
# Create and verify a signed annotated tag locally. Does not push.
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
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || die 'clean checkout required'
[[ -z "$(git show-ref --tags "refs/tags/$tag" || true)" ]] || die 'local tag already exists'

sign_home="$(mktemp -d "${TMPDIR:-/tmp}/shs-tag-sign.XXXXXX")"
cleanup() {
    if [[ -n "${sign_home:-}" ]]; then
        gpgconf --homedir "$sign_home" --kill all >/dev/null 2>&1 || true
        rm -rf "$sign_home"
    fi
}
trap cleanup EXIT
chmod 700 "$sign_home"
if ! gpg --homedir "$SHELLSENTRY_GPG_HOMEDIR" --batch --export-secret-keys "${SHELLSENTRY_PGP_KEY_ID%!}" 2>/dev/null |
    gpg --homedir "$sign_home" --batch --import >/dev/null 2>&1; then
    die 'cannot import signing material into isolated home'
fi
uid="$(gpg --homedir "$sign_home" --batch --with-colons --list-keys | awk -F: '$1=="uid" {print $10;exit}')"
[[ -n "$uid" ]] || die 'signing key has no uid'
name="${uid%% <*}"
email="${uid#*<}"
email="${email%>}"
export GIT_COMMITTER_NAME="$name" GIT_COMMITTER_EMAIL="$email"
export GNUPGHOME="$sign_home"
git -c gpg.format=openpgp -c gpg.program=gpg tag -s -a --cleanup=verbatim \
    -u "$SHELLSENTRY_PGP_KEY_ID" -m "shellsentry $tag" "$tag" HEAD
unset GNUPGHOME
"$root/scripts/verify-pinned-tag.sh"
echo '[ok] signed tag is local only'
