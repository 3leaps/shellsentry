#!/usr/bin/env bash
# Maintainer tagging stays local: signed annotated tags, no push, no CI.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

TAG_SH="$ROOT/scripts/release-tag.sh"
PUB_SH="$ROOT/scripts/release-publish.sh"
REFUSE="$ROOT/scripts/release-ci-refuse.sh"
[ -f "$TAG_SH" ] && [ -f "$PUB_SH" ] && [ -f "$REFUSE" ] || fail "release-tag/publish/refuse scripts missing"

grep -q 'release-ci-refuse.sh' "$TAG_SH" || fail "release-tag.sh must source the CI refuse"
grep -q 'release-ci-refuse.sh' "$PUB_SH" || fail "release-publish.sh must source the CI refuse"
grep -q 'tag -s -a' "$TAG_SH" || fail "release-tag.sh must create a signed annotated tag"
if grep -nE 'git[[:space:]]+push\b' "$TAG_SH"; then
    fail "release-tag.sh must not push"
fi
pass "release-tag is signed, local, and refuses CI"

# Mutant: unsigned tag or a push must be caught.
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-tag-ctrl.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
sed 's/tag -s -a/tag -a/' "$TAG_SH" >"$scratch/unsigned.sh"
if grep -q 'tag -s -a' "$scratch/unsigned.sh"; then
    fail "unsigned mutant still contains tag -s -a"
fi
grep -q 'tag -s -a' "$TAG_SH" || fail "live script lost tag -s -a"
pass "grep rejects an unsigned-tag mutant"

printf '%s\n' 'git push origin "$tag"' >>"$scratch/unsigned.sh"
if grep -nE 'git[[:space:]]+push\b' "$scratch/unsigned.sh" >/dev/null &&
    ! grep -nE 'git[[:space:]]+push\b' "$TAG_SH" >/dev/null; then
    pass "grep rejects a git-push mutant"
else
    fail "git-push mutant was not distinguished from the live script"
fi

# Live GITHUB_ACTIONS refuse (message-specific so a later env-var failure is not a pass).
out="$(GITHUB_ACTIONS=true "$TAG_SH" 2>&1)" && fail "release-tag.sh must refuse GitHub Actions"
echo "$out" | grep -q 'refuse GitHub Actions' || {
    echo "$out" >&2
    fail "release-tag.sh must name the GitHub Actions refuse"
}
out="$(GITHUB_ACTIONS=true "$PUB_SH" v0.0.0 2>&1)" && fail "release-publish.sh must refuse GitHub Actions"
echo "$out" | grep -q 'refuse GitHub Actions' || {
    echo "$out" >&2
    fail "release-publish.sh must name the GitHub Actions refuse"
}
out="$(GITHUB_ACTIONS=true "$ROOT/scripts/upload-release-assets.sh" v0.0.0 2>&1)" &&
    fail "upload-release-assets.sh must refuse GitHub Actions"
echo "$out" | grep -q 'refuse GitHub Actions' || {
    echo "$out" >&2
    fail "upload-release-assets.sh must name the GitHub Actions refuse"
}
pass "maintainer scripts refuse GitHub Actions"

# Mutant: dropping the refuse must lose that message.
sed '/release-ci-refuse/d' "$TAG_SH" >"$scratch/no-refuse.sh"
chmod +x "$scratch/no-refuse.sh"
if GITHUB_ACTIONS=true bash "$scratch/no-refuse.sh" 2>"$scratch/no-refuse.err"; then
    :
fi
if grep -q 'refuse GitHub Actions' "$scratch/no-refuse.err"; then
    fail "stripped refuse mutant still reported the CI refuse"
fi
pass "CI-refuse mutant no longer reports the refuse"

# Isolated GPG home: default homedir and in-repo paths are refused before signing.
unset GITHUB_ACTIONS || true
file_version="$(tr -d ' \n' <VERSION)"
export SHELLSENTRY_RELEASE_TAG="v${file_version}"
export SHELLSENTRY_PGP_KEY_ID=0123456789ABCDEF0123456789ABCDEF01234567!
fake_home="$scratch/home"
mkdir -p "$fake_home/.gnupg"
chmod 700 "$fake_home/.gnupg"
export HOME="$fake_home"
export SHELLSENTRY_GPG_HOMEDIR="$fake_home/.gnupg"
out="$("$TAG_SH" 2>&1)" && fail "release-tag.sh must refuse the default gnupg homedir"
echo "$out" | grep -q 'must not be the default homedir' || {
    echo "$out" >&2
    fail "default homedir refusal (got the log above)"
}
pass "default GPG homedir is refused"

in_repo="$ROOT/dist/.gpg-home-test"
mkdir -p "$in_repo"
chmod 700 "$in_repo"
cleanup_in_repo() { rm -rf "$in_repo" "$scratch"; }
trap cleanup_in_repo EXIT
export SHELLSENTRY_GPG_HOMEDIR="$in_repo"
out="$("$TAG_SH" 2>&1)" && fail "release-tag.sh must refuse a GPG home inside the repository"
echo "$out" | grep -q 'outside the repository' || {
    echo "$out" >&2
    fail "in-repo GPG home refusal (got the log above)"
}
pass "in-repo GPG home is refused"

echo "[ok] release-tag controls"
