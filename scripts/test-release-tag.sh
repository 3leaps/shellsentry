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
if grep -nE -- '--export-secret-(keys|subkeys)' "$TAG_SH"; then
    fail "release-tag.sh must not export secret keys"
fi
grep -Fq 'export GNUPGHOME="$SHELLSENTRY_GPG_HOMEDIR"' "$TAG_SH" ||
    fail "release-tag.sh must bind GNUPGHOME to the operator home"
grep -Fq 'GIT_COMMITTER_NAME="$SHELLSENTRY_TAGGER_NAME"' "$TAG_SH" ||
    fail "release-tag.sh must tag as SHELLSENTRY_TAGGER_NAME, not the first GPG UID"
if grep -nE 'uid="\$\(gpg' "$TAG_SH"; then
    fail "release-tag.sh must not take the tagger from the first GPG UID"
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
export SHELLSENTRY_GPG_SIGNING_FINGERPRINT="$(awk '$1=="gpg" {print $2}' "$ROOT/keys/expected-fingerprints.txt")"
export SHELLSENTRY_TAGGER_NAME='3 Leaps Infosec Team'
export SHELLSENTRY_TAGGER_EMAIL='infosec@3leaps.net'
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

# HOME itself is a symlink; GPG_HOMEDIR is the physical default keyring.
# The refusal must resolve both sides (macOS /var, tests). Do not weaken ! -L.
real_home="$scratch/real-home"
mkdir -p "$real_home/.gnupg"
chmod 700 "$real_home/.gnupg"
ln -s "$real_home" "$scratch/home-link"
export HOME="$scratch/home-link"
phys_gnupg="$(CDPATH= cd -P -- "$real_home/.gnupg" && pwd -P)"
export SHELLSENTRY_GPG_HOMEDIR="$phys_gnupg"
[[ ! -L "$SHELLSENTRY_GPG_HOMEDIR" ]] || fail "fixture GPG home itself must not be a symlink"
[[ "$SHELLSENTRY_GPG_HOMEDIR" != "${HOME}/.gnupg" ]] || fail "fixture must keep HOME unresolved so only phys-dir compare catches it"
out="$("$TAG_SH" 2>&1)" && fail "release-tag.sh must refuse the default homedir when HOME is a symlink"
echo "$out" | grep -q 'must not be the default homedir' || {
	echo "$out" >&2
	fail "HOME-symlink default homedir refusal (got the log above)"
}
pass "default GPG homedir is refused when HOME is a symlink"

# Mutant: compare the physical GPG home to unresolved $HOME/.gnupg. That slips
# through to key lookup instead of the default-homedir refusal.
mkdir -p "$scratch/mut-home/scripts" "$scratch/mut-home/keys"
python3 - "$ROOT/scripts/release-tag-common.sh" "$scratch/mut-home/scripts/release-tag-common.sh" <<'PY' || fail "unresolved-HOME mutant was not distinguished"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'default_home="$(tag_phys_dir "${HOME:-}/.gnupg")" || default_home=""'
new = 'default_home="${HOME:-}/.gnupg"'
if old not in text:
    raise SystemExit('live default_home uses tag_phys_dir on HOME')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('mutant still resolves HOME')
Path(sys.argv[2]).write_text(mut)
PY
printf 'gpg %s\n' "$SHELLSENTRY_GPG_SIGNING_FINGERPRINT" >"$scratch/mut-home/keys/expected-fingerprints.txt"
set +e
mut_out="$(
	SHELLSENTRY_PGP_KEY_ID="$SHELLSENTRY_PGP_KEY_ID" \
		SHELLSENTRY_GPG_SIGNING_FINGERPRINT="$SHELLSENTRY_GPG_SIGNING_FINGERPRINT" \
		SHELLSENTRY_GPG_HOMEDIR="$phys_gnupg" \
		HOME="$scratch/home-link" \
		bash -c 'source "$1"; tag_key_selector' _ "$scratch/mut-home/scripts/release-tag-common.sh" 2>&1
)"
mut_rc=$?
set -e
[[ "$mut_rc" -ne 0 ]] || fail "unresolved-HOME mutant should still fail at key lookup"
echo "$mut_out" | grep -q 'must not be the default homedir' && {
	echo "$mut_out" >&2
	fail "unresolved-HOME mutant still treated the physical GPG home as default"
}
echo "$mut_out" | grep -q 'signing subkey unavailable' || {
	echo "$mut_out" >&2
	fail "unresolved-HOME mutant should reach key lookup after skipping the default-homedir check"
}
pass "default-homedir compare resolves HOME; skipping that lets a symlink HOME slip through"

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
