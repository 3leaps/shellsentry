#!/usr/bin/env bash
# Isolated preflight: dirty tree and missing inputs fail; a complete fixture passes.
set -euo pipefail
unset SHELLSENTRY_RELEASE_TAG RELEASE_TAG SHELLSENTRY_RELEASE_KEY || true
root="$(cd "$(dirname "$0")/.." && pwd -P)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-preflight.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

expect_fail() {
	if "$@" >"$scratch/out" 2>"$scratch/err"; then
		echo "expected preflight rejection: $*" >&2
		cat "$scratch/err" >&2
		exit 1
	fi
}

fixture="$scratch/repo"
mkdir -p "$fixture/scripts" "$fixture/config/release" "$fixture/docs/security" \
	"$fixture/docs/releases" "$fixture/keys"
cp "$root/scripts/release-preflight.sh" "$fixture/scripts/"
chmod +x "$fixture/scripts/release-preflight.sh"
git init -q -b main "$fixture"
git -C "$fixture" config user.name fixture
git -C "$fixture" config user.email fixture@example.invalid

printf '0.1.8\n' >"$fixture/VERSION"
printf '3 Leaps Infosec Team <infosec@3leaps.net>\n' >"$fixture/config/release/tagger-identity.txt"
printf 'pgp\n' >"$fixture/docs/security/release-signing-keys.asc"
printf 'untrusted comment: fixture\nRWTfixture\n' >"$fixture/docs/security/shellsentry-minisign.pub"
printf 'untrusted comment: sfetch fixture\nRWTsfetch\n' >"$fixture/docs/security/sfetch-minisign.pub"
printf 'verifier README\n' >"$fixture/docs/security/README.md"
printf 'gpg %s\nminisign %s\n' "$(printf 'A%.0s' {1..40})" "$(printf 'b%.0s' {1..64})" \
	>"$fixture/keys/expected-fingerprints.txt"
printf '{"schema_version":"v0"}\n' >"$fixture/keys/expected-fingerprints.ndjson"
mkdir -p "$fixture/config/release"
printf 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  decernor_0.1.8_linux_amd64.tar.gz\n' \
	>"$fixture/config/release/decernor-ci-sha256.txt"
printf '## [0.1.8] - 2026-10-25\n\nnotes\n' >"$fixture/CHANGELOG.md"
printf '## v0.1.8\n\nnotes\n' >"$fixture/RELEASE_NOTES.md"
printf 'cut notes\n' >"$fixture/docs/releases/v0.1.8.md"
printf 'tracked\n' >"$fixture/file"
git -C "$fixture" add VERSION config docs keys CHANGELOG.md RELEASE_NOTES.md file scripts
git -C "$fixture" commit -qm fixture

pf="$fixture/scripts/release-preflight.sh"

expect_fail env -u SHELLSENTRY_RELEASE_TAG -u RELEASE_TAG "$pf"
grep -q 'SHELLSENTRY_RELEASE_TAG required' "$scratch/err"

env -u RELEASE_TAG SHELLSENTRY_RELEASE_TAG=v0.1.8 "$pf" >/dev/null

printf 'dirty\n' >"$fixture/file"
expect_fail env -u RELEASE_TAG SHELLSENTRY_RELEASE_TAG=v0.1.8 "$pf"
grep -q 'working tree is not clean' "$scratch/err"
git -C "$fixture" checkout -q -- file

expect_fail env -u SHELLSENTRY_RELEASE_TAG RELEASE_TAG=v0.1.8 "$pf"
grep -q 'RELEASE_TAG is not accepted' "$scratch/err"

expect_fail env -u RELEASE_TAG SHELLSENTRY_RELEASE_TAG=v0.0.0 "$pf"
grep -q 'must equal v0.1.8' "$scratch/err"

printf 'wrong identity\n' >"$fixture/config/release/tagger-identity.txt"
git -C "$fixture" add config/release/tagger-identity.txt
git -C "$fixture" commit -qm 'wrong identity'
expect_fail env -u RELEASE_TAG SHELLSENTRY_RELEASE_TAG=v0.1.8 "$pf"
grep -q 'tagger identity must be' "$scratch/err"
git -C "$fixture" checkout -q HEAD~1 -- config/release/tagger-identity.txt
git -C "$fixture" commit -qm 'restore identity'

rm "$fixture/docs/releases/v0.1.8.md"
git -C "$fixture" add -A
git -C "$fixture" commit -qm 'drop notes'
expect_fail env -u RELEASE_TAG SHELLSENTRY_RELEASE_TAG=v0.1.8 "$pf"
grep -q 'docs/releases/v0.1.8.md is missing' "$scratch/err"

echo '[ok] release preflight controls passed'
