#!/usr/bin/env bash
# Clean-tree pre-tag check: refuse missing release inputs before any tag is created.
set -euo pipefail

die() {
	echo "[!!] $*" >&2
	exit 1
}

ok() { echo "[ok] $*"; }

root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$root"

if [[ -n "${RELEASE_TAG+x}" ]]; then
	die 'RELEASE_TAG is not accepted; set SHELLSENTRY_RELEASE_TAG only'
fi

version="$(tr -d ' \t\r\n' <VERSION)"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
	die 'VERSION must contain one stable semantic version'
tag="v${version}"
[[ -n "${SHELLSENTRY_RELEASE_TAG:-}" ]] || die 'SHELLSENTRY_RELEASE_TAG required'
[[ "$SHELLSENTRY_RELEASE_TAG" == "$tag" ]] || die "SHELLSENTRY_RELEASE_TAG must equal $tag"

# PDR-0008 §2.3: bind the checker before any other preflight work.
# shellcheck source=scripts/release-decernor.sh
source "$root/scripts/release-decernor.sh"
resolve_release_decernor || die 'trusted Decernor identity/version check failed'
ok 'Decernor identity is bound'

[[ -z "$(git status --porcelain --untracked-files=all)" ]] || die 'working tree is not clean'
ok 'working tree is clean'

identity="$root/config/release/tagger-identity.txt"
[[ -f "$identity" && ! -L "$identity" ]] || die 'config/release/tagger-identity.txt is missing'
[[ "$(cat "$identity")" == '3 Leaps Infosec Team <infosec@3leaps.net>' ]] ||
	die 'tagger identity must be 3 Leaps Infosec Team <infosec@3leaps.net>'
ok 'tagger identity is present'

[[ -s "$root/docs/security/release-signing-keys.asc" && ! -L "$root/docs/security/release-signing-keys.asc" ]] ||
	die 'docs/security/release-signing-keys.asc is missing'
[[ -s "$root/docs/security/shellsentry-minisign.pub" && ! -L "$root/docs/security/shellsentry-minisign.pub" ]] ||
	die 'docs/security/shellsentry-minisign.pub is missing'
[[ -s "$root/docs/security/sfetch-minisign.pub" && ! -L "$root/docs/security/sfetch-minisign.pub" ]] ||
	die 'docs/security/sfetch-minisign.pub is missing'
[[ -s "$root/docs/security/README.md" && ! -L "$root/docs/security/README.md" ]] ||
	die 'docs/security/README.md is missing'
[[ -s "$root/keys/expected-fingerprints.txt" && ! -L "$root/keys/expected-fingerprints.txt" ]] ||
	die 'keys/expected-fingerprints.txt is missing'
[[ -s "$root/keys/expected-fingerprints.ndjson" && ! -L "$root/keys/expected-fingerprints.ndjson" ]] ||
	die 'keys/expected-fingerprints.ndjson is missing'
[[ -s "$root/config/release/decernor-ci-sha256.txt" && ! -L "$root/config/release/decernor-ci-sha256.txt" ]] ||
	die 'config/release/decernor-ci-sha256.txt is missing'
ok 'committed public pin and anchors are present'
"$root/scripts/release-verify-committed-anchors.sh" ||
	die 'committed public exports do not match the fingerprint anchors'

grep -Eq "^## \\[${version}\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md ||
	die "CHANGELOG.md lacks a dated [${version}] heading"
grep -Eq "^## ${tag}$" RELEASE_NOTES.md ||
	die "RELEASE_NOTES.md lacks a ${tag} heading"
[[ -s "$root/docs/releases/${tag}.md" ]] || die "docs/releases/${tag}.md is missing"
ok "release notes cover $tag"

echo "[ok] preflight passed for $tag; ready to tag"
