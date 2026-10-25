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

[[ -z "$(git status --porcelain --untracked-files=all)" ]] || die 'working tree is not clean'
ok 'working tree is clean'

identity="$root/config/release/tagger-identity.txt"
[[ -f "$identity" && ! -L "$identity" ]] || die 'config/release/tagger-identity.txt is missing'
[[ "$(cat "$identity")" == '3 Leaps Infosec Team <infosec@3leaps.net>' ]] ||
	die 'tagger identity must be 3 Leaps Infosec Team <infosec@3leaps.net>'
ok 'tagger identity is present'

[[ -s "$root/docs/security/release-signing-keys.asc" && ! -L "$root/docs/security/release-signing-keys.asc" ]] ||
	die 'docs/security/release-signing-keys.asc is missing'
[[ -s "$root/keys/expected-fingerprints.txt" && ! -L "$root/keys/expected-fingerprints.txt" ]] ||
	die 'keys/expected-fingerprints.txt is missing'
ok 'committed public pin and anchors are present'

grep -Eq "^## \\[${version}\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md ||
	die "CHANGELOG.md lacks a dated [${version}] heading"
grep -Eq "^## ${tag}$" RELEASE_NOTES.md ||
	die "RELEASE_NOTES.md lacks a ${tag} heading"
[[ -s "$root/docs/releases/${tag}.md" ]] || die "docs/releases/${tag}.md is missing"
ok "release notes cover $tag"

echo "[ok] preflight passed for $tag; ready to tag"
