#!/usr/bin/env bash
# Promote a draft release to published, only after the draft on GitHub is shown
# to be exactly the locally verified set. Runs on the maintainer machine.
#
# Usage: release-publish.sh vX.Y.Z [source_dir]
#
# Before promotion it reuses the shared helpers, in order:
#   1. release-verify-published-tag (approved primary, staged .anchor bind,
#      then release-verify-tag-anchor: origin, GitHub, origin/main, identity);
#   2. release notes equal the tagged blob;
#   3. the release is a draft whose asset names are exactly the expected set;
#   4. both manifests list exactly the staged archives with matching hashes;
#   5. verify-signatures.sh (minisign and PGP, keys from the tagged commit);
#   6. release-bind-archives.sh (vcs.revision, vcs.modified, delimited version);
#   7. staged public-key assets match the tagged pins, public only;
#   8. every draft asset, downloaded fresh, is byte-identical to the local file.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
# shellcheck source=scripts/release-ci-refuse.sh
source "$root/scripts/release-ci-refuse.sh"
die() {
	echo "error: $*" >&2
	exit 1
}
tag="${1:-}"
src="${2:-dist/release}"
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die 'usage: release-publish.sh vX.Y.Z [source_dir]'
repo="${SHELLSENTRY_RELEASE_REPO:-3leaps/shellsentry}"
for tool in gh python3 minisign gpg gpgconf cmp git go; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool not found in PATH"
done
[[ -d "$src" && ! -L "$src" ]] || die "source dir not found: $src"
packages=(
	shellsentry_linux_amd64.tar.gz
	shellsentry_linux_arm64.tar.gz
	shellsentry_windows_amd64.zip
	shellsentry_windows_arm64.zip
	shellsentry_darwin_arm64.tar.gz
	install-shellsentry.sh
)
provenance=(
	SHA256SUMS SHA256SUMS.asc SHA256SUMS.minisig
	SHA512SUMS SHA512SUMS.asc SHA512SUMS.minisig
	shellsentry-minisign.pub shellsentry-release-signing-key.asc
	"release-notes-${tag}.md"
)
expected=("${packages[@]}" "${provenance[@]}")
for want in "${expected[@]}"; do
	[[ -f "$src/$want" && ! -L "$src/$want" && -s "$src/$want" ]] || die "missing local release file: $want"
done

# 1. The tag still matches the staged anchor (published-tag calls tag-anchor).
anchor="$src.anchor"
[[ -f "$anchor" && ! -L "$anchor" ]] || die "missing $anchor; stage packages with make release-download"
[[ "$(awk -F= '$1=="tag" {print $2}' "$anchor")" == "$tag" ]] || die 'staged anchor is for a different tag'
anchor_object="$(awk -F= '$1=="object" {print $2}' "$anchor")"
anchor_commit="$(awk -F= '$1=="commit" {print $2}' "$anchor")"
SHELLSENTRY_RELEASE_TAG="$tag" SHELLSENTRY_EXPECTED_TAG_OBJECT="$anchor_object" SHELLSENTRY_EXPECTED_COMMIT="$anchor_commit" \
	"$root/scripts/release-verify-published-tag.sh" >/dev/null ||
	die 'published tag no longer matches the verified anchor'

commit="$(git -C "$root" rev-parse --verify --quiet "${tag}^{commit}")" || die "cannot peel tagged commit $tag"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die 'tagged commit is malformed'
[[ "$commit" == "$anchor_commit" ]] || die 'tagged commit differs from the staged anchor'

# The notes asset must be the per-version notes at the anchored tag commit, the
# same bytes the draft body was created from.
tagged_notes="$(git -C "$root" rev-parse --verify --quiet "$commit:docs/releases/$tag.md")" ||
	die "docs/releases/$tag.md is absent at the tagged commit"
[[ "$(git -C "$root" hash-object -- "$src/release-notes-$tag.md")" == "$tagged_notes" ]] ||
	die "release-notes-$tag.md differs from docs/releases/$tag.md at the tagged commit"

# 2. A draft with exactly the expected asset names.
release="$(gh release view "$tag" --repo "$repo" --json isDraft,assets)" || die "no release for $tag"
python3 - "$release" "${expected[@]}" <<'PY' && rc=0 || rc=$?
import json, sys
payload = json.loads(sys.argv[1])
if payload.get("isDraft") is not True:
    raise SystemExit(2)
names = sorted(a.get("name") or "" for a in payload.get("assets") or [])
expected = sorted(sys.argv[2:])
if names != expected:
    raise SystemExit(3)
PY
case "$rc" in
	0) ;;
	2) die "$tag is not a draft; refusing to re-promote" ;;
	3) die 'draft assets differ from the expected set' ;;
	*) die 'could not parse the GitHub release' ;;
esac

# 3. Each manifest lists exactly the packages, and they match.
if ! python3 - "$src" "${packages[@]}" <<'PY'
import hashlib
import pathlib
import sys

src = pathlib.Path(sys.argv[1])
expected = sorted(sys.argv[2:])
for manifest, algorithm, width in (('SHA256SUMS', 'sha256', 64), ('SHA512SUMS', 'sha512', 128)):
    entries = {}
    for line in (src / manifest).read_text().splitlines():
        if not line.strip():
            continue
        digest, sep, name = line.partition('  ')
        name = name.lstrip('*')
        if not sep or len(digest) != width or name in entries:
            raise SystemExit(f'error: malformed or duplicate {manifest} line')
        entries[name] = digest.lower()
    if sorted(entries) != expected:
        raise SystemExit(f'error: {manifest} does not list exactly the expected packages')
    for name in expected:
        actual = hashlib.new(algorithm, (src / name).read_bytes()).hexdigest()
        if actual != entries[name]:
            raise SystemExit(f'error: {manifest} digest mismatch for {name}')
PY
then
	die 'checksum manifests do not list exactly the staged archives with matching hashes'
fi

# 4. Signatures verify against the pins committed in the tagged commit.
"$root/scripts/verify-signatures.sh" "$tag" "$src" >/dev/null

# 5. Archives are bound to the signed tag (shared with create-draft).
"$root/scripts/release-bind-archives.sh" "$tag" "$src" >/dev/null

# Staged public-key assets published beside the signatures must be the tagged
# pins, public only. verify-signatures already checked the signature bytes;
# this is the files consumers will download from the release.
gpg_home="$(mktemp -d /tmp/shs-pb.XXXXXX)"
gpg_home="$(CDPATH= cd -P -- "$gpg_home" && pwd -P)"
fresh="$(mktemp -d /tmp/shs-pb.XXXXXX)"
fresh="$(CDPATH= cd -P -- "$fresh" && pwd -P)"
pinned="$(mktemp -d /tmp/shs-pb.XXXXXX)"
pinned="$(CDPATH= cd -P -- "$pinned" && pwd -P)"
trap 'env -u GNUPGHOME gpgconf --homedir "$gpg_home" --kill all >/dev/null 2>&1 || true; rm -rf "$gpg_home" "$fresh" "$pinned"' EXIT
chmod 700 "$gpg_home"
tagged_blob() {
	local path="$1" out="$2" mode
	mode="$(git -C "$root" ls-tree "$commit" -- "$path" | awk '{print $1}')"
	[[ "$mode" == 100644 || "$mode" == 100755 ]] || die "committed $path required in the tagged commit"
	git -C "$root" cat-file blob "$commit:$path" >"$out"
	[[ -s "$out" ]] || die "committed $path is empty in the tagged commit"
}
tagged_blob keys/expected-fingerprints.txt "$pinned/anchors"
tagged_blob docs/security/release-signing-keys.asc "$pinned/pgp.asc"
pin_gpg="$(awk '$1=="gpg" {print $2}' "$pinned/anchors")"
pin_minisign="$(awk '$1=="minisign" {print $2}' "$pinned/anchors")"
[[ "$pin_gpg" =~ ^[0-9A-F]{40}$ && "$pin_minisign" =~ ^[0-9a-f]{64}$ ]] || die 'committed pins are malformed'
staged_minisign_pub="$src/shellsentry-minisign.pub"
minisign_comment="$(sed -n 1p "$staged_minisign_pub")"
minisign_line="$(sed -n 2p "$staged_minisign_pub")"
cmp -s "$staged_minisign_pub" <(printf '%s\n%s\n' "$minisign_comment" "$minisign_line") &&
	[[ "$minisign_comment" == 'untrusted comment: '* ]] ||
	die 'staged minisign key is not a two-line minisign public key'
[[ "$minisign_line" =~ ^[A-Za-z0-9+/]+=*$ ]] || die 'staged minisign key is not a two-line minisign public key'
staged_minisign="$(printf '%s' "$minisign_line" | python3 -c 'import base64,hashlib,sys; print(hashlib.sha256(base64.b64decode(sys.stdin.read().strip())).hexdigest())')"
[[ "$staged_minisign" == "$pin_minisign" ]] || die 'staged minisign key does not match the pin in the tagged commit'
env -u GNUPGHOME gpg --homedir "$gpg_home" --batch --quiet --import "$pinned/pgp.asc" 2>/dev/null || die 'committed PGP key failed to import'
listing="$(env -u GNUPGHOME gpg --homedir "$gpg_home" --batch --with-colons --with-subkey-fingerprint --list-keys)"
[[ "$(awk -F: '$1=="pub" {n++} END {print n+0}' <<<"$listing")" == 1 ]] || die 'committed PGP key must hold exactly one primary'
[[ "$(awk -F: '$1=="fpr" {print $10; exit}' <<<"$listing")" == "$pin_gpg" ]] || die 'committed PGP key is not the anchored primary'
pin_subkey="$(awk -F: '$1=="sub" {s=1; cap=$12; next} s && $1=="fpr" {if (cap ~ /s/) print $10; s=0}' <<<"$listing")"
[[ "$pin_subkey" =~ ^[0-9A-F]{40}$ ]] || die 'committed PGP key must hold exactly one signing subkey'
staged_home="$(mktemp -d /tmp/shs-pb.XXXXXX)"
staged_home="$(CDPATH= cd -P -- "$staged_home" && pwd -P)"
chmod 700 "$staged_home"
staged_key="$src/shellsentry-release-signing-key.asc"
check_staged_key() {
	local listing
	env -u GNUPGHOME gpg --homedir "$staged_home" --batch --list-packets "$staged_key" >"$staged_home/packets" 2>/dev/null ||
		return 1
	! grep -qE ':secret (key|sub key) packet:' "$staged_home/packets" || return 2
	env -u GNUPGHOME gpg --homedir "$staged_home" --batch --quiet --import "$staged_key" 2>/dev/null || return 1
	listing="$(env -u GNUPGHOME gpg --homedir "$staged_home" --batch --with-colons --with-subkey-fingerprint --list-keys)"
	[[ "$(awk -F: '$1=="sec" {n++} END {print n+0}' <<<"$listing")" == 0 ]] || return 2
	[[ "$(awk -F: '$1=="pub" {n++} END {print n+0}' <<<"$listing")" == 1 ]] || return 3
	[[ "$(awk -F: '$1=="fpr" {print $10; exit}' <<<"$listing")" == "$pin_gpg" ]] || return 3
	[[ "$(awk -F: '$1=="sub" {s=1; cap=$12; next} s && $1=="fpr" {if (cap ~ /s/) print $10; s=0}' <<<"$listing")" == "$pin_subkey" ]] ||
		return 3
}
staged_rc=0
check_staged_key || staged_rc=$?
env -u GNUPGHOME gpgconf --homedir "$staged_home" --kill all >/dev/null 2>&1 || true
rm -rf "$staged_home"
case "$staged_rc" in
	0) ;;
	2) die 'staged PGP key asset contains secret key material' ;;
	3) die 'staged PGP key asset is not the committed primary with its pinned signing subkey' ;;
	*) die 'staged PGP key asset is not a readable OpenPGP public key' ;;
esac

# 6. The draft on GitHub is byte-identical to the verified local set.
gh release download "$tag" --repo "$repo" --dir "$fresh" >/dev/null || die 'could not download the draft assets'
for want in "${expected[@]}"; do
	cmp -s "$fresh/$want" "$src/$want" || die "draft asset differs from the verified local file: $want"
done

# Residual: GitHub has no atomic compare-and-publish, so a writer with release
# access could still swap an asset in the seconds between the comparison above
# and this call. Re-download and verify after publishing if that matters.
gh release edit "$tag" --repo "$repo" --draft=false >/dev/null
echo "[ok] $tag published from ${#expected[@]} byte-verified asset(s)"
