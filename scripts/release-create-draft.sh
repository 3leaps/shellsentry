#!/usr/bin/env bash
# Create the draft GitHub release from locally staged, signed packages.
# Runs on the maintainer machine only; CI holds no write authority.
# Usage: release-create-draft.sh vX.Y.Z [source_dir]
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
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
	die 'usage: release-create-draft.sh vX.Y.Z [source_dir]'
command -v gh >/dev/null 2>&1 || die 'gh (GitHub CLI) not found in PATH'
command -v gpg >/dev/null 2>&1 || die 'gpg is required to verify manifest signatures'
command -v minisign >/dev/null 2>&1 || die 'minisign is required to verify manifest signatures'
command -v python3 >/dev/null 2>&1 || die 'python3 is required to verify checksum manifests'
command -v go >/dev/null 2>&1 || die 'go is required to bind archives to the signed tag'
[[ -d "$src" && ! -L "$src" ]] || die "source dir not found: $src"
packages=(
	shellsentry_linux_amd64.tar.gz
	shellsentry_linux_arm64.tar.gz
	shellsentry_windows_amd64.zip
	shellsentry_windows_arm64.zip
	shellsentry_darwin_arm64.tar.gz
	install-shellsentry.sh
)
manifests=(SHA256SUMS SHA512SUMS)
signatures=(
	SHA256SUMS.minisig
	SHA256SUMS.asc
	SHA512SUMS.minisig
	SHA512SUMS.asc
)
expected=("${packages[@]}" "${manifests[@]}" "${signatures[@]}")
while IFS= read -r -d '' entry; do
	name="${entry##*/}"
	allowed=0
	for want in "${expected[@]}"; do
		[[ "$name" == "$want" ]] && allowed=1
	done
	[[ "$allowed" == 1 ]] || die "unexpected file in $src: $name"
	[[ -f "$entry" && ! -L "$entry" ]] || die "not a regular file: $name"
done < <(find "$src" -mindepth 1 -maxdepth 1 -print0)
for want in "${expected[@]}"; do
	[[ -f "$src/$want" && -s "$src/$want" ]] || die "missing release file: $want"
done

# Each manifest lists exactly the staged archives (and installer), and each hash matches.
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
        raise SystemExit(f'error: {manifest} does not list exactly the expected archives')
    for name in expected:
        actual = hashlib.new(algorithm, (src / name).read_bytes()).hexdigest()
        if actual != entries[name]:
            raise SystemExit(f'error: {manifest} digest mismatch for {name}')
PY
then
	die 'checksum manifests do not list exactly the staged archives with matching hashes'
fi

# Short physical /tmp: macOS TMPDIR under /var/folders overflows gpg-agent sockets.
work="$(mktemp -d /tmp/shs-cd.XXXXXX)"
work="$(CDPATH= cd -P -- "$work" && pwd -P)"
cleanup() {
	env -u GNUPGHOME gpgconf --homedir "$work/gpg" --kill all >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT
mkdir -m 700 "$work/gpg"
object="$(git -C "$root" rev-parse --verify --quiet "refs/tags/$tag")" || die "tag $tag is missing"
[[ "$(git -C "$root" cat-file -t "$object")" == tag ]] || die 'annotated tag required'
git -C "$root" cat-file tag "$object" | grep -q 'BEGIN PGP SIGNATURE' || die 'tag is not GPG-signed'
commit="$(git -C "$root" rev-parse --verify --quiet "${tag}^{commit}")" || die "cannot peel tagged commit $tag"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die 'tagged commit is malformed'
"$root/scripts/release-verify-tag-anchor.sh" "$tag"
gpg_pin="$work/release-signing-keys.asc"
minisign_pin="$work/shellsentry-minisign.pub"
git -C "$root" cat-file blob "$commit:docs/security/release-signing-keys.asc" >"$gpg_pin"
git -C "$root" cat-file blob "$commit:docs/security/shellsentry-minisign.pub" >"$minisign_pin"
[[ -s "$gpg_pin" && -s "$minisign_pin" ]] || die "committed signing keys missing from $tag"
env -u GNUPGHOME gpg --homedir "$work/gpg" --batch --quiet --import "$gpg_pin" 2>/dev/null ||
	die 'committed PGP pin failed to import'
listing="$(env -u GNUPGHOME gpg --homedir "$work/gpg" --batch --with-colons --with-subkey-fingerprint --list-keys)"
[[ "$(awk -F: '$1=="pub" {n++} END {print n+0}' <<<"$listing")" == 1 ]] ||
	die 'committed PGP pin must hold exactly one primary'
primary="$(awk -F: '$1=="fpr" {print $10; exit}' <<<"$listing")"
permitted="$(awk -F: '$1=="sub" {s=1; cap=$12; next} s && $1=="fpr" {if (cap ~ /s/) print $10; s=0}' <<<"$listing")"
[[ "$primary" =~ ^[0-9A-F]{40}$ && "$permitted" =~ ^[0-9A-F]{40}$ && "$permitted" != "$primary" ]] ||
	die 'committed PGP pin must hold exactly one signing subkey'
GNUPGHOME="$work/gpg" git -C "$root" -c gpg.program=gpg verify-tag --raw "$object" >"$work/tag-status" 2>&1 || {
	awk '$1=="[GNUPG:]" {print "signature status:", $2}' "$work/tag-status" >&2
	die 'tag signature invalid under the committed pin'
}
awk -v primary="$primary" -v permitted="$permitted" '
  $1=="[GNUPG:]" && $2=="VALIDSIG" {
    valid++; subkey=$3; signer_primary=$NF
  }
  $1=="[GNUPG:]" && $2=="GOODSIG" {good++}
  $1=="[GNUPG:]" && $2 ~ /^(EXPKEYSIG|EXPSIG|REVKEYSIG|KEYREVOKED|BADSIG|ERRSIG)$/ {bad++}
  END {
    if (bad || good!=1 || valid!=1 || signer_primary!=primary || subkey==primary || subkey!=permitted) exit 1
  }
' "$work/tag-status" || die 'tag is not signed by the committed signing subkey'

verify_minisign() {
	local manifest="$1"
	minisign -V -p "$minisign_pin" -m "$src/$manifest" -x "$src/$manifest.minisig" >/dev/null 2>&1 ||
		die "minisign signature for $manifest is invalid under the committed key"
}
verify_pgp() {
	local manifest="$1"
	env -u GNUPGHOME gpg --homedir "$work/gpg" --batch --status-fd 1 --verify "$src/$manifest.asc" "$src/$manifest" \
		>"$work/pgp-$manifest" 2>/dev/null || die "PGP signature for $manifest is invalid under the committed key"
	awk -v primary="$primary" -v permitted="$permitted" '
	  $1=="[GNUPG:]" && $2=="VALIDSIG" {
	    valid++; subkey=$3; signer_primary=$NF
	  }
	  $1=="[GNUPG:]" && $2=="GOODSIG" {good++}
	  $1=="[GNUPG:]" && $2 ~ /^(EXPKEYSIG|EXPSIG|REVKEYSIG|KEYREVOKED|BADSIG|ERRSIG)$/ {bad++}
	  END {
	    if (bad || good!=1 || valid!=1 || signer_primary!=primary || subkey==primary || subkey!=permitted) exit 1
	  }
	' "$work/pgp-$manifest" || die "PGP signature for $manifest is not the committed signing subkey"
}
verify_minisign SHA256SUMS
verify_minisign SHA512SUMS
verify_pgp SHA256SUMS
verify_pgp SHA512SUMS

"$root/scripts/release-bind-archives.sh" "$tag" "$src"

if gh release view "$tag" --repo 3leaps/shellsentry >/dev/null 2>&1; then
	die "a release for $tag already exists; do not replace it"
fi
notes="$work/release-notes.md"
git -C "$root" cat-file blob "$commit:docs/releases/${tag}.md" >"$notes" 2>/dev/null ||
	die "missing release notes in $tag: docs/releases/${tag}.md"
[[ -s "$notes" ]] || die "missing release notes in $tag: docs/releases/${tag}.md"
title="$(python3 -c 'import pathlib,sys; t=pathlib.Path(sys.argv[1]).read_text(); print(t.splitlines()[0] if t.strip() else "")' "$notes")"
[[ -n "$title" ]] || die "tagged notes have no title line: docs/releases/${tag}.md"
files=()
for want in "${expected[@]}"; do
	files+=("$src/$want")
done
gh release create "$tag" --repo 3leaps/shellsentry --verify-tag --draft \
	--title "$title" --notes-file "$notes" "${files[@]}"
echo "[ok] draft release $tag created from staged packages bound to $tag"
