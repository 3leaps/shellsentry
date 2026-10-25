#!/usr/bin/env bash
# Verify minisign and GPG signatures on checksum manifests using only the
# public keys committed in the tagged commit (PDR-0008 §2.1). Both signatures
# are required on both manifests. Env-named key files are not consulted.
# Usage: verify-signatures.sh vX.Y.Z [dir]
set -euo pipefail
die() {
	echo "error: $*" >&2
	exit 1
}
tag="${1:-}"
dir="${2:-dist/release}"
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
	die 'usage: verify-signatures.sh vX.Y.Z [dir]'
command -v gpg >/dev/null 2>&1 || die 'gpg is required to verify manifest signatures'
command -v minisign >/dev/null 2>&1 || die 'minisign is required to verify manifest signatures'
command -v gh >/dev/null 2>&1 || die 'gh (GitHub CLI) is required to confirm the tag'
[[ -d "$dir" && ! -L "$dir" ]] || die "source dir not found: $dir"
root="$(cd "$(dirname "$0")/.." && pwd -P)"
commit="$(git -C "$root" rev-parse --verify --quiet "${tag}^{commit}")" ||
	die "cannot peel tagged commit $tag"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die 'tagged commit is malformed'
"$root/scripts/release-verify-tag-anchor.sh" "$tag"
# Short physical /tmp: macOS TMPDIR under /var/folders overflows gpg-agent sockets.
work="$(mktemp -d /tmp/shs-vs.XXXXXX)"
work="$(CDPATH= cd -P -- "$work" && pwd -P)"
cleanup() {
	env -u GNUPGHOME gpgconf --homedir "$work/gpg" --kill all >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT
mkdir -m 700 "$work/gpg"
gpg_pin="$work/release-signing-keys.asc"
minisign_pin="$work/shellsentry-minisign.pub"
mode_gpg="$(git -C "$root" ls-tree "$commit" -- docs/security/release-signing-keys.asc | awk '{print $1}')"
mode_ms="$(git -C "$root" ls-tree "$commit" -- docs/security/shellsentry-minisign.pub | awk '{print $1}')"
[[ "$mode_gpg" == 100644 || "$mode_gpg" == 100755 ]] || die "committed PGP pin required in $tag"
[[ "$mode_ms" == 100644 || "$mode_ms" == 100755 ]] || die "committed minisign pin required in $tag"
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

require_sig() {
	local path="$1" kind="$2"
	[[ -f "$path" && -s "$path" && ! -L "$path" ]] || die "missing $kind: ${path##*/}"
}

verify_minisign() {
	local manifest="$1"
	require_sig "$dir/$manifest.minisig" "minisign signature"
	minisign -V -p "$minisign_pin" -m "$dir/$manifest" -x "$dir/$manifest.minisig" >/dev/null 2>&1 ||
		die "minisign signature for $manifest is invalid under the committed key"
	echo "[ok] $manifest.minisig verified under the tagged-commit key"
}

verify_pgp() {
	local manifest="$1"
	require_sig "$dir/$manifest.asc" "PGP signature"
	env -u GNUPGHOME gpg --homedir "$work/gpg" --batch --status-fd 1 --verify "$dir/$manifest.asc" "$dir/$manifest" \
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
	echo "[ok] $manifest.asc verified under the tagged-commit signing subkey"
}

for manifest in SHA256SUMS SHA512SUMS; do
	[[ -f "$dir/$manifest" && -s "$dir/$manifest" && ! -L "$dir/$manifest" ]] ||
		die "missing release file: $manifest"
	verify_minisign "$manifest"
	verify_pgp "$manifest"
done
echo "[ok] minisign and PGP signatures verified for both manifests against $tag"
