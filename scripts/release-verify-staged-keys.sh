#!/usr/bin/env bash
# Verify both staged public keys against the committed fingerprint anchors.
# Decernor is the designated checker; fingerprint and minisign blob are compared
# explicitly so a throwaway staged key cannot pass.
# Usage: release-verify-staged-keys.sh [dir]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$root"
# shellcheck source=scripts/release-decernor.sh
source "$root/scripts/release-decernor.sh"
die() {
	echo "error: $*" >&2
	exit 1
}
command -v gpg >/dev/null 2>&1 || die 'gpg is required to verify staged PGP keys'
command -v python3 >/dev/null 2>&1 || die 'python3 is required to hash the staged minisign blob'
dir="${1:-dist/release}"
[[ -d "$dir" && ! -L "$dir" ]] || die "source dir not found: $dir"
staged_gpg="$dir/shellsentry-release-signing-key.asc"
staged_minisign="$dir/shellsentry-minisign.pub"
[[ -f "$staged_gpg" && -s "$staged_gpg" && ! -L "$staged_gpg" ]] ||
	die "missing staged PGP key: $staged_gpg"
# Both staged keys are required. Do not skip a missing minisign key.
[[ -f "$staged_minisign" && -s "$staged_minisign" && ! -L "$staged_minisign" ]] ||
	die "missing staged minisign key: $staged_minisign"
resolve_release_decernor || die 'trusted Decernor identity/version check failed'
"$root/scripts/verify-public-key.sh" "$staged_gpg" >/dev/null
anchors="$root/keys/expected-fingerprints.txt"
anchors_ndjson="$root/keys/expected-fingerprints.ndjson"
[[ -f "$anchors" && -s "$anchors" && ! -L "$anchors" ]] || die "committed $anchors missing"
[[ -f "$anchors_ndjson" && -s "$anchors_ndjson" && ! -L "$anchors_ndjson" ]] || die "committed $anchors_ndjson missing"
# Checker sees the staged files, not the in-tree exports. An unrelated staged
# key must fail even when the committed exports still match the anchors.
"$RELEASE_DECERNOR_BIN" fingerprint verify \
	--anchors "$anchors" \
	--anchors-ndjson "$anchors_ndjson" \
	--gpg "$staged_gpg" --minisign "$staged_minisign" >/dev/null ||
	die 'staged public keys do not match the committed fingerprint anchors'
pin_gpg="$(awk '$1=="gpg" {print $2}' "$anchors")"
pin_minisign="$(awk '$1=="minisign" {print $2}' "$anchors")"
[[ "$pin_gpg" =~ ^[0-9A-F]{40}$ && "$pin_minisign" =~ ^[0-9a-f]{64}$ ]] || die 'committed pins are malformed'
gpg_home="$(mktemp -d)"
trap 'gpgconf --homedir "$gpg_home" --kill all >/dev/null 2>&1 || true; rm -rf "$gpg_home"' EXIT
chmod 700 "$gpg_home"
gpg --homedir "$gpg_home" --batch --quiet --import "$staged_gpg" 2>/dev/null ||
	die 'staged PGP key failed to import'
listing="$(gpg --homedir "$gpg_home" --batch --with-colons --with-subkey-fingerprint --list-keys)"
[[ "$(awk -F: '$1=="pub" {n++} END {print n+0}' <<<"$listing")" == 1 ]] ||
	die 'staged PGP key must hold exactly one primary'
staged_fpr="$(awk -F: '$1=="fpr" {print $10; exit}' <<<"$listing")"
[[ "$staged_fpr" == "$pin_gpg" ]] ||
	die "staged PGP fingerprint $staged_fpr is not the committed primary $pin_gpg"
staged_subkey="$(awk -F: '$1=="sub" {s=1; cap=$12; next} s && $1=="fpr" {if (cap ~ /s/) print $10; s=0}' <<<"$listing")"
[[ "$staged_subkey" =~ ^[0-9A-F]{40}$ && "$staged_subkey" != "$pin_gpg" ]] ||
	die 'staged PGP key must hold exactly one signing subkey (key id)'
minisign_line="$(sed -n 2p "$staged_minisign")"
[[ "$minisign_line" =~ ^[A-Za-z0-9+/]+=*$ ]] || die 'staged minisign key is not a two-line minisign public key'
staged_blob="$(printf '%s' "$minisign_line" | python3 -c 'import base64, hashlib, sys; print(hashlib.sha256(base64.b64decode(sys.stdin.read().strip())).hexdigest())')"
[[ "$staged_blob" == "$pin_minisign" ]] ||
	die 'staged minisign blob does not match the committed minisign pin'
echo "[ok] staged public keys match committed fingerprint $pin_gpg key id $staged_subkey and minisign blob $pin_minisign"
