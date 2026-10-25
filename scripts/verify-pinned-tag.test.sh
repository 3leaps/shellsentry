#!/usr/bin/env bash
# Throwaway keys in a fixture repo; never the default homedir or this checkout.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
command -v gpg >/dev/null 2>&1 || {
    echo 'error: gpg required' >&2
    exit 1
}

# Committed pin must match the GPG/minisign anchors (fails if either file is swapped).
pin_fpr="$(gpg --show-keys --with-colons "$root/docs/security/release-signing-keys.asc" | awk -F: '$1=="fpr" {print $10; exit}')"
anchor="$(awk '$1=="gpg" {print $2}' "$root/keys/expected-fingerprints.txt")"
[[ "$pin_fpr" == "$anchor" && "$anchor" =~ ^[0-9A-F]{40}$ ]] || {
    echo 'error: committed GPG pin does not match keys/expected-fingerprints.txt' >&2
    exit 1
}
cmp -s "$root/docs/security/shellsentry-minisign.pub" "$root/configs/keys/shellsentry-minisign.pub" || {
    echo 'error: docs/security/shellsentry-minisign.pub must match configs/keys/shellsentry-minisign.pub' >&2
    exit 1
}
minisign_anchor="$(awk '$1=="minisign" {print $2}' "$root/keys/expected-fingerprints.txt")"
minisign_hash="$(python3 - "$root/docs/security/shellsentry-minisign.pub" <<'PY'
import base64, hashlib, pathlib, sys
line = pathlib.Path(sys.argv[1]).read_text().splitlines()[1]
print(hashlib.sha256(base64.b64decode(line)).hexdigest())
PY
)"
[[ "$minisign_hash" == "$minisign_anchor" ]] || {
    echo 'error: minisign public key does not match keys/expected-fingerprints.txt' >&2
    exit 1
}
echo 'PASS: committed pins match expected-fingerprints.txt'
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-verify-tag.XXXXXX")"
cleanup() {
    gpgconf --homedir "$scratch/gpg" --kill all >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup EXIT
export GNUPGHOME="$scratch/gpg"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
    'Synthetic signing <signing@example.invalid>' ed25519 cert 0 >/dev/null 2>&1
primary="$(gpg --batch --with-colons --fingerprint --list-keys | awk -F: '$1=="fpr" {print $10;exit}')"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$primary" ed25519 sign 1d >/dev/null 2>&1
subkey="$(gpg --batch --with-colons --with-subkey-fingerprint --list-keys "$primary" | awk -F: '$1=="sub" {s=1;next} s && $1=="fpr" {print $10;exit}')"
[[ "$primary" =~ ^[0-9A-F]{40}$ && "$subkey" =~ ^[0-9A-F]{40}$ ]] || {
    echo 'error: fixture key fingerprints missing' >&2
    exit 1
}

fixture="$scratch/repo"
git init -q -b main "$fixture"
git -C "$fixture" config gpg.format openpgp
git -C "$fixture" config gpg.program gpg
git -C "$fixture" config commit.gpgsign false
git -C "$fixture" config user.name 'Synthetic signing'
git -C "$fixture" config user.email 'signing@example.invalid'
mkdir -p "$fixture/docs/security" "$fixture/keys" "$fixture/scripts"
cp "$root/scripts/verify-pinned-tag.sh" "$fixture/scripts/"
gpg --batch --armor --export "$primary" >"$fixture/docs/security/release-signing-keys.asc"
printf 'gpg %s\nminisign %s\n' "$primary" "$(printf 'a%.0s' {1..64})" >"$fixture/keys/expected-fingerprints.txt"
printf 'fixture\n' >"$fixture/file"
git -C "$fixture" add file docs/security keys scripts
git -C "$fixture" -c commit.gpgsign=false commit -qm fixture
echo '0.0.0' >"$fixture/VERSION"

export SHELLSENTRY_RELEASE_TAG=v0.0.0
git -C "$fixture" -c gpg.format=openpgp tag -s -a -u "$subkey!" -m 'shellsentry v0.0.0' v0.0.0 HEAD
if ! (cd "$fixture" && ./scripts/verify-pinned-tag.sh); then
    echo 'error: valid signed tag must verify' >&2
    exit 1
fi
echo 'PASS: signed fixture tag verifies against committed pin'

git -C "$fixture" tag -d v0.0.0 >/dev/null
git -C "$fixture" tag -a -m 'unsigned' v0.0.0 HEAD
if (cd "$fixture" && ./scripts/verify-pinned-tag.sh) >/dev/null 2>&1; then
    echo 'error: unsigned annotated tag must not verify' >&2
    exit 1
fi
echo 'PASS: unsigned annotated tag is rejected'

# Wrong pin: replace committed public key with a second throwaway key.
git -C "$fixture" tag -d v0.0.0 >/dev/null
other="$scratch/other"
mkdir -m 700 "$other"
gpg --homedir "$other" --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
    'Other <other@example.invalid>' ed25519 cert 0 >/dev/null 2>&1
other_primary="$(gpg --homedir "$other" --batch --with-colons --fingerprint --list-keys | awk -F: '$1=="fpr" {print $10;exit}')"
gpg --homedir "$other" --batch --armor --export "$other_primary" >"$fixture/docs/security/release-signing-keys.asc"
printf 'gpg %s\nminisign %s\n' "$other_primary" "$(printf 'b%.0s' {1..64})" >"$fixture/keys/expected-fingerprints.txt"
git -C "$fixture" add docs/security/release-signing-keys.asc keys/expected-fingerprints.txt
git -C "$fixture" -c commit.gpgsign=false commit -qm 'wrong pin'
git -C "$fixture" -c gpg.format=openpgp tag -s -a -u "$subkey!" -m 'shellsentry v0.0.0' v0.0.0 HEAD
if (cd "$fixture" && ./scripts/verify-pinned-tag.sh) >/dev/null 2>&1; then
    echo 'error: tag signed by a key other than the committed pin must not verify' >&2
    exit 1
fi
echo 'PASS: pin mismatch is rejected'
echo '[ok] verify-pinned-tag controls'
