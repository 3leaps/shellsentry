#!/usr/bin/env bash
# Throwaway keys in a fixture repo; never the default homedir or this checkout.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
command -v gpg >/dev/null 2>&1 || {
	echo 'error: gpg required' >&2
	exit 1
}

scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-verify-tag.XXXXXX")"
# Bind a throwaway GNUPGHOME before the first gpg call so this test never
# touches ~/.gnupg. Revert-proof: a sentinel in $HOME/.gnupg must stay intact.
fake_home="$scratch/home"
mkdir -p "$fake_home/.gnupg"
chmod 700 "$fake_home/.gnupg"
printf 'sentinel\n' >"$fake_home/.gnupg/sentinel"
# Portable: BSD/macOS find has no -printf.
list_gnupg_rel() {
	(CDPATH= cd -- "$1" && find . -mindepth 1 | sed 's|^\./||' | sort)
}
list_gnupg_rel "$fake_home/.gnupg" >"$scratch/gnupg-before"
export HOME="$fake_home"
export GNUPGHOME="$scratch/gpg"
mkdir -m 700 "$GNUPGHOME"
cleanup() {
	gpgconf --homedir "$GNUPGHOME" --kill all >/dev/null 2>&1 || true
	rm -rf "$scratch"
}
trap cleanup EXIT

# Static order: the first `gpg` in this file must follow the GNUPGHOME bind.
if ! python3 - "$root/scripts/verify-pinned-tag.test.sh" <<'PY'
from pathlib import Path
import re, sys
text = Path(sys.argv[1]).read_text()
bind = re.search(r'^export GNUPGHOME=', text, re.M)
first = re.search(r'^\s*gpg(?:conf)?\s', text, re.M)
if not bind or not first or bind.start() > first.start():
    raise SystemExit('GNUPGHOME bind is missing or after the first gpg call')
mut = text[: bind.start()] + text[bind.end() :]
bind2 = re.search(r'^export GNUPGHOME=', mut, re.M)
first2 = re.search(r'^\s*gpg(?:conf)?\s', mut, re.M)
if bind2 and first2 and bind2.start() < first2.start():
    raise SystemExit('order checker still passes after removing the bind')
PY
then
	echo 'error: verify-pinned-tag.test.sh must bind GNUPGHOME before its first gpg call' >&2
	exit 1
fi

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
git -C "$fixture" config user.name '3 Leaps Infosec Team'
git -C "$fixture" config user.email 'infosec@3leaps.net'
mkdir -p "$fixture/docs/security" "$fixture/keys" "$fixture/scripts" "$fixture/config/release"
cp "$root/scripts/verify-pinned-tag.sh" "$fixture/scripts/"
printf '3 Leaps Infosec Team <infosec@3leaps.net>\n' >"$fixture/config/release/tagger-identity.txt"
gpg --batch --armor --export "$primary" >"$fixture/docs/security/release-signing-keys.asc"
printf 'gpg %s\nminisign %s\n' "$primary" "$(printf 'a%.0s' {1..64})" >"$fixture/keys/expected-fingerprints.txt"
printf 'fixture\n' >"$fixture/file"
git -C "$fixture" add file docs/security keys scripts config
git -C "$fixture" -c commit.gpgsign=false commit -qm fixture
echo '0.0.0' >"$fixture/VERSION"

export SHELLSENTRY_RELEASE_TAG=v0.0.0
# Tagger is the committed infosec identity, not the first GPG UID.
GIT_COMMITTER_NAME='3 Leaps Infosec Team' GIT_COMMITTER_EMAIL=infosec@3leaps.net \
	git -C "$fixture" -c gpg.format=openpgp tag -s -a --cleanup=verbatim \
	-u "$subkey!" -m 'shellsentry v0.0.0'$'\n' v0.0.0 HEAD
if ! (cd "$fixture" && ./scripts/verify-pinned-tag.sh); then
	echo 'error: valid signed tag must verify' >&2
	exit 1
fi
echo 'PASS: signed fixture tag verifies against committed pin'

# Revert-proof: tagging with the first GPG UID must be refused.
git -C "$fixture" tag -d v0.0.0 >/dev/null
GIT_COMMITTER_NAME='Synthetic signing' GIT_COMMITTER_EMAIL='signing@example.invalid' \
	git -C "$fixture" -c gpg.format=openpgp tag -s -a --cleanup=verbatim \
	-u "$subkey!" -m 'shellsentry v0.0.0'$'\n' v0.0.0 HEAD
if (cd "$fixture" && ./scripts/verify-pinned-tag.sh) >/dev/null 2>&1; then
	echo 'error: tagger matching the first GPG UID must be refused' >&2
	exit 1
fi
echo 'PASS: first GPG UID is not accepted as the tagger'
git -C "$fixture" tag -d v0.0.0 >/dev/null
GIT_COMMITTER_NAME='3 Leaps Infosec Team' GIT_COMMITTER_EMAIL=infosec@3leaps.net \
	git -C "$fixture" -c gpg.format=openpgp tag -s -a --cleanup=verbatim \
	-u "$subkey!" -m 'shellsentry v0.0.0'$'\n' v0.0.0 HEAD

git -C "$fixture" tag -d v0.0.0 >/dev/null
git -C "$fixture" tag -a -m 'unsigned' v0.0.0 HEAD
if (cd "$fixture" && ./scripts/verify-pinned-tag.sh) >/dev/null 2>&1; then
	echo 'error: unsigned annotated tag must not verify' >&2
	exit 1
fi
echo 'PASS: unsigned annotated tag is rejected'

# Wrong pin: replace committed public key with a second throwaway key.
# Unset GNUPGHOME so --homedir wins (macOS GnuPG otherwise uses the bound home).
git -C "$fixture" tag -d v0.0.0 >/dev/null
other="$scratch/other"
mkdir -m 700 "$other"
other_gpg() { env -u GNUPGHOME gpg --homedir "$other" "$@"; }
other_gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
	'Other <other@example.invalid>' ed25519 cert 0 >/dev/null 2>&1
other_primary="$(other_gpg --batch --with-colons --fingerprint --list-keys | awk -F: '$1=="fpr" {print $10;exit}')"
other_gpg --batch --armor --export "$other_primary" >"$fixture/docs/security/release-signing-keys.asc"
printf 'gpg %s\nminisign %s\n' "$other_primary" "$(printf 'b%.0s' {1..64})" >"$fixture/keys/expected-fingerprints.txt"
git -C "$fixture" add docs/security/release-signing-keys.asc keys/expected-fingerprints.txt
git -C "$fixture" -c commit.gpgsign=false commit -qm 'wrong pin'
GIT_COMMITTER_NAME='3 Leaps Infosec Team' GIT_COMMITTER_EMAIL=infosec@3leaps.net \
	git -C "$fixture" -c gpg.format=openpgp tag -s -a --cleanup=verbatim \
	-u "$subkey!" -m 'shellsentry v0.0.0'$'\n' v0.0.0 HEAD
if (cd "$fixture" && ./scripts/verify-pinned-tag.sh) >/dev/null 2>&1; then
	echo 'error: tag signed by a key other than the committed pin must not verify' >&2
	exit 1
fi
echo 'PASS: pin mismatch is rejected'

list_gnupg_rel "$fake_home/.gnupg" >"$scratch/gnupg-after"
cmp -s "$scratch/gnupg-before" "$scratch/gnupg-after" || {
	echo 'error: test touched $HOME/.gnupg' >&2
	diff -u "$scratch/gnupg-before" "$scratch/gnupg-after" >&2 || true
	exit 1
}
[[ "$(cat "$fake_home/.gnupg/sentinel")" == sentinel ]] || {
	echo 'error: $HOME/.gnupg sentinel was modified' >&2
	exit 1
}
echo 'PASS: throwaway GNUPGHOME did not touch ~/.gnupg'
echo '[ok] verify-pinned-tag controls'
