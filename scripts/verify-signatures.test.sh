#!/usr/bin/env bash
# Signature verify uses tagged-commit keys only and requires both formats.
# Throwaway keys; never the default homedir. A real signed fixture must pass
# so a gate that accepts everything is not enough.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-verify-sigs.XXXXXX")"
fake_home="$scratch/home"
mkdir -p "$fake_home/.gnupg"
chmod 700 "$fake_home/.gnupg"
printf 'sentinel\n' >"$fake_home/.gnupg/sentinel"
export HOME="$fake_home"
export GNUPGHOME="$scratch/gpg"
mkdir -m 700 "$GNUPGHOME"
cleanup() {
	gpgconf --homedir "$GNUPGHOME" --kill all >/dev/null 2>&1 || true
	gpgconf --homedir "$scratch/other-gpg" --kill all >/dev/null 2>&1 || true
	rm -rf "$scratch"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}
pass() { echo "PASS: $*"; }

command -v gpg >/dev/null 2>&1 || fail 'gpg required'
command -v minisign >/dev/null 2>&1 || fail 'minisign required'
command -v python3 >/dev/null 2>&1 || fail 'python3 required'

script="$root/scripts/verify-signatures.sh"
[[ -x "$script" ]] || fail 'verify-signatures.sh must be executable'
grep -q 'cat-file blob' "$script" || fail 'verify-signatures.sh must read keys from the tagged commit'
if grep -nE '\$\{SHELLSENTRY_MINISIGN_PUB|\$SHELLSENTRY_MINISIGN_PUB\b' "$script"; then
	fail 'verify-signatures.sh must not read SHELLSENTRY_MINISIGN_PUB'
fi
if grep -nE '\$\{SHELLSENTRY_GPG_HOMEDIR|\$SHELLSENTRY_GPG_HOMEDIR\b' "$script"; then
	fail 'verify-signatures.sh must not read SHELLSENTRY_GPG_HOMEDIR'
fi
if grep -q '\[skip\] No minisign signature' "$script" || grep -q '\[skip\] No PGP signature' "$script"; then
	fail 'verify-signatures.sh must not skip a missing signature'
fi
grep -E '^release-verify-signatures:' -A3 "$root/Makefile" | grep -q 'require-release-tag' ||
	fail 'release-verify-signatures must depend on require-release-tag'
if grep -E '^release-verify-signatures:' -A6 "$root/Makefile" | grep -q 'SHELLSENTRY_MINISIGN_PUB'; then
	fail 'release-verify-signatures must not pass SHELLSENTRY_MINISIGN_PUB'
fi
grep -E '^release-tag-tests:' -A40 "$root/Makefile" | grep -q 'test-verify-signatures' ||
	fail 'release-tag-tests must run test-verify-signatures'
pass 'Makefile and script bind verification to the tagged-commit keys'

if ! python3 - "$root/scripts/verify-signatures.test.sh" <<'PY'
from pathlib import Path
import re, sys
text = Path(sys.argv[1]).read_text()
bind = re.search(r'^export GNUPGHOME=', text, re.M)
first = re.search(r'^\s*gpg(?:conf)?\s', text, re.M)
if not bind or not first or bind.start() > first.start():
    raise SystemExit('GNUPGHOME bind is missing or after the first gpg call')
PY
then
	fail 'test must bind GNUPGHOME before its first gpg call'
fi

gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
	'Synthetic signing <signing@example.invalid>' ed25519 cert 0 >/dev/null 2>&1
primary="$(gpg --batch --with-colons --fingerprint --list-keys | awk -F: '$1=="fpr" {print $10;exit}')"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$primary" ed25519 sign 1d >/dev/null 2>&1
subkey="$(gpg --batch --with-colons --with-subkey-fingerprint --list-keys "$primary" | awk -F: '$1=="sub" {s=1;next} s && $1=="fpr" {print $10;exit}')"
[[ "$primary" =~ ^[0-9A-F]{40}$ && "$subkey" =~ ^[0-9A-F]{40}$ ]] || fail 'fixture signing key missing'

mkdir -m 700 "$scratch/other-gpg"
# Unset GNUPGHOME so --homedir wins (macOS GnuPG otherwise uses the bound home).
other_gpg() { env -u GNUPGHOME gpg --homedir "$scratch/other-gpg" "$@"; }
other_gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
	'Synthetic other <other@example.invalid>' ed25519 cert 0 >/dev/null 2>&1
other_primary="$(other_gpg --batch --with-colons --fingerprint --list-keys | awk -F: '$1=="fpr" {print $10;exit}')"
other_gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$other_primary" ed25519 sign 1d >/dev/null 2>&1
other_subkey="$(other_gpg --batch --with-colons --with-subkey-fingerprint --list-keys "$other_primary" | awk -F: '$1=="sub" {s=1;next} s && $1=="fpr" {print $10;exit}')"
other_gpg --batch --armor --export "$other_primary" >"$scratch/other.asc"

minisign -G -W -p "$scratch/good.pub" -s "$scratch/good.key" >/dev/null 2>&1 || fail 'minisign keygen failed'
minisign -G -W -p "$scratch/env.pub" -s "$scratch/env.key" >/dev/null 2>&1 || fail 'env minisign keygen failed'

fixture="$scratch/repo"
git init -q -b main "$fixture"
git -C "$fixture" config commit.gpgsign false
git -C "$fixture" config user.name Fixture
git -C "$fixture" config user.email fixture@example.invalid
mkdir -p "$fixture/docs/security" "$fixture/scripts"
cp "$script" "$fixture/scripts/"
chmod +x "$fixture/scripts/"*.sh
gpg --batch --armor --export "$primary" >"$fixture/docs/security/release-signing-keys.asc"
cp "$scratch/good.pub" "$fixture/docs/security/shellsentry-minisign.pub"
git -C "$fixture" add docs scripts
git -C "$fixture" -c commit.gpgsign=false commit -qm fixture
git -C "$fixture" tag -am 'v1.2.3' v1.2.3
fixture_script="$fixture/scripts/verify-signatures.sh"
restore_script() {
	cp "$script" "$fixture_script"
	chmod +x "$fixture_script"
}

write_manifests() {
	local dest="$1"
	mkdir -p "$dest"
	printf 'payload-a\n' >"$dest/SHA256SUMS"
	printf 'payload-b\n' >"$dest/SHA512SUMS"
}

sign_committed() {
	local dest="$1"
	minisign -S -s "$scratch/good.key" -m "$dest/SHA256SUMS" -x "$dest/SHA256SUMS.minisig" >/dev/null
	minisign -S -s "$scratch/good.key" -m "$dest/SHA512SUMS" -x "$dest/SHA512SUMS.minisig" >/dev/null
	gpg --batch --yes --armor --local-user "$subkey!" --detach-sign -o "$dest/SHA256SUMS.asc" "$dest/SHA256SUMS"
	gpg --batch --yes --armor --local-user "$subkey!" --detach-sign -o "$dest/SHA512SUMS.asc" "$dest/SHA512SUMS"
}

run_verify() {
	"$fixture_script" v1.2.3 "$1"
}

ok="$scratch/ok"
write_manifests "$ok"
sign_committed "$ok"
if ! run_verify "$ok" >/dev/null 2>"$scratch/ok.err"; then
	fail "positive throwaway-key fixture must verify (log: $(cat "$scratch/ok.err"))"
fi
pass 'positive control verifies real throwaway minisign and GPG signatures'

# Env points at a different key; committed-key signatures must still pass.
export SHELLSENTRY_MINISIGN_PUB="$scratch/env.pub"
export SHELLSENTRY_GPG_HOMEDIR="$scratch/other-gpg"
if ! run_verify "$ok" >/dev/null 2>"$scratch/env-ignore.err"; then
	fail "env-supplied keys must be ignored when the committed keys verify (log: $(cat "$scratch/env-ignore.err"))"
fi
pass 'env-supplied keys are ignored for a valid tagged-commit signature'

# Signatures from the env keys must not verify against the committed pins.
env_signed="$scratch/env-signed"
write_manifests "$env_signed"
minisign -S -s "$scratch/env.key" -m "$env_signed/SHA256SUMS" -x "$env_signed/SHA256SUMS.minisig" >/dev/null
minisign -S -s "$scratch/env.key" -m "$env_signed/SHA512SUMS" -x "$env_signed/SHA512SUMS.minisig" >/dev/null
other_gpg --batch --yes --armor --local-user "$other_subkey!" \
	--detach-sign -o "$env_signed/SHA256SUMS.asc" "$env_signed/SHA256SUMS"
other_gpg --batch --yes --armor --local-user "$other_subkey!" \
	--detach-sign -o "$env_signed/SHA512SUMS.asc" "$env_signed/SHA512SUMS"
if run_verify "$env_signed" >/dev/null 2>"$scratch/env-signed.err"; then
	fail 'signatures from an env-supplied key must be refused'
fi
grep -Eq 'minisign signature|PGP signature|committed' "$scratch/env-signed.err" ||
	fail "env-signed refusal (log: $(cat "$scratch/env-signed.err"))"
pass 'signatures produced with env keys are refused against the tagged-commit pins'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'minisign -V -p "$minisign_pin"'
new = 'minisign -V -p "${SHELLSENTRY_MINISIGN_PUB:-$minisign_pin}"'
if old not in text:
    raise SystemExit('live script does not pass the tagged minisign pin')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('env minisign mutant still uses only the tagged pin')
gpg_old = 'env -u GNUPGHOME gpg --homedir "$work/gpg" --batch --status-fd 1 --verify'
gpg_new = 'env -u GNUPGHOME gpg --homedir "${SHELLSENTRY_GPG_HOMEDIR:-$work/gpg}" --batch --status-fd 1 --verify'
if gpg_old not in mut:
    raise SystemExit('live script does not verify PGP in the isolated home')
mut = mut.replace(gpg_old, gpg_new, 1)
awk_old = '''	awk -v primary="$primary" -v permitted="$permitted" '''
if awk_old not in mut:
    raise SystemExit('live script is missing the committed-subkey VALIDSIG check')
mut = mut.replace(awk_old, '	true && awk -v primary="$primary" -v permitted="$permitted" ', 1)
# The env homedir's signature is valid but not the committed subkey; drop that pin.
mut = mut.replace(
    '\' "$work/pgp-$manifest" || die "PGP signature for $manifest is not the committed signing subkey"',
    '\' "$work/pgp-$manifest" || true',
    1,
)
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'env-key mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$env_signed" >/dev/null 2>"$scratch/mut-env.err"; then
	fail "reading keys from the environment must accept env-signed manifests (log: $(cat "$scratch/mut-env.err"))"
fi
restore_script
pass 'reverting to env keys accepts a signature that the tagged commit would refuse'

unset SHELLSENTRY_MINISIGN_PUB SHELLSENTRY_GPG_HOMEDIR

ms_only="$scratch/ms-only"
write_manifests "$ms_only"
sign_committed "$ms_only"
rm -f "$ms_only/SHA256SUMS.asc" "$ms_only/SHA512SUMS.asc"
if run_verify "$ms_only" >/dev/null 2>"$scratch/ms-only.err"; then
	fail 'valid minisign with missing GPG signatures must be refused'
fi
grep -q 'missing PGP signature' "$scratch/ms-only.err" ||
	fail "missing-GPG refusal (log: $(cat "$scratch/ms-only.err"))"
pass 'valid minisign with missing GPG signatures is refused'

wrong_gpg="$scratch/wrong-gpg"
write_manifests "$wrong_gpg"
sign_committed "$wrong_gpg"
other_gpg --batch --yes --armor --local-user "$other_subkey!" \
	--detach-sign -o "$wrong_gpg/SHA256SUMS.asc" "$wrong_gpg/SHA256SUMS"
if run_verify "$wrong_gpg" >/dev/null 2>"$scratch/wrong-gpg.err"; then
	fail 'valid minisign with a wrong-signer GPG signature must be refused'
fi
grep -Eq 'PGP signature|committed' "$scratch/wrong-gpg.err" ||
	fail "wrong-GPG refusal (log: $(cat "$scratch/wrong-gpg.err"))"
pass 'valid minisign with a wrong-signer GPG signature is refused'

gpg_only="$scratch/gpg-only"
write_manifests "$gpg_only"
sign_committed "$gpg_only"
rm -f "$gpg_only/SHA256SUMS.minisig" "$gpg_only/SHA512SUMS.minisig"
if run_verify "$gpg_only" >/dev/null 2>"$scratch/gpg-only.err"; then
	fail 'valid GPG with missing minisign signatures must be refused'
fi
grep -q 'missing minisign signature' "$scratch/gpg-only.err" ||
	fail "missing-minisign refusal (log: $(cat "$scratch/gpg-only.err"))"
pass 'valid GPG with missing minisign signatures is refused'

wrong_ms="$scratch/wrong-ms"
write_manifests "$wrong_ms"
sign_committed "$wrong_ms"
minisign -S -s "$scratch/env.key" -m "$wrong_ms/SHA256SUMS" -x "$wrong_ms/SHA256SUMS.minisig" >/dev/null
if run_verify "$wrong_ms" >/dev/null 2>"$scratch/wrong-ms.err"; then
	fail 'valid GPG with a wrong-signer minisign signature must be refused'
fi
grep -q 'minisign signature' "$scratch/wrong-ms.err" ||
	fail "wrong-minisign refusal (log: $(cat "$scratch/wrong-ms.err"))"
pass 'valid GPG with a wrong-signer minisign signature is refused'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''require_sig() {
	local path="$1" kind="$2"
	[[ -f "$path" && -s "$path" && ! -L "$path" ]] || die "missing $kind: ${path##*/}"
}'''
new = '''require_sig() {
	local path="$1" kind="$2"
	[[ -f "$path" && -s "$path" && ! -L "$path" ]] || return 0
}'''
if old not in text:
    raise SystemExit('live script is missing the required-signature check')
mut = text.replace(old, new, 1)
ms_old = '''	minisign -V -p "$minisign_pin" -m "$dir/$manifest" -x "$dir/$manifest.minisig" >/dev/null 2>&1 ||
		die "minisign signature for $manifest is invalid under the committed key"'''
ms_new = '''	if [[ -f "$dir/$manifest.minisig" ]]; then
		minisign -V -p "$minisign_pin" -m "$dir/$manifest" -x "$dir/$manifest.minisig" >/dev/null 2>&1 ||
			die "minisign signature for $manifest is invalid under the committed key"
	fi'''
if ms_old not in mut:
    raise SystemExit('live script is missing required minisign -V')
mut = mut.replace(ms_old, ms_new, 1)
pgp_old = '''	env -u GNUPGHOME gpg --homedir "$work/gpg" --batch --status-fd 1 --verify "$dir/$manifest.asc" "$dir/$manifest" \\
		>"$work/pgp-$manifest" 2>/dev/null || die "PGP signature for $manifest is invalid under the committed key"'''
pgp_new = '''	if [[ -f "$dir/$manifest.asc" ]]; then
	env -u GNUPGHOME gpg --homedir "$work/gpg" --batch --status-fd 1 --verify "$dir/$manifest.asc" "$dir/$manifest" \\
		>"$work/pgp-$manifest" 2>/dev/null || die "PGP signature for $manifest is invalid under the committed key"
	else
		return 0
	fi'''
if pgp_old not in mut:
    raise SystemExit('live script is missing required gpg --verify')
mut = mut.replace(pgp_old, pgp_new, 1)
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'one-of-two mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$ms_only" >/dev/null 2>"$scratch/mut-one.err"; then
	fail "skipping a missing GPG signature must accept minisign-only manifests (log: $(cat "$scratch/mut-one.err"))"
fi
if ! "$fixture_script" v1.2.3 "$gpg_only" >/dev/null 2>"$scratch/mut-one-gpg.err"; then
	fail "skipping a missing minisign signature must accept GPG-only manifests (log: $(cat "$scratch/mut-one-gpg.err"))"
fi
restore_script
pass 'reverting the both-required check accepts a single-format signature'

echo '[ok] signature verify uses tagged-commit keys and requires both formats'
