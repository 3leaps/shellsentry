#!/usr/bin/env bash
# Staged public keys must both be present and match the committed anchors.
# Throwaway keys only; never the default homedir. Decernor is a recording stub
# so the explicit fingerprint / blob compares are what catch a bad fixture.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-staged-keys.XXXXXX")"
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

mutant_repo="$scratch/mutant-repo"
mutant_sh="$mutant_repo/scripts/release-verify-staged-keys.sh"
mkdir -p "$mutant_repo/scripts" "$mutant_repo/keys" "$mutant_repo/docs/security"
cp "$root/scripts/release-decernor.sh" "$root/scripts/verify-public-key.sh" "$mutant_repo/scripts/"
cp "$root/keys/expected-fingerprints.txt" "$root/keys/expected-fingerprints.ndjson" "$mutant_repo/keys/"
cp "$root/docs/security/release-signing-keys.asc" "$root/docs/security/shellsentry-minisign.pub" \
	"$mutant_repo/docs/security/"

command -v gpg >/dev/null 2>&1 || fail 'gpg required'
command -v minisign >/dev/null 2>&1 || fail 'minisign required'
command -v python3 >/dev/null 2>&1 || fail 'python3 required'

script="$root/scripts/release-verify-staged-keys.sh"
[[ -x "$script" ]] || fail 'release-verify-staged-keys.sh must be executable'
grep -q 'release-verify-staged-keys.sh' "$root/Makefile" ||
	fail 'Makefile must invoke release-verify-staged-keys.sh'
grep -E '^release-verify-keys:' -A8 "$root/Makefile" | grep -q 'release-verify-staged-keys.sh' ||
	fail 'release-verify-keys must run release-verify-staged-keys.sh'
if grep -E '^release-verify-keys:' -A20 "$root/Makefile" | grep -q '\[skip\] No minisign'; then
	fail 'release-verify-keys must not skip a missing staged minisign key'
fi
grep -E '^release-tag-tests:' -A40 "$root/Makefile" | grep -q 'test-release-verify-staged-keys' ||
	fail 'release-tag-tests must run test-release-verify-staged-keys'
pass 'Makefile requires both staged keys and runs the invertibility harness'

# Static order: GNUPGHOME is bound before the first gpg call in this file.
if ! python3 - "$root/scripts/release-verify-staged-keys.test.sh" <<'PY'
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

decernor_log="$scratch/decernor.log"
cat >"$scratch/decernor" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>'$decernor_log'
case "\$1 \${2:-}" in
  'version ') echo 'decernor 0.1.8' ;;
  'version -e') printf 'Version:         0.1.8\nCommit:          testdata\nBuild Date:      testdata\nGo Version:      testdata\nGofulmen:        testdata\nCrucible:        testdata\n' ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$scratch/decernor"
export SHELLSENTRY_DECERNOR_BIN="$scratch/decernor"

committed_gpg="$root/docs/security/release-signing-keys.asc"
committed_minisign="$root/docs/security/shellsentry-minisign.pub"
[[ -s "$committed_gpg" && -s "$committed_minisign" ]] || fail 'committed public pins missing'

stage_ok() {
	local dest="$1"
	mkdir -p "$dest"
	cp "$committed_gpg" "$dest/shellsentry-release-signing-key.asc"
	cp "$committed_minisign" "$dest/shellsentry-minisign.pub"
}

: >"$decernor_log"
ok_dir="$scratch/ok"
stage_ok "$ok_dir"
"$script" "$ok_dir" >/dev/null || fail 'committed staged keys must verify'
if ! python3 - "$decernor_log" "$ok_dir" <<'PY'
from pathlib import Path
import sys
log, staged = Path(sys.argv[1]).read_text(), sys.argv[2]
if 'fingerprint verify' not in log:
    raise SystemExit('Decernor was not invoked')
if f'--gpg {staged}/shellsentry-release-signing-key.asc' not in log:
    raise SystemExit(f'Decernor --gpg was not the staged key: {log!r}')
if f'--minisign {staged}/shellsentry-minisign.pub' not in log:
    raise SystemExit(f'Decernor --minisign was not the staged key: {log!r}')
if 'docs/security/release-signing-keys.asc' in log or 'docs/security/shellsentry-minisign.pub' in log:
    raise SystemExit('Decernor saw in-tree exports instead of staged files')
PY
then
	fail 'Decernor must fingerprint-verify the staged files, not the in-tree exports'
fi
pass 'committed staged keys verify; Decernor saw the staged paths'

# Unrelated throwaway PGP key with a signing subkey, plus the committed minisign pin.
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
	'Synthetic unrelated <unrelated@example.invalid>' ed25519 cert 0 >/dev/null 2>&1
unrelated_primary="$(gpg --batch --with-colons --fingerprint --list-keys | awk -F: '$1=="fpr" {print $10;exit}')"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$unrelated_primary" ed25519 sign 1d >/dev/null 2>&1
unrelated_dir="$scratch/unrelated-gpg"
stage_ok "$unrelated_dir"
gpg --batch --armor --export "$unrelated_primary" >"$unrelated_dir/shellsentry-release-signing-key.asc"
if "$script" "$unrelated_dir" >/dev/null 2>"$scratch/unrelated.err"; then
	fail 'unrelated staged PGP key must be refused'
fi
grep -q 'staged PGP fingerprint' "$scratch/unrelated.err" ||
	fail "unrelated PGP refusal (log: $(cat "$scratch/unrelated.err"))"
pass 'unrelated staged PGP key is refused'

if ! python3 - "$script" "$mutant_sh" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
needle = '[[ "$staged_fpr" == "$pin_gpg" ]] ||'
if needle not in text:
    raise SystemExit('live script is missing the fingerprint compare')
mut = text.replace(needle, 'true ||', 1)
if needle in mut:
    raise SystemExit('fingerprint mutant still compares')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'fingerprint-compare mutant was not distinguished'
fi
chmod +x "$mutant_sh"
if ! "$mutant_sh" "$unrelated_dir" >/dev/null 2>"$scratch/mut-unrelated.err"; then
	fail "dropping the fingerprint compare must accept the unrelated PGP key (log: $(cat "$scratch/mut-unrelated.err"))"
fi
pass 'reverting the PGP fingerprint compare accepts the unrelated key'

# Missing staged minisign key.
missing_dir="$scratch/missing-minisign"
stage_ok "$missing_dir"
rm -f "$missing_dir/shellsentry-minisign.pub"
if "$script" "$missing_dir" >/dev/null 2>"$scratch/missing.err"; then
	fail 'missing staged minisign key must be refused'
fi
grep -q 'missing staged minisign key' "$scratch/missing.err" ||
	fail "missing minisign refusal (log: $(cat "$scratch/missing.err"))"
pass 'missing staged minisign key is refused'

if ! python3 - "$script" "$mutant_sh" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''[[ -f "$staged_minisign" && -s "$staged_minisign" && ! -L "$staged_minisign" ]] ||
	die "missing staged minisign key: $staged_minisign"'''
new = '''if [[ ! -f "$staged_minisign" ]]; then echo "[skip] No minisign public key"; exit 0; fi'''
if old not in text:
    raise SystemExit('live script is missing the required minisign check')
mut = text.replace(old, new, 1)
if 'missing staged minisign key' in mut:
    raise SystemExit('minisign-required mutant still dies on a missing key')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'missing-minisign mutant was not distinguished'
fi
chmod +x "$mutant_sh"
if ! "$mutant_sh" "$missing_dir" >/dev/null 2>"$scratch/mut-missing.err"; then
	fail "dropping the required minisign check must skip a missing key (log: $(cat "$scratch/mut-missing.err"))"
fi
pass 'reverting the required minisign check accepts a missing key'

# Wrong minisign public key with the committed PGP pin.
wrong_dir="$scratch/wrong-minisign"
stage_ok "$wrong_dir"
minisign -G -W -p "$scratch/wrong.pub" -s "$scratch/wrong.key" >/dev/null 2>&1 ||
	fail 'minisign keygen failed'
cp "$scratch/wrong.pub" "$wrong_dir/shellsentry-minisign.pub"
if "$script" "$wrong_dir" >/dev/null 2>"$scratch/wrong.err"; then
	fail 'wrong staged minisign key must be refused'
fi
grep -q 'staged minisign blob' "$scratch/wrong.err" ||
	fail "wrong minisign refusal (log: $(cat "$scratch/wrong.err"))"
pass 'wrong staged minisign key is refused'

if ! python3 - "$script" "$mutant_sh" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
needle = '[[ "$staged_blob" == "$pin_minisign" ]] ||'
if needle not in text:
    raise SystemExit('live script is missing the minisign blob compare')
mut = text.replace(needle, 'true ||', 1)
if needle in mut:
    raise SystemExit('blob mutant still compares')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'minisign-blob mutant was not distinguished'
fi
chmod +x "$mutant_sh"
if ! "$mutant_sh" "$wrong_dir" >/dev/null 2>"$scratch/mut-blob.err"; then
	fail "dropping the minisign blob compare must accept the wrong key (log: $(cat "$scratch/mut-blob.err"))"
fi
pass 'reverting the minisign blob compare accepts the wrong key'

# Mutant: Decernor fingerprints the in-tree exports. The argv log must catch it.
if ! python3 - "$script" "$mutant_sh" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '--gpg "$staged_gpg" --minisign "$staged_minisign"'
new = '--gpg "$root/docs/security/release-signing-keys.asc" --minisign "$root/docs/security/shellsentry-minisign.pub"'
if old not in text:
    raise SystemExit('live script does not pass staged files to Decernor')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('in-tree Decernor mutant still uses staged files')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'in-tree Decernor mutant was not distinguished'
fi
chmod +x "$mutant_sh"
: >"$decernor_log"
"$mutant_sh" "$ok_dir" >/dev/null || fail 'in-tree Decernor mutant should still pass a good fixture'
if ! python3 - "$decernor_log" "$ok_dir" <<'PY'
from pathlib import Path
import sys
log, staged = Path(sys.argv[1]).read_text(), sys.argv[2]
if f'--gpg {staged}/shellsentry-release-signing-key.asc' in log:
    raise SystemExit('mutant still passed the staged GPG path')
if 'docs/security/release-signing-keys.asc' not in log:
    raise SystemExit('mutant did not pass the in-tree GPG export')
PY
then
	fail 'Decernor argv log did not distinguish the in-tree mutant'
fi
pass 'Decernor argv log distinguishes fingerprinting in-tree exports'

echo '[ok] staged public keys refuse unrelated, missing, and wrong keys'
