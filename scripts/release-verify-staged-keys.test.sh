#!/usr/bin/env bash
# Staged public keys must both be present and match the committed anchors.
# Throwaway keys only; never the default homedir. Decernor is a recording stub
# so the explicit fingerprint / blob compares are what catch a bad fixture.
set -eEuo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
# Do not use TMPDIR: macOS /var/folders paths overflow gpg-agent sockets.
scratch="$(mktemp -d /tmp/shs-sk.XXXXXX)"
scratch="$(CDPATH= cd -P -- "$scratch" && pwd -P)"
fake_home="$scratch/home"
mkdir -p "$fake_home/.gnupg"
chmod 700 "$fake_home/.gnupg"
printf 'sentinel\n' >"$fake_home/.gnupg/sentinel"
export HOME="$fake_home"
unset GPG_AGENT_INFO || true
export GNUPGHOME="$scratch/gpg"
mkdir -m 700 "$GNUPGHOME"
printf 'allow-loopback-pinentry\ndisable-scdaemon\n' >"$GNUPGHOME/gpg-agent.conf"
printf 'pinentry-mode loopback\n' >"$GNUPGHOME/gpg.conf"
cleanup() {
	env -u GNUPGHOME gpgconf --homedir "$GNUPGHOME" --kill all >/dev/null 2>&1 || true
	env -u GNUPGHOME gpgconf --homedir "$scratch/other-gpg" --kill all >/dev/null 2>&1 || true
	rm -rf "$scratch"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}
pass() { echo "PASS: $*"; }
trap 'echo "FAIL: $BASH_COMMAND (line ${BASH_LINENO[0]}, status $?)" >&2' ERR

[[ ${#GNUPGHOME} -lt 80 ]] || fail "GNUPGHOME too long for gpg-agent sockets (${#GNUPGHOME}): $GNUPGHOME"

fixture="$scratch/repo"
fixture_script="$fixture/scripts/release-verify-staged-keys.sh"
mkdir -p "$fixture/scripts" "$fixture/keys" "$fixture/docs/security"
cp "$root/scripts/release-decernor.sh" "$root/scripts/verify-public-key.sh" \
	"$root/scripts/release-verify-staged-keys.sh" "$root/scripts/release-verify-tag-anchor.sh" \
	"$fixture/scripts/"
cp "$root/keys/expected-fingerprints.txt" "$root/keys/expected-fingerprints.ndjson" "$fixture/keys/"
cp "$root/docs/security/release-signing-keys.asc" "$root/docs/security/shellsentry-minisign.pub" \
	"$fixture/docs/security/"
git init -q -b main "$fixture"
git -C "$fixture" config user.name Fixture
git -C "$fixture" config user.email fixture@example.invalid
git -C "$fixture" config commit.gpgsign false
git -C "$fixture" add docs keys scripts
git -C "$fixture" -c commit.gpgsign=false commit -qm fixture
git -C "$fixture" tag -am 'v1.2.3' v1.2.3
git init -q --bare "$scratch/origin.git"
git -C "$fixture" remote add origin "$scratch/origin.git"
git -C "$fixture" push -q origin HEAD:main
git -C "$fixture" push -q origin v1.2.3
git -C "$fixture" fetch -q origin
restore_script() {
	cp "$root/scripts/release-verify-staged-keys.sh" "$fixture_script"
	chmod +x "$fixture_script"
}
chmod +x "$fixture/scripts/"*.sh
mkdir -p "$scratch/bin-path"
tag_object="$(git -C "$fixture" rev-parse refs/tags/v1.2.3)"
full="$(git -C "$fixture" rev-parse HEAD)"
export GH_TAG_OBJECT="$tag_object"
export GH_TAG_JSON="$scratch/tag.json"
cat >"$GH_TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$full"},"verification":{"verified":true,"reason":"valid"}}
JSON
cat >"$scratch/bin-path/gh" <<'SH'
#!/usr/bin/env bash
case "$*" in
  *git/ref/tags/*)
    printf '{"object":{"type":"tag","sha":"%s"}}\n' "${GH_TAG_OBJECT:?}"
    ;;
  *'/git/tags/'*)
    cat "${GH_TAG_JSON:?}"
    ;;
  *)
    exit 0
    ;;
esac
SH
chmod +x "$scratch/bin-path/gh"
export PATH="$scratch/bin-path:$PATH"

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
grep -q 'cat-file blob "$commit:keys/expected-fingerprints.txt"' "$script" ||
	fail 'release-verify-staged-keys.sh must read anchors from the tagged commit'
grep -q 'release-verify-tag-anchor.sh' "$script" ||
	fail 'release-verify-staged-keys.sh must call the tag-anchor helper'
grep -E '^release-verify-keys:' -A8 "$root/Makefile" | grep -q 'SHELLSENTRY_RELEASE_TAG' ||
	fail 'release-verify-keys must pass the tag to release-verify-staged-keys.sh'
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
"$fixture_script" v1.2.3 "$ok_dir" >/dev/null || fail 'committed staged keys must verify'
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
gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase '' --quick-generate-key \
	'Synthetic unrelated <unrelated@example.invalid>' ed25519 cert 0 \
	|| fail 'gpg generate-key failed'
listing="$(gpg --batch --with-colons --fingerprint --list-keys)" || fail 'gpg list-keys failed'
unrelated_primary="$(awk -F: '$1=="fpr" {print $10; exit}' <<<"$listing")"
gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase '' --quick-add-key \
	"$unrelated_primary" ed25519 sign 0 \
	|| fail 'gpg add signing subkey failed'
unrelated_dir="$scratch/unrelated-gpg"
stage_ok "$unrelated_dir"
gpg --batch --armor --export "$unrelated_primary" >"$unrelated_dir/shellsentry-release-signing-key.asc"
if "$fixture_script" v1.2.3 "$unrelated_dir" >/dev/null 2>"$scratch/unrelated.err"; then
	fail 'unrelated staged PGP key must be refused'
fi
grep -q 'staged PGP fingerprint' "$scratch/unrelated.err" ||
	fail "unrelated PGP refusal (log: $(cat "$scratch/unrelated.err"))"
pass 'unrelated staged PGP key is refused'

if ! python3 - "$script" "$fixture_script" <<'PY'
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
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$unrelated_dir" >/dev/null 2>"$scratch/mut-unrelated.err"; then
	fail "dropping the fingerprint compare must accept the unrelated PGP key (log: $(cat "$scratch/mut-unrelated.err"))"
fi
restore_script
pass 'reverting the PGP fingerprint compare accepts the unrelated key'

# Missing staged minisign key.
missing_dir="$scratch/missing-minisign"
stage_ok "$missing_dir"
rm -f "$missing_dir/shellsentry-minisign.pub"
if "$fixture_script" v1.2.3 "$missing_dir" >/dev/null 2>"$scratch/missing.err"; then
	fail 'missing staged minisign key must be refused'
fi
grep -q 'missing staged minisign key' "$scratch/missing.err" ||
	fail "missing minisign refusal (log: $(cat "$scratch/missing.err"))"
pass 'missing staged minisign key is refused'

if ! python3 - "$script" "$fixture_script" <<'PY'
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
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$missing_dir" >/dev/null 2>"$scratch/mut-missing.err"; then
	fail "dropping the required minisign check must skip a missing key (log: $(cat "$scratch/mut-missing.err"))"
fi
restore_script
pass 'reverting the required minisign check accepts a missing key'

# Wrong minisign public key with the committed PGP pin.
wrong_dir="$scratch/wrong-minisign"
stage_ok "$wrong_dir"
minisign -G -W -p "$scratch/wrong.pub" -s "$scratch/wrong.key" >/dev/null 2>&1 ||
	fail 'minisign keygen failed'
cp "$scratch/wrong.pub" "$wrong_dir/shellsentry-minisign.pub"
if "$fixture_script" v1.2.3 "$wrong_dir" >/dev/null 2>"$scratch/wrong.err"; then
	fail 'wrong staged minisign key must be refused'
fi
grep -q 'staged minisign blob' "$scratch/wrong.err" ||
	fail "wrong minisign refusal (log: $(cat "$scratch/wrong.err"))"
pass 'wrong staged minisign key is refused'

if ! python3 - "$script" "$fixture_script" <<'PY'
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
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$wrong_dir" >/dev/null 2>"$scratch/mut-blob.err"; then
	fail "dropping the minisign blob compare must accept the wrong key (log: $(cat "$scratch/mut-blob.err"))"
fi
restore_script
pass 'reverting the minisign blob compare accepts the wrong key'

# Mutant: Decernor fingerprints the in-tree exports. The argv log must catch it.
if ! python3 - "$script" "$fixture_script" <<'PY'
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
chmod +x "$fixture_script"
: >"$decernor_log"
"$fixture_script" v1.2.3 "$ok_dir" >/dev/null || fail 'in-tree Decernor mutant should still pass a good fixture'
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
restore_script

# Anchors come from the tagged commit (PDR-0008 §2.1), not the working tree.
tagged_minisign="$(git -C "$fixture" show v1.2.3:keys/expected-fingerprints.txt | awk '$1=="minisign" {print $2}')"
printf 'gpg %s\nminisign %s\n' "$unrelated_primary" "$tagged_minisign" \
	>"$fixture/keys/expected-fingerprints.txt"
if "$fixture_script" v1.2.3 "$unrelated_dir" >/dev/null 2>"$scratch/wt-anchors.err"; then
	fail 'working-tree fingerprint anchors must not authorize an unrelated staged key'
fi
grep -q 'staged PGP fingerprint' "$scratch/wt-anchors.err" ||
	fail "tagged-anchor refusal (log: $(cat "$scratch/wt-anchors.err"))"
pass 'staged keys are checked against tagged-commit anchors, not the working tree'

if ! python3 - "$script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'git -C "$root" cat-file blob "$commit:keys/expected-fingerprints.txt" >"$anchors"'
new = 'cp "$root/keys/expected-fingerprints.txt" "$anchors"'
if old not in text:
    raise SystemExit('live script does not cat-file tagged fingerprint anchors')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('working-tree anchor mutant still uses cat-file')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'working-tree anchor mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$unrelated_dir" >/dev/null 2>"$scratch/mut-wt-anchors.err"; then
	fail "reading anchors from the working tree must accept the unrelated key (log: $(cat "$scratch/mut-wt-anchors.err"))"
fi
restore_script
pass 'reverting anchors to the working tree accepts an unrelated staged key'

echo '[ok] staged public keys refuse unrelated, missing, and wrong keys'
