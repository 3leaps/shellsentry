#!/usr/bin/env bash
# Draft creation verifies real manifests, signatures, and tag-bound archives.
# Throwaway keys only; never the default homedir or dummy checksum files.
set -eEuo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
gopath="$(go env GOPATH)"
gocache="$(go env GOCACHE)"
gomodcache="$(go env GOMODCACHE)"
gotoolchain="${GOTOOLCHAIN:-local}"
# Do not use TMPDIR: macOS runners put it under /var/folders (a symlink to
# /private/var/folders) with a path too long for gpg-agent sockets (~104 bytes).
scratch="$(mktemp -d /tmp/shs-cd.XXXXXX)"
scratch="$(CDPATH= cd -P -- "$scratch" && pwd -P)"
fake_home="$scratch/home"
mkdir -p "$fake_home/.gnupg"
chmod 700 "$fake_home/.gnupg"
printf 'sentinel\n' >"$fake_home/.gnupg/sentinel"
export HOME="$fake_home"
unset GPG_AGENT_INFO || true
export GNUPGHOME="$scratch/gpg"
mkdir -m 700 "$GNUPGHOME"
# Loopback pinentry and no scdaemon: macOS CI has no TTY or token, and
# --quick-add-key otherwise waits ~10s then exits 2 with no FAIL line.
printf 'allow-loopback-pinentry\ndisable-scdaemon\n' >"$GNUPGHOME/gpg-agent.conf"
printf 'pinentry-mode loopback\n' >"$GNUPGHOME/gpg.conf"
cleanup() {
	env -u GNUPGHOME gpgconf --homedir "$GNUPGHOME" --kill all >/dev/null 2>&1 || true
	env -u GNUPGHOME gpgconf --homedir "$scratch/other-gpg" --kill all >/dev/null 2>&1 || true
	chmod -R u+w "$scratch" >/dev/null 2>&1 || true
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

command -v gpg >/dev/null 2>&1 || fail 'gpg required'
command -v minisign >/dev/null 2>&1 || fail 'minisign required'
command -v python3 >/dev/null 2>&1 || fail 'python3 required'
command -v go >/dev/null 2>&1 || fail 'go required'

script="$root/scripts/release-create-draft.sh"
[[ -x "$script" ]] || fail 'release-create-draft.sh must be executable'
grep -E '^release-tag-tests:' -A40 "$root/Makefile" | grep -q 'test-release-create-draft' ||
	fail "release-tag-tests must run test-release-create-draft"
grep -q 'release-ci-refuse.sh' "$script" || fail "release-create-draft.sh must refuse GitHub Actions"
grep -q -- '--draft' "$script" || fail "release-create-draft.sh must pass --draft"
if grep -nE -- '--draft=false|draft=false' "$script"; then
	fail "release-create-draft.sh must not publish"
fi
grep -q -- '--verify-tag' "$script" || fail "release-create-draft.sh must pass --verify-tag"
grep -q 'does not list exactly the expected archives' "$script" ||
	fail 'release-create-draft.sh must verify checksum listings'
grep -q 'minisign -V' "$script" || fail 'release-create-draft.sh must verify minisign signatures'
grep -q 'VALIDSIG' "$script" || fail 'release-create-draft.sh must verify GPG signatures'
grep -q 'main.version=' "$script" || fail 'release-create-draft.sh must bind archives to the tag version'
grep -q 'main.gitCommit=' "$script" || fail 'release-create-draft.sh must bind archives to the tagged commit'
grep -q 'mktemp -d /tmp/shs-cd.XXXXXX' "$script" || fail 'create-draft work dir must be a short /tmp path'
if grep -nE 'mktemp -d "\$\{TMPDIR' "$script"; then
	fail 'create-draft GPG homes must not be created under TMPDIR'
fi
grep -q 'scratch="$(mktemp -d /tmp/shs-cd.XXXXXX)"' "$root/scripts/release-create-draft.test.sh" ||
	fail 'test scratch must be a short /tmp path'
pass 'create-draft script stays a verified draft and checks manifests, signatures, and tag bind'

if ! python3 - "$script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
if 'gh release create' not in text or '--draft' not in text:
    raise SystemExit('live script does not create a draft')
if '--draft=false' in text:
    raise SystemExit('live script publishes')
mut = text.replace(' --draft', '', 1)
if '--draft' in mut:
    raise SystemExit('mutant still has --draft')
if 'gh release create' not in mut:
    raise SystemExit('mutant lost gh release create')
PY
then
	fail "--draft mutant was not distinguished"
fi
pass "dropping --draft from create-draft is distinguished"

if ! python3 - "$root/scripts/release-create-draft.test.sh" <<'PY'
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

# awk exit in a pipefail pipeline SIGPIPEs gpg; BSD gpg then fails the assignment.
gpg_listing_fpr() {
	awk -F: '$1=="fpr" {print $10; exit}' <<<"$1"
}
gpg_listing_subkey() {
	awk -F: '$1=="sub" {s=1; next} s && $1=="fpr" {print $10; exit}' <<<"$1"
}

gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase '' --quick-generate-key \
	'Synthetic signing <signing@example.invalid>' ed25519 cert 0 \
	|| fail 'gpg generate-key failed'
listing="$(gpg --batch --with-colons --fingerprint --list-keys)" || fail 'gpg list-keys failed'
primary="$(gpg_listing_fpr "$listing")"
gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase '' --quick-add-key \
	"$primary" ed25519 sign 0 \
	|| fail 'gpg add signing subkey failed'
listing="$(gpg --batch --with-colons --with-subkey-fingerprint --list-keys "$primary")" ||
	fail 'gpg list-subkeys failed'
subkey="$(gpg_listing_subkey "$listing")"
[[ "$primary" =~ ^[0-9A-F]{40}$ && "$subkey" =~ ^[0-9A-F]{40}$ ]] || fail 'fixture signing key missing'

mkdir -m 700 "$scratch/other-gpg"
printf 'allow-loopback-pinentry\ndisable-scdaemon\n' >"$scratch/other-gpg/gpg-agent.conf"
printf 'pinentry-mode loopback\n' >"$scratch/other-gpg/gpg.conf"
# Unset GNUPGHOME so --homedir wins (macOS GnuPG otherwise uses the bound home).
other_gpg() { env -u GNUPGHOME gpg --homedir "$scratch/other-gpg" "$@"; }
other_gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase '' --quick-generate-key \
	'Synthetic other <other@example.invalid>' ed25519 cert 0 \
	|| fail 'other gpg generate-key failed'
listing="$(other_gpg --batch --with-colons --fingerprint --list-keys)" || fail 'other gpg list-keys failed'
other_primary="$(gpg_listing_fpr "$listing")"
other_gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase '' --quick-add-key \
	"$other_primary" ed25519 sign 0 \
	|| fail 'other gpg add signing subkey failed'
listing="$(other_gpg --batch --with-colons --with-subkey-fingerprint --list-keys "$other_primary")" ||
	fail 'other gpg list-subkeys failed'
other_subkey="$(gpg_listing_subkey "$listing")"
[[ "$other_primary" =~ ^[0-9A-F]{40}$ && "$other_subkey" =~ ^[0-9A-F]{40}$ ]] || fail 'other fixture signing key missing'

minisign -G -W -p "$scratch/good.pub" -s "$scratch/good.key" >/dev/null 2>&1 || fail 'minisign keygen failed'
minisign -G -W -p "$scratch/bad.pub" -s "$scratch/bad.key" >/dev/null 2>&1 || fail 'wrong minisign keygen failed'

fixture="$scratch/repo"
git init -q -b main "$fixture"
git -C "$fixture" config gpg.format openpgp
git -C "$fixture" config gpg.program gpg
git -C "$fixture" config commit.gpgsign false
git -C "$fixture" config user.name '3 Leaps Infosec Team'
git -C "$fixture" config user.email 'infosec@3leaps.net'
mkdir -p "$fixture/docs/security" "$fixture/docs/releases" "$fixture/scripts"
cp "$script" "$root/scripts/release-ci-refuse.sh" "$fixture/scripts/"
chmod +x "$fixture/scripts/"*.sh
fixture_script="$fixture/scripts/release-create-draft.sh"
restore_draft() {
	cp "$script" "$fixture_script"
	chmod +x "$fixture_script"
}
gpg --batch --armor --export "$primary" >"$fixture/docs/security/release-signing-keys.asc"
cp "$scratch/good.pub" "$fixture/docs/security/shellsentry-minisign.pub"
printf 'notes for v1.2.3\n' >"$fixture/docs/releases/v1.2.3.md"
git -C "$fixture" add docs scripts
git -C "$fixture" -c commit.gpgsign=false commit -qm fixture
short="$(git -C "$fixture" rev-parse --short HEAD)"
GIT_COMMITTER_NAME='3 Leaps Infosec Team' GIT_COMMITTER_EMAIL=infosec@3leaps.net \
	git -C "$fixture" -c gpg.format=openpgp tag -s -a --cleanup=verbatim \
	-u "$subkey!" -m 'shellsentry v1.2.3'$'\n' v1.2.3 HEAD ||
	fail 'signed fixture tag failed'

go_build() {
	GOPATH="$gopath" GOCACHE="$gocache" GOMODCACHE="$gomodcache" GOTOOLCHAIN="$gotoolchain" \
		CGO_ENABLED=0 go build "$@"
}
mkdir -p "$scratch/bin"
(cd "$root" && go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=${short}" \
	-o "$scratch/bin/shellsentry" .)
[[ -s "$scratch/bin/shellsentry" ]] || fail 'fixture binary missing'
(cd "$root" && go_build -trimpath \
	-ldflags="-s -w -X main.version=9.9.9 -X main.gitCommit=${short}" \
	-o "$scratch/bin/wrong-version" .)
(cd "$root" && go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=deadbee" \
	-o "$scratch/bin/wrong-commit" .)

pack_from() {
	local binary="$1" dest="$2"
	rm -rf "$dest"
	mkdir -p "$dest"
	python3 - "$binary" "$dest" "$root/scripts/install-shellsentry.sh" <<'PY'
import hashlib
import io
import pathlib
import sys
import tarfile
import zipfile

binary = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
installer_src = pathlib.Path(sys.argv[3])
payload = binary.read_bytes()
for name in (
    "shellsentry_linux_amd64.tar.gz",
    "shellsentry_linux_arm64.tar.gz",
    "shellsentry_darwin_arm64.tar.gz",
):
    with tarfile.open(dest / name, "w:gz") as tf:
        info = tarfile.TarInfo("shellsentry")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
for name in (
    "shellsentry_windows_amd64.zip",
    "shellsentry_windows_arm64.zip",
):
    with zipfile.ZipFile(dest / name, "w") as zf:
        zf.writestr("shellsentry.exe", payload)
(dest / "install-shellsentry.sh").write_bytes(installer_src.read_bytes())
packages = [
    "shellsentry_linux_amd64.tar.gz",
    "shellsentry_linux_arm64.tar.gz",
    "shellsentry_windows_amd64.zip",
    "shellsentry_windows_arm64.zip",
    "shellsentry_darwin_arm64.tar.gz",
    "install-shellsentry.sh",
]
for manifest, algo in (("SHA256SUMS", "sha256"), ("SHA512SUMS", "sha512")):
    lines = []
    for name in packages:
        digest = hashlib.new(algo, (dest / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    (dest / manifest).write_text("\n".join(lines) + "\n")
PY
}

sign_dir() {
	local dest="$1"
	minisign -S -s "$scratch/good.key" -m "$dest/SHA256SUMS" -x "$dest/SHA256SUMS.minisig" >/dev/null
	minisign -S -s "$scratch/good.key" -m "$dest/SHA512SUMS" -x "$dest/SHA512SUMS.minisig" >/dev/null
	gpg --batch --yes --armor --local-user "$subkey!" --detach-sign -o "$dest/SHA256SUMS.asc" "$dest/SHA256SUMS"
	gpg --batch --yes --armor --local-user "$subkey!" --detach-sign -o "$dest/SHA512SUMS.asc" "$dest/SHA512SUMS"
}

pack_from "$scratch/bin/shellsentry" "$scratch/dist"
sign_dir "$scratch/dist"

mkdir -p "$scratch/bin-path"
export GH_TRACE="$scratch/trace"
: >"$GH_TRACE"
cat >"$scratch/bin-path/gh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${GH_TRACE}"
case "$*" in
  *'release view'*)
    exit "${FIXTURE_VIEW_RC:-1}"
    ;;
  *'release create'*)
    printf '%s\n' "$*" >"${GH_TRACE}.create"
    ;;
  *)
    exit 0
    ;;
esac
SH
chmod +x "$scratch/bin-path/gh"
export PATH="$scratch/bin-path:$PATH"
unset GITHUB_ACTIONS || true
run_draft() {
	"$fixture/scripts/release-create-draft.sh" v1.2.3 "$1"
}

if env GITHUB_ACTIONS=true run_draft "$scratch/dist" >/dev/null 2>&1; then
	fail "create-draft must refuse GitHub Actions"
fi
pass "create-draft refuses GitHub Actions"

: >"$GH_TRACE"
rm -f "$GH_TRACE.create"
if ! run_draft "$scratch/dist" >/dev/null 2>"$scratch/ok.err"; then
	fail "create-draft must succeed for real signed packages (log: $(cat "$scratch/ok.err"))"
fi
grep -q -- '--draft' "$GH_TRACE.create" || fail "gh release create must pass --draft"
grep -q -- '--verify-tag' "$GH_TRACE.create" || fail "gh release create must pass --verify-tag"
if grep -nE -- '--draft=false|draft=false' "$GH_TRACE.create"; then
	fail "gh release create must not pass --draft=false"
fi
grep -q 'SHA256SUMS.minisig' "$GH_TRACE.create" || fail 'draft must upload minisign signatures'
grep -q 'SHA256SUMS.asc' "$GH_TRACE.create" || fail 'draft must upload GPG signatures'
pass "create-draft opens a verified draft from real signed packages"

: >"$GH_TRACE"
export FIXTURE_VIEW_RC=0
if run_draft "$scratch/dist" >/dev/null 2>&1; then
	fail "create-draft must refuse an existing release"
fi
if grep -q 'release create' "$GH_TRACE"; then
	fail "create-draft must not call create when a release already exists"
fi
unset FIXTURE_VIEW_RC
pass "create-draft refuses an existing release"

extra="$scratch/extra"
cp -a "$scratch/dist" "$extra"
printf 'nope\n' >"$extra/unexpected.bin"
if run_draft "$extra" >/dev/null 2>"$scratch/extra.err"; then
	fail 'create-draft must refuse an unexpected file'
fi
grep -q 'unexpected file' "$scratch/extra.err" ||
	fail "unexpected-file refusal (log: $(cat "$scratch/extra.err"))"
pass 'create-draft refuses an unexpected file'

dummy="$scratch/dummy"
cp -a "$scratch/dist" "$dummy"
printf 'x\n' >"$dummy/SHA256SUMS"
printf 'x\n' >"$dummy/SHA512SUMS"
sign_dir "$dummy"
if run_draft "$dummy" >/dev/null 2>"$scratch/dummy.err"; then
	fail 'create-draft must refuse dummy manifests'
fi
grep -Eq 'malformed|exactly the expected archives|matching hashes' "$scratch/dummy.err" ||
	fail "dummy-manifest refusal (log: $(cat "$scratch/dummy.err"))"
pass 'create-draft refuses dummy manifests'

omit="$scratch/omit"
cp -a "$scratch/dist" "$omit"
python3 - "$omit/SHA256SUMS" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
lines = [ln for ln in p.read_text().splitlines() if 'darwin_arm64' not in ln]
p.write_text('\n'.join(lines) + '\n')
PY
sign_dir "$omit"
if run_draft "$omit" >/dev/null 2>"$scratch/omit.err"; then
	fail 'create-draft must refuse a manifest that omits a staged archive'
fi
grep -q 'exactly the expected archives' "$scratch/omit.err" ||
	fail "omit-from-manifest refusal (log: $(cat "$scratch/omit.err"))"
pass 'create-draft refuses a manifest that omits a staged archive'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'import hashlib\n'
new = 'raise SystemExit(0)\nimport hashlib\n'
if old not in text:
    raise SystemExit('live script is missing checksum verification')
mut = text.replace(old, new, 1)
if mut.count('raise SystemExit(0)\nimport hashlib') != 1:
    raise SystemExit('checksum mutant was not applied once')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'checksum mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$omit" >/dev/null 2>"$scratch/mut-sums.err"; then
	fail "dropping checksum listing must accept an incomplete manifest (log: $(cat "$scratch/mut-sums.err"))"
fi
restore_draft
pass 'reverting checksum listing accepts an omitted archive'

mismatch="$scratch/mismatch"
cp -a "$scratch/dist" "$mismatch"
python3 - "$mismatch/SHA256SUMS" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
lines = p.read_text().splitlines(True)
c = lines[0][0]
lines[0] = ('0' if c != '0' else '1') + lines[0][1:]
p.write_text(''.join(lines))
PY
sign_dir "$mismatch"
if run_draft "$mismatch" >/dev/null 2>"$scratch/mismatch.err"; then
	fail 'create-draft must refuse a digest mismatch'
fi
grep -q 'digest mismatch' "$scratch/mismatch.err" ||
	fail "digest-mismatch refusal (log: $(cat "$scratch/mismatch.err"))"
pass 'create-draft refuses a digest mismatch'

bad_ms="$scratch/bad-minisig"
cp -a "$scratch/dist" "$bad_ms"
minisign -S -s "$scratch/bad.key" -m "$bad_ms/SHA256SUMS" -x "$bad_ms/SHA256SUMS.minisig" >/dev/null
if run_draft "$bad_ms" >/dev/null 2>"$scratch/bad-ms.err"; then
	fail 'create-draft must refuse a minisign signature from the wrong key'
fi
grep -q 'minisign signature' "$scratch/bad-ms.err" ||
	fail "bad minisign refusal (log: $(cat "$scratch/bad-ms.err"))"
pass 'create-draft refuses a wrong minisign key'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'minisign -V -p "$minisign_pin" -m "$src/$manifest" -x "$src/$manifest.minisig" >/dev/null 2>&1 ||'
new = 'true ||'
if old not in text:
    raise SystemExit('live script is missing minisign -V')
mut = text.replace(old, new, 1)
if 'minisign -V' in mut:
    raise SystemExit('minisign mutant still verifies')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'minisign mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$bad_ms" >/dev/null 2>"$scratch/mut-ms.err"; then
	fail "dropping minisign verify must accept the wrong key (log: $(cat "$scratch/mut-ms.err"))"
fi
restore_draft
pass 'reverting minisign verification accepts a wrong-key signature'

bad_gpg="$scratch/bad-gpg"
cp -a "$scratch/dist" "$bad_gpg"
other_gpg --batch --yes --armor --local-user "$other_subkey!" \
	--detach-sign -o "$bad_gpg/SHA256SUMS.asc" "$bad_gpg/SHA256SUMS"
if run_draft "$bad_gpg" >/dev/null 2>"$scratch/bad-gpg.err"; then
	fail 'create-draft must refuse a GPG signature from the wrong key'
fi
grep -Eq 'PGP signature|committed' "$scratch/bad-gpg.err" ||
	fail "bad GPG refusal (log: $(cat "$scratch/bad-gpg.err"))"
pass 'create-draft refuses a wrong GPG key'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''verify_pgp() {
	local manifest="$1"
	env -u GNUPGHOME gpg --homedir "$work/gpg" --batch --status-fd 1 --verify "$src/$manifest.asc" "$src/$manifest" \\
		>"$work/pgp-$manifest" 2>/dev/null || die "PGP signature for $manifest is invalid under the committed key"
'''
new = '''verify_pgp() {
	local manifest="$1"
	return 0
	env -u GNUPGHOME gpg --homedir "$work/gpg" --batch --status-fd 1 --verify "$src/$manifest.asc" "$src/$manifest" \\
		>"$work/pgp-$manifest" 2>/dev/null || die "PGP signature for $manifest is invalid under the committed key"
'''
if old not in text:
    raise SystemExit('live script is missing verify_pgp')
mut = text.replace(old, new, 1)
if mut.count('return 0') < 1:
    raise SystemExit('gpg mutant did not skip verification')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'GPG mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$bad_gpg" >/dev/null 2>"$scratch/mut-gpg.err"; then
	fail "dropping GPG verify must accept the wrong key (log: $(cat "$scratch/mut-gpg.err"))"
fi
restore_draft
pass 'reverting GPG verification accepts a wrong-key signature'

missing_sig="$scratch/missing-sig"
cp -a "$scratch/dist" "$missing_sig"
rm -f "$missing_sig/SHA256SUMS.minisig"
if run_draft "$missing_sig" >/dev/null 2>"$scratch/missing-sig.err"; then
	fail 'create-draft must refuse a missing minisign signature'
fi
grep -q 'missing release file' "$scratch/missing-sig.err" ||
	fail "missing signature refusal (log: $(cat "$scratch/missing-sig.err"))"
pass 'create-draft refuses a missing minisign signature'

wrong_ver="$scratch/wrong-ver"
pack_from "$scratch/bin/wrong-version" "$wrong_ver"
sign_dir "$wrong_ver"
if run_draft "$wrong_ver" >/dev/null 2>"$scratch/wrong-ver.err"; then
	fail 'create-draft must refuse archives not bound to the tag version'
fi
grep -q 'not bound to signed tag' "$scratch/wrong-ver.err" ||
	fail "wrong-version refusal (log: $(cat "$scratch/wrong-ver.err"))"
pass 'create-draft refuses a wrong-version binary'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '\tbind_archive "$archive"\n'
new = '\ttrue "$archive"\n'
if old not in text:
    raise SystemExit('live script is missing bind_archive calls')
mut = text.replace(old, new, 1)
if 'bind_archive "$archive"' in mut:
    raise SystemExit('bind mutant still binds archives')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'archive-bind mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$wrong_ver" >/dev/null 2>"$scratch/mut-bind.err"; then
	fail "dropping archive bind must accept a wrong-version binary (log: $(cat "$scratch/mut-bind.err"))"
fi
restore_draft
pass 'reverting archive bind accepts a wrong-version binary'

wrong_commit="$scratch/wrong-commit"
pack_from "$scratch/bin/wrong-commit" "$wrong_commit"
sign_dir "$wrong_commit"
if run_draft "$wrong_commit" >/dev/null 2>"$scratch/wrong-commit.err"; then
	fail 'create-draft must refuse archives not bound to the tagged commit'
fi
grep -q 'not bound to signed tag' "$scratch/wrong-commit.err" ||
	fail "wrong-commit refusal (log: $(cat "$scratch/wrong-commit.err"))"
pass 'create-draft refuses a wrong-commit binary'

git -C "$fixture" tag -d v1.2.3 >/dev/null
git -C "$fixture" tag -a -m 'unsigned' v1.2.3 HEAD
if run_draft "$scratch/dist" >/dev/null 2>"$scratch/unsigned.err"; then
	fail 'create-draft must refuse an unsigned tag'
fi
grep -q 'tag is not GPG-signed' "$scratch/unsigned.err" ||
	fail "unsigned-tag refusal (log: $(cat "$scratch/unsigned.err"))"
pass 'create-draft refuses an unsigned tag'

echo '[ok] release-create-draft verifies real manifests, signatures, and tag bind'
