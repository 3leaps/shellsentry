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
grep -q 'vcs.revision' "$script" || fail 'release-create-draft.sh must bind archives via go version -m vcs.revision'
grep -q 'delimited' "$script" || fail 'release-create-draft.sh must bind ldflag strings with left and right boundaries'
grep -q 'release-verify-tag-anchor.sh' "$script" || fail 'release-create-draft.sh must verify the tag against origin'
grep -q 'cat-file blob "$commit:docs/releases/' "$script" ||
	fail 'release-create-draft.sh must read release notes from the tagged commit'
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
mkdir -p "$fixture/docs/security" "$fixture/docs/releases" "$fixture/scripts" "$fixture/keys"
cp "$script" "$root/scripts/release-ci-refuse.sh" "$root/scripts/release-verify-tag-anchor.sh" \
	"$fixture/scripts/"
chmod +x "$fixture/scripts/"*.sh
cp -a "$root/internal" "$fixture/"
cp "$root/main.go" "$root/go.mod" "$root/go.sum" "$fixture/"
fixture_script="$fixture/scripts/release-create-draft.sh"
restore_draft() {
	cp "$script" "$fixture_script"
	chmod +x "$fixture_script"
}
gpg --batch --armor --export "$primary" >"$fixture/docs/security/release-signing-keys.asc"
cp "$scratch/good.pub" "$fixture/docs/security/shellsentry-minisign.pub"
printf 'notes for v1.2.3\n' >"$fixture/docs/releases/v1.2.3.md"
blob="$(python3 -c 'import base64,hashlib,pathlib,sys; print(hashlib.sha256(base64.b64decode(pathlib.Path(sys.argv[1]).read_text().splitlines()[1])).hexdigest())' "$scratch/good.pub")"
printf 'gpg %s\nminisign %s\n' "$primary" "$blob" >"$fixture/keys/expected-fingerprints.txt"
printf '{"schema_version":"v0"}\n{"schema_version":"v0"}\n' >"$fixture/keys/expected-fingerprints.ndjson"
git -C "$fixture" add docs keys scripts internal main.go go.mod go.sum
git -C "$fixture" -c commit.gpgsign=false commit -qm fixture
full="$(git -C "$fixture" rev-parse HEAD)"
short="$(git -C "$fixture" rev-parse --short HEAD)"
GIT_COMMITTER_NAME='3 Leaps Infosec Team' GIT_COMMITTER_EMAIL=infosec@3leaps.net \
	git -C "$fixture" -c gpg.format=openpgp tag -s -a --cleanup=verbatim \
	-u "$subkey!" -m 'shellsentry v1.2.3'$'\n' v1.2.3 HEAD ||
	fail 'signed fixture tag failed'
git init -q --bare "$scratch/origin.git"
git -C "$fixture" remote add origin "$scratch/origin.git"
git -C "$fixture" push -q origin HEAD:main
git -C "$fixture" push -q origin v1.2.3
git -C "$fixture" fetch -q origin

go_build() {
	GOPATH="$gopath" GOCACHE="$gocache" GOMODCACHE="$gomodcache" GOTOOLCHAIN="$gotoolchain" \
		CGO_ENABLED=0 go build "$@"
}
mkdir -p "$scratch/bin"
(cd "$fixture" && go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=${full}" \
	-o "$scratch/bin/shellsentry" .)
[[ -s "$scratch/bin/shellsentry" ]] || fail 'fixture binary missing'
(cd "$fixture" && go_build -trimpath \
	-ldflags="-s -w -X main.version=9.9.9 -X main.gitCommit=${full}" \
	-o "$scratch/bin/wrong-version" .)
(cd "$fixture" && go_build -buildvcs=false -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=deadbee000000000000000000000000000000000" \
	-o "$scratch/bin/wrong-commit" .)
(cd "$fixture" && GOOS=darwin GOARCH=arm64 go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=${full}" \
	-o "$scratch/bin/shellsentry-darwin" .)
[[ -s "$scratch/bin/shellsentry-darwin" ]] || fail 'darwin fixture binary missing'
(cd "$fixture" && go_build -buildvcs=false -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=zz${short}" \
	-o "$scratch/bin/forged-zz" .)
(cd "$fixture" && go_build -trimpath \
	-ldflags="-s -w -X main.version=11.2.3 -X main.gitCommit=${full}" \
	-o "$scratch/bin/forged-version" .)
(cd "$fixture" && go_build -buildvcs=false -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=cafebabeface0000000000000000000000000000 -X main.buildTime=${full}" \
	-o "$scratch/bin/forged-buildtime" .)
printf 'working-tree notes must not be used\n' >"$fixture/docs/releases/v1.2.3.md"

pack_from() {
	local binary="$1" dest="$2" darwin="${3:-$1}"
	rm -rf "$dest"
	mkdir -p "$dest"
	python3 - "$binary" "$dest" "$root/scripts/install-shellsentry.sh" "$darwin" <<'PY'
import hashlib
import io
import pathlib
import sys
import tarfile
import zipfile

binary = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
installer_src = pathlib.Path(sys.argv[3])
darwin_bin = pathlib.Path(sys.argv[4])
payload = binary.read_bytes()
darwin_payload = darwin_bin.read_bytes()
for name in (
    "shellsentry_linux_amd64.tar.gz",
    "shellsentry_linux_arm64.tar.gz",
):
    with tarfile.open(dest / name, "w:gz") as tf:
        info = tarfile.TarInfo("shellsentry")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
with tarfile.open(dest / "shellsentry_darwin_arm64.tar.gz", "w:gz") as tf:
    info = tarfile.TarInfo("shellsentry")
    info.size = len(darwin_payload)
    tf.addfile(info, io.BytesIO(darwin_payload))
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

pack_from "$scratch/bin/shellsentry" "$scratch/dist" "$scratch/bin/shellsentry-darwin"
sign_dir "$scratch/dist"

mkdir -p "$scratch/bin-path"
export GH_TRACE="$scratch/trace"
: >"$GH_TRACE"
tag_object="$(git -C "$fixture" rev-parse refs/tags/v1.2.3)"
export GH_TAG_OBJECT="$tag_object"
export GH_TAG_COMMIT="$full"
export GH_TAG_JSON="$scratch/tag.json"
cat >"$GH_TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$full"},"verification":{"verified":true,"reason":"valid"}}
JSON
cat >"$scratch/bin-path/gh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${GH_TRACE}"
case "$*" in
  *'release view'*)
    exit "${FIXTURE_VIEW_RC:-1}"
    ;;
  *'release create'*)
    printf '%s\n' "$*" >"${GH_TRACE}.create"
    prev=""
    for arg in "$@"; do
      if [[ "$prev" == --notes-file ]]; then
        cp "$arg" "${GH_TRACE}.notes"
      fi
      prev="$arg"
    done
    ;;
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
grep -q 'release-notes.md' "$GH_TRACE.create" || fail 'draft must pass notes extracted from the tagged commit'
if grep -q "$fixture/docs/releases" "$GH_TRACE.create"; then
	fail 'draft must not read release notes from the working tree'
fi
[[ -s "$GH_TRACE.notes" ]] || fail 'gh stub must record the notes file'
grep -qx 'notes for v1.2.3' "$GH_TRACE.notes" ||
	fail "notes must come from the tagged commit (got: $(cat "$GH_TRACE.notes"))"
if grep -q 'working-tree notes must not be used' "$GH_TRACE.notes"; then
	fail 'draft must not read release notes from the working tree'
fi
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

omit512="$scratch/omit512"
cp -a "$scratch/dist" "$omit512"
python3 - "$omit512/SHA512SUMS" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
lines = [ln for ln in p.read_text().splitlines() if 'darwin_arm64' not in ln]
p.write_text('\n'.join(lines) + '\n')
PY
sign_dir "$omit512"
if run_draft "$omit512" >/dev/null 2>"$scratch/omit512.err"; then
	fail 'create-draft must refuse a SHA512 manifest that omits a staged archive'
fi
grep -q 'exactly the expected archives' "$scratch/omit512.err" ||
	fail "SHA512 omit-from-manifest refusal (log: $(cat "$scratch/omit512.err"))"
pass 'create-draft refuses a SHA512 manifest that omits a staged archive'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = "for manifest, algorithm, width in (('SHA256SUMS', 'sha256', 64), ('SHA512SUMS', 'sha512', 128)):"
new = "for manifest, algorithm, width in (('SHA256SUMS', 'sha256', 64),):"
if old not in text:
    raise SystemExit('live script is missing the SHA512 checksum pass')
mut = text.replace(old, new, 1)
if 'SHA512SUMS' in mut.split('bind_archive', 1)[0] and old in mut:
    raise SystemExit('SHA512 checksum mutant still lists SHA512SUMS')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'SHA512 checksum mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$omit512" >/dev/null 2>"$scratch/mut-sha512.err"; then
	fail "dropping the SHA512 listing check must accept an incomplete SHA512SUMS (log: $(cat "$scratch/mut-sha512.err"))"
fi
restore_draft
pass 'reverting the SHA512 listing check accepts an omitted archive'

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

bad_ms512="$scratch/bad-minisig-512"
cp -a "$scratch/dist" "$bad_ms512"
minisign -S -s "$scratch/bad.key" -m "$bad_ms512/SHA512SUMS" -x "$bad_ms512/SHA512SUMS.minisig" >/dev/null
if run_draft "$bad_ms512" >/dev/null 2>"$scratch/bad-ms512.err"; then
	fail 'create-draft must refuse a SHA512 minisign signature from the wrong key'
fi
grep -q 'minisign signature' "$scratch/bad-ms512.err" ||
	fail "bad SHA512 minisign refusal (log: $(cat "$scratch/bad-ms512.err"))"
pass 'create-draft refuses a wrong SHA512 minisign key'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'verify_minisign SHA512SUMS\n'
new = 'true\n'
if old not in text:
    raise SystemExit('live script is missing SHA512 minisign verify')
mut = text.replace(old, new, 1)
if 'verify_minisign SHA512SUMS' in mut:
    raise SystemExit('SHA512 minisign mutant still verifies')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'SHA512 minisign mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$bad_ms512" >/dev/null 2>"$scratch/mut-ms512.err"; then
	fail "dropping SHA512 minisign verify must accept the wrong key (log: $(cat "$scratch/mut-ms512.err"))"
fi
restore_draft
pass 'reverting SHA512 minisign verification accepts a wrong-key signature'

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

bad_gpg512="$scratch/bad-gpg-512"
cp -a "$scratch/dist" "$bad_gpg512"
other_gpg --batch --yes --armor --local-user "$other_subkey!" \
	--detach-sign -o "$bad_gpg512/SHA512SUMS.asc" "$bad_gpg512/SHA512SUMS"
if run_draft "$bad_gpg512" >/dev/null 2>"$scratch/bad-gpg512.err"; then
	fail 'create-draft must refuse a SHA512 GPG signature from the wrong key'
fi
grep -Eq 'PGP signature|committed' "$scratch/bad-gpg512.err" ||
	fail "bad SHA512 GPG refusal (log: $(cat "$scratch/bad-gpg512.err"))"
pass 'create-draft refuses a wrong SHA512 GPG key'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'verify_pgp SHA512SUMS\n'
new = 'true\n'
if old not in text:
    raise SystemExit('live script is missing SHA512 GPG verify')
mut = text.replace(old, new, 1)
if 'verify_pgp SHA512SUMS' in mut:
    raise SystemExit('SHA512 GPG mutant still verifies')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'SHA512 GPG mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$bad_gpg512" >/dev/null 2>"$scratch/mut-gpg512.err"; then
	fail "dropping SHA512 GPG verify must accept the wrong key (log: $(cat "$scratch/mut-gpg512.err"))"
fi
restore_draft
pass 'reverting SHA512 GPG verification accepts a wrong-key signature'

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

forged_zz="$scratch/forged-zz"
pack_from "$scratch/bin/forged-zz" "$forged_zz"
sign_dir "$forged_zz"
if run_draft "$forged_zz" >/dev/null 2>"$scratch/forged-zz.err"; then
	fail 'create-draft must refuse gitCommit=zz<short> as a tag bind'
fi
grep -q 'not bound to signed tag' "$scratch/forged-zz.err" ||
	fail "forged-zz refusal (log: $(cat "$scratch/forged-zz.err"))"
pass 'create-draft refuses gitCommit=zz<short>'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''	if ! python3 - "$bin" "$version" "$commit" "$info" <<'PY'
from pathlib import Path
import sys

data = Path(sys.argv[1]).read_bytes()
version, full_commit, info = sys.argv[2], sys.argv[3], sys.argv[4]
'''
new = '''	short="$(git -C "$root" rev-parse --short "$commit")"
	if ! python3 - "$bin" "$version" "$short" <<'PY'
from pathlib import Path
import sys

data = Path(sys.argv[1]).read_bytes()
version, commit = sys.argv[2], sys.argv[3]

def has_injected(value: str) -> bool:
    needle = value.encode("ascii")
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            return False
        right = i + len(needle) == len(data) or data[i + len(needle)] == 0
        if right:
            return True
        start = i + 1

if not has_injected(version):
    raise SystemExit("error: archive is not bound to tag version " + version)
if not has_injected(commit):
    raise SystemExit("error: archive is not bound to tagged commit " + commit)
raise SystemExit(0)
version, full_commit, info = sys.argv[2], sys.argv[3], sys.argv[4]
'''
if old not in text:
    raise SystemExit('live script is missing the vcs.revision bind')
mut = text.replace(old, new, 1)
if 'rev-parse --short' not in mut:
    raise SystemExit('zz mutant did not switch to a short commit bind')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'forged-zz mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$forged_zz" >/dev/null 2>"$scratch/mut-zz.err"; then
	fail "restoring a 7-char right-NUL bind must accept gitCommit=zz<short> (log: $(cat "$scratch/mut-zz.err"))"
fi
restore_draft
pass 'reverting to a 7-char right-NUL bind accepts gitCommit=zz<short>'

forged_ver="$scratch/forged-version"
pack_from "$scratch/bin/forged-version" "$forged_ver"
sign_dir "$forged_ver"
if run_draft "$forged_ver" >/dev/null 2>"$scratch/forged-ver.err"; then
	fail 'create-draft must refuse version=11.2.3 for tag 1.2.3'
fi
grep -q 'not bound to signed tag' "$scratch/forged-ver.err" ||
	fail "forged-version refusal (log: $(cat "$scratch/forged-ver.err"))"
pass 'create-draft refuses version=11.2.3 for tag 1.2.3'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '            left_ok = i == 0 or not (48 <= data[i - 1] <= 57)'
new = '            left_ok = True'
if old not in text:
    raise SystemExit('live script is missing the version left-boundary check')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('version-boundary mutant still checks the left digit')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'forged-version mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$forged_ver" >/dev/null 2>"$scratch/mut-ver.err"; then
	fail "dropping the version left boundary must accept 11.2.3 (log: $(cat "$scratch/mut-ver.err"))"
fi
restore_draft
pass 'reverting the version left boundary accepts 11.2.3'

forged_bt="$scratch/forged-buildtime"
pack_from "$scratch/bin/forged-buildtime" "$forged_bt"
sign_dir "$forged_bt"
if run_draft "$forged_bt" >/dev/null 2>"$scratch/forged-bt.err"; then
	fail 'create-draft must refuse a tagged-commit hash placed only in buildTime'
fi
grep -q 'not bound to signed tag' "$scratch/forged-bt.err" ||
	fail "forged-buildtime refusal (log: $(cat "$scratch/forged-bt.err"))"
pass 'create-draft refuses a tagged-commit hash placed only in buildTime'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''if vcs_revision != full_commit:
    raise SystemExit("error: archive vcs.revision is not the tagged commit")
if vcs_modified != "false":
    raise SystemExit("error: archive vcs.modified is not false")
'''
new = '''if vcs_revision is not None and vcs_revision != full_commit:
    raise SystemExit("error: archive vcs.revision is not the tagged commit")
if vcs_revision is None and not delimited(full_commit):
    raise SystemExit("error: archive is not bound to tagged commit " + full_commit)
'''
if old not in text:
    raise SystemExit('live script does not require vcs.revision')
mut = text.replace(old, new, 1)
if 'if vcs_revision != full_commit:' in mut:
    raise SystemExit('buildTime mutant still requires vcs.revision')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'forged-buildtime mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$forged_bt" >/dev/null 2>"$scratch/mut-bt.err"; then
	fail "falling back to a delimited hash must accept buildTime=${full} (log: $(cat "$scratch/mut-bt.err"))"
fi
restore_draft
pass 'reverting vcs.revision to a delimited-hash fallback accepts buildTime'

nongo="$scratch/nongo"
python3 - "$nongo" "$root/scripts/install-shellsentry.sh" <<'PY'
import hashlib
import io
import pathlib
import sys
import tarfile
import zipfile

dest = pathlib.Path(sys.argv[1])
dest.mkdir(parents=True)
installer_src = pathlib.Path(sys.argv[2])
payload = b"#!/bin/sh\n# not a Go binary\nversion 1.2.3\x00"
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
sign_dir "$nongo"
if run_draft "$nongo" >/dev/null 2>"$scratch/nongo.err"; then
	fail 'create-draft must refuse a non-Go binary'
fi
grep -q 'is not a Go binary' "$scratch/nongo.err" ||
	fail "non-Go refusal (log: $(cat "$scratch/nongo.err"))"
pass 'create-draft refuses a non-Go binary'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'info="$(go version -m "$bin" 2>/dev/null)" || die "$archive is not a Go binary"'
new = 'info="$(go version -m "$bin" 2>/dev/null)" || info=$\'build\\tvcs.revision=\'"$commit"$\'\\nbuild\\tvcs.modified=false\''
if old not in text:
    raise SystemExit('live script is missing the is-Go-binary check')
mut = text.replace(old, new, 1)
if 'is not a Go binary' in mut:
    raise SystemExit('non-Go mutant still dies on go version -m')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'non-Go mutant was not distinguished'
fi
chmod +x "$fixture_script"
if ! "$fixture_script" v1.2.3 "$nongo" >/dev/null 2>"$scratch/mut-nongo.err"; then
	fail "dropping the is-Go-binary check must accept a shell script payload (log: $(cat "$scratch/mut-nongo.err"))"
fi
restore_draft
pass 'reverting the is-Go-binary check accepts a non-Go archive'

if ! python3 - "$fixture_script" "$fixture_script" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'git -C "$root" cat-file blob "$commit:docs/releases/${tag}.md" >"$notes" 2>/dev/null ||'
new = 'cp "$root/docs/releases/${tag}.md" "$notes" 2>/dev/null ||'
if old not in text:
    raise SystemExit('live script does not read notes from the tagged commit')
mut = text.replace(old, new, 1)
if 'cat-file blob "$commit:docs/releases/' in mut:
    raise SystemExit('notes mutant still reads the tagged blob')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'working-tree notes mutant was not distinguished'
fi
chmod +x "$fixture_script"
: >"$GH_TRACE"
rm -f "$GH_TRACE.create" "$GH_TRACE.notes"
if ! "$fixture_script" v1.2.3 "$scratch/dist" >/dev/null 2>"$scratch/mut-notes.err"; then
	fail "reading notes from the working tree must still create a draft (log: $(cat "$scratch/mut-notes.err"))"
fi
grep -q 'working-tree notes must not be used' "$GH_TRACE.notes" ||
	fail "working-tree notes mutant did not upload dirty notes (got: $(cat "$GH_TRACE.notes" 2>/dev/null))"
restore_draft
pass 'reverting notes to the working tree uploads dirty release notes'

git -C "$fixture" tag -d v1.2.3 >/dev/null
git -C "$fixture" tag -a -m 'unsigned' v1.2.3 HEAD
if run_draft "$scratch/dist" >/dev/null 2>"$scratch/unsigned.err"; then
	fail 'create-draft must refuse an unsigned tag'
fi
grep -q 'tag is not GPG-signed' "$scratch/unsigned.err" ||
	fail "unsigned-tag refusal (log: $(cat "$scratch/unsigned.err"))"
pass 'create-draft refuses an unsigned tag'

echo '[ok] release-create-draft verifies real manifests, signatures, and tag bind'
