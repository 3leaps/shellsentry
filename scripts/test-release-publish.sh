#!/usr/bin/env bash
# Publish gate: shared tag-anchor, tagged-key, and bind helpers, plus
# publish-only exact asset set and byte cmp. Throwaway keys only.
set -eEuo pipefail
unset GITHUB_ACTIONS || true
root="$(cd "$(dirname "$0")/.." && pwd -P)"
gopath="$(go env GOPATH)"
gocache="$(go env GOCACHE)"
gomodcache="$(go env GOMODCACHE)"
gotoolchain="${GOTOOLCHAIN:-local}"
scratch="$(mktemp -d /tmp/shs-pb.XXXXXX)"
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
command -v jq >/dev/null 2>&1 || fail 'jq required'

script="$root/scripts/release-publish.sh"
[[ -x "$script" ]] || fail 'release-publish.sh must be executable'
grep -q 'release-verify-published-tag.sh' "$script" ||
	fail 'publish must re-check the published tag'
[[ "$(grep -c 'scripts/release-verify-published-tag.sh' "$script")" -ge 2 ]] ||
	fail 'publish must re-verify the tag immediately before --draft=false'
grep -q 'Re-verify the tag immediately before promotion' "$script" ||
	fail 'publish must re-verify the tag immediately before promotion'
grep -q 'verify-signatures.sh' "$script" ||
	fail 'publish must verify signatures via the tagged-key helper'
grep -q 'release-bind-archives.sh' "$script" ||
	fail 'publish must bind archives via the shared helper'
grep -q 'mod version is not' "$root/scripts/release-bind-archives.sh" ||
	fail 'bind must require go version -m mod to equal the tag'
grep -q 'archive is not bound to tag version' "$root/scripts/release-bind-archives.sh" ||
	fail 'bind must require a delimited main.version Go string'
grep -q 'archive version label is not unique' "$root/scripts/release-bind-archives.sh" ||
	fail 'bind must require exactly one delimited version label'
grep -q 'cannot tell which -X variable a string belongs to' "$root/scripts/release-bind-archives.sh" ||
	fail 'bind must document that a byte scan cannot name the -X variable'
grep -q 'cannot tell which' "$root/RELEASE_CHECKLIST.md" ||
	fail 'RELEASE_CHECKLIST.md must document the byte-scan -X limit'
grep -q 'archive buildTime is not RFC3339' "$root/scripts/release-bind-archives.sh" ||
	fail 'bind must require a delimited RFC3339 buildTime'
grep -q 'archive buildTime is not unique' "$root/scripts/release-bind-archives.sh" ||
	fail 'bind must require a unique RFC3339 buildTime'
grep -q 'archive buildTime is not a real date' "$root/scripts/release-bind-archives.sh" ||
	fail 'bind must require buildTime to be a real date'
grep -q 'archive gitCommit is not the tagged commit' "$root/scripts/release-bind-archives.sh" ||
	fail 'bind must require a delimited 40-hex gitCommit'
grep -q 'archive gitCommit is not unique' "$root/scripts/release-bind-archives.sh" ||
	fail 'bind must require a unique 40-hex gitCommit'
grep -q 'release-verify-tag-anchor.sh' "$root/scripts/release-verify-published-tag.sh" ||
	fail 'published-tag must call tag-anchor'
grep -q "repo='3leaps/shellsentry'" "$script" ||
	fail 'publish must target 3leaps/shellsentry'
if grep -q 'SHELLSENTRY_RELEASE_REPO' "$script"; then
	fail 'publish must not honor a SHELLSENTRY_RELEASE_REPO override'
fi
grep -q 'tagName' "$script" || fail 'publish must check the release tagName'
grep -q 'release title or body differs from the tagged notes' "$script" ||
	fail 'publish must require the release title and body to equal the tagged notes'
STRIP='title = line[2:] if line.startswith("# ") else line'
grep -Fq "$STRIP" "$script" ||
	fail 'publish must strip a leading "# " from the notes title'
grep -Fq "$STRIP" "$root/scripts/release-create-draft.sh" ||
	fail 'create-draft must strip a leading "# " identically'
python3 - "$script" "$root/scripts/release-create-draft.sh" <<'PY' || fail '## x and #x titles must stay unchanged in both scripts'
from pathlib import Path
import sys

needle = 'title = line[2:] if line.startswith("# ") else line'
assign = 'line = notes.splitlines()[0] if notes.strip() else ""\n' + needle

def title_from(path, notes):
    text = Path(path).read_text()
    if needle not in text:
        raise SystemExit(f'{path} is missing the heading strip')
    ns = {"notes": notes}
    exec(assign, ns)
    return ns["title"]

for script in sys.argv[1:]:
    if title_from(script, "## x\n") != "## x":
        raise SystemExit(f'{script} must leave "## x" unchanged')
    if title_from(script, "#x\n") != "#x":
        raise SystemExit(f'{script} must leave "#x" unchanged')
    if title_from(script, "# hello\n") != "hello":
        raise SystemExit(f'{script} must strip a leading "# "')
PY
grep -q 'missing local release file' "$script" ||
	fail 'publish must require local release files as regular files'
grep -q 'tagged commit differs from the staged anchor' "$script" ||
	fail 'publish must require the tagged commit to equal the staged anchor'
grep -q 'staged anchor is for a different tag' "$script" ||
	fail 'publish must check the staged anchor tag name'
grep -E '^release-tag-tests:' -A50 "$root/Makefile" | grep -q 'test-release-publish' ||
	fail 'release-tag-tests must run test-release-publish'
pass 'publish reuses tag-anchor, tagged-key, and bind helpers'

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
export SHELLSENTRY_GPG_SIGNING_FINGERPRINT="$primary"

mkdir -m 700 "$scratch/other-gpg"
printf 'allow-loopback-pinentry\ndisable-scdaemon\n' >"$scratch/other-gpg/gpg-agent.conf"
printf 'pinentry-mode loopback\n' >"$scratch/other-gpg/gpg.conf"
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

minisign -G -W -p "$scratch/good.pub" -s "$scratch/good.key" >/dev/null 2>&1 || fail 'minisign keygen failed'
minisign -G -W -p "$scratch/bad.pub" -s "$scratch/bad.key" >/dev/null 2>&1 || fail 'wrong minisign keygen failed'

cat >"$scratch/decernor" <<'EOF'
#!/usr/bin/env bash
case "$1 ${2:-}" in
  'version ') echo 'decernor 0.1.8' ;;
  'version -e') printf 'Version:         0.1.8\nCommit:          testdata\nBuild Date:      testdata\nGo Version:      testdata\nGofulmen:        testdata\nCrucible:        testdata\n' ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$scratch/decernor"
export SHELLSENTRY_DECERNOR_BIN="$scratch/decernor"

repo="$scratch/repo"
git init -q -b main "$repo"
git -C "$repo" config gpg.format openpgp
git -C "$repo" config gpg.program gpg
git -C "$repo" config commit.gpgsign false
git -C "$repo" config user.name '3 Leaps Infosec Team'
git -C "$repo" config user.email 'infosec@3leaps.net'
mkdir -p "$repo/docs/security" "$repo/docs/releases" "$repo/scripts" "$repo/keys" "$repo/config/release"
cp "$script" "$root/scripts/release-ci-refuse.sh" "$root/scripts/release-verify-tag-anchor.sh" \
	"$root/scripts/release-bind-archives.sh" "$root/scripts/verify-signatures.sh" \
	"$root/scripts/release-verify-published-tag.sh" "$root/scripts/verify-pinned-tag.sh" \
	"$root/scripts/release-decernor.sh" "$root/scripts/release-create-draft.sh" \
	"$root/scripts/upload-release-assets.sh" "$repo/scripts/"
chmod +x "$repo/scripts/"*.sh
cp "$root/config/release/tagger-identity.txt" "$repo/config/release/"
cp -a "$root/internal" "$repo/"
cp "$root/main.go" "$root/go.mod" "$root/go.sum" "$repo/"
gpg --batch --armor --export "$primary" >"$repo/docs/security/release-signing-keys.asc"
cp "$scratch/good.pub" "$repo/docs/security/shellsentry-minisign.pub"
printf '# shellsentry v1.2.3\n\nnotes for v1.2.3\n' >"$repo/docs/releases/v1.2.3.md"
blob="$(python3 -c 'import base64,hashlib,pathlib,sys; print(hashlib.sha256(base64.b64decode(pathlib.Path(sys.argv[1]).read_text().splitlines()[1])).hexdigest())' "$scratch/good.pub")"
printf 'gpg %s\nminisign %s\n' "$primary" "$blob" >"$repo/keys/expected-fingerprints.txt"
printf '{"schema_version":"v0"}\n{"schema_version":"v0"}\n' >"$repo/keys/expected-fingerprints.ndjson"
git -C "$repo" add docs keys scripts internal main.go go.mod go.sum config
git -C "$repo" -c commit.gpgsign=false commit -qm fixture
full="$(git -C "$repo" rev-parse HEAD)"
rfc3339='2020-01-02T03:04:05Z'
go_build() {
	GOPATH="$gopath" GOCACHE="$gocache" GOMODCACHE="$gomodcache" GOTOOLCHAIN="$gotoolchain" \
		CGO_ENABLED=0 go build "$@"
}
mkdir -p "$scratch/bin"
# Stamp mod as v0.9.9 on this same commit, then retag v1.2.3 for the gate.
git -C "$repo" tag -a v0.9.9 -m tmp
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=${full} -X main.buildTime=${rfc3339}" \
	-o "$scratch/bin/wrong-version" .)
git -C "$repo" tag -d v0.9.9 >/dev/null
GIT_COMMITTER_NAME='3 Leaps Infosec Team' GIT_COMMITTER_EMAIL=infosec@3leaps.net \
	git -C "$repo" -c gpg.format=openpgp tag -s -a --cleanup=verbatim \
	-u "$subkey!" -m 'shellsentry v1.2.3'$'\n' v1.2.3 HEAD ||
	fail 'signed fixture tag failed'
orig_object="$(git -C "$repo" rev-parse refs/tags/v1.2.3)"
git init -q --bare "$scratch/origin.git"
git -C "$repo" remote add origin "$scratch/origin.git"
git -C "$repo" push -q origin HEAD:main
git -C "$repo" push -q origin v1.2.3
# Signed replacement object for the L6 download-time tag swap; restore the orig ref.
GIT_COMMITTER_NAME='3 Leaps Infosec Team' GIT_COMMITTER_EMAIL=infosec@3leaps.net \
	git -C "$repo" tag -fs -a --cleanup=verbatim -u "$subkey!" \
	-m 'replaced-on-download'$'\n' v1.2.3 HEAD >/dev/null
replacement_object="$(git -C "$repo" rev-parse refs/tags/v1.2.3)"
git -C "$repo" push -q --force origin refs/tags/v1.2.3
git -C "$scratch/origin.git" update-ref refs/tags/v1.2.3 "$orig_object"
git -C "$repo" update-ref refs/tags/v1.2.3 "$orig_object"
export FIXTURE_REPLACEMENT_OBJECT="$replacement_object"
git -C "$repo" remote set-url origin https://github.com/3leaps/shellsentry.git
git -C "$repo" config url."$scratch/origin.git".insteadOf https://github.com/3leaps/shellsentry.git
git -C "$repo" fetch -q origin

(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=${full} -X main.buildTime=${rfc3339}" \
	-o "$scratch/bin/shellsentry" .)
[[ -s "$scratch/bin/shellsentry" ]] || fail 'fixture binary missing'
[[ -s "$scratch/bin/wrong-version" ]] || fail 'wrong-mod fixture binary missing'
(cd "$repo" && GOOS=darwin GOARCH=arm64 go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=${full} -X main.buildTime=${rfc3339}" \
	-o "$scratch/bin/shellsentry-darwin" .)
[[ -s "$scratch/bin/shellsentry-darwin" ]] || fail 'darwin fixture binary missing'
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=9.9.9 -X main.gitCommit=${full} -X main.buildTime=${rfc3339}" \
	-o "$scratch/bin/wrong-ldflag-999" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=x1.2.3 -X main.gitCommit=${full} -X main.buildTime=${rfc3339}" \
	-o "$scratch/bin/wrong-ldflag-x" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.gitCommit=${full} -X main.buildTime=${rfc3339}" \
	-o "$scratch/bin/wrong-ldflag-dev" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=X1.2.3 -X main.gitCommit=${full} -X main.buildTime=${rfc3339}" \
	-o "$scratch/bin/wrong-ldflag-X" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.30 -X main.gitCommit=${full} -X main.buildTime=${rfc3339}" \
	-o "$scratch/bin/wrong-ldflag-130" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=pre-1.2.3 -X main.gitCommit=${full} -X main.buildTime=${rfc3339}" \
	-o "$scratch/bin/wrong-ldflag-pre" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=release_1.2.3 -X main.gitCommit=${full} -X main.buildTime=${rfc3339}" \
	-o "$scratch/bin/wrong-ldflag-rel" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=9.9.9 -X main.gitCommit=${full} -X main.buildTime=1.2.3" \
	-o "$scratch/bin/stuffed-buildtime" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=9.9.9 -X main.gitCommit=1.2.3 -X main.buildTime=${rfc3339}" \
	-o "$scratch/bin/stuffed-gitcommit" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=9.9.9 -X main.gitCommit=-1.2.3 -X main.buildTime=${rfc3339}" \
	-o "$scratch/bin/stuffed-gitcommit-dash" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=${full} -X main.buildTime=${rfc3339} -X github.com/3leaps/shellsentry/internal/cli.Version=1.2.3" \
	-o "$scratch/bin/double-version" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=9.9.9 -X main.gitCommit=${full} -X main.buildTime=${rfc3339} -X github.com/3leaps/shellsentry/internal/cli.Version=1.2.3" \
	-o "$scratch/bin/cli-version" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=${full} -X main.buildTime=9999-99-99T99:99:99Z" \
	-o "$scratch/bin/invalid-date" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=${full} -X main.buildTime=${rfc3339} -X github.com/3leaps/shellsentry/internal/cli.BuildTime=2021-01-02T03:04:05Z" \
	-o "$scratch/bin/double-buildtime" .)
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=${full} -X main.buildTime=${rfc3339} -X github.com/3leaps/shellsentry/internal/cli.GitCommit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	-o "$scratch/bin/double-gitcommit" .)

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

d="$scratch/dist"
stage() {
	pack_from "$scratch/bin/shellsentry" "$d" "$scratch/bin/shellsentry-darwin"
	sign_dir "$d"
	cp "$scratch/good.pub" "$d/shellsentry-minisign.pub"
	git -C "$repo" cat-file blob "$full:docs/security/release-signing-keys.asc" \
		>"$d/shellsentry-release-signing-key.asc"
	git -C "$repo" cat-file blob "$full:docs/releases/v1.2.3.md" >"$d/release-notes-v1.2.3.md"
	printf 'tag=v1.2.3\nobject=%s\ncommit=%s\n' "$orig_object" "$full" >"$d.anchor"
	rm -rf "$scratch/draft"
	mkdir -p "$scratch/draft"
	cp "$d"/* "$scratch/draft/"
}
restage_from() {
	local binary="$1"
	pack_from "$binary" "$d" "$binary"
	sign_dir "$d"
	cp "$scratch/good.pub" "$d/shellsentry-minisign.pub"
	git -C "$repo" cat-file blob "$full:docs/security/release-signing-keys.asc" \
		>"$d/shellsentry-release-signing-key.asc"
	git -C "$repo" cat-file blob "$full:docs/releases/v1.2.3.md" >"$d/release-notes-v1.2.3.md"
	printf 'tag=v1.2.3\nobject=%s\ncommit=%s\n' "$orig_object" "$full" >"$d.anchor"
	rm -rf "$scratch/draft"
	mkdir -p "$scratch/draft"
	cp "$d"/* "$scratch/draft/"
}

mkdir -p "$scratch/bin-path"
export FIXTURE_LOG="$scratch/gh.log"
export FIXTURE_DRAFT="$scratch/draft"
export FIXTURE_REMOTE="$scratch/origin.git"
export GH_TAG_JSON="$scratch/tag.json"
cat >"$GH_TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$full"},"verification":{"verified":true,"reason":"valid"}}
JSON
cat >"$scratch/bin-path/gh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FIXTURE_LOG"
case "$1 $2" in
"api "*)
	if [[ "$2" == *git/ref/tags/* ]]; then
		tag="${2##*/}"
		object="$(git -C "$FIXTURE_REMOTE" rev-parse "refs/tags/$tag" 2>/dev/null)" || exit 1
		printf '{"object":{"type":"tag","sha":"%s"}}\n' "$object"
		exit 0
	fi
	if [[ "$2" == *'/git/tags/'* ]]; then
		cat "$GH_TAG_JSON"
		exit 0
	fi
	exit 1
	;;
"release view")
	if [[ "${FIXTURE_RELEASE_EXISTS:-1}" != 1 ]]; then
		[[ -n "${FIXTURE_GH_EXISTS:-}" && -f "$FIXTURE_GH_EXISTS" ]] || exit 1
	fi
	if [[ "$*" == *isDraft* && "$*" == *--jq* ]]; then
		printf '%s\n' "${FIXTURE_IS_DRAFT:-true}"
		exit 0
	fi
	names="$(cd "$FIXTURE_DRAFT" && ls -1 | jq -R . | jq -s 'map({name: .})')"
	body="${FIXTURE_RELEASE_BODY-# shellsentry v1.2.3

notes for v1.2.3
}"
	jq -n --argjson a "$names" --argjson d "${FIXTURE_IS_DRAFT:-true}" \
		--arg tag "${FIXTURE_TAG_NAME:-v1.2.3}" \
		--arg name "${FIXTURE_RELEASE_TITLE:-shellsentry v1.2.3}" \
		--arg body "$body" \
		'{isDraft: $d, assets: $a, tagName: $tag, name: $name, body: $body}'
	;;
"release create")
	mkdir -p "$FIXTURE_DRAFT"
	[[ -n "${FIXTURE_GH_EXISTS:-}" ]] && : >"$FIXTURE_GH_EXISTS"
	prev=""
	for arg in "$@"; do
		if [[ "$prev" == --notes-file && -f "$arg" ]]; then
			cp "$arg" "$FIXTURE_DRAFT/.notes-body" 2>/dev/null || true
		elif [[ "$arg" != --* && -f "$arg" ]]; then
			cp "$arg" "$FIXTURE_DRAFT/"
		fi
		prev="$arg"
	done
	;;
"release upload")
	mkdir -p "$FIXTURE_DRAFT"
	for arg in "$@"; do
		if [[ "$arg" != --* && -f "$arg" ]]; then
			cp "$arg" "$FIXTURE_DRAFT/"
		fi
	done
	;;
"release download")
	if [[ "${FIXTURE_REPLACE_TAG_ON_DOWNLOAD:-}" == 1 ]]; then
		git -C "$FIXTURE_REMOTE" update-ref refs/tags/v1.2.3 "${FIXTURE_REPLACEMENT_OBJECT:?}"
	fi
	dir=""
	while [[ $# -gt 0 ]]; do
		[[ "$1" == --dir ]] && dir="$2"
		shift
	done
	cp "$FIXTURE_DRAFT"/* "$dir/"
	;;
"release edit") ;;
*) exit 1 ;;
esac
SH
chmod +x "$scratch/bin-path/gh"
export PATH="$scratch/bin-path:$PATH"
fixture_publish="$repo/scripts/release-publish.sh"
fixture_bind="$repo/scripts/release-bind-archives.sh"
fixture_published_tag="$repo/scripts/release-verify-published-tag.sh"
restore_publish() {
	cp "$script" "$fixture_publish"
	chmod +x "$fixture_publish"
}
restore_bind() {
	cp "$root/scripts/release-bind-archives.sh" "$fixture_bind"
	chmod +x "$fixture_bind"
}
restore_published_tag() {
	cp "$root/scripts/release-verify-published-tag.sh" "$fixture_published_tag"
	chmod +x "$fixture_published_tag"
}
restore_upload() {
	cp "$root/scripts/upload-release-assets.sh" "$repo/scripts/upload-release-assets.sh"
	chmod +x "$repo/scripts/upload-release-assets.sh"
}
fixture_upload="$repo/scripts/upload-release-assets.sh"
grep -q 'gh release upload "$TAG" "$NOTES_FILE" --clobber' "$root/scripts/upload-release-assets.sh" ||
	fail 'upload must attach release-notes-<tag>.md as a draft asset'
stub_published_tag() {
	cat >"$fixture_published_tag" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
	chmod +x "$fixture_published_tag"
}

refuse() {
	local reason="$1"
	: >"$FIXTURE_LOG"
	if (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >"$scratch/out" 2>&1; then
		echo "error: expected rejection: $reason" >&2
		cat "$scratch/out" >&2
		exit 1
	fi
	grep -q "$reason" "$scratch/out" || {
		echo "error: missing named rejection: $reason" >&2
		cat "$scratch/out" >&2
		exit 1
	}
	! grep -q '^release edit' "$FIXTURE_LOG" || {
		echo "error: promoted despite: $reason" >&2
		exit 1
	}
}

stage
if (cd "$repo" && env GITHUB_ACTIONS=true ./scripts/release-publish.sh v1.2.3 "$d") >"$scratch/out" 2>&1; then
	fail 'publish must refuse GitHub Actions'
fi
grep -q 'refuse GitHub Actions' "$scratch/out" || {
	echo "error: missing named rejection: refuse GitHub Actions" >&2
	cat "$scratch/out" >&2
	exit 1
}
pass 'publish refuses GitHub Actions'

# Replaced tag: same commit, new annotated object, approved key. .anchor is the old object.
stage
GIT_COMMITTER_NAME='3 Leaps Infosec Team' GIT_COMMITTER_EMAIL=infosec@3leaps.net \
	git -C "$repo" tag -fs -a --cleanup=verbatim -u "$subkey!" -m 'replaced'$'\n' v1.2.3 HEAD >/dev/null
git -C "$repo" push -q --force origin refs/tags/v1.2.3
# Keep the staging anchor on the original object; restore the local tag so the
# operator checkout still looks like it did at staging time.
git -C "$repo" update-ref refs/tags/v1.2.3 "$orig_object"
refuse 'published tag no longer matches the verified anchor'
git -C "$scratch/origin.git" update-ref refs/tags/v1.2.3 "$orig_object"
git -C "$repo" update-ref refs/tags/v1.2.3 "$orig_object"
pass 'replaced tag is refused'

stage
printf 'sneaky post-tag edit\n' >>"$d/release-notes-v1.2.3.md"
cp "$d/release-notes-v1.2.3.md" "$scratch/draft/"
refuse 'differs from docs/releases/v1.2.3.md at the tagged commit'
pass 'notes edited after tagging are refused'

stage
FIXTURE_IS_DRAFT=false refuse 'is not a draft'
unset FIXTURE_IS_DRAFT
pass 'non-draft release is refused'

stage
printf 'extra\n' >"$scratch/draft/extra.bin"
refuse 'draft assets differ from the expected set'
pass 'extra draft asset is refused'

stage
rm -f "$scratch/draft/shellsentry_linux_arm64.tar.gz"
refuse 'draft assets differ from the expected set'
pass 'missing draft asset is refused'

stage
printf 'tampered\n' >>"$d/shellsentry_linux_amd64.tar.gz"
refuse 'digest mismatch'
pass 'tampered local bytes are refused'

stage
python3 - "$d/SHA256SUMS" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
lines = [ln for ln in p.read_text().splitlines() if 'linux_arm64' not in ln]
p.write_text('\n'.join(lines) + '\n')
PY
sign_dir "$d"
cp "$d/SHA256SUMS" "$d/SHA256SUMS.minisig" "$d/SHA256SUMS.asc" "$scratch/draft/"
refuse 'does not list exactly the expected packages'
pass 'manifest that omits a package is refused'

stage
cp "$scratch/bad.pub" "$d/shellsentry-minisign.pub"
cp "$d/shellsentry-minisign.pub" "$scratch/draft/"
refuse 'does not match the pin in the tagged commit'
pass 'staged minisign key that is not the tagged pin is refused'

stage
printf 'trailing line\n' >>"$d/shellsentry-minisign.pub"
cp "$d/shellsentry-minisign.pub" "$scratch/draft/"
refuse 'is not a two-line minisign public key'
pass 'minisign key with extra lines is refused'

stage
python3 - "$d/SHA256SUMS.minisig" <<'PY'
import base64
import sys
lines = open(sys.argv[1]).read().split('\n')
sig = bytearray(base64.b64decode(lines[1]))
sig[-1] ^= 1
lines[1] = base64.b64encode(bytes(sig)).decode()
open(sys.argv[1], 'w').write('\n'.join(lines))
PY
cp "$d/SHA256SUMS.minisig" "$scratch/draft/"
refuse 'minisign signature for SHA256SUMS is invalid'
pass 'tampered minisign signature is refused'

stage
other_gpg --batch --yes --armor --local-user "$other_subkey!" --detach-sign \
	-o "$d/SHA512SUMS.asc" "$d/SHA512SUMS"
cp "$d/SHA512SUMS.asc" "$scratch/draft/"
refuse 'PGP signature for SHA512SUMS is invalid under the committed key'
pass 'wrong-signer PGP signature is refused'

stage
printf 'swapped on the server\n' >"$scratch/draft/shellsentry_darwin_arm64.tar.gz"
refuse 'draft asset differs from the verified local file'
pass 'draft that differs from the local set is refused'

stage
other_gpg --batch --armor --export "$other_primary" >"$d/shellsentry-release-signing-key.asc"
cp "$d/shellsentry-release-signing-key.asc" "$scratch/draft/"
refuse 'staged PGP key asset is not the committed primary with its pinned signing subkey'
pass 'unrelated staged PGP key asset is refused'

stage
gpg --batch --pinentry-mode loopback --passphrase '' --armor --export-secret-keys "$primary" \
	>"$d/shellsentry-release-signing-key.asc"
cp "$d/shellsentry-release-signing-key.asc" "$scratch/draft/"
refuse 'staged PGP key asset contains secret key material'
pass 'secret-key PGP asset is refused'

# L1: edited GitHub title or body must not promote.
stage
export FIXTURE_RELEASE_BODY='edited notes
'
refuse 'release title or body differs from the tagged notes'
unset FIXTURE_RELEASE_BODY
pass 'edited release body is refused'

stage
export FIXTURE_RELEASE_TITLE='Edited Title'
refuse 'release title or body differs from the tagged notes'
unset FIXTURE_RELEASE_TITLE
pass 'edited release title is refused'

if ! python3 - "$fixture_publish" "$fixture_publish" <<'PY'
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = 'title = line[2:] if line.startswith("# ") else line'
new = 'title = line'
if old not in text:
    raise SystemExit('live publish is missing the heading strip')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('heading-strip mutant still strips')
dest.write_text(mut)
PY
then
	fail 'publish heading-strip mutant was not distinguished'
fi
chmod +x "$fixture_publish"
stage
refuse 'release title or body differs from the tagged notes'
restore_publish
pass 'publish heading-strip mutant is distinguished'

if ! python3 - "$fixture_publish" "$fixture_publish" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'if payload.get("name") != title or got_body != want_body:\n    raise SystemExit(5)\n'
new = 'if False and (payload.get("name") != title or got_body != want_body):\n    raise SystemExit(5)\n'
if old not in text:
    raise SystemExit('live script is missing the title/body check')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('title/body mutant still compares name and body')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'title/body mutant was not distinguished'
fi
chmod +x "$fixture_publish"
stage
export FIXTURE_RELEASE_BODY='edited notes
'
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-body.err"; then
	fail "dropping the title/body check must accept an edited body (log: $(cat "$scratch/mut-body.err"))"
fi
unset FIXTURE_RELEASE_BODY
restore_publish
pass 'reverting the title/body check accepts an edited body'

# L2: release.tagName must equal the signed tag.
stage
export FIXTURE_TAG_NAME=v9.9.9
refuse 'release tagName differs from the signed tag'
unset FIXTURE_TAG_NAME
pass 'mismatched release tagName is refused'

if ! python3 - "$fixture_publish" "$fixture_publish" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'if payload.get("tagName") != tag:\n    raise SystemExit(4)\n'
new = 'if False and payload.get("tagName") != tag:\n    raise SystemExit(4)\n'
if old not in text:
    raise SystemExit('live script is missing the tagName check')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('tagName mutant still compares tagName')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'tagName mutant was not distinguished'
fi
chmod +x "$fixture_publish"
stage
export FIXTURE_TAG_NAME=v9.9.9
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-tagname.err"; then
	fail "dropping the tagName check must accept a mismatched tagName (log: $(cat "$scratch/mut-tagname.err"))"
fi
unset FIXTURE_TAG_NAME
restore_publish
pass 'reverting the tagName check accepts a mismatched tagName'

# L3/L4: bind-archives call. Wrong-mod archives (v0.9.9 stamp, same commit).
stage
pack_from "$scratch/bin/wrong-version" "$d" "$scratch/bin/wrong-version"
sign_dir "$d"
cp "$d"/* "$scratch/draft/"
git -C "$repo" cat-file blob "$full:docs/security/release-signing-keys.asc" \
	>"$d/shellsentry-release-signing-key.asc"
cp "$scratch/good.pub" "$d/shellsentry-minisign.pub"
git -C "$repo" cat-file blob "$full:docs/releases/v1.2.3.md" >"$d/release-notes-v1.2.3.md"
cp "$d/shellsentry-release-signing-key.asc" "$d/shellsentry-minisign.pub" \
	"$d/release-notes-v1.2.3.md" "$scratch/draft/"
printf 'tag=v1.2.3\nobject=%s\ncommit=%s\n' "$orig_object" "$full" >"$d.anchor"
refuse 'not bound to signed tag'
pass 'wrong-mod archives are refused'

if ! python3 - "$fixture_publish" "$fixture_publish" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '"$root/scripts/release-bind-archives.sh" "$tag" "$src" >/dev/null'
new = 'true'
if old not in text:
    raise SystemExit('live script is missing the bind helper call')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('bind mutant still binds archives')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'publish bind mutant was not distinguished'
fi
chmod +x "$fixture_publish"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-bind.err"; then
	fail "dropping bind-archives must accept a v0.9.9 stamp (log: $(cat "$scratch/mut-bind.err"))"
fi
restore_publish
pass 'reverting bind-archives accepts a v0.9.9 stamp'

# Tagged builds whose main.version ldflag is not the tag: mod and vcs match.
restage_from "$scratch/bin/wrong-ldflag-999"
refuse 'not bound to signed tag'
pass 'publish refuses -X main.version=9.9.9'
restage_from "$scratch/bin/wrong-ldflag-x"
refuse 'not bound to signed tag'
pass 'publish refuses -X main.version=x1.2.3'
restage_from "$scratch/bin/wrong-ldflag-dev"
refuse 'not bound to signed tag'
pass 'publish refuses a tagged build with default main.version=dev'

if ! python3 - "$fixture_bind" "$fixture_bind" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''if hits == 0:
    raise SystemExit("error: archive is not bound to tag version " + version)
if hits != 1:
    raise SystemExit("error: archive version label is not unique")
'''
new = '''if False and hits == 0:
    raise SystemExit("error: archive is not bound to tag version " + version)
if False and hits != 1:
    raise SystemExit("error: archive version label is not unique")
'''
if old not in text:
    raise SystemExit('live script is missing the main.version byte scan')
mut = text.replace(old, new, 1)
if 'if hits == 0:' in mut:
    raise SystemExit('version-scan mutant still requires a delimited main.version')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'publish main.version mutant was not distinguished'
fi
chmod +x "$fixture_bind"
restage_from "$scratch/bin/wrong-ldflag-999"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-ldflag-999.err"; then
	fail "dropping the main.version scan must accept 9.9.9 (log: $(cat "$scratch/mut-ldflag-999.err"))"
fi
restage_from "$scratch/bin/wrong-ldflag-x"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-ldflag-x.err"; then
	fail "dropping the main.version scan must accept x1.2.3 (log: $(cat "$scratch/mut-ldflag-x.err"))"
fi
restage_from "$scratch/bin/wrong-ldflag-dev"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-ldflag-dev.err"; then
	fail "dropping the main.version scan must accept default dev (log: $(cat "$scratch/mut-ldflag-dev.err"))"
fi
restore_bind
pass 'reverting the main.version byte scan accepts 9.9.9, x1.2.3, and default dev'

restage_from "$scratch/bin/wrong-ldflag-X"
refuse 'not bound to signed tag'
pass 'publish refuses -X main.version=X1.2.3'
restage_from "$scratch/bin/wrong-ldflag-130"
refuse 'not bound to signed tag'
pass 'publish refuses -X main.version=1.2.30'
restage_from "$scratch/bin/wrong-ldflag-pre"
refuse 'not bound to signed tag'
pass 'publish refuses -X main.version=pre-1.2.3'
restage_from "$scratch/bin/wrong-ldflag-rel"
refuse 'not bound to signed tag'
pass 'publish refuses -X main.version=release_1.2.3'
restage_from "$scratch/bin/stuffed-buildtime"
refuse 'not bound to signed tag'
pass 'publish refuses buildTime=1.2.3 with version=9.9.9'
restage_from "$scratch/bin/stuffed-gitcommit"
refuse 'not bound to signed tag'
pass 'publish refuses gitCommit=1.2.3 with version=9.9.9'
restage_from "$scratch/bin/stuffed-gitcommit-dash"
refuse 'not bound to signed tag'
pass 'publish refuses gitCommit=-1.2.3 with version=9.9.9'
restage_from "$scratch/bin/double-version"
refuse 'not bound to signed tag'
pass 'publish refuses two delimited 1.2.3 labels'
restage_from "$scratch/bin/invalid-date"
refuse 'not bound to signed tag'
pass 'publish refuses buildTime=9999-99-99T99:99:99Z'
restage_from "$scratch/bin/double-buildtime"
refuse 'not bound to signed tag'
pass 'publish refuses two delimited RFC3339 timestamps'
restage_from "$scratch/bin/double-gitcommit"
refuse 'not bound to signed tag'
pass 'publish refuses two delimited 40-hex commits'

if ! python3 - "$fixture_bind" "$fixture_bind" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '48 <= left <= 57 or 65 <= left <= 90 or 97 <= left <= 122'
new = '48 <= left <= 57 or 97 <= left <= 122'
if old not in text:
    raise SystemExit('live script is missing the uppercase left boundary')
mut = text.replace(old, new, 1)
if '65 <= left <= 90' in mut.split('def go_string', 1)[0]:
    raise SystemExit('uppercase mutant still forbids A-Z')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'publish uppercase mutant was not distinguished'
fi
chmod +x "$fixture_bind"
restage_from "$scratch/bin/wrong-ldflag-X"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-X.err"; then
	fail "dropping uppercase left must accept X1.2.3 (log: $(cat "$scratch/mut-X.err"))"
fi
restore_bind
pass 'reverting the uppercase left boundary accepts X1.2.3'

if ! python3 - "$fixture_bind" "$fixture_bind" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''        right_ok = i + n == len(data) or data[i + n] == 0
        if left_ok and right_ok:
            hits += 1
'''
new = '''        right_ok = True
        if left_ok and right_ok:
            hits += 1
'''
if old not in text:
    raise SystemExit('live script is missing the version right-NUL check')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('right-NUL mutant still requires NUL after the version')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'publish right-NUL mutant was not distinguished'
fi
chmod +x "$fixture_bind"
restage_from "$scratch/bin/wrong-ldflag-130"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-130.err"; then
	fail "dropping right-NUL must accept 1.2.30 (log: $(cat "$scratch/mut-130.err"))"
fi
restore_bind
pass 'reverting the right-NUL boundary accepts 1.2.30'

if ! python3 - "$fixture_bind" "$fixture_bind" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '\n            or left in (45, 95)'
new = ''
if old not in text:
    raise SystemExit('live script is missing the hyphen/underscore left boundary')
mut = text.replace(old, new, 1)
if 'left in (45, 95)' in mut:
    raise SystemExit('hyphen mutant still forbids - and _')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'publish hyphen/underscore mutant was not distinguished'
fi
chmod +x "$fixture_bind"
restage_from "$scratch/bin/wrong-ldflag-pre"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-pre.err"; then
	fail "dropping hyphen/underscore left must accept pre-1.2.3 (log: $(cat "$scratch/mut-pre.err"))"
fi
restage_from "$scratch/bin/wrong-ldflag-rel"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-rel.err"; then
	fail "dropping hyphen/underscore left must accept release_1.2.3 (log: $(cat "$scratch/mut-rel.err"))"
fi
restore_bind
pass 'reverting hyphen/underscore left accepts pre-1.2.3 and release_1.2.3'

if ! python3 - "$fixture_bind" "$fixture_bind" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''if hits != 1:
    raise SystemExit("error: archive version label is not unique")
'''
new = '''if False and hits != 1:
    raise SystemExit("error: archive version label is not unique")
'''
if old not in text:
    raise SystemExit('live script is missing the unique version-label check')
mut = text.replace(old, new, 1)
if 'if hits != 1:' in mut:
    raise SystemExit('unique-label mutant still requires exactly one match')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'publish unique-label mutant was not distinguished'
fi
chmod +x "$fixture_bind"
restage_from "$scratch/bin/double-version"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-double.err"; then
	fail "dropping unique-label must accept two 1.2.3 strings (log: $(cat "$scratch/mut-double.err"))"
fi
restore_bind
pass 'reverting unique-label accepts two delimited 1.2.3 strings'

if ! python3 - "$fixture_bind" "$fixture_bind" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''if not rfc_hits:
    raise SystemExit("error: archive buildTime is not RFC3339")
'''
new = '''if False and not rfc_hits:
    raise SystemExit("error: archive buildTime is not RFC3339")
'''
if old not in text:
    raise SystemExit('live script is missing the RFC3339 buildTime check')
mut = text.replace(old, new, 1)
if 'if not rfc_hits:' in mut:
    raise SystemExit('RFC3339 mutant still requires buildTime')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'publish RFC3339 mutant was not distinguished'
fi
chmod +x "$fixture_bind"
restage_from "$scratch/bin/stuffed-buildtime"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-bt-rfc.err"; then
	fail "dropping RFC3339 must accept buildTime=1.2.3 (log: $(cat "$scratch/mut-bt-rfc.err"))"
fi
restore_bind
pass 'reverting RFC3339 buildTime accepts buildTime=1.2.3'

if ! python3 - "$fixture_bind" "$fixture_bind" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''if not go_string(full_commit):
    raise SystemExit("error: archive gitCommit is not the tagged commit")
'''
new = '''if False and not go_string(full_commit):
    raise SystemExit("error: archive gitCommit is not the tagged commit")
'''
if old not in text:
    raise SystemExit('live script is missing the gitCommit 40-hex check')
mut = text.replace(old, new, 1)
if 'if not go_string(full_commit):' in mut:
    raise SystemExit('gitCommit mutant still requires the tagged commit')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'publish gitCommit mutant was not distinguished'
fi
chmod +x "$fixture_bind"
restage_from "$scratch/bin/stuffed-gitcommit"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-gc.err"; then
	fail "dropping gitCommit 40-hex must accept gitCommit=1.2.3 (log: $(cat "$scratch/mut-gc.err"))"
fi
restore_bind
pass 'reverting gitCommit 40-hex accepts gitCommit=1.2.3'

if ! python3 - "$fixture_bind" "$fixture_bind" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''if rfc_hits:
    try:
        datetime.strptime(rfc_hits[0].decode("ascii"), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise SystemExit("error: archive buildTime is not a real date")
'''
new = '''if rfc_hits:
    try:
        pass
    except ValueError:
        raise SystemExit("error: archive buildTime is not a real date")
'''
if old not in text:
    raise SystemExit('live script is missing the real-date buildTime check')
mut = text.replace(old, new, 1)
if 'datetime.strptime(rfc_hits[0]' in mut:
    raise SystemExit('real-date mutant still parses buildTime')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'publish real-date mutant was not distinguished'
fi
chmod +x "$fixture_bind"
restage_from "$scratch/bin/invalid-date"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-date.err"; then
	fail "dropping real-date must accept 9999-99-99T99:99:99Z (log: $(cat "$scratch/mut-date.err"))"
fi
restore_bind
pass 'reverting real-date buildTime accepts 9999-99-99T99:99:99Z'

if ! python3 - "$fixture_bind" "$fixture_bind" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''if len(rfc_hits) > 1:
    raise SystemExit("error: archive buildTime is not unique")
'''
new = '''if False and len(rfc_hits) > 1:
    raise SystemExit("error: archive buildTime is not unique")
'''
if old not in text:
    raise SystemExit('live script is missing the unique RFC3339 check')
mut = text.replace(old, new, 1)
if 'if len(rfc_hits) > 1:' in mut:
    raise SystemExit('unique-RFC3339 mutant still requires one timestamp')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'publish unique-RFC3339 mutant was not distinguished'
fi
chmod +x "$fixture_bind"
restage_from "$scratch/bin/double-buildtime"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-dbl-bt.err"; then
	fail "dropping unique RFC3339 must accept two timestamps (log: $(cat "$scratch/mut-dbl-bt.err"))"
fi
restore_bind
pass 'reverting unique RFC3339 accepts two delimited timestamps'

if ! python3 - "$fixture_bind" "$fixture_bind" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''if len(delimited_matches(rb"[0-9a-f]{40}")) > 1:
    raise SystemExit("error: archive gitCommit is not unique")
'''
new = '''if False and len(delimited_matches(rb"[0-9a-f]{40}")) > 1:
    raise SystemExit("error: archive gitCommit is not unique")
'''
if old not in text:
    raise SystemExit('live script is missing the unique 40-hex check')
mut = text.replace(old, new, 1)
if 'if len(delimited_matches(rb"[0-9a-f]{40}")) > 1:' in mut:
    raise SystemExit('unique-40-hex mutant still requires one commit string')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'publish unique-40-hex mutant was not distinguished'
fi
chmod +x "$fixture_bind"
restage_from "$scratch/bin/double-gitcommit"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-dbl-gc.err"; then
	fail "dropping unique 40-hex must accept two commits (log: $(cat "$scratch/mut-dbl-gc.err"))"
fi
restore_bind
pass 'reverting unique 40-hex accepts two delimited commits'

"$scratch/bin/cli-version" version 2>&1 | grep -q '9.9.9' ||
	fail 'cli.Version fixture must report main.version=9.9.9'
restage_from "$scratch/bin/cli-version"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/cli-version.err"; then
	fail "publish must accept cli.Version=1.2.3 with main.version=9.9.9 (known limit) (log: $(cat "$scratch/cli-version.err"))"
fi
pass 'publish accepts cli.Version=1.2.3 with main.version=9.9.9 (known byte-scan limit)'

# L4: commit-equals-anchor. Stub published-tag so only the publish.sh compare remains.
stub_published_tag
stage
printf 'tag=v1.2.3\nobject=%s\ncommit=%s\n' "$orig_object" "$(printf 'a%.0s' {1..40})" >"$d.anchor"
refuse 'tagged commit differs from the staged anchor'
pass 'mismatched staged-anchor commit is refused'

if ! python3 - "$fixture_publish" "$fixture_publish" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '[[ "$commit" == "$anchor_commit" ]] || die \'tagged commit differs from the staged anchor\'\n'
new = ''
if old not in text:
    raise SystemExit('live script is missing commit-equals-anchor')
mut = text.replace(old, new, 1)
if 'tagged commit differs from the staged anchor' in mut:
    raise SystemExit('commit-equals-anchor mutant still compares')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'commit-equals-anchor mutant was not distinguished'
fi
chmod +x "$fixture_publish"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-commit.err"; then
	fail "dropping commit-equals-anchor must accept a mismatched anchor commit (log: $(cat "$scratch/mut-commit.err"))"
fi
restore_publish
restore_published_tag
pass 'reverting commit-equals-anchor accepts a mismatched anchor commit'

# L4: staged anchor tag name.
stage
printf 'tag=v9.9.9\nobject=%s\ncommit=%s\n' "$orig_object" "$full" >"$d.anchor"
refuse 'staged anchor is for a different tag'
pass 'mismatched staged-anchor tag name is refused'

if ! python3 - "$fixture_publish" "$fixture_publish" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''[[ "$(awk -F= '$1=="tag" {print $2}' "$anchor")" == "$tag" ]] || die 'staged anchor is for a different tag'
'''
new = 'true\n'
if old not in text:
    raise SystemExit('live script is missing the anchor tag-name check')
mut = text.replace(old, new, 1)
if 'staged anchor is for a different tag' in mut:
    raise SystemExit('anchor tag-name mutant still compares')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'anchor tag-name mutant was not distinguished'
fi
chmod +x "$fixture_publish"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-anchor-tag.err"; then
	fail "dropping the anchor tag-name check must accept tag=v9.9.9 (log: $(cat "$scratch/mut-anchor-tag.err"))"
fi
restore_publish
pass 'reverting the anchor tag-name check accepts tag=v9.9.9'

# L4: local file presence. A symlink is a regular-file lookalike once ! -L is dropped.
stage
mv "$d/install-shellsentry.sh" "$d/.real-install"
ln -s .real-install "$d/install-shellsentry.sh"
refuse 'missing local release file'
pass 'symlinked local release file is refused'

if ! python3 - "$fixture_publish" "$fixture_publish" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '[[ -f "$src/$want" && ! -L "$src/$want" && -s "$src/$want" ]] || die "missing local release file: $want"'
new = '[[ -f "$src/$want" && -s "$src/$want" ]] || die "missing local release file: $want"'
if old not in text:
    raise SystemExit('live script is missing the local-file presence loop')
mut = text.replace(old, new, 1)
if '! -L "$src/$want"' in mut:
    raise SystemExit('presence mutant still rejects symlinks')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'local-file presence mutant was not distinguished'
fi
chmod +x "$fixture_publish"
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-presence.err"; then
	fail "dropping ! -L must accept a symlinked local file (log: $(cat "$scratch/mut-presence.err"))"
fi
restore_publish
pass 'reverting local-file presence accepts a symlink'

# L5: SHELLSENTRY_RELEASE_REPO must not retarget gh.
if ! python3 - "$fixture_publish" "$fixture_publish" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = "repo='3leaps/shellsentry'\n"
new = 'repo="${SHELLSENTRY_RELEASE_REPO:-3leaps/shellsentry}"\n'
if old not in text:
    raise SystemExit('live script does not hardcode 3leaps/shellsentry')
mut = text.replace(old, new, 1)
if "repo='3leaps/shellsentry'" in mut:
    raise SystemExit('repo-override mutant still hardcodes the repo')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'repo-override mutant was not distinguished'
fi
chmod +x "$fixture_publish"
stage
: >"$FIXTURE_LOG"
if ! (cd "$repo" && env SHELLSENTRY_RELEASE_REPO=attacker/shellsentry \
	./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-repo.err"; then
	fail "restoring SHELLSENTRY_RELEASE_REPO must retarget gh (log: $(cat "$scratch/mut-repo.err"))"
fi
grep -q -- '--repo attacker/shellsentry' "$FIXTURE_LOG" ||
	fail 'repo-override mutant must pass --repo attacker/shellsentry'
restore_publish
pass 'reverting the hardcoded repo accepts SHELLSENTRY_RELEASE_REPO'

# L6: tag replacement between download and --draft=false.
stage
export FIXTURE_REPLACE_TAG_ON_DOWNLOAD=1
refuse 'published tag no longer matches the verified anchor'
unset FIXTURE_REPLACE_TAG_ON_DOWNLOAD
git -C "$scratch/origin.git" update-ref refs/tags/v1.2.3 "$orig_object"
git -C "$repo" update-ref refs/tags/v1.2.3 "$orig_object"
pass 'tag replaced on download is refused'

if ! python3 - "$fixture_publish" "$fixture_publish" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '''# Re-verify the tag immediately before promotion. GitHub has no atomic
# compare-and-publish, so a replacement tag between the earlier checks and
# --draft=false must still be refused.
SHELLSENTRY_RELEASE_TAG="$tag" SHELLSENTRY_EXPECTED_TAG_OBJECT="$anchor_object" SHELLSENTRY_EXPECTED_COMMIT="$anchor_commit" \\
	"$root/scripts/release-verify-published-tag.sh" >/dev/null ||
	die 'published tag no longer matches the verified anchor'
gh release edit "$tag" --repo "$repo" --draft=false >/dev/null
'''
new = '''gh release edit "$tag" --repo "$repo" --draft=false >/dev/null
'''
if old not in text:
    raise SystemExit('live script is missing the pre-promotion tag re-verify')
mut = text.replace(old, new, 1)
if 'Re-verify the tag immediately before promotion' in mut:
    raise SystemExit('L6 mutant still re-verifies before promotion')
Path(sys.argv[2]).write_text(mut)
PY
then
	fail 'pre-promotion re-verify mutant was not distinguished'
fi
chmod +x "$fixture_publish"
stage
export FIXTURE_REPLACE_TAG_ON_DOWNLOAD=1
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/mut-l6.err"; then
	fail "dropping the pre-promotion re-verify must promote a replaced tag (log: $(cat "$scratch/mut-l6.err"))"
fi
unset FIXTURE_REPLACE_TAG_ON_DOWNLOAD
git -C "$scratch/origin.git" update-ref refs/tags/v1.2.3 "$orig_object"
git -C "$repo" update-ref refs/tags/v1.2.3 "$orig_object"
restore_publish
pass 'reverting the pre-promotion re-verify publishes a replaced tag'

# Positive control: throwaway-key signed set promotes exactly once, after download.
stage
: >"$FIXTURE_LOG"
if ! (cd "$repo" && env SHELLSENTRY_RELEASE_REPO=attacker/shellsentry \
	./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/ok.err"; then
	fail "positive control must publish (log: $(cat "$scratch/ok.err"))"
fi
[[ "$(grep -c '^release edit v1.2.3 .*--draft=false' "$FIXTURE_LOG")" == 1 ]] ||
	fail 'positive control must promote exactly once'
[[ "$(grep -n '' "$FIXTURE_LOG" | grep -E 'release (download|edit)' | head -1)" == *'release download'* ]] ||
	fail 'promotion must happen after the draft download'
grep -q -- '--repo 3leaps/shellsentry' "$FIXTURE_LOG" ||
	fail 'publish must pass --repo 3leaps/shellsentry'
if grep -q -- '--repo attacker/shellsentry' "$FIXTURE_LOG"; then
	fail 'publish must ignore SHELLSENTRY_RELEASE_REPO'
fi
pass 'positive control signed with throwaway keys publishes after byte comparison'

# Documented ceremony: create-draft, then notes, then upload, then publish.
# create-draft refuses an existing release, so upload cannot run first.
# The e2e calls the scripts those make targets wrap (release-verify is not
# cheap to reproduce here).
grep -E '^release-create-draft: require-release-tag' -A2 "$root/Makefile" | grep -q 'release-create-draft.sh' ||
	fail 'make release-create-draft must invoke release-create-draft.sh'
grep -E '^release-upload: require-release-tag' -A2 "$root/Makefile" | grep -q 'upload-release-assets.sh' ||
	fail 'make release-upload must invoke upload-release-assets.sh'
grep -E '^release-publish: require-release-tag' -A2 "$root/Makefile" | grep -q 'release-publish.sh' ||
	fail 'make release-publish must invoke release-publish.sh'
grep -q 'gh release upload "$TAG" "$NOTES_FILE" --clobber' "$fixture_upload" ||
	fail 'fixture upload must attach release-notes-<tag>.md'
python3 - "$root/RELEASE_CHECKLIST.md" <<'PY' || fail 'RELEASE_CHECKLIST ceremony order does not match'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
steps = [
    "make release-create-draft",
    "make release-notes",
    "make release-upload",
    "make release-publish",
]
idx = []
for s in steps:
    i = text.find(s)
    if i < 0:
        raise SystemExit(f"missing {s}")
    idx.append(i)
if idx != sorted(idx):
    raise SystemExit(f"ceremony order is {steps} but appeared at {idx}")
up = text[idx[2]:idx[3]]
if "release-notes-" not in up:
    raise SystemExit("release-upload section must name the notes asset")
heading = "11. **Upload remaining assets**"
hi = text.find(heading)
if hi < 0:
    raise SystemExit("missing step 11 remaining-assets heading")
if "Upload remaining keys" in text:
    raise SystemExit("stale Upload remaining keys heading")
if not (idx[1] < hi < idx[2]):
    raise SystemExit("step 11 heading must sit between release-notes and release-upload")
PY

run_ceremony() {
	local upload="$1"
	stage
	rm -rf "$scratch/draft"
	mkdir -p "$scratch/draft" "$scratch/e2e-aside"
	rm -f "$FIXTURE_GH_EXISTS"
	mv "$d/shellsentry-minisign.pub" "$d/shellsentry-release-signing-key.asc" \
		"$d/release-notes-v1.2.3.md" "$scratch/e2e-aside/"
	if ! (cd "$repo" && ./scripts/release-create-draft.sh v1.2.3 "$d") \
		>"$scratch/e2e-cd.out" 2>&1; then
		fail "create-draft in ceremony must succeed (log: $(cat "$scratch/e2e-cd.out"))"
	fi
	mv "$scratch/e2e-aside"/* "$d/"
	if ! (cd "$repo" && "$upload" v1.2.3 "$d") >"$scratch/e2e-up.out" 2>&1; then
		fail "upload in ceremony must succeed (log: $(cat "$scratch/e2e-up.out"))"
	fi
}

export FIXTURE_RELEASE_EXISTS=0
export FIXTURE_GH_EXISTS="$scratch/gh-exists"
: >"$FIXTURE_LOG"
run_ceremony "$fixture_upload"
[[ -f "$scratch/draft/release-notes-v1.2.3.md" ]] ||
	fail 'ceremony upload must put release-notes-<tag>.md on the draft'
cmp -s "$d/release-notes-v1.2.3.md" "$scratch/draft/release-notes-v1.2.3.md" ||
	fail 'draft notes asset must match the staged notes file'
: >"$FIXTURE_LOG"
if ! (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/e2e-ok.err"; then
	fail "create-draft then upload then publish must succeed (log: $(cat "$scratch/e2e-ok.err"))"
fi
[[ "$(grep -c '^release edit v1.2.3 .*--draft=false' "$FIXTURE_LOG")" == 1 ]] ||
	fail 'ceremony publish must promote exactly once'
pass 'create-draft then upload then publish promotes with the notes asset'

if ! python3 - "$fixture_upload" "$fixture_upload" <<'PY'
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = '''echo "[upload] Release notes asset"
gh release upload "$TAG" "$NOTES_FILE" --clobber
'''
if old not in text:
    raise SystemExit('live upload is missing the notes-asset upload')
mut = text.replace(old, '', 1)
if 'gh release upload "$TAG" "$NOTES_FILE" --clobber' in mut:
    raise SystemExit('notes-asset mutant still uploads NOTES_FILE')
dest.write_text(mut)
PY
then
	fail 'ceremony notes-asset mutant was not distinguished'
fi
chmod +x "$fixture_upload"
: >"$FIXTURE_LOG"
run_ceremony "$fixture_upload"
if (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null 2>"$scratch/e2e-mut.err"; then
	fail 'accepted publish after dropping the notes-asset upload'
fi
grep -q 'draft assets differ from the expected set' "$scratch/e2e-mut.err" || {
	echo "error: missing named rejection after dropping notes upload" >&2
	cat "$scratch/e2e-mut.err" >&2
	exit 1
}
restore_upload
unset FIXTURE_RELEASE_EXISTS FIXTURE_GH_EXISTS
pass 'dropping the notes-asset upload makes publish refuse the draft set'

echo '[ok] publish promotes only a byte-verified, pin-signed draft bound to the tag'
