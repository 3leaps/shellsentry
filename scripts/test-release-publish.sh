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
grep -q 'verify-signatures.sh' "$script" ||
	fail 'publish must verify signatures via the tagged-key helper'
grep -q 'release-bind-archives.sh' "$script" ||
	fail 'publish must bind archives via the shared helper'
grep -q 'release-verify-tag-anchor.sh' "$root/scripts/release-verify-published-tag.sh" ||
	fail 'published-tag must call tag-anchor'
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
	"$root/scripts/release-decernor.sh" "$repo/scripts/"
chmod +x "$repo/scripts/"*.sh
cp "$root/config/release/tagger-identity.txt" "$repo/config/release/"
cp -a "$root/internal" "$repo/"
cp "$root/main.go" "$root/go.mod" "$root/go.sum" "$repo/"
gpg --batch --armor --export "$primary" >"$repo/docs/security/release-signing-keys.asc"
cp "$scratch/good.pub" "$repo/docs/security/shellsentry-minisign.pub"
printf 'notes for v1.2.3\n' >"$repo/docs/releases/v1.2.3.md"
blob="$(python3 -c 'import base64,hashlib,pathlib,sys; print(hashlib.sha256(base64.b64decode(pathlib.Path(sys.argv[1]).read_text().splitlines()[1])).hexdigest())' "$scratch/good.pub")"
printf 'gpg %s\nminisign %s\n' "$primary" "$blob" >"$repo/keys/expected-fingerprints.txt"
printf '{"schema_version":"v0"}\n{"schema_version":"v0"}\n' >"$repo/keys/expected-fingerprints.ndjson"
git -C "$repo" add docs keys scripts internal main.go go.mod go.sum config
git -C "$repo" -c commit.gpgsign=false commit -qm fixture
full="$(git -C "$repo" rev-parse HEAD)"
GIT_COMMITTER_NAME='3 Leaps Infosec Team' GIT_COMMITTER_EMAIL=infosec@3leaps.net \
	git -C "$repo" -c gpg.format=openpgp tag -s -a --cleanup=verbatim \
	-u "$subkey!" -m 'shellsentry v1.2.3'$'\n' v1.2.3 HEAD ||
	fail 'signed fixture tag failed'
orig_object="$(git -C "$repo" rev-parse refs/tags/v1.2.3)"
git init -q --bare "$scratch/origin.git"
git -C "$repo" remote add origin "$scratch/origin.git"
git -C "$repo" push -q origin HEAD:main
git -C "$repo" push -q origin v1.2.3
git -C "$repo" remote set-url origin https://github.com/3leaps/shellsentry.git
git -C "$repo" config url."$scratch/origin.git".insteadOf https://github.com/3leaps/shellsentry.git
git -C "$repo" fetch -q origin

go_build() {
	GOPATH="$gopath" GOCACHE="$gocache" GOMODCACHE="$gomodcache" GOTOOLCHAIN="$gotoolchain" \
		CGO_ENABLED=0 go build "$@"
}
mkdir -p "$scratch/bin"
(cd "$repo" && go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=${full}" \
	-o "$scratch/bin/shellsentry" .)
[[ -s "$scratch/bin/shellsentry" ]] || fail 'fixture binary missing'
(cd "$repo" && GOOS=darwin GOARCH=arm64 go_build -trimpath \
	-ldflags="-s -w -X main.version=1.2.3 -X main.gitCommit=${full}" \
	-o "$scratch/bin/shellsentry-darwin" .)
[[ -s "$scratch/bin/shellsentry-darwin" ]] || fail 'darwin fixture binary missing'

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
	names="$(cd "$FIXTURE_DRAFT" && ls -1 | jq -R . | jq -s 'map({name: .})')"
	jq -n --argjson a "$names" --argjson d "${FIXTURE_IS_DRAFT:-true}" '{isDraft: $d, assets: $a}'
	;;
"release download")
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

# Positive control: throwaway-key signed set promotes exactly once, after download.
stage
: >"$FIXTURE_LOG"
(cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null
[[ "$(grep -c '^release edit v1.2.3 .*--draft=false' "$FIXTURE_LOG")" == 1 ]] ||
	fail 'positive control must promote exactly once'
[[ "$(grep -n '' "$FIXTURE_LOG" | grep -E 'release (download|edit)' | head -1)" == *'release download'* ]] ||
	fail 'promotion must happen after the draft download'
pass 'positive control signed with throwaway keys publishes after byte comparison'

echo '[ok] publish promotes only a byte-verified, pin-signed draft bound to the tag'
