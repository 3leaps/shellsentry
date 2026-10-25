#!/usr/bin/env bash
# Stub gh/git remotes: remote object must equal local, and GitHub must report
# verification.verified == true with reason == valid.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-remote-tag.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

mkdir -p "$scratch/bin" "$scratch/repo"
cp "$root/scripts/release-verify-remote-tag.sh" "$root/scripts/release-tag-common.sh" \
	"$root/scripts/release-guard-tag-version.sh" "$scratch/repo/"
# verify-pinned-tag is invoked; stub it.
cat >"$scratch/repo/verify-pinned-tag.sh" <<'SH'
#!/usr/bin/env bash
echo '[ok] stub pin verify'
SH
chmod +x "$scratch/repo/"*.sh
# Scripts resolve sibling paths via dirname/../scripts; keep that layout.
mkdir -p "$scratch/tree/scripts" "$scratch/tree/config/release"
mv "$scratch/repo/"*.sh "$scratch/tree/scripts/"
printf '1.2.3\n' >"$scratch/tree/VERSION"
printf '3 Leaps Infosec Team <infosec@3leaps.net>\n' >"$scratch/tree/config/release/tagger-identity.txt"

git init -q -b main "$scratch/tree"
git -C "$scratch/tree" config user.name fixture
git -C "$scratch/tree" config user.email fixture@example.invalid
printf 'x\n' >"$scratch/tree/file"
git -C "$scratch/tree" add VERSION file config scripts
git -C "$scratch/tree" commit -qm fixture
git -C "$scratch/tree" tag -a v1.2.3 -m 'fixture'
object="$(git -C "$scratch/tree" rev-parse refs/tags/v1.2.3)"
commit="$(git -C "$scratch/tree" rev-parse HEAD)"
git -C "$scratch/tree" update-ref refs/remotes/origin/main "$commit"
git -C "$scratch/tree" remote add origin https://github.com/3leaps/shellsentry.git

cat >"$scratch/bin/git" <<SH
#!/usr/bin/env bash
real="$(command -v git)"
case "\$*" in
  'config --get remote.origin.url') printf '%s\n' 'https://github.com/3leaps/shellsentry.git' ;;
  'ls-remote origin refs/tags/v1.2.3')
    printf '%s\t%s\n' "\${REMOTE_OBJECT:-$object}" 'refs/tags/v1.2.3'
    ;;
  *) exec "\$real" "\$@" ;;
esac
SH
chmod +x "$scratch/bin/git"

cat >"$scratch/bin/gh" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == *git/ref/tags/* ]]; then
	printf '{"object":{"type":"%s","sha":"%s"}}\n' "${REF_TYPE:-tag}" "${REF_SHA:?}"
	exit 0
fi
if [[ "$*" == *'/git/tags/'* ]]; then
	cat "$TAG_JSON"
	exit 0
fi
echo "unhandled gh: $*" >&2
exit 1
SH
chmod +x "$scratch/bin/gh"

export PATH="$scratch/bin:$PATH"
export SHELLSENTRY_RELEASE_TAG=v1.2.3
export REF_SHA="$object"
export TAG_JSON="$scratch/tag.json"
cat >"$TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$commit"},"verification":{"verified":true,"reason":"valid"}}
JSON

(
	cd "$scratch/tree"
	./scripts/release-verify-remote-tag.sh
) >"$scratch/ok.out"
grep -q 'remote signed tag matches local object' "$scratch/ok.out"

expect_fail() {
	if "$@" >/dev/null 2>&1; then
		echo "expected remote-tag rejection" >&2
		exit 1
	fi
}

# Remote object differs.
expect_fail env REMOTE_OBJECT="$(printf 'a%.0s' {1..40})" \
	bash -c 'cd "$1" && ./scripts/release-verify-remote-tag.sh' _ "$scratch/tree"

# verified != true
cat >"$TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$commit"},"verification":{"verified":false,"reason":"valid"}}
JSON
expect_fail env -C "$scratch/tree" ./scripts/release-verify-remote-tag.sh

# reason != valid
cat >"$TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$commit"},"verification":{"verified":true,"reason":"unsigned"}}
JSON
expect_fail env -C "$scratch/tree" ./scripts/release-verify-remote-tag.sh

echo '[ok] remote tag object and GitHub verification controls passed'
