#!/usr/bin/env bash
# Revert-proof: refuse an existing remote tag, and verify after a successful push.
# Local bare origin; GitHub API stubbed. Never the default homedir or this checkout.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
unset GITHUB_ACTIONS RELEASE_TAG || true
command -v jq >/dev/null 2>&1 || {
	echo 'error: jq required' >&2
	exit 1
}

scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-push-tag.XXXXXX")"
scratch="$(CDPATH= cd -P -- "$scratch" && pwd -P)"
trap 'rm -rf "$scratch"' EXIT

tree="$scratch/tree"
remote="$scratch/remote.git"
mkdir -p "$tree/scripts" "$tree/config/release" "$scratch/bin"
git init -q --bare "$remote"
git init -q -b main "$tree"
git -C "$tree" config user.name fixture
git -C "$tree" config user.email fixture@example.invalid

cp "$root/scripts/release-push-tag.sh" \
	"$root/scripts/release-tag-common.sh" \
	"$root/scripts/release-guard-tag-version.sh" \
	"$root/scripts/release-ci-refuse.sh" \
	"$root/scripts/release-verify-remote-tag.sh" \
	"$tree/scripts/"
cat >"$tree/scripts/verify-pinned-tag.sh" <<'SH'
#!/usr/bin/env bash
echo '[ok] stub pin verify'
SH
cat >"$tree/scripts/release-inspect-tag-ruleset.sh" <<'SH'
#!/usr/bin/env bash
echo "FOUND: stub ruleset for $1"
SH
chmod +x "$tree/scripts/"*.sh
printf '1.2.3\n' >"$tree/VERSION"
printf '3 Leaps Infosec Team <infosec@3leaps.net>\n' >"$tree/config/release/tagger-identity.txt"
printf 'tracked\n' >"$tree/file"
git -C "$tree" add VERSION file config scripts
git -C "$tree" commit -qm fixture
git -C "$tree" tag -a v1.2.3 -m 'fixture'
object="$(git -C "$tree" rev-parse refs/tags/v1.2.3)"
commit="$(git -C "$tree" rev-parse HEAD)"
git -C "$tree" remote add origin https://github.com/3leaps/shellsentry.git
git -C "$tree" config "url.$remote.insteadOf" https://github.com/3leaps/shellsentry.git
git -C "$tree" push -q origin main
git -C "$tree" update-ref refs/remotes/origin/main "$commit"

cat >"$scratch/bin/gh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${GH_LOG:?}"
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
export GH_LOG="$scratch/gh.log"
export REF_SHA="$object"
export TAG_JSON="$scratch/tag.json"
cat >"$TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$commit"},"verification":{"verified":true,"reason":"valid"}}
JSON
: >"$GH_LOG"

grep -F "remote tag already exists" "$tree/scripts/release-push-tag.sh" >/dev/null || {
	echo 'error: live release-push-tag.sh must refuse an existing remote tag' >&2
	exit 1
}
grep -F 'release-verify-remote-tag.sh' "$tree/scripts/release-push-tag.sh" >/dev/null || {
	echo 'error: live release-push-tag.sh must call release-verify-remote-tag.sh' >&2
	exit 1
}

python3 - "$tree/scripts/release-push-tag.sh" "$tree/scripts/release-push-tag.no-exist.sh" <<'PY'
from pathlib import Path
import sys
src, dst = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
needle = "remote tag already exists"
if needle not in text:
    raise SystemExit('live script lost the remote-exists refusal')
lines = [line for line in text.splitlines(True) if needle not in line]
if needle in ''.join(lines):
    raise SystemExit('exist-check mutant still refuses an existing remote tag')
dst.write_text(''.join(lines))
PY
python3 - "$tree/scripts/release-push-tag.sh" "$tree/scripts/release-push-tag.no-verify.sh" <<'PY'
from pathlib import Path
import sys
src, dst = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
needle = "release-verify-remote-tag.sh"
if needle not in text:
    raise SystemExit('live script lost the post-push verify call')
lines = [line for line in text.splitlines(True) if needle not in line]
if needle in ''.join(lines):
    raise SystemExit('verify mutant still calls release-verify-remote-tag.sh')
dst.write_text(''.join(lines))
PY
chmod +x "$tree/scripts/release-push-tag.no-exist.sh" "$tree/scripts/release-push-tag.no-verify.sh"

run_push() {
	(cd "$tree" && "$@")
}

# --- (b) post-push remote verification (empty remote) ---
: >"$GH_LOG"
if ! run_push ./scripts/release-push-tag.sh >"$scratch/live-push.out" 2>&1; then
	echo 'error: live push of a missing remote tag must succeed' >&2
	cat "$scratch/live-push.out" >&2
	exit 1
fi
grep -q 'remote signed tag matches local object' "$scratch/live-push.out" || {
	echo 'error: live push must run remote verification' >&2
	cat "$scratch/live-push.out" >&2
	exit 1
}
grep -q 'git/ref/tags' "$GH_LOG" || {
	echo 'error: live push must call the GitHub tag API' >&2
	cat "$GH_LOG" >&2
	exit 1
}
[[ -n "$(git --git-dir="$remote" show-ref --tags refs/tags/v1.2.3)" ]] || {
	echo 'error: live push did not publish the tag to the bare remote' >&2
	exit 1
}
echo 'PASS: live push publishes the tag and verifies the remote object'

git --git-dir="$remote" update-ref -d refs/tags/v1.2.3
: >"$GH_LOG"
if ! run_push ./scripts/release-push-tag.no-verify.sh >"$scratch/mut-verify.out" 2>&1; then
	echo 'error: post-push-verify mutant should still push' >&2
	cat "$scratch/mut-verify.out" >&2
	exit 1
fi
if grep -q 'remote signed tag matches local object' "$scratch/mut-verify.out"; then
	echo 'error: post-push-verify mutant still reported remote verification' >&2
	cat "$scratch/mut-verify.out" >&2
	exit 1
fi
if grep -q 'git/ref/tags' "$GH_LOG" || grep -q '/git/tags/' "$GH_LOG"; then
	echo 'error: post-push-verify mutant still called the GitHub tag API' >&2
	cat "$GH_LOG" >&2
	exit 1
fi
[[ -n "$(git --git-dir="$remote" show-ref --tags refs/tags/v1.2.3)" ]] || {
	echo 'error: post-push-verify mutant did not push the tag' >&2
	exit 1
}
echo 'PASS: dropping post-push verification still pushes but skips GitHub verification'

# --- (a) refusal when the remote tag already exists ---
: >"$GH_LOG"
if run_push ./scripts/release-push-tag.sh >"$scratch/live-exist.out" 2>&1; then
	echo 'error: live push must refuse when the remote tag already exists' >&2
	cat "$scratch/live-exist.out" >&2
	exit 1
fi
grep -q 'remote tag already exists' "$scratch/live-exist.out" || {
	echo 'error: live refusal must name the existing remote tag' >&2
	cat "$scratch/live-exist.out" >&2
	exit 1
}
if grep -q 'git/ref/tags' "$GH_LOG"; then
	echo 'error: exist-check must run before remote verification' >&2
	cat "$GH_LOG" >&2
	exit 1
fi
echo 'PASS: live push refuses an existing remote tag'

: >"$GH_LOG"
if ! run_push ./scripts/release-push-tag.no-exist.sh >"$scratch/mut-exist.out" 2>&1; then
	echo 'error: exist-check mutant must succeed when the remote already has the same tag' >&2
	cat "$scratch/mut-exist.out" >&2
	exit 1
fi
if grep -q 'remote tag already exists' "$scratch/mut-exist.out"; then
	echo 'error: exist-check mutant still reported remote tag already exists' >&2
	cat "$scratch/mut-exist.out" >&2
	exit 1
fi
grep -q 'remote signed tag matches local object' "$scratch/mut-exist.out" || {
	echo 'error: exist-check mutant should fall through to post-push verification' >&2
	cat "$scratch/mut-exist.out" >&2
	exit 1
}
echo 'PASS: dropping the exist-check lets an already-published tag through'

echo '[ok] release-push-tag exist-check and post-push verify controls'
