#!/usr/bin/env bash
# Tag anchor: local object equals origin, GitHub verified/valid, ancestor of
# origin/main, identity files byte-identical to origin/main.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
scratch="$(mktemp -d /tmp/shs-ta.XXXXXX)"
scratch="$(CDPATH= cd -P -- "$scratch" && pwd -P)"
trap 'rm -rf "$scratch"' EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}
pass() { echo "PASS: $*"; }

script="$root/scripts/release-verify-tag-anchor.sh"
[[ -x "$script" ]] || fail 'release-verify-tag-anchor.sh must be executable'
grep -q 'release-verify-tag-anchor.sh' "$root/scripts/release-create-draft.sh" ||
	fail 'create-draft must verify the tag against origin and GitHub'
grep -q 'release-verify-tag-anchor.sh' "$root/scripts/verify-signatures.sh" ||
	fail 'verify-signatures must verify the tag against origin and GitHub'
grep -q 'release-verify-tag-anchor.sh' "$root/scripts/release-verify-published-tag.sh" ||
	fail 'published-tag must call the shared tag-anchor helper'
grep -q 'release-verify-tag-anchor.sh' "$root/scripts/release-verify-staged-keys.sh" ||
	fail 'verify-staged-keys must verify the tag against origin and GitHub'
grep -q 'release-bind-archives.sh' "$root/scripts/release-create-draft.sh" ||
	fail 'create-draft must bind archives via the shared helper'
grep -q 'release-bind-archives.sh' "$root/scripts/release-publish.sh" ||
	fail 'publish must bind archives via the shared helper'
grep -q 'verify-signatures.sh' "$root/scripts/release-publish.sh" ||
	fail 'publish must verify signatures via the tagged-key helper'
grep -q 'release-verify-published-tag.sh' "$root/scripts/release-publish.sh" ||
	fail 'publish must re-check the published tag (which calls tag-anchor)'
grep -E '^release-tag-tests:' -A50 "$root/Makefile" | grep -q 'test-release-verify-tag-anchor' ||
	fail 'release-tag-tests must run test-release-verify-tag-anchor'
pass 'create-draft, verify-signatures, staged-keys, published-tag, and publish reuse tag-anchor'

tree="$scratch/tree"
mkdir -p "$tree/scripts" "$tree/docs/security" "$tree/keys"
cp "$script" "$tree/scripts/"
chmod +x "$tree/scripts/"*.sh
printf 'gpg AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nminisign %s\n' "$(printf 'a%.0s' {1..64})" \
	>"$tree/keys/expected-fingerprints.txt"
printf '{"schema_version":"v0"}\n{"schema_version":"v0"}\n' >"$tree/keys/expected-fingerprints.ndjson"
printf 'good-gpg\n' >"$tree/docs/security/release-signing-keys.asc"
printf 'good-minisign\n' >"$tree/docs/security/shellsentry-minisign.pub"
printf 'notes\n' >"$tree/docs/security/placeholder"
git init -q -b main "$tree"
git -C "$tree" config user.name fixture
git -C "$tree" config user.email fixture@example.invalid
git -C "$tree" add docs keys scripts
git -C "$tree" commit -qm fixture
git -C "$tree" tag -a v1.2.3 -m 'fixture'
object="$(git -C "$tree" rev-parse refs/tags/v1.2.3)"
commit="$(git -C "$tree" rev-parse HEAD)"
git init -q --bare "$scratch/origin.git"
git -C "$scratch/origin.git" symbolic-ref HEAD refs/heads/main
git -C "$tree" remote add origin "$scratch/origin.git"
git -C "$tree" push -q origin HEAD:main
git -C "$tree" push -q origin v1.2.3
git -C "$tree" fetch -q origin
git -C "$tree" update-ref refs/remotes/origin/main "$commit"

mkdir -p "$scratch/bin"
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
export REF_SHA="$object"
export TAG_JSON="$scratch/tag.json"
cat >"$TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$commit"},"verification":{"verified":true,"reason":"valid"}}
JSON

expect_fail() {
	local msg="$1"
	shift
	if "$@" >/dev/null 2>"$scratch/err"; then
		fail "expected refusal: $msg"
	fi
	grep -q "$msg" "$scratch/err" || fail "refusal for $msg (log: $(cat "$scratch/err"))"
}

if ! "$tree/scripts/release-verify-tag-anchor.sh" v1.2.3 >/dev/null; then
	fail 'matching origin tag, GitHub verification, ancestry, and identity must pass'
fi
pass 'positive tag-anchor fixture verifies'

other="$scratch/other"
git clone -q -b main "$scratch/origin.git" "$other"
git -C "$other" config user.name fixture
git -C "$other" config user.email fixture@example.invalid
printf 'other\n' >"$other/other"
git -C "$other" add other
git -C "$other" commit -qm other
git -C "$other" tag -a v9.9.9 -m other
wrong_object="$(git -C "$other" rev-parse refs/tags/v9.9.9)"
git -C "$other" push -q origin "refs/tags/v9.9.9:refs/tags/v1.2.3" --force
expect_fail 'remote tag object differs from local tag' \
	"$tree/scripts/release-verify-tag-anchor.sh" v1.2.3
git -C "$tree" push -q origin v1.2.3 --force
pass 'remote tag object mismatch is refused'

cat >"$TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$commit"},"verification":{"verified":false,"reason":"valid"}}
JSON
expect_fail 'GitHub does not report a verified tag' \
	"$tree/scripts/release-verify-tag-anchor.sh" v1.2.3
cat >"$TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$commit"},"verification":{"verified":true,"reason":"unsigned"}}
JSON
expect_fail 'GitHub does not report a verified tag' \
	"$tree/scripts/release-verify-tag-anchor.sh" v1.2.3
cat >"$TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$commit"},"verification":{"verified":true,"reason":"valid"}}
JSON
pass 'GitHub unverified and non-valid tags are refused'

# Attacker commit: own keys and own signed/annotated tag, not on origin/main.
attack="$scratch/attack"
git clone -q -b main "$scratch/origin.git" "$attack"
git -C "$attack" config user.name atk
git -C "$attack" config user.email atk@example.invalid
mkdir -p "$attack/scripts" "$attack/docs/security" "$attack/keys"
cp "$script" "$attack/scripts/"
chmod +x "$attack/scripts/"*.sh
printf 'attacker-gpg\n' >"$attack/docs/security/release-signing-keys.asc"
printf 'attacker-minisign\n' >"$attack/docs/security/shellsentry-minisign.pub"
printf 'gpg BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\nminisign %s\n' "$(printf 'b%.0s' {1..64})" \
	>"$attack/keys/expected-fingerprints.txt"
git -C "$attack" add docs keys
git -C "$attack" -c user.name=atk -c user.email=atk@example.invalid commit -qm attacker
git -C "$attack" tag -d v1.2.3 >/dev/null
git -C "$attack" tag -a v1.2.3 -m attacker
attack_object="$(git -C "$attack" rev-parse refs/tags/v1.2.3)"
attack_commit="$(git -C "$attack" rev-parse HEAD)"
git -C "$attack" remote remove origin
git init -q --bare "$scratch/attack-origin.git"
git -C "$attack" remote add origin "$scratch/attack-origin.git"
# origin/main is the good commit so fetch cannot be skipped: the attacker tag
# is a child of that commit, not an ancestor.
git -C "$attack" push -q origin "$commit:refs/heads/main"
git -C "$attack" push -q origin v1.2.3 --force
export REF_SHA="$attack_object"
cat >"$TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$attack_commit"},"verification":{"verified":true,"reason":"valid"}}
JSON
expect_fail 'tagged commit is not an ancestor of origin/main' \
	"$attack/scripts/release-verify-tag-anchor.sh" v1.2.3
python3 - "$script" "$attack/scripts/release-verify-tag-anchor.sh" <<'PY' || fail 'ancestor mutant was not distinguished'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'git -C "$root" merge-base --is-ancestor "$commit" origin/main ||'
new = 'true ||'
if old not in text:
    raise SystemExit('live script is missing the ancestor check')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('ancestor mutant still checks ancestry')
# Identity still differs on every pin file; skip those compares too.
ident = '[[ "$tagged_blob" == "$main_blob" ]] ||'
if ident not in mut:
    raise SystemExit('live script is missing the identity compare')
mut = mut.replace(ident, 'true ||')
if ident in mut:
    raise SystemExit('identity mutant still compares blobs')
Path(sys.argv[2]).write_text(mut)
PY
chmod +x "$attack/scripts/release-verify-tag-anchor.sh"
if ! "$attack/scripts/release-verify-tag-anchor.sh" v1.2.3 >/dev/null 2>"$scratch/mut-attack.err"; then
	fail "dropping ancestor and identity checks must accept the attacker tag (log: $(cat "$scratch/mut-attack.err"))"
fi
cp "$script" "$attack/scripts/release-verify-tag-anchor.sh"
chmod +x "$attack/scripts/release-verify-tag-anchor.sh"
pass 'attacker commit with its own keys and tag is refused'

# Identity files on the tagged commit differ from origin/main (tag is still an ancestor).
printf 'rotated-minisign\n' >"$tree/docs/security/shellsentry-minisign.pub"
git -C "$tree" add docs/security/shellsentry-minisign.pub
git -C "$tree" commit -qm rotate
git -C "$tree" push -q origin HEAD:main
git -C "$tree" fetch -q origin
export REF_SHA="$object"
cat >"$TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$commit"},"verification":{"verified":true,"reason":"valid"}}
JSON
expect_fail 'identity file docs/security/shellsentry-minisign.pub on v1.2.3 differs from origin/main' \
	"$tree/scripts/release-verify-tag-anchor.sh" v1.2.3
pass 'identity mismatch versus origin/main is refused'
# Put origin/main back on the tagged commit so later checks are not identity failures.
git -C "$tree" push -q origin "$commit:refs/heads/main" --force
git -C "$tree" fetch -q origin
export REF_SHA="$object"
cat >"$TAG_JSON" <<JSON
{"tag":"v1.2.3","object":{"type":"commit","sha":"$commit"},"verification":{"verified":true,"reason":"valid"}}
JSON

python3 - "$script" <<'PY' || fail 'tag-anchor source checks missing'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
for needle in (
    'ls-remote origin',
    'verification',
    'merge-base --is-ancestor',
    'origin/main',
    'fetch --quiet origin',
    'origin remote is required',
    'expected-fingerprints.txt',
    'release-signing-keys.asc',
    'cat-file -t',
    'obj.get("sha")',
):
    if needle not in text:
        raise SystemExit('missing ' + needle)
PY
pass 'tag-anchor source includes remote, GitHub, ancestor, fetch, and identity checks'

# L3: no origin remote is a named refusal.
git -C "$tree" remote remove origin
expect_fail 'origin remote is required' \
	"$tree/scripts/release-verify-tag-anchor.sh" v1.2.3
git -C "$tree" remote add origin "$scratch/origin.git"
git -C "$tree" fetch -q origin
pass 'missing origin remote is refused with a clear message'

# L3: GitHub ref SHA mismatch, with a revert proof.
export REF_SHA="$(printf '%040d' 9)"
expect_fail 'GitHub tag ref mismatch' \
	"$tree/scripts/release-verify-tag-anchor.sh" v1.2.3
python3 - "$script" "$tree/scripts/release-verify-tag-anchor.sh" <<'PY' || fail 'ref-sha mutant was not distinguished'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'if obj.get("type") != "tag" or obj.get("sha") != sys.argv[2]:'
new = 'if obj.get("type") != "tag" or False:'
if old not in text:
    raise SystemExit('live script is missing the GitHub ref sha check')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('ref-sha mutant still compares sha')
Path(sys.argv[2]).write_text(mut)
PY
chmod +x "$tree/scripts/release-verify-tag-anchor.sh"
if ! "$tree/scripts/release-verify-tag-anchor.sh" v1.2.3 >/dev/null 2>"$scratch/mut-refsha.err"; then
	fail "dropping the GitHub ref sha check must accept a mismatched ref (log: $(cat "$scratch/mut-refsha.err"))"
fi
cp "$script" "$tree/scripts/release-verify-tag-anchor.sh"
chmod +x "$tree/scripts/release-verify-tag-anchor.sh"
export REF_SHA="$object"
pass 'reverting the GitHub ref sha check accepts a mismatched ref'

# L3: annotated-tag check, with a revert proof. Push a lightweight tag whose
# GitHub stub still claims type=tag so only the local cat-file check catches it.
git -C "$tree" tag -d v1.2.3 >/dev/null
git -C "$tree" tag v1.2.3 "$commit"
light_object="$(git -C "$tree" rev-parse refs/tags/v1.2.3)"
git -C "$tree" push -q origin v1.2.3 --force
export REF_SHA="$light_object"
expect_fail 'annotated tag required' \
	"$tree/scripts/release-verify-tag-anchor.sh" v1.2.3
python3 - "$script" "$tree/scripts/release-verify-tag-anchor.sh" <<'PY' || fail 'annotated-tag mutant was not distinguished'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = '[[ "$(git -C "$root" cat-file -t "$object")" == tag ]] || die \'annotated tag required\''
new = 'true || die \'annotated tag required\''
if old not in text:
    raise SystemExit('live script is missing the annotated-tag check')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('annotated-tag mutant still checks cat-file -t')
Path(sys.argv[2]).write_text(mut)
PY
chmod +x "$tree/scripts/release-verify-tag-anchor.sh"
if ! "$tree/scripts/release-verify-tag-anchor.sh" v1.2.3 >/dev/null 2>"$scratch/mut-annotated.err"; then
	fail "dropping the annotated-tag check must accept a lightweight tag (log: $(cat "$scratch/mut-annotated.err"))"
fi
cp "$script" "$tree/scripts/release-verify-tag-anchor.sh"
chmod +x "$tree/scripts/release-verify-tag-anchor.sh"
git -C "$tree" tag -d v1.2.3 >/dev/null
git -C "$tree" tag -a v1.2.3 -m 'fixture' "$commit"
object="$(git -C "$tree" rev-parse refs/tags/v1.2.3)"
git -C "$tree" push -q origin v1.2.3 --force
export REF_SHA="$object"
pass 'reverting the annotated-tag check accepts a lightweight tag'

# L1: fetch origin/main before ancestry. A stale tracking ref would still see
# the tagged commit as an ancestor after origin/main moved away.
stale="$scratch/stale-main"
git init -q -b main "$stale"
git -C "$stale" config user.name fixture
git -C "$stale" config user.email fixture@example.invalid
mkdir -p "$stale/docs/security" "$stale/keys"
cp "$tree/docs/security/release-signing-keys.asc" "$tree/docs/security/shellsentry-minisign.pub" \
	"$stale/docs/security/"
cp "$tree/keys/expected-fingerprints.txt" "$tree/keys/expected-fingerprints.ndjson" "$stale/keys/"
git -C "$stale" add docs keys
git -C "$stale" commit -qm unrelated
git -C "$stale" push -q "$scratch/origin.git" HEAD:main --force
# Restore a stale origin/main at the tagged commit so only fetch can see the move.
git -C "$tree" update-ref refs/remotes/origin/main "$commit"
expect_fail 'tagged commit is not an ancestor of origin/main' \
	"$tree/scripts/release-verify-tag-anchor.sh" v1.2.3
git -C "$tree" update-ref refs/remotes/origin/main "$commit"
python3 - "$script" "$tree/scripts/release-verify-tag-anchor.sh" <<'PY' || fail 'fetch-origin/main mutant was not distinguished'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
old = 'git -C "$root" fetch --quiet origin "+refs/heads/main:refs/remotes/origin/main" ||'
new = 'true ||'
if old not in text:
    raise SystemExit('live script is missing the origin/main fetch')
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit('fetch mutant still fetches origin/main')
Path(sys.argv[2]).write_text(mut)
PY
chmod +x "$tree/scripts/release-verify-tag-anchor.sh"
if ! "$tree/scripts/release-verify-tag-anchor.sh" v1.2.3 >/dev/null 2>"$scratch/mut-fetch.err"; then
	fail "dropping the origin/main fetch must accept a stale tracking ref (log: $(cat "$scratch/mut-fetch.err"))"
fi
cp "$script" "$tree/scripts/release-verify-tag-anchor.sh"
chmod +x "$tree/scripts/release-verify-tag-anchor.sh"
git -C "$tree" push -q origin "$commit:refs/heads/main" --force
git -C "$tree" fetch -q origin
pass 'reverting the origin/main fetch accepts a stale tracking ref'

echo '[ok] tag-anchor refuses remote mismatch, unverified GitHub, attacker commit, identity drift, lightweight tags, and stale origin/main'
