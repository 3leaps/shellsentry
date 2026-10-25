#!/usr/bin/env bash
# Ceremony targets take SHELLSENTRY_RELEASE_TAG only; bare RELEASE_TAG is refused.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-make-tag.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

if grep -nE '^[[:space:]]*RELEASE_TAG[[:space:]]*(\?=|:=|\+=|=)' Makefile; then
    fail "Makefile must not assign RELEASE_TAG"
fi
if grep -nE 'RELEASE_TAG' Makefile | grep -vE 'SHELLSENTRY_RELEASE_TAG|not accepted|RELEASE_TAG is not'; then
    fail "Makefile mentions RELEASE_TAG outside a refusal"
fi
grep -q 'SHELLSENTRY_RELEASE_TAG' Makefile || fail "Makefile must consume SHELLSENTRY_RELEASE_TAG"
grep -q 'require-release-tag' Makefile || fail "Makefile must define require-release-tag"
pass "Makefile does not assign RELEASE_TAG"

for target in release-tag release-verify-tag release-publish release-download release-notes release-sign release-upload; do
    grep -E "^${target}: require-release-tag" Makefile >/dev/null ||
        fail "$target must depend on require-release-tag first"
done
grep -E '^release-tag: require-release-tag' -A2 Makefile | grep -q 'release-tag.sh' ||
    fail "release-tag must invoke scripts/release-tag.sh"
grep -E '^release-verify-tag: require-release-tag' -A2 Makefile | grep -q 'verify-pinned-tag.sh' ||
    fail "release-verify-tag must invoke scripts/verify-pinned-tag.sh"
grep -E '^release-publish: require-release-tag' -A2 Makefile | grep -q 'release-publish.sh' ||
    fail "release-publish must invoke scripts/release-publish.sh"
pass "ceremony targets depend on require-release-tag"

# Mutant: dropping the tag guard from release-tag must fail this check.
python3 - "$ROOT/Makefile" <<'PY' || fail "require-release-tag mutant was not distinguished"
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r'^release-tag:.*', text, re.M)
if not m or 'require-release-tag' not in m.group(0):
    raise SystemExit('live release-tag missing require-release-tag')
mut = re.sub(r'^release-tag: require-release-tag', 'release-tag:', text, count=1, flags=re.M)
if re.search(r'^release-tag: require-release-tag', mut, re.M):
    raise SystemExit('mutant still has require-release-tag')
PY
pass "grep rejects a release-tag without require-release-tag"

unset RELEASE_TAG || true
if env -u SHELLSENTRY_RELEASE_TAG -u RELEASE_TAG make -s release-notes >"$scratch/missing.out" 2>&1; then
    fail "make release-notes without SHELLSENTRY_RELEASE_TAG must be refused"
fi
grep -q 'SHELLSENTRY_RELEASE_TAG required' "$scratch/missing.out" ||
    fail "missing-tag refusal (log: $(cat "$scratch/missing.out"))"
pass "missing SHELLSENTRY_RELEASE_TAG is refused"

file_version="$(tr -d ' \n' <VERSION)"
if make -s release-notes SHELLSENTRY_RELEASE_TAG=v0.0.0 >"$scratch/ver.out" 2>&1; then
    fail "make release-notes with a tag that is not v$(VERSION) must be refused"
fi
grep -q "must equal v${file_version}" "$scratch/ver.out" ||
    fail "VERSION mismatch refusal (log: $(cat "$scratch/ver.out"))"
pass "SHELLSENTRY_RELEASE_TAG must equal v\$(VERSION)"

if make -s release-notes RELEASE_TAG=v0.0.0 "SHELLSENTRY_RELEASE_TAG=v${file_version}" >"$scratch/rt.out" 2>&1; then
    fail "make release-notes RELEASE_TAG=... must be refused"
fi
grep -qi 'RELEASE_TAG is not accepted' "$scratch/rt.out" ||
    fail "refusal must name RELEASE_TAG (log: $(cat "$scratch/rt.out"))"
pass "command-line RELEASE_TAG is refused"

if make -s release-tag >"$scratch/tag-missing.out" 2>&1; then
    fail "make release-tag without SHELLSENTRY_RELEASE_TAG must be refused"
fi
grep -q 'SHELLSENTRY_RELEASE_TAG required' "$scratch/tag-missing.out" ||
    fail "release-tag missing-tag refusal (log: $(cat "$scratch/tag-missing.out"))"
pass "make release-tag does not tag without SHELLSENTRY_RELEASE_TAG"

echo "[ok] Makefile SHELLSENTRY_RELEASE_TAG-only"
