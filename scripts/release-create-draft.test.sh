#!/usr/bin/env bash
# Maintainer-only draft creation: refuse CI, refuse an existing release, stay a draft.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-create-draft.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}
pass() { echo "PASS: $*"; }

script="$root/scripts/release-create-draft.sh"
grep -E '^release-tag-tests:' -A40 "$root/Makefile" | grep -q 'test-release-create-draft' ||
	fail "release-tag-tests must run test-release-create-draft"
grep -q 'release-ci-refuse.sh' "$script" || fail "release-create-draft.sh must refuse GitHub Actions"
grep -q -- '--draft' "$script" || fail "release-create-draft.sh must pass --draft"
if grep -nE -- '--draft=false|draft=false' "$script"; then
	fail "release-create-draft.sh must not publish"
fi
grep -q -- '--verify-tag' "$script" || fail "release-create-draft.sh must pass --verify-tag"
pass "create-draft script stays a verified draft"

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

mkdir -p "$scratch/bin" "$scratch/dist" "$scratch/repo/docs/releases" "$scratch/repo/scripts"
cp "$script" "$root/scripts/release-ci-refuse.sh" "$scratch/repo/scripts/"
chmod +x "$scratch/repo/scripts/"*.sh
printf 'notes\n' >"$scratch/repo/docs/releases/v1.2.3.md"
for name in \
	shellsentry_linux_amd64.tar.gz \
	shellsentry_linux_arm64.tar.gz \
	shellsentry_windows_amd64.zip \
	shellsentry_windows_arm64.zip \
	shellsentry_darwin_arm64.tar.gz \
	install-shellsentry.sh \
	SHA256SUMS \
	SHA512SUMS
do
	printf 'x\n' >"$scratch/dist/$name"
done
export GH_TRACE="$scratch/trace"
: >"$GH_TRACE"
cat >"$scratch/bin/gh" <<'SH'
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
chmod +x "$scratch/bin/gh"
export PATH="$scratch/bin:$PATH"
unset GITHUB_ACTIONS || true

if env GITHUB_ACTIONS=true "$scratch/repo/scripts/release-create-draft.sh" v1.2.3 "$scratch/dist" >/dev/null 2>&1; then
	fail "create-draft must refuse GitHub Actions"
fi
pass "create-draft refuses GitHub Actions"

if "$scratch/repo/scripts/release-create-draft.sh" v1.2.3 "$scratch/dist" >/dev/null 2>&1; then
	:
else
	fail "create-draft must succeed for a missing draft with staged packages"
fi
grep -q -- '--draft' "$GH_TRACE.create" || fail "gh release create must pass --draft"
grep -q -- '--verify-tag' "$GH_TRACE.create" || fail "gh release create must pass --verify-tag"
if grep -nE -- '--draft=false|draft=false' "$GH_TRACE.create"; then
	fail "gh release create must not pass --draft=false"
fi
pass "create-draft opens a verified draft"

: >"$GH_TRACE"
export FIXTURE_VIEW_RC=0
if "$scratch/repo/scripts/release-create-draft.sh" v1.2.3 "$scratch/dist" >/dev/null 2>&1; then
	fail "create-draft must refuse an existing release"
fi
if grep -q 'release create' "$GH_TRACE"; then
	fail "create-draft must not call create when a release already exists"
fi
pass "create-draft refuses an existing release"

echo '[ok] release-create-draft controls'
