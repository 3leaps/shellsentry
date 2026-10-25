#!/usr/bin/env bash
# release-upload must keep the GitHub release a draft. Promotion is
# release-publish after byte verification.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
unset GITHUB_ACTIONS || true

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

UPLOAD="${ROOT}/scripts/upload-release-assets.sh"
[ -f "$UPLOAD" ] || fail "upload-release-assets.sh missing"
grep -q 'release-ci-refuse.sh' "$UPLOAD" || fail "upload-release-assets.sh must refuse GitHub Actions"
if grep -nE -- '--draft=false|draft=false' "$UPLOAD"; then
    fail "upload-release-assets.sh must not publish (no --draft=false)"
fi
grep -q 'isDraft' "$UPLOAD" || fail "upload-release-assets.sh must assert the release stays a draft"
grep -q 'draft=true' "$UPLOAD" || fail "upload-release-assets.sh must pass --draft=true on edit"
pass "upload script never publishes"

# Mutant: restoring --draft=false must be caught.
mut="$(mktemp "${TMPDIR:-/tmp}/shs-upload-mut.XXXXXX")"
trap 'rm -f "$mut"' EXIT
sed 's/--draft=true/--draft=false/' "$UPLOAD" >"$mut"
if grep -nE -- '--draft=false|draft=false' "$mut" >/dev/null &&
    ! grep -nE -- '--draft=false|draft=false' "$UPLOAD" >/dev/null; then
    pass "grep catches a --draft=false mutant"
else
    fail "mutant assertion for --draft=false did not hold"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/shs-upload-draft.XXXXXX")"
trap 'rm -rf "$WORK" "$mut"' EXIT
mkdir -p "$WORK/bin" "$WORK/dist"
cat >"$WORK/bin/gh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${GH_TRACE}"
case "$*" in
  *'release view'*'isDraft'*)
    printf '%s\n' "${FIXTURE_DRAFT:-false}"
    ;;
  *'release view'*)
    printf '{"isDraft":false,"tagName":"v0.0.0"}\n'
    ;;
  'release upload '*)
    shift 3
    for asset in "$@"; do
      [[ "$asset" == --* ]] || cp "$asset" "${FIXTURE_ASSET_DIR:?}/"
    done
    ;;
  *)
    exit 0
    ;;
esac
SH
chmod +x "$WORK/bin/gh"
printf 'notes\n' >"$WORK/dist/release-notes-v0.0.0.md"
printf 'bin\n' >"$WORK/dist/shellsentry_linux_amd64.tar.gz"
: >"$WORK/dist/SHA256SUMS"
: >"$WORK/dist/SHA512SUMS"
: >"$WORK/dist/install-shellsentry.sh"
export GH_TRACE="$WORK/trace"
export PATH="$WORK/bin:$PATH"
: >"$GH_TRACE"
if "$UPLOAD" v0.0.0 "$WORK/dist" >/dev/null 2>&1; then
    fail "upload must refuse when the release is not a draft"
fi
grep -q 'release view' "$GH_TRACE" || fail "upload must read isDraft before mutating"
if grep -q 'release upload' "$GH_TRACE"; then
    fail "upload must not mutate assets before the draft check"
fi
if grep -q 'release edit' "$GH_TRACE"; then
    fail "upload must not edit the release before the draft check"
fi
pass "upload refuses a non-draft release without mutating it"

mkdir -p "$WORK/assets"
: >"$GH_TRACE"
FIXTURE_DRAFT=true FIXTURE_ASSET_DIR="$WORK/assets" "$UPLOAD" v0.0.0 "$WORK/dist" >/dev/null
grep -q -- '--draft=true' "$GH_TRACE" || fail "notes edit must preserve draft state"
if grep -q -- '--draft=false' "$GH_TRACE"; then
    fail "upload must not pass --draft=false"
fi
pass "normal upload preserves draft state"

echo "[ok] release-upload stays draft"
