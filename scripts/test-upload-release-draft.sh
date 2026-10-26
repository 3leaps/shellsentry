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
grep -q 'gh release upload "$TAG" "$NOTES_FILE" --clobber' "$UPLOAD" ||
    fail "upload-release-assets.sh must upload release-notes-<tag>.md as a draft asset"
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
[[ -f "$WORK/assets/release-notes-v0.0.0.md" ]] ||
    fail "upload must put release-notes-<tag>.md on the draft"
pass "upload attaches the notes file as a draft asset"

python3 - "$ROOT/RELEASE_CHECKLIST.md" <<'PY' || fail "RELEASE_CHECKLIST ceremony order does not match"
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
PY
pass "RELEASE_CHECKLIST ceremony order is create-draft, notes, upload, publish"

python3 - "$UPLOAD" "$mut" <<'PY' || fail "notes-asset mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = '''echo "[upload] Release notes asset"
gh release upload "$TAG" "$NOTES_FILE" --clobber
'''
if old not in text:
    raise SystemExit("live upload is missing the notes-asset upload")
mut = text.replace(old, "", 1)
if "gh release upload \"$TAG\" \"$NOTES_FILE\" --clobber" in mut:
    raise SystemExit("notes-asset mutant still uploads NOTES_FILE")
dest.write_text(mut)
PY
mkdir -p "$WORK/mut-root/scripts"
cp "$mut" "$WORK/mut-root/scripts/upload-release-assets.sh"
cp "$ROOT/scripts/release-ci-refuse.sh" "$WORK/mut-root/scripts/"
chmod +x "$WORK/mut-root/scripts/upload-release-assets.sh"
rm -rf "$WORK/assets"
mkdir -p "$WORK/assets"
: >"$GH_TRACE"
FIXTURE_DRAFT=true FIXTURE_ASSET_DIR="$WORK/assets" \
    "$WORK/mut-root/scripts/upload-release-assets.sh" v0.0.0 "$WORK/dist" >/dev/null
if [[ -f "$WORK/assets/release-notes-v0.0.0.md" ]]; then
    fail "accepted upload after dropping the notes-asset upload"
fi
pass "notes-asset upload mutant is distinguished"

echo "[ok] release-upload stays draft"
