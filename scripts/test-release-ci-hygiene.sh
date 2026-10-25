#!/usr/bin/env bash
# Maintainer signing/publish scripts must not be invoked from GitHub Actions,
# and workflows must not carry signing-key secrets.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

WF_DIR=".github/workflows"
[[ -d "$WF_DIR" ]] || fail "workflows directory missing"

# Do not use \b after release-tag: it matches make release-tag-tests (the
# hyphen is a word boundary). Require a non-name character or end of string.
CEREMONY_MAKE='make[[:space:]]+(release-tag|release-push-tag|release-publish|release-sign|release-upload)([^[:alnum:]_-]|$)'

printf 'make release-tag\n' | grep -Eq "$CEREMONY_MAKE" ||
    fail "ceremony regex must match make release-tag"
printf 'make release-tag-tests\n' | grep -Eq "$CEREMONY_MAKE" &&
    fail "ceremony regex must not match make release-tag-tests"
pass "ceremony regex allows make release-tag-tests and still matches make release-tag"

if grep -nE "$CEREMONY_MAKE" "$WF_DIR"/*; then
    fail "workflows must not invoke maintainer signing or publish targets"
fi
if grep -nE 'scripts/(release-tag|release-push-tag|release-publish|sign-release-assets|upload-release-assets)\.sh' "$WF_DIR"/*; then
    fail "workflows must not invoke maintainer signing or publish scripts"
fi
pass "workflows do not invoke release-tag/publish/sign/upload"

if grep -nE 'SHELLSENTRY_(MINISIGN_KEY|PGP_KEY_ID|GPG_HOMEDIR)\s*:' "$WF_DIR"/*; then
    fail "workflows must not set signing-key environment"
fi
if grep -nE 'secrets\.(MINISIGN|GPG|PGP|SIGNING)' "$WF_DIR"/*; then
    fail "workflows must not reference signing secrets"
fi
pass "workflows do not pass signing credentials"

# Mutant: splicing a publish step into CI must fail this check.
if ! grep -q 'make prepush' "$WF_DIR/ci.yml"; then
    fail "ci.yml must still run make prepush (sanity)"
fi
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-ci-hygiene.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
cp "$WF_DIR/ci.yml" "$scratch/ci.yml"
printf '\n      - run: make release-publish\n' >>"$scratch/ci.yml"
if grep -nE "$CEREMONY_MAKE" "$scratch/ci.yml" >/dev/null; then
    pass "hygiene grep catches make release-publish spliced into ci.yml"
else
    fail "hygiene grep missed a spliced make release-publish"
fi
cp "$WF_DIR/ci.yml" "$scratch/ci-script.yml"
printf '\n      - run: ./scripts/release-tag.sh\n' >>"$scratch/ci-script.yml"
if grep -nE 'scripts/(release-tag|release-publish|sign-release-assets|upload-release-assets)\.sh' "$scratch/ci-script.yml" >/dev/null; then
    pass "hygiene grep catches scripts/release-tag.sh spliced into ci.yml"
else
    fail "hygiene grep missed a spliced release-tag.sh"
fi
