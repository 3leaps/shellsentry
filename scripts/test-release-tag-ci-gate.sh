#!/usr/bin/env bash
# Exercise the tag entry point with a failing CI gate. No real signing keys.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
unset GITHUB_ACTIONS RELEASE_TAG SHELLSENTRY_REQUIRE_TAG || true
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-tag-ci.XXXXXX")"
scratch="$(CDPATH='' cd -P -- "$scratch" && pwd -P)"
trap 'rm -rf "$scratch"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

repo="$scratch/repo"
remote="$scratch/remote.git"
mkdir -p "$repo/scripts" "$repo/config/release" "$repo/keys" "$scratch/bin" "$scratch/home" "$scratch/v1.2.3"
mkdir -m 700 "$scratch/gpg"
export HOME="$scratch/home" GIT_CONFIG_NOSYSTEM=1
REAL_GIT="$(command -v git)"
export REAL_GIT
export CI_GATE_LOG="$scratch/gate.log" SIGNING_LOG="$scratch/signing.log"
export SHELLSENTRY_RELEASE_TAG=v1.2.3
export SHELLSENTRY_TAGGER_NAME=Fixture SHELLSENTRY_TAGGER_EMAIL=fixture@example.invalid
export SHELLSENTRY_GPG_SIGNING_FINGERPRINT=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
export SHELLSENTRY_PGP_KEY_ID=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB!
export SHELLSENTRY_GPG_HOMEDIR="$scratch/gpg"
export SHELLSENTRY_TAG_MESSAGE_DIR="$scratch/v1.2.3"
printf 'shellsentry v1.2.3\n' >"$SHELLSENTRY_TAG_MESSAGE_DIR/message.txt"
printf 'Fixture <fixture@example.invalid>\n' >"$repo/config/release/tagger-identity.txt"
printf 'gpg %s\n' "$SHELLSENTRY_GPG_SIGNING_FINGERPRINT" >"$repo/keys/expected-fingerprints.txt"
printf '1.2.3\n' >"$repo/VERSION"
cp "$root/scripts/release-tag.sh" "$root/scripts/release-tag-common.sh" \
	"$root/scripts/release-ci-refuse.sh" "$root/scripts/release-guard-tag-version.sh" \
	"$root/scripts/release-prepare-tag-message.py" "$repo/scripts/"
cat >"$repo/scripts/release-require-native-ci.sh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$#" "$@" >>"${CI_GATE_LOG:?}"
echo 'fixture: native CI gate refused' >&2
exit 73
SH
# Only public listing is simulated. Any signing command is recorded and refused.
cat >"$scratch/bin/gpg" <<'SH'
#!/usr/bin/env bash
case " $* " in
    *' --list-keys '*)
        printf 'pub:::::::::::\nfpr:::::::::%s:\n' "$SHELLSENTRY_GPG_SIGNING_FINGERPRINT"
        printf 'sub:::::::::::s:\nfpr:::::::::%s:\n' "${SHELLSENTRY_PGP_KEY_ID%!}"
        ;;
    *) printf 'gpg\n' >>"${SIGNING_LOG:?}"; exit 91 ;;
esac
SH
cat >"$scratch/bin/git" <<'SH'
#!/usr/bin/env bash
args=("$@")
while [[ "${1:-}" == -c ]]; do shift 2; done
if [[ "${1:-}" == tag ]]; then
    printf 'git tag\n' >>"${SIGNING_LOG:?}"
    exit 91
fi
exec "${REAL_GIT:?}" "${args[@]}"
SH
chmod +x "$scratch/bin/"* "$repo/scripts/"*
export PATH="$scratch/bin:$PATH"
git init -q -b main "$repo"
git -C "$repo" config user.name Fixture
git -C "$repo" config user.email fixture@example.invalid
git -C "$repo" config commit.gpgsign false
git -C "$repo" add .
git -C "$repo" commit -qm fixture
git clone -q --bare "$repo" "$remote"
git -C "$repo" remote add origin https://github.com/3leaps/shellsentry.git
git -C "$repo" config "url.$remote.insteadOf" https://github.com/3leaps/shellsentry.git

run_tag() {
    rm -f "$CI_GATE_LOG" "$SIGNING_LOG"
    tag_rc=0
    (cd "$repo" && bash scripts/release-tag.sh) >"$scratch/tag.out" 2>&1 || tag_rc=$?
}
assert_gate_blocks_signing() {
    [[ ! -e "$SIGNING_LOG" ]] || { echo 'signing was attempted' >&2; return 1; }
    [[ "$tag_rc" == 73 ]] || { echo 'missing CI gate refusal status' >&2; return 1; }
    grep -q 'fixture: native CI gate refused' "$scratch/tag.out" || return 1
    printf '1\n%s\n' "$(git -C "$repo" rev-parse HEAD)" >"$scratch/expected-gate.log"
    cmp -s "$scratch/expected-gate.log" "$CI_GATE_LOG" || {
        echo 'CI gate did not receive exactly HEAD once' >&2
        return 1
    }
    [[ -z "$(git -C "$repo" tag --list)" ]] || return 1
}

run_tag
if ! assert_gate_blocks_signing; then
    cat "$scratch/tag.out" >&2
    fail 'release-tag.sh must stop at the failing CI gate before signing'
fi
pass 'release-tag.sh passes exact HEAD once and refuses signing after CI gate failure'

# Remove only the invocation; the same behavioral assertion must now fail.
python3 - "$repo/scripts/release-tag.sh" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
call = '"$tag_root/scripts/release-require-native-ci.sh" "$(git rev-parse HEAD)"\n'
if text.count(call) != 1:
    raise SystemExit('expected exactly one CI gate invocation')
path.write_text(text.replace(call, '', 1))
PY
git -C "$repo" add scripts/release-tag.sh
git -C "$repo" commit -qm 'mutant: remove CI gate invocation'
git -C "$remote" fetch -q "$repo" main:main
run_tag
if assert_gate_blocks_signing >"$scratch/assert.out" 2>&1; then
    fail 'CI gate invocation mutant escaped the regression assertion'
fi
[[ "$tag_rc" == 91 && -s "$SIGNING_LOG" && ! -e "$CI_GATE_LOG" ]] || {
    cat "$scratch/tag.out" >&2
    fail 'CI gate invocation mutant must reach the signing sentinel'
}
grep -q 'signing was attempted' "$scratch/assert.out" || fail 'mutant failed for the wrong reason'
pass 'removing the CI gate invocation fails the same assertion and reaches the signing sentinel'
