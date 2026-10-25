#!/usr/bin/env bash
# Smartcard / non-exportable key custody: sign in the operator GPG home.
# Throwaway software keys only; never the default homedir or this checkout.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$ROOT"
unset GITHUB_ACTIONS || true

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

TAG_SH="$ROOT/scripts/release-tag.sh"
[ -f "$TAG_SH" ] || fail "release-tag.sh missing"

if grep -nE -- '--export-secret-(keys|subkeys)' "$TAG_SH"; then
    fail "release-tag.sh must not export secret keys"
fi
grep -Fq 'export GNUPGHOME="$SHELLSENTRY_GPG_HOMEDIR"' "$TAG_SH" ||
    fail 'release-tag.sh must bind GNUPGHOME to the operator home'
if grep -nE 'gpgconf[[:space:]]+--homedir[[:space:]]+"\$SHELLSENTRY_GPG_HOMEDIR"' "$TAG_SH"; then
    fail "release-tag.sh must not gpgconf --kill the operator homedir"
fi
if grep -nE 'gpgconf[[:space:]]+([^ ]|[[:space:]])*--kill' "$TAG_SH"; then
    fail "release-tag.sh must not gpgconf --kill (including via GNUPGHOME)"
fi
if grep -nE 'mktemp .*tag-sign|sign_home=' "$TAG_SH"; then
    fail "release-tag.sh must not copy secrets into a throwaway signing home"
fi
pass "release-tag.sh does not export secrets or kill the operator home"

# Mutant: restoring the export-into-temp path must be caught.
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-tag-card.XXXXXX")"
cleanup() {
    gpgconf --homedir "$scratch/op" --kill all >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup EXIT
{
    printf '%s\n' 'sign_home="$(mktemp "${TMPDIR:-/tmp}/shs-tag-sign.XXXXXX")"'
    printf '%s\n' 'gpg --homedir "$SHELLSENTRY_GPG_HOMEDIR" --batch --export-secret-keys "${SHELLSENTRY_PGP_KEY_ID%!}" |'
    printf '%s\n' '    gpg --homedir "$sign_home" --batch --import'
    printf '%s\n' 'export GNUPGHOME="$sign_home"'
    printf '%s\n' 'gpgconf --homedir "$SHELLSENTRY_GPG_HOMEDIR" --kill all'
} >"$scratch/old-path.sh"
if grep -nE -- '--export-secret-(keys|subkeys)' "$scratch/old-path.sh" >/dev/null &&
    ! grep -nE -- '--export-secret-(keys|subkeys)' "$TAG_SH" >/dev/null; then
    pass "grep rejects an export-secret-keys mutant"
else
    fail "export-secret-keys mutant was not distinguished from the live script"
fi
if grep -nE 'gpgconf[[:space:]]+--homedir[[:space:]]+"\$SHELLSENTRY_GPG_HOMEDIR"' "$scratch/old-path.sh" >/dev/null &&
    ! grep -nE 'gpgconf[[:space:]]+--homedir[[:space:]]+"\$SHELLSENTRY_GPG_HOMEDIR"' "$TAG_SH" >/dev/null; then
    pass "grep rejects an operator-home gpgconf --kill mutant"
else
    fail "operator gpgconf --kill mutant was not distinguished from the live script"
fi
printf '%s\n' 'export GNUPGHOME="$SHELLSENTRY_GPG_HOMEDIR"' 'gpgconf --kill all' >"$scratch/bare-kill.sh"
if grep -nE 'gpgconf[[:space:]]+([^ ]|[[:space:]])*--kill' "$scratch/bare-kill.sh" >/dev/null &&
    ! grep -nE 'gpgconf[[:space:]]+([^ ]|[[:space:]])*--kill' "$TAG_SH" >/dev/null; then
    pass "grep rejects a bare gpgconf --kill mutant"
else
    fail "bare gpgconf --kill mutant was not distinguished from the live script"
fi

command -v gpg >/dev/null 2>&1 || fail "gpg required"
command -v gpgconf >/dev/null 2>&1 || fail "gpgconf required"

op="$scratch/op"
mkdir -m 700 "$op"
gpg --homedir "$op" --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
    'Synthetic signing <signing@example.invalid>' ed25519 cert 0 >/dev/null 2>&1
primary="$(gpg --homedir "$op" --batch --with-colons --fingerprint --list-keys | awk -F: '$1=="fpr" {print $10;exit}')"
gpg --homedir "$op" --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$primary" ed25519 sign 1d >/dev/null 2>&1
subkey="$(gpg --homedir "$op" --batch --with-colons --with-subkey-fingerprint --list-keys "$primary" |
    awk -F: '$1=="sub" {s=1;next} s && $1=="fpr" {print $10;exit}')"
[[ "$primary" =~ ^[0-9A-F]{40}$ && "$subkey" =~ ^[0-9A-F]{40}$ ]] || fail "fixture key fingerprints missing"
printf 'operator-owned\n' >"$op/preserve"

real_gpg="$(command -v gpg)"
real_gpgconf="$(command -v gpgconf)"
mkdir -p "$scratch/bin"
cat >"$scratch/bin/gpg" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "${GNUPGHOME:-}" >>"${GNUPGHOME_LOG:?}"
for arg in "$@"; do
    case "$arg" in
    --export-secret-keys | --export-secret-subkeys)
        printf 'attempted\n' >>"${NO_EXPORT_MARKER:?}"
        echo 'fixture: secret key is not exportable' >&2
        exit 90
        ;;
    esac
done
exec "${REAL_GPG:?}" "$@"
SH
cat >"$scratch/bin/gpgconf" <<'SH'
#!/usr/bin/env bash
homedir=""
kill=0
prev=""
for arg in "$@"; do
    if [[ "$prev" == --homedir ]]; then
        homedir="$arg"
    fi
    case "$arg" in
    --kill) kill=1 ;;
    esac
    prev="$arg"
done
# Bare `gpgconf --kill` uses GNUPGHOME when --homedir is omitted.
effective="${homedir:-${GNUPGHOME:-}}"
if [[ "$kill" == 1 && -n "$effective" && "$effective" == "${OPERATOR_HOME:?}" ]]; then
    printf 'attempted\n' >>"${OPERATOR_AGENT_MARKER:?}"
    echo 'fixture: operator agent must stay running' >&2
    exit 91
fi
exec "${REAL_GPGCONF:?}" "$@"
SH
cat >"$scratch/bin/gpgconf.homedir-only" <<'SH'
#!/usr/bin/env bash
homedir=""
kill=0
prev=""
for arg in "$@"; do
    if [[ "$prev" == --homedir ]]; then
        homedir="$arg"
    fi
    case "$arg" in
    --kill) kill=1 ;;
    esac
    prev="$arg"
done
if [[ "$kill" == 1 && -n "$homedir" && "$homedir" == "${OPERATOR_HOME:?}" ]]; then
    printf 'attempted\n' >>"${OPERATOR_AGENT_MARKER:?}"
    echo 'fixture: operator agent must stay running' >&2
    exit 91
fi
exit 0
SH
chmod +x "$scratch/bin/gpg" "$scratch/bin/gpgconf" "$scratch/bin/gpgconf.homedir-only"

fixture="$scratch/repo"
remote="$scratch/remote.git"
git init -q -b main "$fixture"
git init -q --bare "$remote"
git -C "$fixture" config gpg.format openpgp
git -C "$fixture" config gpg.program gpg
git -C "$fixture" config commit.gpgsign false
git -C "$fixture" config user.name '3 Leaps Infosec Team'
git -C "$fixture" config user.email 'infosec@3leaps.net'
mkdir -p "$fixture/docs/security" "$fixture/keys" "$fixture/scripts" "$fixture/config/release"
cp "$ROOT/scripts/release-tag.sh" "$ROOT/scripts/verify-pinned-tag.sh" \
	"$ROOT/scripts/release-ci-refuse.sh" "$ROOT/scripts/release-tag-common.sh" \
	"$ROOT/scripts/release-guard-tag-version.sh" "$ROOT/scripts/release-tag-body.sh" \
	"$ROOT/scripts/release-prepare-tag-message.py" "$fixture/scripts/"
chmod +x "$fixture/scripts/"*
printf '3 Leaps Infosec Team <infosec@3leaps.net>\n' >"$fixture/config/release/tagger-identity.txt"
gpg --homedir "$op" --batch --armor --export "$primary" >"$fixture/docs/security/release-signing-keys.asc"
printf 'gpg %s\nminisign %s\n' "$primary" "$(printf 'a%.0s' {1..64})" >"$fixture/keys/expected-fingerprints.txt"
echo '0.0.0' >"$fixture/VERSION"
printf 'fixture\n' >"$fixture/file"
git -C "$fixture" add VERSION file docs/security keys scripts config
git -C "$fixture" -c commit.gpgsign=false commit -qm fixture
git -C "$fixture" remote add origin https://github.com/3leaps/shellsentry.git
git -C "$fixture" config "url.$remote.insteadOf" https://github.com/3leaps/shellsentry.git
git -C "$fixture" push -q origin main
git -C "$fixture" update-ref refs/remotes/origin/main "$(git -C "$fixture" rev-parse HEAD)"
msgdir="$scratch/v0.0.0"
mkdir -p "$msgdir"
printf 'shellsentry v0.0.0\n' >"$msgdir/message.txt"

export PATH="$scratch/bin:$PATH"
export REAL_GPG="$real_gpg" REAL_GPGCONF="$real_gpgconf"
export NO_EXPORT_MARKER="$scratch/secret-export-attempt"
export OPERATOR_HOME="$op" OPERATOR_AGENT_MARKER="$scratch/operator-agent-kill-attempt"
export GNUPGHOME_LOG="$scratch/gnupghome.log"
: >"$GNUPGHOME_LOG"
rm -f "$NO_EXPORT_MARKER" "$OPERATOR_AGENT_MARKER"

# Prove the stub refuses export before exercising production.
if gpg --homedir "$op" --export-secret-keys "$subkey" >/dev/null 2>&1; then
    fail "gpg stub must refuse --export-secret-keys"
fi
[[ -s "$NO_EXPORT_MARKER" ]] || fail "export stub did not record the attempt"
rm -f "$NO_EXPORT_MARKER"
: >"$GNUPGHOME_LOG"

# Prove the stub refuses a bare kill while GNUPGHOME is the operator home.
if GNUPGHOME="$op" gpgconf --kill all >/dev/null 2>&1; then
    fail "gpgconf stub must refuse --kill when GNUPGHOME is the operator home"
fi
[[ -s "$OPERATOR_AGENT_MARKER" ]] || fail "bare gpgconf --kill did not record the attempt"
rm -f "$OPERATOR_AGENT_MARKER"
if GNUPGHOME="$op" "$scratch/bin/gpgconf.homedir-only" --kill all >/dev/null 2>&1; then
    pass "homedir-only gpgconf mutant misses a GNUPGHOME kill"
else
    fail "homedir-only gpgconf mutant must not catch a bare --kill"
fi
[[ ! -e "$OPERATOR_AGENT_MARKER" ]] || fail "homedir-only mutant recorded a kill it should miss"

fake_home="$scratch/home"
mkdir -p "$fake_home/.gnupg"
chmod 700 "$fake_home/.gnupg"
export HOME="$fake_home"
export SHELLSENTRY_RELEASE_TAG=v0.0.0
export SHELLSENTRY_PGP_KEY_ID="${subkey}!"
export SHELLSENTRY_GPG_SIGNING_FINGERPRINT="$primary"
export SHELLSENTRY_GPG_HOMEDIR="$op"
export SHELLSENTRY_TAGGER_NAME='3 Leaps Infosec Team'
export SHELLSENTRY_TAGGER_EMAIL='infosec@3leaps.net'
export SHELLSENTRY_TAG_MESSAGE_DIR="$msgdir"

if ! (cd "$fixture" && ./scripts/release-tag.sh) >"$scratch/tag.out" 2>&1; then
    cat "$scratch/tag.out" >&2
    fail "release-tag.sh must sign in the operator home without exporting secrets"
fi
grep -q 'signed tag is local only' "$scratch/tag.out" || fail "release-tag.sh did not report local-only success"
[[ ! -e "$NO_EXPORT_MARKER" ]] || fail "release-tag.sh attempted --export-secret-keys"
[[ ! -e "$OPERATOR_AGENT_MARKER" ]] || fail "cleanup ran gpgconf --kill on the operator homedir"
[[ "$(cat "$op/preserve")" == operator-owned ]] || fail "operator home was modified or replaced"
if grep -qx "$op" "$GNUPGHOME_LOG"; then
    pass "GNUPGHOME during signing is the operator home"
else
    echo "GNUPGHOME log:" >&2
    cat "$GNUPGHOME_LOG" >&2
    fail "GNUPGHOME was not the operator home during signing"
fi
if grep -E '/shs-tag-sign\.|/tmp/[^/]*tag-sign' "$GNUPGHOME_LOG"; then
    fail "GNUPGHOME was a throwaway signing home"
fi
[[ "$(git -C "$fixture" cat-file -t "refs/tags/v0.0.0")" == tag ]] || fail "signed annotated tag missing"
pass "fixture signs without exporting secrets or killing the operator agent"

# Mutant: insert a bare gpgconf --kill after the GNUPGHOME bind.
git -C "$fixture" tag -d v0.0.0 >/dev/null
awk '
    { print }
    /export GNUPGHOME=/ { print "gpgconf --kill all" }
' "$TAG_SH" >"$fixture/scripts/release-tag.sh"
chmod +x "$fixture/scripts/release-tag.sh"
grep -q 'gpgconf --kill all' "$fixture/scripts/release-tag.sh" ||
    fail "bare-kill mutant was not constructed"
git -C "$fixture" add scripts/release-tag.sh
git -C "$fixture" -c commit.gpgsign=false commit -qm 'mutant: bare gpgconf --kill'
git -C "$fixture" push -q origin HEAD:main
rm -f "$OPERATOR_AGENT_MARKER" "$NO_EXPORT_MARKER"
: >"$GNUPGHOME_LOG"
set +e
(cd "$fixture" && ./scripts/release-tag.sh) >"$scratch/mut-kill.out" 2>&1
mut_rc=$?
set -e
if [ "$mut_rc" -eq 0 ]; then
    cat "$scratch/mut-kill.out" >&2
    fail "bare gpgconf --kill mutant must not succeed"
fi
[[ -s "$OPERATOR_AGENT_MARKER" ]] || {
    cat "$scratch/mut-kill.out" >&2
    fail "bare gpgconf --kill mutant was not caught while GNUPGHOME was the operator home"
}
pass "bare gpgconf --kill while GNUPGHOME is the operator home is refused"

echo "[ok] smartcard tag signing controls"
