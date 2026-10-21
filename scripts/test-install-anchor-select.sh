#!/usr/bin/env bash
# Unit/coherence tests for install-shellsentry.sh pin-map anchor selection.
# Sources installer functions from a temp copy with the `main "$@"` entry call
# stripped (same bytes as shipped). Never executes the installer. No network.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

INSTALLER="${ROOT}/scripts/install-shellsentry.sh"
ANCHOR="${ROOT}/configs/keys/shellsentry-minisign.pub"

[ -f "$INSTALLER" ] || fail "installer missing"
[ -f "$ANCHOR" ] || fail "embedded anchor missing"

# Entry-call strip must match exactly one line; sourcing an unstripped copy
# would execute the installer.
[ "$(grep -c '^main "$@"$' "$INSTALLER")" -eq 1 ] || fail "installer entry line not exactly-once (refusing to source)"
SRC_COPY="$(mktemp "${TMPDIR:-/tmp}/shs-install-src.XXXXXX")"
trap 'rm -f "$SRC_COPY"' EXIT
grep -v '^main "$@"$' "$INSTALLER" >"$SRC_COPY"
grep -q '^main ' "$SRC_COPY" && fail "strip failed: main invocation remains"
# Ambient overrides must not leak into the coherence checks.
unset SHELLSENTRY_MINISIGN_PUBKEY SHELLSENTRY_PGP_FPR
# shellcheck source=scripts/install-shellsentry.sh
# shellcheck disable=SC1090
. "$SRC_COPY"

command -v is_exact_semver_tag >/dev/null || fail "is_exact_semver_tag not loaded"
command -v semver_le_tag >/dev/null || fail "semver_le_tag not loaded"
command -v select_trust_anchor >/dev/null || fail "select_trust_anchor not loaded"
command -v verify_signature >/dev/null || fail "verify_signature not loaded"

# --- shipped trust constants, pinned by value ---
# minisign key id = bytes 2..10 of the decoded key, little-endian.
minisign_key_id() {
    printf '%s' "$1" | base64 -d 2>/dev/null | od -An -tx1 -j2 -N8 |
        tr -d ' \n' | sed -E 's/(..)(..)(..)(..)(..)(..)(..)(..)/\8\7\6\5\4\3\2\1/' |
        tr '[:lower:]' '[:upper:]'
}
[ "$(minisign_key_id "$SHELLSENTRY_MINISIGN_PUBKEY")" = "6DC067B6CF9F51EA" ] || fail "current minisign key id"
[ "$(minisign_key_id "$SHELLSENTRY_MINISIGN_PUBKEY_LEGACY")" = "DE44B5D37442A1C0" ] || fail "legacy minisign key id"
[ "$SHELLSENTRY_PGP_FPR" = "0CACA49B3119B6BC12B2CA11B9B485F294B9FE07" ] || fail "current GPG fingerprint"
[ "$SHELLSENTRY_PGP_FPR_LEGACY" = "94BB7811D4AD49B2310E0C08FA0651DE91B828ED" ] || fail "legacy GPG fingerprint"
pass "shipped trust constants match pinned values"

# --- shipped selection: each tag selects exactly one generation ---
expect_selection() {
    local tag="$1" gen="$2" key="$3" fpr="$4"
    ACTIVE_MINISIGN_PUBKEY="" ACTIVE_PGP_FPR="" ANCHOR_GEN=""
    select_trust_anchor "$tag" 2>/dev/null
    [ "$ANCHOR_GEN" = "$gen" ] || fail "$tag: expected $gen, got ${ANCHOR_GEN:-<none>}"
    [ "$ACTIVE_MINISIGN_PUBKEY" = "$key" ] || fail "$tag: wrong minisign anchor for $gen"
    [ "$ACTIVE_PGP_FPR" = "$fpr" ] || fail "$tag: wrong GPG pin for $gen"
}
for tag in v0.0.1 v0.1.0 v0.1.4 v0.1.6; do
    expect_selection "$tag" legacy "$SHELLSENTRY_MINISIGN_PUBKEY_LEGACY" "$SHELLSENTRY_PGP_FPR_LEGACY"
done
for tag in v0.1.7 v0.1.10 v0.2.0 v1.0.0; do
    expect_selection "$tag" current "$SHELLSENTRY_MINISIGN_PUBKEY" "$SHELLSENTRY_PGP_FPR"
done
for tag in "" latest v0.1.07 v0.1.7-rc1 0.1.7; do
    if (select_trust_anchor "$tag") >/dev/null 2>&1; then fail "non-semver tag '$tag' must be refused"; fi
done
pass "select_trust_anchor picks one generation per tag; refuses non-semver"

# --- tag shape: strict vMAJOR.MINOR.PATCH, no leading zeros ---
is_exact_semver_tag "v0.1.6" || fail "accept v0.1.6"
is_exact_semver_tag "v0.0.0" || fail "accept v0.0.0"
is_exact_semver_tag "v10.20.30" || fail "accept multi-digit"
if is_exact_semver_tag ""; then fail "reject empty"; fi
if is_exact_semver_tag "latest"; then fail "reject latest"; fi
if is_exact_semver_tag "v0.1.06"; then fail "reject leading zero v0.1.06"; fi
if is_exact_semver_tag "v0.1"; then fail "reject short v0.1"; fi
if is_exact_semver_tag "v1.2.3.4"; then fail "reject long v1.2.3.4"; fi
if is_exact_semver_tag "1.2.3"; then fail "reject missing v"; fi
if is_exact_semver_tag "v1.2.x"; then fail "reject non-numeric"; fi
pass "installer tag shape strict"

# --- comparison boundaries against the v0.1.6 cutoff ---
semver_le_tag "v0.1.6" "v0.1.6" || fail "v0.1.6 <= cutoff"
semver_le_tag "v0.1.5" "v0.1.6" || fail "v0.1.5 <= cutoff"
semver_le_tag "v0.1.0" "v0.1.6" || fail "v0.1.0 <= cutoff"
semver_le_tag "v0.0.99" "v0.1.6" || fail "v0.0.99 <= cutoff"
if semver_le_tag "v0.1.7" "v0.1.6"; then fail "v0.1.7 above cutoff"; fi
if semver_le_tag "v0.1.10" "v0.1.6"; then fail "v0.1.10 above cutoff"; fi
if semver_le_tag "v0.2.0" "v0.1.6"; then fail "v0.2.0 above cutoff"; fi
if semver_le_tag "v1.0.0" "v0.1.6"; then fail "v1.0.0 above cutoff"; fi
# Huge components must not wrap into range (length-then-lexical, no arithmetic).
if semver_le_tag "v18446744073709551616.1.5" "v0.1.6"; then fail "huge major must not alias below cutoff"; fi
if semver_le_tag "v0.1.18446744073709551615" "v0.1.6"; then fail "huge patch must not alias below cutoff"; fi
if semver_le_tag "v0.18446744073709551616.0" "v0.1.6"; then fail "huge minor must not alias below cutoff"; fi
pass "installer pin-map comparison boundaries"

# --- constants coherence ---
[ "${SHELLSENTRY_PREVKEY_MAX:-}" = "v0.1.6" ] || fail "installer PREVKEY cutoff must be v0.1.6"
[ "${SHELLSENTRY_MINISIGN_PUBKEY_LEGACY:-}" != "${SHELLSENTRY_MINISIGN_PUBKEY:-}" ] || fail "legacy and current minisign anchors must differ"
[ "${SHELLSENTRY_PGP_FPR_LEGACY:-}" != "${SHELLSENTRY_PGP_FPR:-}" ] || fail "legacy and current GPG pins must differ"
[[ "${SHELLSENTRY_PGP_FPR_LEGACY:-}" =~ ^[0-9A-F]{40}$ ]] || fail "legacy GPG pin shape (got: ${SHELLSENTRY_PGP_FPR_LEGACY:-})"
[[ "${SHELLSENTRY_PGP_FPR:-}" =~ ^[0-9A-F]{40}$ ]] || fail "current GPG pin shape (got: ${SHELLSENTRY_PGP_FPR:-})"
pass "installer legacy constants coherent"

# Embedded anchor carries the current key only (legacy is pin-scoped, never default).
ANCHOR_RW="$(grep -E '^RW' "$ANCHOR" | head -n1 | tr -d '\r\n')"
[ -n "$ANCHOR_RW" ] || fail "anchor has no RW line"
[ "$ANCHOR_RW" = "${SHELLSENTRY_MINISIGN_PUBKEY:-}" ] || fail "installer current anchor must equal embedded anchor"
if grep -q "${SHELLSENTRY_MINISIGN_PUBKEY_LEGACY}" "$ANCHOR"; then fail "embedded anchor must not carry the legacy key"; fi
pass "embedded anchor stays single-current"

# --- shipped selection through shipped verification (hermetic, throwaway keys) ---
# Stand-in keys replace the anchors so real signatures can be produced locally;
# selection and verify_signature run unmodified.
if command -v minisign >/dev/null 2>&1; then
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/shs-anchor.XXXXXX")"
    trap 'rm -f "$SRC_COPY"; rm -rf "$WORK"' EXIT
    minisign -G -W -p "$WORK/cur.pub" -s "$WORK/cur.key" >/dev/null 2>&1 || fail "keygen current"
    minisign -G -W -p "$WORK/old.pub" -s "$WORK/old.key" >/dev/null 2>&1 || fail "keygen legacy"
    SHELLSENTRY_MINISIGN_PUBKEY="$(sed -n 2p "$WORK/cur.pub")"
    SHELLSENTRY_MINISIGN_PUBKEY_LEGACY="$(sed -n 2p "$WORK/old.pub")"
    printf 'abc  shellsentry_linux_amd64.tar.gz\n' >"$WORK/SHA256SUMS"
    VERIFY_MINISIGN=true VERIFY_GPG=false REQUIRE_MINISIGN=true REQUIRE_SIGNATURE=true

    # verify_as TAG SIGNER: 0 if the shipped path accepts SIGNER's signature for TAG.
    verify_as() {
        local tag="$1" signer="$2" d
        d="$(mktemp -d "$WORK/v.XXXXXX")"
        cp "$WORK/SHA256SUMS" "$d/SHA256SUMS"
        minisign -S -s "$WORK/${signer}.key" -m "$d/SHA256SUMS" -x "$d/SHA256SUMS.minisig" >/dev/null 2>&1 ||
            fail "sign as $signer"
        (
            select_trust_anchor "$tag"
            verify_signature "$d/SHA256SUMS" "$d"
        ) >/dev/null 2>&1
    }
    verify_as v0.1.6 old || fail "v0.1.6 must verify under the legacy key"
    verify_as v0.1.7 cur || fail "v0.1.7 must verify under the current key"
    if verify_as v0.1.6 cur; then fail "v0.1.6 must reject a current-key signature (no fallback)"; fi
    if verify_as v0.1.7 old; then fail "v0.1.7 must reject a legacy-key signature (no fallback)"; fi
    pass "selection through verify_signature: each generation accepts only its own key"

    # GPG route (minisign not required): the fingerprint pin follows the tag.
    if command -v gpg >/dev/null 2>&1; then
        GH="$WORK/gnupg"
        mkdir -m 700 "$GH"
        gpg_gen() {
            gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase '' \
                --quick-gen-key "$1" ed25519 sign never >/dev/null 2>&1 || fail "gpg keygen $1"
            gpg --homedir "$GH" --with-colons --fingerprint "$1" | awk -F: '/^fpr:/ {print $10; exit}'
        }
        FPR_CUR="$(gpg_gen 'cur@test.invalid')"
        FPR_OLD="$(gpg_gen 'old@test.invalid')"
        SHELLSENTRY_PGP_FPR="$FPR_CUR"
        SHELLSENTRY_PGP_FPR_LEGACY="$FPR_OLD"
        # gpg_verify_as TAG SIGNER [MINISIG_SIGNER]: GPG-signed sums; optional
        # minisig from MINISIG_SIGNER exercises the minisign-reject path first.
        gpg_verify_as() {
            local tag="$1" signer="$2" msigner="${3:-}" d
            d="$(mktemp -d "$WORK/g.XXXXXX")"
            cp "$WORK/SHA256SUMS" "$d/SHA256SUMS"
            gpg --homedir "$GH" --batch --armor --export "${signer}@test.invalid" \
                >"$d/shellsentry-release-signing-key.asc"
            gpg --homedir "$GH" --batch --yes --pinentry-mode loopback --passphrase '' \
                -u "${signer}@test.invalid" --armor --detach-sign -o "$d/SHA256SUMS.asc" "$d/SHA256SUMS" ||
                fail "gpg sign as $signer"
            if [ -n "$msigner" ]; then
                minisign -S -s "$WORK/${msigner}.key" -m "$d/SHA256SUMS" -x "$d/SHA256SUMS.minisig" >/dev/null 2>&1 ||
                    fail "minisign as $msigner"
            fi
            (
                VERIFY_GPG=true REQUIRE_MINISIGN=false
                select_trust_anchor "$tag"
                verify_signature "$d/SHA256SUMS" "$d"
            ) >/dev/null 2>&1
        }
        VERIFY_MINISIGN=false
        gpg_verify_as v0.1.6 old || fail "v0.1.6 must verify under the legacy GPG pin"
        gpg_verify_as v0.1.7 cur || fail "v0.1.7 must verify under the current GPG pin"
        if gpg_verify_as v0.1.6 cur; then fail "v0.1.6 must reject the current GPG key"; fi
        if gpg_verify_as v0.1.7 old; then fail "v0.1.7 must reject the legacy GPG key"; fi
        # A rejected minisign signature must not fall through to a valid GPG one.
        VERIFY_MINISIGN=true
        if gpg_verify_as v0.1.7 cur old; then fail "minisign reject must not fall back to gpg"; fi
        gpg_verify_as v0.1.7 cur cur || fail "v0.1.7 with valid minisign + gpg must verify"
        VERIFY_MINISIGN=true
        pass "gpg route: fingerprint pin follows the tag; minisign reject does not fall back"
    else
        [ "${CI:-}" != "true" ] || fail "gpg required in CI for the gpg half"
        echo "SKIP: gpg not installed; gpg half not run"
    fi
else
    [ "${CI:-}" != "true" ] || fail "minisign required in CI for the verification half"
    echo "SKIP: minisign not installed; verification half not run"
fi

echo "[ok] install anchor-select regression harness complete"
