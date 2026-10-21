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

echo "[ok] install anchor-select regression harness complete"
