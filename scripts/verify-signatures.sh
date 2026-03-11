#!/usr/bin/env bash
set -euo pipefail

# Verify release signatures (minisign and optional PGP) on checksum manifests.
#
# Usage: verify-signatures.sh [dir]
#
# Env:
#   SHELLSENTRY_MINISIGN_PUB - path to minisign public key (required for minisign)
#   SHELLSENTRY_GPG_HOMEDIR  - isolated gpg homedir for PGP verification (optional)

DIR=${1:-dist/release}

if [ ! -d "$DIR" ]; then
    echo "error: directory $DIR not found" >&2
    exit 1
fi

SHELLSENTRY_MINISIGN_PUB=${SHELLSENTRY_MINISIGN_PUB:-}
SHELLSENTRY_GPG_HOMEDIR=${SHELLSENTRY_GPG_HOMEDIR:-}

verified=0
failed=0

verify_minisign() {
    local manifest="$1"
    local base="${DIR}/${manifest}"
    local sig="${base}.minisig"

    if [ ! -f "${sig}" ]; then
        echo "[skip] No minisign signature for ${manifest}"
        return 0
    fi

    if [ -z "${SHELLSENTRY_MINISIGN_PUB}" ]; then
        echo "[warn] SHELLSENTRY_MINISIGN_PUB not set, cannot verify ${manifest}.minisig"
        failed=$((failed + 1))
        return 1
    fi

    if [ ! -f "${SHELLSENTRY_MINISIGN_PUB}" ]; then
        echo "error: SHELLSENTRY_MINISIGN_PUB=${SHELLSENTRY_MINISIGN_PUB} not found" >&2
        failed=$((failed + 1))
        return 1
    fi

    if ! command -v minisign >/dev/null 2>&1; then
        echo "error: minisign not found in PATH" >&2
        failed=$((failed + 1))
        return 1
    fi

    echo "[verify] minisign ${manifest}"
    if minisign -V -p "${SHELLSENTRY_MINISIGN_PUB}" -m "${base}"; then
        echo "[ok] ${manifest}.minisig verified"
        verified=$((verified + 1))
    else
        echo "[FAIL] ${manifest}.minisig verification FAILED"
        failed=$((failed + 1))
    fi
}

verify_pgp() {
    local manifest="$1"
    local base="${DIR}/${manifest}"
    local sig="${base}.asc"

    if [ ! -f "${sig}" ]; then
        echo "[skip] No PGP signature for ${manifest}"
        return 0
    fi

    if ! command -v gpg >/dev/null 2>&1; then
        echo "[warn] gpg not found, cannot verify ${manifest}.asc"
        failed=$((failed + 1))
        return 1
    fi

    local -a gpg_opts=()
    if [ -n "${SHELLSENTRY_GPG_HOMEDIR}" ] && [ -d "${SHELLSENTRY_GPG_HOMEDIR}" ]; then
        gpg_opts=("--homedir" "${SHELLSENTRY_GPG_HOMEDIR}")
    fi

    echo "[verify] PGP ${manifest}"
    if gpg "${gpg_opts[@]}" --verify "${sig}" "${base}" 2>&1; then
        echo "[ok] ${manifest}.asc verified"
        verified=$((verified + 1))
    else
        echo "[FAIL] ${manifest}.asc verification FAILED"
        failed=$((failed + 1))
    fi
}

echo "Verifying release signatures in ${DIR}..."
echo ""

verify_minisign "SHA256SUMS"
verify_minisign "SHA512SUMS"

echo ""

verify_pgp "SHA256SUMS"
verify_pgp "SHA512SUMS"

echo ""
echo "================================================================"
if [ $failed -gt 0 ]; then
    echo "[FAIL] Signature verification: ${verified} passed, ${failed} FAILED"
    exit 1
elif [ $verified -eq 0 ]; then
    echo "[warn] No signatures found to verify"
    exit 1
else
    echo "[ok] Signature verification: ${verified} passed"
fi
