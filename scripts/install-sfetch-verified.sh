#!/usr/bin/env bash
# install-sfetch-verified.sh — Makefile/local entrypoint for verified sfetch install.
#
# Retrieves the shared sfetch bootstrap engine at an immutable git SHA, verifies a
# pinned SHA-256 of that script, then runs it (dual-route minisig/SHA256SUMS).
# Does not pipe install-sfetch.sh to bash. Does not resolve engines from the
# consumer workspace as an action substitute (that path is GITHUB_ACTION only).
#
# Pins live in the Makefile (SFETCH_VERSION, SFETCH_ENGINE_SHA, SFETCH_ENGINE_SHA256)
# and are passed as env or flags so one place owns the reviewable constants.
#
set -euo pipefail

SFETCH_VERSION="${SFETCH_VERSION:-}"
SFETCH_ENGINE_SHA="${SFETCH_ENGINE_SHA:-}"
SFETCH_ENGINE_SHA256="${SFETCH_ENGINE_SHA256:-}"
INSTALL_DIR="${INSTALL_DIR:-}"
GONEAT_VERSION="${GONEAT_VERSION:-}"
REPO_SLUG="${SFETCH_ENGINE_REPO:-3leaps/sfetch}"

usage() {
    cat <<'EOF' >&2
Usage: install-sfetch-verified.sh --version vX.Y.Z --dir PATH \
  --engine-sha <git-sha> --engine-sha256 <hex> [--goneat-version vX.Y.Z]

Env equivalents: SFETCH_VERSION, INSTALL_DIR, SFETCH_ENGINE_SHA,
SFETCH_ENGINE_SHA256, GONEAT_VERSION.
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            SFETCH_VERSION="$2"
            shift 2
            ;;
        --dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --engine-sha)
            SFETCH_ENGINE_SHA="$2"
            shift 2
            ;;
        --engine-sha256)
            SFETCH_ENGINE_SHA256="$2"
            shift 2
            ;;
        --goneat-version)
            GONEAT_VERSION="$2"
            shift 2
            ;;
        -h | --help) usage ;;
        *)
            echo "error: unknown option: $1" >&2
            usage
            ;;
    esac
done

[ -n "$SFETCH_VERSION" ] || {
    echo "error: --version / SFETCH_VERSION required" >&2
    exit 1
}
[ -n "$INSTALL_DIR" ] || {
    echo "error: --dir / INSTALL_DIR required" >&2
    exit 1
}
[ -n "$SFETCH_ENGINE_SHA" ] || {
    echo "error: --engine-sha / SFETCH_ENGINE_SHA required" >&2
    exit 1
}
[ -n "$SFETCH_ENGINE_SHA256" ] || {
    echo "error: --engine-sha256 / SFETCH_ENGINE_SHA256 required" >&2
    exit 1
}

case "$SFETCH_VERSION" in
    latest | LATEST | main | master | HEAD | "")
        echo "error: refusing floating sfetch version ${SFETCH_VERSION:-empty}" >&2
        exit 1
        ;;
esac

# Full-length SHA preferred; accept 40-char hex
if ! [[ "$SFETCH_ENGINE_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
    echo "error: engine-sha must be a 40-char commit SHA (got: $SFETCH_ENGINE_SHA)" >&2
    exit 1
fi
if ! [[ "$SFETCH_ENGINE_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "error: engine-sha256 must be 64-char hex" >&2
    exit 1
fi

command -v curl >/dev/null 2>&1 || {
    echo "error: curl required" >&2
    exit 1
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/shs-sfetch-engine.XXXXXX")"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

ENGINE="${WORK}/bootstrap-sfetch-verified.sh"
URL="https://raw.githubusercontent.com/${REPO_SLUG}/${SFETCH_ENGINE_SHA}/scripts/bootstrap-sfetch-verified.sh"
echo "[..] fetching sfetch engine @ ${SFETCH_ENGINE_SHA}" >&2
curl -fsSL --retry 3 --retry-delay 1 -o "$ENGINE" "$URL"
chmod 0755 "$ENGINE"

# Portable digest (sha256sum | shasum | openssl) — Git Bash lacks shasum.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GOT="$("${SCRIPT_DIR}/sha256-file.sh" "$ENGINE")"
if [ "$GOT" != "$SFETCH_ENGINE_SHA256" ]; then
    echo "error: engine SHA-256 mismatch" >&2
    echo "  expected: $SFETCH_ENGINE_SHA256" >&2
    echo "  got:      $GOT" >&2
    exit 1
fi
echo "[ok] engine digest verified" >&2

mkdir -p "$INSTALL_DIR"
ARGS=(--version "$SFETCH_VERSION" --dir "$INSTALL_DIR" --yes)
if [ -n "$GONEAT_VERSION" ]; then
    ARGS+=(--goneat-version "$GONEAT_VERSION")
fi
exec bash "$ENGINE" "${ARGS[@]}"
