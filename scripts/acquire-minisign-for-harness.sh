#!/usr/bin/env bash
# Install pinned minisign 0.12 into a directory AFTER verified sfetch bootstrap.
# Used only by negative-control harnesses — not the sfetch TCB path.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${1-}"
[ -n "$DIR" ] || {
    echo "usage: acquire-minisign-for-harness.sh <dir>" >&2
    exit 2
}
mkdir -p "$DIR"
DIR="$(cd "$DIR" && pwd)"

# Reuse sfetch engine pins from Makefile (caller should already have verified sfetch).
ENGINE_SHA="${SFETCH_ENGINE_SHA:-c44577261902c848119d3c89b0138becb613b158}"
ENGINE_SUM="${SFETCH_ENGINE_SHA256:-9a074a15db18bca93601e23eca54d411ee72ce69413e802e083f535f8203c79a}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/shs-minisign-harness.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT
ENGINE="${WORK}/bootstrap-sfetch-verified.sh"
curl -fsSL --retry 3 -o "$ENGINE" \
    "https://raw.githubusercontent.com/3leaps/sfetch/${ENGINE_SHA}/scripts/bootstrap-sfetch-verified.sh"
chmod 0755 "$ENGINE"
GOT="$("$ROOT/scripts/sha256-file.sh" "$ENGINE")"
if [ "$GOT" != "$ENGINE_SUM" ]; then
    echo "error: engine digest mismatch for harness minisign acquire" >&2
    echo "  expected $ENGINE_SUM got $GOT" >&2
    exit 1
fi
bash "$ENGINE" --acquire-minisign-only --dir "$DIR"
echo "[ok] harness minisign installed under $DIR"
