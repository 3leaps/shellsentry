#!/usr/bin/env bash
# Print SHA-256 hex of a file (portable: sha256sum | shasum | openssl).
# Usage: sha256-file.sh <path>
set -euo pipefail
f="${1-}"
[ -n "$f" ] && [ -f "$f" ] || {
    echo "usage: sha256-file.sh <path>" >&2
    exit 2
}
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
elif command -v openssl >/dev/null 2>&1; then
    # OpenSSL prints "SHA256(file)= hex" or "SHA2-256(file)= hex"
    openssl dgst -sha256 "$f" | awk '{print $NF}'
else
    echo "error: need sha256sum, shasum, or openssl" >&2
    exit 1
fi
