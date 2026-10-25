#!/usr/bin/env bash
# §2.5 in-tree verification: mismatch fails. Uses a fixture copy of the pins.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
bin="${SHELLSENTRY_DECERNOR_BIN:-}"
[[ -n "$bin" && -x "$bin" && "$bin" == /* && ! -L "$bin" ]] || {
	echo 'error: SHELLSENTRY_DECERNOR_BIN required (CI installs Decernor from config/release/decernor-ci-sha256.txt)' >&2
	exit 1
}
export SHELLSENTRY_DECERNOR_BIN="$bin"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
fixture="$scratch/repo"
mkdir -p "$fixture/scripts" "$fixture/docs/security" "$fixture/keys"
cp "$root/scripts/release-verify-committed-anchors.sh" "$root/scripts/release-decernor.sh" \
	"$fixture/scripts/"
chmod +x "$fixture/scripts/"*.sh
cp "$root/docs/security/release-signing-keys.asc" "$root/docs/security/shellsentry-minisign.pub" \
	"$fixture/docs/security/"
cp "$root/keys/expected-fingerprints.txt" "$root/keys/expected-fingerprints.ndjson" \
	"$fixture/keys/"

env -u SHELLSENTRY_PGP_KEY_ID -u SHELLSENTRY_GPG_SIGNING_FINGERPRINT -u SHELLSENTRY_MINISIGN_PUB \
	"$fixture/scripts/release-verify-committed-anchors.sh" >/dev/null

python3 - "$fixture/keys/expected-fingerprints.txt" "$scratch/bad.txt" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
lines = text.splitlines()
lines[1] = 'minisign ' + ('0' * 64)
Path(sys.argv[2]).write_text('\n'.join(lines) + '\n')
PY
cp "$scratch/bad.txt" "$fixture/keys/expected-fingerprints.txt"
if env -u SHELLSENTRY_PGP_KEY_ID -u SHELLSENTRY_GPG_SIGNING_FINGERPRINT -u SHELLSENTRY_MINISIGN_PUB \
	"$fixture/scripts/release-verify-committed-anchors.sh" >/dev/null 2>&1; then
	echo 'error: mismatched minisign anchor was accepted' >&2
	exit 1
fi
echo '[ok] committed-anchor verification uses only in-tree material'
