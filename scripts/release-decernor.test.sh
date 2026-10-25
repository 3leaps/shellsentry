#!/usr/bin/env bash
# Ceremony binding: SHELLSENTRY_DECERNOR_BIN only. No PATH / DECERNOR_BIN fallback.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

fail() {
	if "$@" >"$scratch/out" 2>"$scratch/err"; then
		echo "error: expected rejection: $*" >&2
		cat "$scratch/err" >&2
		exit 1
	fi
}

write_ok_stub() {
	cat >"$1" <<'EOF'
#!/usr/bin/env bash
case "$1 ${2:-}" in
  'version ') echo 'decernor 0.1.8' ;;
  'version -e') printf 'Version:         0.1.8\nCommit:          testdata\nBuild Date:      testdata\nGo Version:      testdata\nGofulmen:        testdata\nCrucible:        testdata\n' ;;
  *) exit 0 ;;
esac
EOF
	chmod +x "$1"
}

ok="$scratch/decernor"
write_ok_stub "$ok"

# shellcheck source=scripts/release-decernor.sh
source "$root/scripts/release-decernor.sh"

fail env -u SHELLSENTRY_DECERNOR_BIN bash -c 'source "$1"; resolve_release_decernor' _ "$root/scripts/release-decernor.sh"
grep -q 'SHELLSENTRY_DECERNOR_BIN is required' "$scratch/err"

fail env SHELLSENTRY_DECERNOR_BIN=decernor bash -c 'source "$1"; resolve_release_decernor' _ "$root/scripts/release-decernor.sh"
grep -q 'absolute executable regular file' "$scratch/err"

fail env SHELLSENTRY_DECERNOR_BIN="$scratch/missing" bash -c 'source "$1"; resolve_release_decernor' _ "$root/scripts/release-decernor.sh"

ln -s "$ok" "$scratch/link"
fail env SHELLSENTRY_DECERNOR_BIN="$scratch/link" bash -c 'source "$1"; resolve_release_decernor' _ "$root/scripts/release-decernor.sh"
grep -q 'absolute executable regular file' "$scratch/err"

# PATH / unprefixed fallback must not satisfy ceremony.
mkdir -p "$scratch/path"
cp "$ok" "$scratch/path/decernor"
fail env -u SHELLSENTRY_DECERNOR_BIN PATH="$scratch/path:$PATH" \
	bash -c 'source "$1"; resolve_release_decernor' _ "$root/scripts/release-decernor.sh"
grep -q 'SHELLSENTRY_DECERNOR_BIN is required' "$scratch/err"
fail env -u SHELLSENTRY_DECERNOR_BIN DECERNOR_BIN="$ok" \
	bash -c 'source "$1"; resolve_release_decernor' _ "$root/scripts/release-decernor.sh"
grep -q 'SHELLSENTRY_DECERNOR_BIN is required' "$scratch/err"

# Live resolver accepts a well-formed 0.1.8 stub.
(
	export SHELLSENTRY_DECERNOR_BIN="$ok"
	resolve_release_decernor
	[[ "$RELEASE_DECERNOR_BIN" == "$ok" ]]
)

cat >"$scratch/old" <<'EOF'
#!/usr/bin/env bash
case "$1 ${2:-}" in
  'version ') echo 'decernor 0.1.7' ;;
  'version -e') printf 'Version:         0.1.7\nCommit:          testdata\nBuild Date:      testdata\nGo Version:      testdata\nGofulmen:        testdata\nCrucible:        testdata\n' ;;
esac
EOF
chmod +x "$scratch/old"
fail env SHELLSENTRY_DECERNOR_BIN="$scratch/old" bash -c 'source "$1"; resolve_release_decernor' _ "$root/scripts/release-decernor.sh"

cat >"$scratch/wrong" <<'EOF'
#!/usr/bin/env bash
case "$1 ${2:-}" in
  'version ') echo 'other 0.1.8' ;;
  'version -e') printf 'Version:         0.1.8\nCommit:          testdata\nBuild Date:      testdata\nGo Version:      testdata\nGofulmen:        testdata\nCrucible:        testdata\n' ;;
esac
EOF
chmod +x "$scratch/wrong"
fail env SHELLSENTRY_DECERNOR_BIN="$scratch/wrong" bash -c 'source "$1"; resolve_release_decernor' _ "$root/scripts/release-decernor.sh"

# Mutant: allowing DECERNOR_BIN must be distinguished.
if ! python3 - "$root/scripts/release-decernor.sh" <<'PY'
import re
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
unprefixed = re.compile(r'\$\{DECERNOR_BIN\b|\$DECERNOR_BIN\b')
if unprefixed.search(text):
    raise SystemExit('live resolver expands unprefixed DECERNOR_BIN')
if 'command -v decernor' in text:
    raise SystemExit('live resolver looks up PATH')
mut = text.replace(
    'candidate="$SHELLSENTRY_DECERNOR_BIN"',
    'candidate="${DECERNOR_BIN:-$SHELLSENTRY_DECERNOR_BIN}"',
)
if not unprefixed.search(mut):
    raise SystemExit('DECERNOR_BIN fallback mutant was not distinguished')
PY
then
	echo 'error: DECERNOR_BIN fallback mutant was not distinguished' >&2
	exit 1
fi

echo '[ok] Decernor ceremony binding has no PATH or DECERNOR_BIN fallback'
