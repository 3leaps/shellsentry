#!/usr/bin/env bash
# Regression: assert-tool-pins must not SIGPIPE (exit 141) on extra version lines.
# A piped `head -n1` under `set -o pipefail` fails when the tool writes more
# than one line. This check uses stubs that keep writing after the first line.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

LIVE="$ROOT/scripts/assert-tool-pins.sh"
[ -f "$LIVE" ] || fail "assert-tool-pins.sh missing"

if grep -nE '\|[[:space:]]*head[[:space:]]+-n1' "$LIVE"; then
    fail "assert-tool-pins.sh must not pipe version output through head"
fi
pass "live script does not pipe version output through head"

scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-tool-pins.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

mkdir -p "$scratch/bin" "$scratch/scripts"
cat >"$scratch/bin/sfetch" <<'SH'
#!/usr/bin/env bash
echo "sfetch 0.4.13"
echo "second line that would SIGPIPE a piped head"
# Keep the writer alive after the first line so head closing the pipe is 141.
dd if=/dev/zero bs=65536 count=8 status=none
SH
cat >"$scratch/bin/goneat" <<'SH'
#!/usr/bin/env bash
echo "goneat version 0.6.6"
echo "second line that would SIGPIPE a piped head"
dd if=/dev/zero bs=65536 count=8 status=none
SH
chmod +x "$scratch/bin/sfetch" "$scratch/bin/goneat"
cp "$ROOT/scripts/version-matches-pin.sh" "$scratch/scripts/version-matches-pin.sh"

export SFETCH_BIN="$scratch/bin/sfetch"
export GONEAT_BIN="$scratch/bin/goneat"

if ! "$LIVE" v0.4.13 v0.6.6 >"$scratch/live.out" 2>"$scratch/live.err"; then
    cat "$scratch/live.out" "$scratch/live.err" >&2
    fail "live assert-tool-pins.sh must succeed when tools write extra version lines"
fi
grep -q 'exact pins: sfetch=v0.4.13 goneat=v0.6.6' "$scratch/live.out" ||
    fail "live assert-tool-pins.sh did not report matching pins"
pass "live script survives extra version lines"

# Mutant: restore the pipefail+head path. Stubs keep writing, so this must fail.
sed -e 's/2>&1)"/2>\&1 | head -n1)"/' -e '/%%\$/d' "$LIVE" >"$scratch/scripts/assert-tool-pins.sh"
chmod +x "$scratch/scripts/assert-tool-pins.sh"
grep -q '| head -n1' "$scratch/scripts/assert-tool-pins.sh" ||
    fail "head mutant was not constructed"
set +e
"$scratch/scripts/assert-tool-pins.sh" v0.4.13 v0.6.6 >"$scratch/mut.out" 2>"$scratch/mut.err"
mut_rc=$?
set -e
if [ "$mut_rc" -eq 0 ]; then
    cat "$scratch/mut.out" "$scratch/mut.err" >&2
    fail "head mutant must not succeed against extra version lines"
fi
if [ "$mut_rc" -ne 141 ]; then
    echo "mutant exit: $mut_rc" >&2
    cat "$scratch/mut.out" "$scratch/mut.err" >&2
    fail "head mutant must exit 141 (SIGPIPE) against extra version lines"
fi
pass "piped-head mutant exits 141 on extra version lines"

echo "[ok] assert-tool-pins SIGPIPE controls"
