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
# First line is the pin; exec dd so a piped head's SIGPIPE is the stub's status.
# 256KiB exceeds a typical pipe buffer. stderr discarded so it cannot become line 1.
cat >"$scratch/bin/sfetch" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'sfetch 0.4.13'
exec dd if=/dev/zero bs=1024 count=256 2>/dev/null
SH
cat >"$scratch/bin/goneat" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'goneat version 0.6.6'
exec dd if=/dev/zero bs=1024 count=256 2>/dev/null
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
pass "piped-head mutant fails against extra version lines (exit ${mut_rc})"

echo "[ok] assert-tool-pins SIGPIPE controls"
