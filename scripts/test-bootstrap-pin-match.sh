#!/bin/sh
# Regression: bootstrap pin matching (exact normalized version comparison).
# Uses scripts/version-matches-pin.sh only — no network.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MATCH="$ROOT/scripts/version-matches-pin.sh"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

pass() {
	echo "PASS: $*"
}

# --- current pin matches ---
if "$MATCH" "sfetch 0.4.9" "v0.4.9"; then
	pass "sfetch current pin (v-prefix pin, bare version line)"
else
	fail "sfetch 0.4.9 should match pin v0.4.9"
fi

if "$MATCH" "goneat v0.5.15" "v0.5.15"; then
	pass "goneat current pin (v-prefix in both)"
else
	fail "goneat v0.5.15 should match pin v0.5.15"
fi

if "$MATCH" "sfetch 0.4.9" "0.4.9"; then
	pass "sfetch current pin (bare pin)"
else
	fail "sfetch 0.4.9 should match bare pin 0.4.9"
fi

if "$MATCH" "goneat version 0.5.15" "v0.5.15"; then
	pass "goneat multi-token version line"
else
	fail "goneat version 0.5.15 should match pin v0.5.15"
fi

# --- stale pin rejects ---
if "$MATCH" "sfetch 0.4.5" "v0.4.9"; then
	fail "stale sfetch 0.4.5 must not match pin v0.4.9"
else
	pass "stale sfetch pin rejected"
fi

if "$MATCH" "goneat v0.5.7" "v0.5.15"; then
	fail "stale goneat v0.5.7 must not match pin v0.5.15"
else
	pass "stale goneat pin rejected"
fi

# --- substring false-positive rejects (exact match required) ---
if "$MATCH" "sfetch 0.4.90" "v0.4.9"; then
	fail "sfetch 0.4.90 must not satisfy pin v0.4.9 (substring)"
else
	pass "longer patch version 0.4.90 rejected for pin 0.4.9"
fi

if "$MATCH" "sfetch 0.4.9-extra" "v0.4.9"; then
	fail "sfetch 0.4.9-extra must not satisfy pin v0.4.9"
else
	pass "suffixed version token rejected"
fi

if "$MATCH" "tool 10.4.9" "v0.4.9"; then
	fail "10.4.9 must not satisfy pin v0.4.9 (substring)"
else
	pass "different major with shared suffix rejected"
fi

# --- empty pin never matches ---
if "$MATCH" "sfetch 0.4.9" ""; then
	fail "empty pin must not match"
else
	pass "empty pin rejected"
fi

# --- glob / pathname expansion must not fail-open ---
# A version line with "*" must not match via CWD filename equal to the pin.
glob_tmp="$(mktemp -d "${TMPDIR:-/tmp}/shs-pin-glob.XXXXXX")"
(
	cd "$glob_tmp" || exit 1
	# Create a CWD file named like the normalized pin.
	: >"0.4.9"
	if "$MATCH" "sfetch *" "v0.4.9"; then
		fail "glob metacharacter in version line must not match via CWD expand"
	else
		pass "glob version line rejected (no pathname expansion fail-open)"
	fi
)
rm -rf "$glob_tmp"

echo "[ok] bootstrap pin-match regression complete"
