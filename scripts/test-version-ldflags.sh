#!/usr/bin/env bash
# Build outside the repository, then check injected version and commit SHA.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$ROOT"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

VERSION="$(tr -d '[:space:]' <VERSION)"
[[ -n "$VERSION" && "$VERSION" != "dev" ]] || fail "VERSION file is ${VERSION:-empty}"
COMMIT="$(git rev-parse HEAD)"
[[ -n "$COMMIT" && "$COMMIT" != "unknown" ]] || fail "git commit is ${COMMIT:-empty}"

GOOS="$(go env GOOS)"
GOARCH="$(go env GOARCH)"
EXT=""
if [[ "$GOOS" == "windows" ]]; then
	EXT=".exe"
fi

ISOLATED="$(mktemp -d "${TMPDIR:-/tmp}/shs-ldflags.XXXXXX")"
trap 'rm -rf "$ISOLATED"' EXIT
HOME_DIR="$ISOLATED/home"
mkdir -p "$HOME_DIR" "$ISOLATED/bin"
isolated_real="$(cd "$ISOLATED" && pwd -P)"
root_real="$(cd "$ROOT" && pwd -P)"
case "$isolated_real/" in
"$root_real"/*) fail "isolated build directory is inside the repository" ;;
esac

OUT="$ISOLATED/bin/shellsentry${EXT}"
# Build with the same LDFLAGS the Makefile uses, writing the binary outside the tree.
make -s build BUILD_ARTIFACT="$OUT"
[[ -f "$OUT" ]] || fail "binary not written outside the repo: $OUT"
chmod +x "$OUT"

run_cmd() {
	local errf out
	errf="$(mktemp "$ISOLATED/err.XXXXXX")"
	out="$(cd "$ISOLATED/bin" && HOME="$HOME_DIR" USERPROFILE="$HOME_DIR" "$OUT" "$@" 2>"$errf")" || {
		fail "$* failed: $(cat "$errf") stdout=$out"
	}
	# Version flags print to stderr.
	if [[ -z "$out" && -s "$errf" ]]; then
		out="$(cat "$errf")"
	elif [[ -s "$errf" ]]; then
		fail "$* wrote unexpected stderr: $(cat "$errf") stdout=$out"
	fi
	printf '%s' "$out"
}

short="$(run_cmd --version)"
[[ "$short" == "shellsentry ${VERSION}" || "$short" == "shellsentry ${VERSION}"$'\n' ]] ||
	fail "--version stdout=$short want 'shellsentry ${VERSION}'"
[[ "$short" != *'shellsentry dev'* ]] || fail "--version output is uninjected dev"
pass "--version contains ${VERSION}"

extended="$(run_cmd --version-extended)"
[[ "$extended" == *"shellsentry ${VERSION}"* ]] || fail "extended missing version: $extended"
[[ "$extended" != *'shellsentry dev'* ]] || fail "extended output is uninjected dev"
[[ "$extended" == *"Commit:"*"${COMMIT}"* ]] || fail "extended missing commit ${COMMIT}: $extended"
[[ "$extended" != *'Commit:    unknown'* ]] || fail "commit is unknown: $extended"
pass "--version-extended commit is ${COMMIT}"

# Mutant: a binary built without LDFLAGS must fail these checks.
plain="$ISOLATED/bin/plain${EXT}"
(cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$plain" .)
plain_out="$(cd "$ISOLATED/bin" && HOME="$HOME_DIR" "$plain" --version 2>&1 || true)"
if [[ "$plain_out" == "shellsentry ${VERSION}" || "$plain_out" == "shellsentry ${VERSION}"$'\n' ]]; then
	fail "LDFLAGS-free mutant still reports injected VERSION"
fi
[[ "$plain_out" == *'shellsentry dev'* ]] || fail "LDFLAGS-free mutant should report dev, got: $plain_out"
pass "LDFLAGS-free mutant is distinguished"

echo "[ok] version ldflags outside the repository"
