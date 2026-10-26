#!/usr/bin/env bash
# Regression: parser and lint pins stay on the cooled current versions.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

MAKEFILE="${ROOT}/Makefile"
GOMOD="${ROOT}/go.mod"

want_mvdan="v3.14.1"
want_staticcheck="v0.8.2"
want_govulncheck="v1.9.0"

validate() {
    local makefile="$1" gomod="$2"
    grep -Eq "^STATICCHECK_VERSION \\?= ${want_staticcheck}\$" "$makefile" || {
        echo "STATICCHECK_VERSION must be ${want_staticcheck}" >&2
        return 1
    }
    grep -Eq "^GOVULNCHECK_VERSION \\?= ${want_govulncheck}\$" "$makefile" || {
        echo "GOVULNCHECK_VERSION must be ${want_govulncheck}" >&2
        return 1
    }
    grep -Eq "honnef.co/go/tools/cmd/staticcheck@\\\$\(STATICCHECK_VERSION\)" "$makefile" || {
        echo "lint must run staticcheck at STATICCHECK_VERSION" >&2
        return 1
    }
    grep -Eq "golang.org/x/vuln/cmd/govulncheck@\\\$\(GOVULNCHECK_VERSION\)" "$makefile" || {
        echo "govulncheck must run at GOVULNCHECK_VERSION" >&2
        return 1
    }
    grep -Eq "^[[:space:]]*mvdan.cc/sh/v3 ${want_mvdan}\$" "$gomod" || {
        echo "go.mod must require mvdan.cc/sh/v3 ${want_mvdan}" >&2
        return 1
    }
    return 0
}

validate "$MAKEFILE" "$GOMOD" || fail "live parser/lint pins were rejected"
pass "parser and lint pins are ${want_mvdan} / ${want_staticcheck} / ${want_govulncheck}"

scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-tool-pins.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

python3 - "$MAKEFILE" "$scratch/Makefile" <<'PY' || fail "staticcheck pin mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "STATICCHECK_VERSION ?= v0.8.2"
if old not in text:
    raise SystemExit("live Makefile is missing STATICCHECK_VERSION ?= v0.8.2")
dest.write_text(text.replace(old, "STATICCHECK_VERSION ?= v0.6.1", 1))
PY
cp "$GOMOD" "$scratch/go.mod"
if validate "$scratch/Makefile" "$scratch/go.mod" >/dev/null 2>"$scratch/staticcheck.err"; then
    fail "accepted Makefile after reverting staticcheck to v0.6.1"
fi
grep -q 'STATICCHECK_VERSION must be v0.8.2' "$scratch/staticcheck.err" ||
    fail "staticcheck mutant refusal (log: $(cat "$scratch/staticcheck.err"))"
pass "reverting staticcheck to v0.6.1 fails this check"

python3 - "$MAKEFILE" "$scratch/Makefile-govuln" <<'PY' || fail "govulncheck pin mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "GOVULNCHECK_VERSION ?= v1.9.0"
if old not in text:
    raise SystemExit("live Makefile is missing GOVULNCHECK_VERSION ?= v1.9.0")
dest.write_text(text.replace(old, "GOVULNCHECK_VERSION ?= v1.6.0", 1))
PY
if validate "$scratch/Makefile-govuln" "$GOMOD" >/dev/null 2>"$scratch/govuln.err"; then
    fail "accepted Makefile after reverting govulncheck to v1.6.0"
fi
grep -q 'GOVULNCHECK_VERSION must be v1.9.0' "$scratch/govuln.err" ||
    fail "govulncheck mutant refusal (log: $(cat "$scratch/govuln.err"))"
pass "reverting govulncheck to v1.6.0 fails this check"

python3 - "$GOMOD" "$scratch/go.mod" <<'PY' || fail "mvdan pin mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "mvdan.cc/sh/v3 v3.14.1"
if old not in text:
    raise SystemExit("live go.mod is missing mvdan.cc/sh/v3 v3.14.1")
dest.write_text(text.replace(old, "mvdan.cc/sh/v3 v3.13.1", 1))
PY
if validate "$MAKEFILE" "$scratch/go.mod" >/dev/null 2>"$scratch/mvdan.err"; then
    fail "accepted go.mod after reverting mvdan.cc/sh/v3 to v3.13.1"
fi
grep -q 'mvdan.cc/sh/v3 v3.14.1' "$scratch/mvdan.err" ||
    fail "mvdan mutant refusal (log: $(cat "$scratch/mvdan.err"))"
pass "reverting mvdan.cc/sh/v3 to v3.13.1 fails this check"
