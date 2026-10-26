#!/usr/bin/env bash
# Maintainer signing/publish scripts must not be invoked from GitHub Actions,
# and workflows must not carry signing-key secrets.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

WF_DIR=".github/workflows"
[[ -d "$WF_DIR" ]] || fail "workflows directory missing"

# Do not use \b after release-tag: it matches make release-tag-tests (the
# hyphen is a word boundary). Require a non-name character or end of string.
CEREMONY_MAKE='make[[:space:]]+(release-tag|release-push-tag|release-publish|release-sign|release-upload|release-create-draft)([^[:alnum:]_-]|$)'

printf 'make release-tag\n' | grep -Eq "$CEREMONY_MAKE" ||
    fail "ceremony regex must match make release-tag"
printf 'make release-tag-tests\n' | grep -Eq "$CEREMONY_MAKE" &&
    fail "ceremony regex must not match make release-tag-tests"
pass "ceremony regex allows make release-tag-tests and still matches make release-tag"

if grep -nE "$CEREMONY_MAKE" "$WF_DIR"/*; then
    fail "workflows must not invoke maintainer signing or publish targets"
fi
if grep -nE 'scripts/(release-tag|release-push-tag|release-publish|sign-release-assets|upload-release-assets|release-create-draft|release-fetch-ci-artifacts)\.sh' "$WF_DIR"/*; then
    fail "workflows must not invoke maintainer signing or publish scripts"
fi
pass "workflows do not invoke release-tag/publish/sign/upload/create-draft/fetch"

if grep -nE 'SHELLSENTRY_(MINISIGN_KEY|PGP_KEY_ID|GPG_HOMEDIR)\s*:' "$WF_DIR"/*; then
    fail "workflows must not set signing-key environment"
fi
if grep -nE 'secrets\.(MINISIGN|GPG|PGP|SIGNING)' "$WF_DIR"/*; then
    fail "workflows must not reference signing secrets"
fi
pass "workflows do not pass signing credentials"

# Mutant: splicing a publish step into CI must fail this check.
if ! grep -q 'make prepush' "$WF_DIR/ci.yml"; then
    fail "ci.yml must still run make prepush (sanity)"
fi
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-ci-hygiene.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
cp "$WF_DIR/ci.yml" "$scratch/ci.yml"
printf '\n      - run: make release-publish\n' >>"$scratch/ci.yml"
if grep -nE "$CEREMONY_MAKE" "$scratch/ci.yml" >/dev/null; then
    pass "hygiene grep catches make release-publish spliced into ci.yml"
else
    fail "hygiene grep missed a spliced make release-publish"
fi
cp "$WF_DIR/ci.yml" "$scratch/ci-script.yml"
printf '\n      - run: ./scripts/release-tag.sh\n' >>"$scratch/ci-script.yml"
if grep -nE 'scripts/(release-tag|release-publish|sign-release-assets|upload-release-assets|release-create-draft|release-fetch-ci-artifacts)\.sh' "$scratch/ci-script.yml" >/dev/null; then
    pass "hygiene grep catches scripts/release-tag.sh spliced into ci.yml"
else
    fail "hygiene grep missed a spliced release-tag.sh"
fi
cp "$WF_DIR/ci.yml" "$scratch/ci-create-draft.yml"
printf '\n      - run: make release-create-draft\n' >>"$scratch/ci-create-draft.yml"
if grep -nE "$CEREMONY_MAKE" "$scratch/ci-create-draft.yml" >/dev/null; then
    pass "hygiene grep catches make release-create-draft spliced into ci.yml"
else
    fail "hygiene grep missed a spliced make release-create-draft"
fi

# Job bodies from ci.yml (2-space job keys under jobs:).
parse_jobs() {
    python3 - "$1" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r"(?m)^jobs:\n", text)
if not m:
    raise SystemExit("ci.yml has no jobs:")
parts = re.split(r"(?m)^  ([A-Za-z0-9_-]+):\n", text[m.end():])
jobs = {}
it = iter(parts[1:])
for name in it:
    jobs[name] = next(it)
need = ("test", "macos-bootstrap-smoke")
missing = [n for n in need if n not in jobs]
if missing:
    raise SystemExit("missing jobs: " + ",".join(missing))
macos = jobs["macos-bootstrap-smoke"]
linux = jobs["test"]
if "ci-install-decernor.sh" in macos:
    raise SystemExit("macos-bootstrap-smoke must not install linux_amd64 Decernor")
# Structural: make release-tag-tests must be a top-level command in the
# Signed-tag tooling tests run script, not nested under if/while/for.
steps = re.split(r"(?m)^      - ", macos)
run_body = None
for step in steps:
    if not re.search(r"(?m)^name: Signed-tag tooling tests\s*$", step):
        continue
    capturing = False
    lines = []
    for line in step.splitlines():
        if not capturing:
            if re.match(r"^        run: \|", line):
                capturing = True
            continue
        if line.startswith("          "):
            lines.append(line[10:])
            continue
        if line == "":
            lines.append("")
            continue
        break
    run_body = "\n".join(lines)
    break
if run_body is None:
    raise SystemExit("macos Signed-tag tooling tests run block missing")
if re.search(r"(?m)^(?:        )?continue-on-error:\s*true\b", step):
    raise SystemExit("macos Signed-tag tooling tests must not set continue-on-error")
cmd = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*make\s+release-tag-tests\s*$")
openers = re.compile(r"^(if|while|until|for|case)\b")
closers = re.compile(r"^(fi|done|esac)\b")
depth = 0
live = False
for raw in run_body.splitlines():
    s = raw.strip()
    if not s or s.startswith("#"):
        continue
    if closers.match(s):
        depth = max(0, depth - 1)
        continue
    if depth == 0 and cmd.match(s):
        live = True
    if openers.match(s):
        depth += 1
if not live:
    raise SystemExit("macos-bootstrap-smoke must run make release-tag-tests")
install = linux.find("ci-install-decernor.sh")
verify = linux.find("release-verify-committed-anchors.sh")
if install < 0 or verify < 0:
    raise SystemExit("linux amd64 must install Decernor and verify committed anchors")
if install > verify:
    raise SystemExit("linux amd64 must install Decernor before verifying anchors")
print("ok")
PY
}

parse_jobs "$WF_DIR/ci.yml" >/dev/null || fail "ci.yml identity/anchor CI wiring is missing"
pass "macos runs make release-tag-tests; linux amd64 installs Decernor then verifies anchors"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-no-macos-tag-tests.yml" <<'PY' || fail "macos release-tag-tests mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
mut = text.replace("GOTOOLCHAIN=go1.26.10 make release-tag-tests", "GOTOOLCHAIN=go1.26.10 make test")
if "make release-tag-tests" in mut:
    raise SystemExit("mutant still has make release-tag-tests")
dest.write_text(mut)
PY
if parse_jobs "$scratch/ci-no-macos-tag-tests.yml" >/dev/null 2>"$scratch/macos-mut.err"; then
    fail "hygiene accepted ci.yml after removing macos make release-tag-tests"
fi
grep -q 'make release-tag-tests' "$scratch/macos-mut.err" ||
    fail "macos mutant refusal (log: $(cat "$scratch/macos-mut.err"))"
pass "removing macos make release-tag-tests fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-macos-if-false.yml" <<'PY' || fail "macos if-false wrap mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
live = "          GOTOOLCHAIN=go1.26.10 make release-tag-tests"
wrapped = (
    "          if false; then\n"
    "          GOTOOLCHAIN=go1.26.10 make release-tag-tests\n"
    "          fi"
)
if live not in text:
    raise SystemExit("live ci.yml missing macos release-tag-tests run line")
mut = text.replace(live, wrapped, 1)
if live in mut.split("macos-bootstrap-smoke:", 1)[1].split("windows-dogfood-x64:", 1)[0] and wrapped not in mut:
    raise SystemExit("mutant did not wrap macos release-tag-tests")
dest.write_text(mut)
PY
if parse_jobs "$scratch/ci-macos-if-false.yml" >/dev/null 2>"$scratch/macos-iffalse.err"; then
    fail "hygiene accepted ci.yml after wrapping macos make release-tag-tests in if false"
fi
grep -q 'make release-tag-tests' "$scratch/macos-iffalse.err" ||
    fail "macos if-false mutant refusal (log: $(cat "$scratch/macos-iffalse.err"))"
pass "wrapping macos make release-tag-tests in if false fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-macos-or-true.yml" <<'PY' || fail "macos || true mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
live = "          GOTOOLCHAIN=go1.26.10 make release-tag-tests"
mut_line = "          GOTOOLCHAIN=go1.26.10 make release-tag-tests || true"
if live not in text:
    raise SystemExit("live ci.yml missing macos release-tag-tests run line")
mut = text.replace(live, mut_line, 1)
if live + "\n" in mut:
    raise SystemExit("mutant still has the live macos release-tag-tests line")
if mut_line not in mut:
    raise SystemExit("mutant did not append || true")
dest.write_text(mut)
PY
if parse_jobs "$scratch/ci-macos-or-true.yml" >/dev/null 2>"$scratch/macos-ortrue.err"; then
    fail "hygiene accepted ci.yml after changing macos make release-tag-tests to || true"
fi
grep -q 'make release-tag-tests' "$scratch/macos-ortrue.err" ||
    fail "macos || true mutant refusal (log: $(cat "$scratch/macos-ortrue.err"))"
pass "changing macos make release-tag-tests to || true fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-macos-continue.yml" <<'PY' || fail "macos continue-on-error mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
live = "      - name: Signed-tag tooling tests"
mut_line = "      - name: Signed-tag tooling tests\n        continue-on-error: true"
if live not in text:
    raise SystemExit("live ci.yml missing macos Signed-tag tooling tests step")
mut = text.replace(live, mut_line, 1)
if "continue-on-error: true" not in mut:
    raise SystemExit("mutant did not set continue-on-error")
dest.write_text(mut)
PY
if parse_jobs "$scratch/ci-macos-continue.yml" >/dev/null 2>"$scratch/macos-continue.err"; then
    fail "hygiene accepted ci.yml after setting continue-on-error on macos release-tag-tests"
fi
grep -q 'continue-on-error' "$scratch/macos-continue.err" ||
    fail "macos continue-on-error mutant refusal (log: $(cat "$scratch/macos-continue.err"))"
pass "setting continue-on-error on macos make release-tag-tests fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-no-verify.yml" <<'PY' || fail "anchor-verify mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
mut = text.replace("./scripts/release-verify-committed-anchors.sh", "./scripts/release-preflight.sh")
if "release-verify-committed-anchors.sh" in mut:
    raise SystemExit("mutant still verifies committed anchors")
dest.write_text(mut)
PY
if parse_jobs "$scratch/ci-no-verify.yml" >/dev/null 2>"$scratch/verify-mut.err"; then
    fail "hygiene accepted ci.yml after removing committed-anchor verification"
fi
grep -q 'verify committed anchors' "$scratch/verify-mut.err" ||
    fail "anchor-verify mutant refusal (log: $(cat "$scratch/verify-mut.err"))"
pass "removing linux amd64 committed-anchor verification fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-swap-order.yml" <<'PY' || fail "install-before-verify mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
# Swap the two unique script names so verify appears first.
a, b = "ci-install-decernor.sh", "release-verify-committed-anchors.sh"
if text.find(a) < 0 or text.find(b) < 0 or text.find(a) > text.find(b):
    raise SystemExit("live ci.yml is not install-then-verify")
mut = text.replace(a, "DECERNOR_INSTALL_PLACEHOLDER").replace(b, a).replace("DECERNOR_INSTALL_PLACEHOLDER", b)
if mut.find(a) < mut.find(b):
    raise SystemExit("mutant did not reverse install/verify order")
dest.write_text(mut)
PY
if parse_jobs "$scratch/ci-swap-order.yml" >/dev/null 2>"$scratch/order-mut.err"; then
    fail "hygiene accepted ci.yml after swapping Decernor install and verify"
fi
grep -q 'before verifying anchors' "$scratch/order-mut.err" ||
    fail "install-order mutant refusal (log: $(cat "$scratch/order-mut.err"))"
pass "linux amd64 Decernor install must precede committed-anchor verification"

check_ci() {
    python3 "$ROOT/scripts/workflow_native_guards.py" --ci "$1"
}

check_ci "$WF_DIR/ci.yml" >/dev/null || fail "ci.yml native guards rejected the live workflow"
pass "ci.yml pins five native runners, refuses skippable build steps, and packs Windows zips"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-ubuntu-latest.yml" <<'PY' || fail "ubuntu-latest mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "    runs-on: ubuntu-24.04"
if old not in text:
    raise SystemExit("live ci.yml is missing ubuntu-24.04")
mut = text.replace(old, "    runs-on: ubuntu-latest", 1)
if old in mut:
    raise SystemExit("ubuntu-latest mutant still has ubuntu-24.04")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-ubuntu-latest.yml" >/dev/null 2>"$scratch/ci-ubuntu-latest.err"; then
	fail "hygiene accepted ci.yml after changing linux amd64 to ubuntu-latest"
fi
grep -q 'ubuntu-latest' "$scratch/ci-ubuntu-latest.err" ||
	fail "ubuntu-latest mutant refusal (log: $(cat "$scratch/ci-ubuntu-latest.err"))"
pass "changing linux amd64 to ubuntu-latest fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-macos-latest.yml" <<'PY' || fail "macos-latest mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "    runs-on: macos-15"
if old not in text:
    raise SystemExit("live ci.yml is missing macos-15")
mut = text.replace(old, "    runs-on: macos-latest", 1)
if old in mut:
    raise SystemExit("macos-latest mutant still has macos-15")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-macos-latest.yml" >/dev/null 2>"$scratch/ci-macos-latest.err"; then
	fail "hygiene accepted ci.yml after changing macos to macos-latest"
fi
grep -q 'macos-latest' "$scratch/ci-macos-latest.err" ||
	fail "macos-latest mutant refusal (log: $(cat "$scratch/ci-macos-latest.err"))"
pass "changing macos-15 to macos-latest fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-windows-latest.yml" <<'PY' || fail "windows-latest mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "    runs-on: windows-2022"
if old not in text:
    raise SystemExit("live ci.yml is missing windows-2022")
mut = text.replace(old, "    runs-on: windows-latest", 1)
if old in mut:
    raise SystemExit("windows-latest mutant still has windows-2022")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-windows-latest.yml" >/dev/null 2>"$scratch/ci-windows-latest.err"; then
	fail "hygiene accepted ci.yml after changing windows amd64 to windows-latest"
fi
grep -q 'windows-latest' "$scratch/ci-windows-latest.err" ||
	fail "windows-latest mutant refusal (log: $(cat "$scratch/ci-windows-latest.err"))"
pass "changing windows-2022 to windows-latest fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-no-host.yml" <<'PY' || fail "host-assert mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = '= "darwin/arm64"'
if old not in text:
    raise SystemExit("live ci.yml is missing the macos host assert")
mut = text.replace(old, '= "linux/amd64"', 1)
if old in mut:
    raise SystemExit("host-assert mutant still requires darwin/arm64")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-no-host.yml" >/dev/null 2>"$scratch/ci-no-host.err"; then
	fail "hygiene accepted ci.yml after dropping the macos host assert"
fi
grep -q 'darwin/arm64' "$scratch/ci-no-host.err" ||
	fail "host-assert mutant refusal (log: $(cat "$scratch/ci-no-host.err"))"
pass "dropping the macos native host assert fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-host-if-false.yml" <<'PY' || fail "host if: false mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "      - name: Assert native host\n"
new = "      - name: Assert native host\n        if: false\n"
if old not in text:
    raise SystemExit("live ci.yml is missing Assert native host")
mut = text.replace(old, new, 1)
if "        if: false\n" not in mut:
    raise SystemExit("mutant did not set if: false on the host check")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-host-if-false.yml" >/dev/null 2>"$scratch/ci-host-if-false.err"; then
	fail "hygiene accepted ci.yml after setting if: false on the host check"
fi
grep -q 'must not set if:' "$scratch/ci-host-if-false.err" ||
	fail "host if: false mutant refusal (log: $(cat "$scratch/ci-host-if-false.err"))"
pass "setting if: false on the host check fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-host-or-true.yml" <<'PY' || fail "host || true mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = '          test "$(go env GOHOSTOS)/$(go env GOHOSTARCH)" = "linux/amd64"'
new = old + " || true"
if old not in text:
    raise SystemExit("live ci.yml is missing the linux amd64 host test")
mut = text.replace(old, new, 1)
if old + "\n" in mut:
    raise SystemExit("mutant still has the live linux amd64 host test")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-host-or-true.yml" >/dev/null 2>"$scratch/ci-host-or-true.err"; then
	fail "hygiene accepted ci.yml after appending || true to the host check"
fi
grep -q '|| true' "$scratch/ci-host-or-true.err" ||
	fail "host || true mutant refusal (log: $(cat "$scratch/ci-host-or-true.err"))"
pass "appending || true to the host check fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-host-if-wrap.yml" <<'PY' || fail "host if-false wrap mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
live = '          test "$(go env GOHOSTOS)/$(go env GOHOSTARCH)" = "linux/amd64"'
wrapped = (
    "          if false; then\n"
    '          test "$(go env GOHOSTOS)/$(go env GOHOSTARCH)" = "linux/amd64"\n'
    "          fi"
)
if live not in text:
    raise SystemExit("live ci.yml is missing the linux amd64 host test")
mut = text.replace(live, wrapped, 1)
if wrapped not in mut:
    raise SystemExit("mutant did not wrap the host check in if false")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-host-if-wrap.yml" >/dev/null 2>"$scratch/ci-host-if-wrap.err"; then
	fail "hygiene accepted ci.yml after wrapping the host check in if false"
fi
grep -q 'if false' "$scratch/ci-host-if-wrap.err" ||
	fail "host if-false wrap mutant refusal (log: $(cat "$scratch/ci-host-if-wrap.err"))"
pass "wrapping the host check in if false fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-host-continue.yml" <<'PY' || fail "host continue-on-error mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "      - name: Assert native host\n"
new = "      - name: Assert native host\n        continue-on-error: true\n"
if old not in text:
    raise SystemExit("live ci.yml is missing Assert native host")
mut = text.replace(old, new, 1)
if "continue-on-error: true" not in mut.split("      - name: Assert native host\n", 1)[1][:80]:
    raise SystemExit("mutant did not set continue-on-error on the host check")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-host-continue.yml" >/dev/null 2>"$scratch/ci-host-continue.err"; then
	fail "hygiene accepted ci.yml after setting continue-on-error on the host check"
fi
grep -q 'continue-on-error' "$scratch/ci-host-continue.err" ||
	fail "host continue-on-error mutant refusal (log: $(cat "$scratch/ci-host-continue.err"))"
pass "setting continue-on-error on the host check fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-job-if.yml" <<'PY' || fail "job-level if: mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "  test:\n    name: Linux quality (amd64)\n    runs-on: ubuntu-24.04\n"
new = "  test:\n    if: false\n    name: Linux quality (amd64)\n    runs-on: ubuntu-24.04\n"
if old not in text:
    raise SystemExit("live ci.yml is missing the linux amd64 job header")
mut = text.replace(old, new, 1)
if "  test:\n    if: false\n" not in mut:
    raise SystemExit("mutant did not set job-level if: false")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-job-if.yml" >/dev/null 2>"$scratch/ci-job-if.err"; then
	fail "hygiene accepted ci.yml after setting job-level if: on linux amd64"
fi
grep -q 'job-level if:' "$scratch/ci-job-if.err" ||
	fail "job-level if: mutant refusal (log: $(cat "$scratch/ci-job-if.err"))"
pass "setting job-level if: on a platform build job fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-no-zip.yml" <<'PY' || fail "windows zip mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
mut = text.replace("./scripts/package-windows-zip.sh", "python -c pass")
if "package-windows-zip.sh" in mut:
    raise SystemExit("mutant still calls package-windows-zip.sh")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-no-zip.yml" >/dev/null 2>"$scratch/ci-no-zip.err"; then
	fail "hygiene accepted ci.yml after dropping package-windows-zip.sh"
fi
grep -q 'package-windows-zip.sh' "$scratch/ci-no-zip.err" ||
	fail "windows zip mutant refusal (log: $(cat "$scratch/ci-no-zip.err"))"
pass "dropping package-windows-zip.sh from Windows CI fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-no-setup-python.yml" <<'PY' || fail "setup-python mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
mut = text.replace("actions/setup-python@", "actions/setup-go@")
if "actions/setup-python@" in mut:
    raise SystemExit("mutant still pins setup-python")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-no-setup-python.yml" >/dev/null 2>"$scratch/ci-no-setup-python.err"; then
	fail "hygiene accepted ci.yml after dropping setup-python"
fi
grep -q 'setup-python' "$scratch/ci-no-setup-python.err" ||
	fail "setup-python mutant refusal (log: $(cat "$scratch/ci-no-setup-python.err"))"
pass "dropping setup-python from Windows CI fails this check"

python3 - "$ROOT/scripts/package-windows-zip.sh" "$scratch/zip-no-windowsapps.sh" <<'PY' || fail "WindowsApps script mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
mut = text.replace("WindowsApps", "System32")
if "WindowsApps" in mut:
    raise SystemExit("mutant still mentions WindowsApps")
dest.write_text(mut)
PY
if python3 - "$ROOT/scripts" "$scratch/zip-no-windowsapps.sh" <<'PY' >/dev/null 2>"$scratch/zip-no-windowsapps.err"
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from workflow_native_guards import validate_windows_zip_script
fails = validate_windows_zip_script(Path(sys.argv[2]).read_text())
if fails:
    print("; ".join(fails), file=sys.stderr)
    raise SystemExit(1)
print("ok")
PY
then
	fail "hygiene accepted package-windows-zip.sh after dropping the WindowsApps refusal"
fi
grep -q 'Windows Store python stub' "$scratch/zip-no-windowsapps.err" ||
	fail "WindowsApps mutant refusal (log: $(cat "$scratch/zip-no-windowsapps.err"))"
pass "dropping the Windows Store python stub refusal from package-windows-zip.sh fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-freshness-rename.yml" <<'PY' || fail "freshness rename mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "      - name: sfetch pin freshness (informational soft-warn only)"
new = "      - name: sfetch pin freshness"
if old not in text:
    raise SystemExit("live ci.yml is missing the named sfetch pin-freshness exemption")
mut = text.replace(old, new, 1)
if old in mut:
    raise SystemExit("mutant still has the exempt freshness step name")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-freshness-rename.yml" >/dev/null 2>"$scratch/ci-freshness-rename.err"; then
	fail "hygiene accepted ci.yml after renaming the sfetch pin-freshness exemption"
fi
grep -q 'continue-on-error' "$scratch/ci-freshness-rename.err" ||
	fail "freshness rename mutant refusal (log: $(cat "$scratch/ci-freshness-rename.err"))"
pass "continue-on-error is refused unless the sfetch pin-freshness step keeps its name"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-freshness-swap.yml" <<'PY' || fail "freshness swap mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
real = (
    "      - name: sfetch pin freshness (informational soft-warn only)\n"
    "        run: make check-sfetch-pin-freshness\n"
    "        continue-on-error: true\n"
)
boot = (
    "      - name: Consumer bootstrap negative controls\n"
    "        run: |\n"
    '          export PATH="$PWD/bin:$PATH"\n'
    "          make test-bootstrap-negative-controls\n"
)
swapped = (
    "      - name: sfetch pin freshness (informational soft-warn only)\n"
    "        continue-on-error: true\n"
    "        run: |\n"
    '          export PATH="$PWD/bin:$PATH"\n'
    "          make test-bootstrap-negative-controls\n"
)
if real not in text or boot not in text:
    raise SystemExit("live ci.yml is missing freshness or bootstrap steps")
mut = text.replace(real, "", 1).replace(boot, swapped, 1)
if real in mut:
    raise SystemExit("swap mutant still has the real freshness run")
if mut.count("sfetch pin freshness (informational soft-warn only)") != 1:
    raise SystemExit("swap mutant must keep exactly one freshness name")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-freshness-swap.yml" >/dev/null 2>"$scratch/ci-freshness-swap.err"; then
	fail "hygiene accepted ci.yml after swapping the freshness name onto another step"
fi
grep -q 'must be exactly make check-sfetch-pin-freshness' "$scratch/ci-freshness-swap.err" ||
	fail "freshness swap mutant refusal (log: $(cat "$scratch/ci-freshness-swap.err"))"
pass "renaming another step to the freshness exemption fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-freshness-append.yml" <<'PY' || fail "freshness append mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "        run: make check-sfetch-pin-freshness"
new = "        run: make test && make check-sfetch-pin-freshness"
if old not in text:
    raise SystemExit("live ci.yml is missing the exact freshness run")
mut = text.replace(old, new, 1)
if old + "\n" in mut:
    raise SystemExit("append mutant still has the exact freshness run")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-freshness-append.yml" >/dev/null 2>"$scratch/ci-freshness-append.err"; then
	fail "hygiene accepted ci.yml after appending a command to the freshness run"
fi
grep -q 'must be exactly make check-sfetch-pin-freshness' "$scratch/ci-freshness-append.err" ||
	fail "freshness append mutant refusal (log: $(cat "$scratch/ci-freshness-append.err"))"
pass "appending a command to the freshness run fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-host-exit-0.yml" <<'PY' || fail "host exit 0 mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = '          test "$(go env GOHOSTOS)/$(go env GOHOSTARCH)" = "linux/amd64"'
new = old + "\n          exit 0"
if old not in text:
    raise SystemExit("live ci.yml is missing the linux amd64 host test")
mut = text.replace(old, new, 1)
if "exit 0" not in mut.split("Assert native host", 1)[1].split("Install system tools", 1)[0]:
    raise SystemExit("mutant did not append exit 0 to the host check")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-host-exit-0.yml" >/dev/null 2>"$scratch/ci-host-exit-0.err"; then
	fail "hygiene accepted ci.yml after appending exit 0 to the host check"
fi
grep -q 'must not exit 0' "$scratch/ci-host-exit-0.err" ||
	fail "host exit 0 mutant refusal (log: $(cat "$scratch/ci-host-exit-0.err"))"
pass "appending exit 0 to the host check fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-host-shell.yml" <<'PY' || fail "host shell mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "      - name: Assert native host\n        run: |"
new = "      - name: Assert native host\n        shell: bash {0}\n        run: |"
if old not in text:
    raise SystemExit("live ci.yml is missing Assert native host")
mut = text.replace(old, new, 1)
if "shell: bash {0}" not in mut:
    raise SystemExit("mutant did not set a custom shell: on the host check")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-host-shell.yml" >/dev/null 2>"$scratch/ci-host-shell.err"; then
	fail "hygiene accepted ci.yml after setting a custom shell: on the host check"
fi
grep -q 'custom shell:' "$scratch/ci-host-shell.err" ||
	fail "host shell mutant refusal (log: $(cat "$scratch/ci-host-shell.err"))"
pass "setting a custom shell: on the host check fails this check"

python3 - "$WF_DIR/ci.yml" "$scratch/ci-quality-or-colon.yml" <<'PY' || fail "|| : mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = "          make prepush"
new = "          make prepush || :"
if old not in text:
    raise SystemExit("live ci.yml is missing make prepush")
mut = text.replace(old, new, 1)
if old + "\n" in mut:
    raise SystemExit("mutant still has the live make prepush line")
dest.write_text(mut)
PY
if check_ci "$scratch/ci-quality-or-colon.yml" >/dev/null 2>"$scratch/ci-quality-or-colon.err"; then
	fail "hygiene accepted ci.yml after appending || : to make prepush"
fi
grep -q '|| :' "$scratch/ci-quality-or-colon.err" ||
	fail "|| : mutant refusal (log: $(cat "$scratch/ci-quality-or-colon.err"))"
pass "appending || : to a platform-job run fails this check"
