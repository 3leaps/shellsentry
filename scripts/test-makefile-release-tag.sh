#!/usr/bin/env bash
# Ceremony targets take SHELLSENTRY_RELEASE_TAG only; bare RELEASE_TAG is refused.
# Matrix: env, command line, stale prefixed alias, unset.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-make-tag.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}
pass() { echo "PASS: $*"; }

if grep -nE '^[[:space:]]*RELEASE_TAG[[:space:]]*(\?=|:=|\+=|=)' Makefile; then
	fail "Makefile must not assign RELEASE_TAG"
fi
if grep -nE 'git[[:space:]]+describe' Makefile; then
	fail "Makefile must not fall back to git describe"
fi
if grep -nE 'RELEASE_TAG' Makefile | grep -vE 'SHELLSENTRY_RELEASE_TAG|not accepted|RELEASE_TAG is not|origin RELEASE_TAG'; then
	fail "Makefile mentions RELEASE_TAG outside a refusal"
fi
grep -q 'SHELLSENTRY_RELEASE_TAG' Makefile || fail "Makefile must consume SHELLSENTRY_RELEASE_TAG"
grep -q 'require-release-tag' Makefile || fail "Makefile must define require-release-tag"
pass "Makefile does not assign RELEASE_TAG or git describe"

# Stale prefixed alias: RELEASE_TAG ?= $(SHELLSENTRY_RELEASE_TAG) must be rejected.
python3 - "$ROOT/Makefile" <<'PY' || fail "stale prefixed RELEASE_TAG alias was not distinguished"
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
assign = re.compile(r'^\s*RELEASE_TAG\s*(\?=|:=|\+=|=)', re.M)
if assign.search(text):
    raise SystemExit('live Makefile assigns RELEASE_TAG')
mut = text.replace(
    'define require_shellsentry_release_tag\n',
    'RELEASE_TAG ?= $(SHELLSENTRY_RELEASE_TAG)\ndefine require_shellsentry_release_tag\n',
    1,
)
if not assign.search(mut):
    raise SystemExit('mutant did not insert the prefixed alias')
if 'RELEASE_TAG ?= $(SHELLSENTRY_RELEASE_TAG)' not in mut:
    raise SystemExit('mutant lost the prefixed alias')
PY
python3 - "$ROOT/Makefile" <<'PY' || fail "git describe fallback mutant was not distinguished"
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
if 'git describe' in text:
    raise SystemExit('live Makefile uses git describe')
mut = 'RELEASE_TAG ?= $(shell git describe --tags --abbrev=0)\n' + text
if 'git describe' not in mut:
    raise SystemExit('mutant did not insert git describe')
PY
pass "stale prefixed alias and git describe fallback are distinguished"

for target in release-preflight release-guard-tag-version release-prepare-tag-message release-tag \
	release-push-tag release-verify-tag release-verify-remote-tag \
	release-publish release-download release-notes release-sign release-create-draft release-upload \
	release-export-key release-export-minisign-key release-export-keys release-verify-signatures release-verify-keys; do
	grep -E "^${target}: require-release-tag" Makefile >/dev/null ||
		fail "$target must depend on require-release-tag first"
done
grep -E '^release-create-draft: require-release-tag' -A2 Makefile | grep -q 'release-create-draft.sh' ||
	fail "release-create-draft must invoke scripts/release-create-draft.sh"
grep -E '^release-tag: require-release-tag' -A2 Makefile | grep -q 'release-tag-operator.sh local-tag' ||
	fail "release-tag must invoke scripts/release-tag-operator.sh local-tag"
grep -E '^release-push-tag: require-release-tag' -A2 Makefile | grep -q 'release-tag-operator.sh remote-push' ||
	fail "release-push-tag must invoke scripts/release-tag-operator.sh remote-push"
grep -E '^release-verify-tag: require-release-tag' -A2 Makefile | grep -q 'verify-pinned-tag.sh' ||
	fail "release-verify-tag must invoke scripts/verify-pinned-tag.sh"
grep -E '^release-verify-remote-tag: require-release-tag' -A2 Makefile | grep -q 'release-verify-remote-tag.sh' ||
	fail "release-verify-remote-tag must invoke scripts/release-verify-remote-tag.sh"
for target in release-export-key release-export-minisign-key release-export-keys; do
	grep -E "^${target}: require-release-tag" -A3 Makefile | grep -q 'release-stage-tagged-pubkeys.sh' ||
		fail "$target must stage public keys from the tagged commit"
done
if grep -E '^release-export-(key|minisign-key|keys):' -A6 Makefile | grep -q 'export-release-key.sh'; then
	fail "release-export-* must not export from the operator keyring"
fi
pass "ceremony targets depend on require-release-tag"

python3 - "$ROOT/Makefile" "$scratch/Makefile.export-mut" <<'PY' || fail "working-tree export mutant was not distinguished"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
live = "release-stage-tagged-pubkeys.sh"
old = "export-release-key.sh"
if live not in text:
    raise SystemExit("live Makefile does not stage tagged public keys")
export_block = text.split("release-export-key:", 1)[1].split("verify-release-key:", 1)[0]
if old in export_block:
    raise SystemExit("live release-export-* still calls export-release-key.sh")
mut = text.replace(
    "./scripts/release-stage-tagged-pubkeys.sh $(SHELLSENTRY_RELEASE_TAG) $(DIST_RELEASE)",
    "./scripts/export-release-key.sh $(SHELLSENTRY_PGP_KEY_ID) $(DIST_RELEASE)",
    1,
)
if old not in mut.split("release-export-key:", 1)[1].split("verify-release-key:", 1)[0]:
    raise SystemExit("mutant did not restore operator-keyring export")
Path(sys.argv[2]).write_text(mut)
PY
if grep -E '^release-export-(key|minisign-key|keys):' -A6 "$scratch/Makefile.export-mut" | grep -q 'export-release-key.sh'; then
	pass "grep catches release-export-key restored to operator-keyring export"
else
	fail "export-key mutant was not distinguished"
fi

# Mutant: dropping the tag guard from release-tag must fail this check.
python3 - "$ROOT/Makefile" <<'PY' || fail "require-release-tag mutant was not distinguished"
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r'^release-tag:.*', text, re.M)
if not m or 'require-release-tag' not in m.group(0):
    raise SystemExit('live release-tag missing require-release-tag')
mut = re.sub(r'^release-tag: require-release-tag', 'release-tag:', text, count=1, flags=re.M)
if re.search(r'^release-tag: require-release-tag', mut, re.M):
    raise SystemExit('mutant still has require-release-tag')
PY
pass "grep rejects a release-tag without require-release-tag"

python3 - "$ROOT/Makefile" <<'PY' || fail "release-preflight require-release-tag mutant was not distinguished"
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r'^release-preflight:.*', text, re.M)
if not m or 'require-release-tag' not in m.group(0):
    raise SystemExit('live release-preflight missing require-release-tag')
mut = re.sub(r'^release-preflight: require-release-tag', 'release-preflight:', text, count=1, flags=re.M)
if re.search(r'^release-preflight: require-release-tag', mut, re.M):
    raise SystemExit('mutant still has require-release-tag on release-preflight')
PY
pass "grep rejects a release-preflight without require-release-tag"

file_version="$(tr -d ' \n' <VERSION)"

# Unset: missing SHELLSENTRY_RELEASE_TAG must fail before side effects.
if env -u SHELLSENTRY_RELEASE_TAG -u RELEASE_TAG make -s release-notes >"$scratch/missing.out" 2>&1; then
	fail "make release-notes without SHELLSENTRY_RELEASE_TAG must be refused"
fi
grep -q 'SHELLSENTRY_RELEASE_TAG required' "$scratch/missing.out" ||
	fail "missing-tag refusal (log: $(cat "$scratch/missing.out"))"
pass "unset SHELLSENTRY_RELEASE_TAG is refused"

if make -s release-notes SHELLSENTRY_RELEASE_TAG=v0.0.0 >"$scratch/ver.out" 2>&1; then
	fail "make release-notes with a tag that is not v$(VERSION) must be refused"
fi
grep -q "must equal v${file_version}" "$scratch/ver.out" ||
	fail "VERSION mismatch refusal (log: $(cat "$scratch/ver.out"))"
pass "SHELLSENTRY_RELEASE_TAG must equal v\$(VERSION)"

# Command line: RELEASE_TAG=... is a defined input.
if make -s release-notes RELEASE_TAG=v0.0.0 "SHELLSENTRY_RELEASE_TAG=v${file_version}" >"$scratch/rt.out" 2>&1; then
	fail "make release-notes RELEASE_TAG=... must be refused"
fi
grep -qi 'RELEASE_TAG is not accepted' "$scratch/rt.out" ||
	fail "refusal must name RELEASE_TAG (log: $(cat "$scratch/rt.out"))"
pass "command-line RELEASE_TAG is refused"

if make -s release-notes RELEASE_TAG= "SHELLSENTRY_RELEASE_TAG=v${file_version}" >"$scratch/empty-rt.out" 2>&1; then
	fail "make RELEASE_TAG= must be refused"
fi
grep -qi 'RELEASE_TAG is not accepted' "$scratch/empty-rt.out" ||
	fail "empty RELEASE_TAG= refusal (log: $(cat "$scratch/empty-rt.out"))"
pass "empty command-line RELEASE_TAG is refused"

# Environment: inherited RELEASE_TAG must be refused (origin=environment).
if env RELEASE_TAG=v0.0.0 SHELLSENTRY_RELEASE_TAG="v${file_version}" \
	make -s release-notes >"$scratch/env.out" 2>&1; then
	fail "inherited RELEASE_TAG must be refused"
fi
grep -qi 'RELEASE_TAG is not accepted' "$scratch/env.out" ||
	fail "env RELEASE_TAG refusal (log: $(cat "$scratch/env.out"))"
pass "environment RELEASE_TAG is refused"

if env -u SHELLSENTRY_RELEASE_TAG -u RELEASE_TAG make -s release-tag >"$scratch/tag-missing.out" 2>&1; then
	fail "make release-tag without SHELLSENTRY_RELEASE_TAG must be refused"
fi
grep -q 'SHELLSENTRY_RELEASE_TAG required' "$scratch/tag-missing.out" ||
	fail "release-tag missing-tag refusal (log: $(cat "$scratch/tag-missing.out"))"
pass "make release-tag does not tag without SHELLSENTRY_RELEASE_TAG"

if env -u SHELLSENTRY_RELEASE_TAG -u RELEASE_TAG make -s release-preflight >"$scratch/preflight-missing.out" 2>&1; then
	fail "make release-preflight without SHELLSENTRY_RELEASE_TAG must be refused"
fi
grep -q 'SHELLSENTRY_RELEASE_TAG required' "$scratch/preflight-missing.out" ||
	fail "release-preflight missing-tag refusal (log: $(cat "$scratch/preflight-missing.out"))"
pass "make release-preflight requires SHELLSENTRY_RELEASE_TAG"

grep -q 'release-verify-committed-anchors.sh' "$ROOT/scripts/release-preflight.sh" ||
	fail "release-preflight.sh must run release-verify-committed-anchors.sh"
grep -q 'resolve_release_decernor' "$ROOT/scripts/release-preflight.sh" ||
	fail "release-preflight.sh must bind SHELLSENTRY_DECERNOR_BIN"
if env -u SHELLSENTRY_DECERNOR_BIN -u RELEASE_TAG SHELLSENTRY_RELEASE_TAG="v${file_version}" \
	make -s release-preflight >"$scratch/pf-dec.out" 2>&1; then
	fail "make release-preflight without SHELLSENTRY_DECERNOR_BIN must be refused"
fi
grep -q 'SHELLSENTRY_DECERNOR_BIN is required' "$scratch/pf-dec.out" ||
	fail "preflight Decernor refusal (log: $(cat "$scratch/pf-dec.out"))"
pass "make release-preflight fails closed without SHELLSENTRY_DECERNOR_BIN"

grep -E '^release-verify-keys:' -A6 Makefile | grep -q 'release-verify-committed-anchors.sh' ||
	fail "release-verify-keys must run release-verify-committed-anchors.sh"
grep -E '^release-verify-keys:' -A6 Makefile | grep -q 'release-verify-staged-keys.sh' ||
	fail "release-verify-keys must run release-verify-staged-keys.sh"
grep -E '^release-verify-keys:' -A6 Makefile | grep -q 'SHELLSENTRY_RELEASE_TAG' ||
	fail "release-verify-keys must pass the tag to release-verify-staged-keys.sh"
if grep -E '^release-verify-keys:' -A20 Makefile | grep -q '\[skip\] No minisign'; then
	fail "release-verify-keys must not skip a missing staged minisign key"
fi
if env -u SHELLSENTRY_DECERNOR_BIN -u RELEASE_TAG SHELLSENTRY_RELEASE_TAG="v${file_version}" \
	make -s release-verify-keys >"$scratch/vk-dec.out" 2>&1; then
	fail "make release-verify-keys without SHELLSENTRY_DECERNOR_BIN must be refused"
fi
grep -q 'SHELLSENTRY_DECERNOR_BIN is required' "$scratch/vk-dec.out" ||
	fail "release-verify-keys Decernor refusal (log: $(cat "$scratch/vk-dec.out"))"
pass "make release-verify-keys fails closed without SHELLSENTRY_DECERNOR_BIN"

python3 - "$ROOT/Makefile" <<'PY' || fail "release-tag-tests must stay macOS-safe (no linux_amd64 Decernor download)"
from pathlib import Path
import re, sys
text = Path(sys.argv[1]).read_text()
m = re.search(r'(?ms)^release-tag-tests:.*?^\S', text)
if not m:
    raise SystemExit('release-tag-tests target missing')
body = m.group(0)
if 'test-release-decernor' not in body or 'test-release-stage-tagged-pubkeys' not in body:
    raise SystemExit('release-tag-tests must run ceremony binding and tagged-blob staging tests')
if 'test-release-verify-staged-keys' not in body:
    raise SystemExit('release-tag-tests must run test-release-verify-staged-keys')
if 'test-verify-signatures' not in body:
    raise SystemExit('release-tag-tests must run test-verify-signatures')
if 'test-release-verify-tag-anchor' not in body:
    raise SystemExit('release-tag-tests must run test-release-verify-tag-anchor')
if 'test-release-create-draft' not in body:
    raise SystemExit('release-tag-tests must run test-release-create-draft')
if 'ci-install-decernor' in body or 'test-release-verify-committed-anchors' in body:
    raise SystemExit('release-tag-tests must not download linux_amd64 Decernor')
mut = body.replace('test-release-decernor', 'test-ci-install-decernor', 1)
if 'ci-install-decernor' not in mut:
    raise SystemExit('linux_amd64 download mutant was not distinguished')
PY
pass "release-tag-tests is macOS-safe and still covers ceremony binding"

echo "[ok] Makefile SHELLSENTRY_RELEASE_TAG-only"
