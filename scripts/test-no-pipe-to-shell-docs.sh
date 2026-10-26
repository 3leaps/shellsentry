#!/usr/bin/env bash
# Fail if user-facing docs recommend curl | bash installs, a bare
# `sha256sum -c` with no file, or an installer run that is not chained to
# signature and checksum checks.
#
# Pattern names like `curl | bash` without a URL, and `curl | shellsentry`,
# are allowed. Analysis examples that are not install recipes are allowed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
pass() { echo "PASS: $*"; }

# curl + URL + install-*.sh + pipe to a shell.
PIPE_PATTERN='curl[^|[:cntrl:]]*https?://[^|[:cntrl:]]*install-[^|[:cntrl:]]*\|[[:space:]]*(bash|sh|zsh|dash)\b'
PIPE_PATTERN_POSIX='curl[^|]*https?://[^|]*install-[^|]*[|][[:space:]]*(bash|sh|zsh|dash)([^a-zA-Z]|$)'
# GNU sha256sum -c with no file/stdin token. `sha256sum -c -` is the portable form.
BARE_SHA_PATTERN='sha256sum[[:space:]]+-c[[:space:]]*$'

SCAN_PATHS=(
    README.md
    CHANGELOG.md
    RELEASE_NOTES.md
    RELEASE_CHECKLIST.md
    docs
    scripts/install-shellsentry.sh
    internal/selfupdate/verify.go
)

have_rg=0
if command -v rg >/dev/null 2>&1; then
    have_rg=1
elif ! command -v grep >/dev/null 2>&1; then
    fail "ripgrep (rg) or grep required"
fi

scan_pipe() {
    local target="$1"
    if [ "$have_rg" -eq 1 ]; then
        rg -n --glob '!scripts/test-no-pipe-to-shell-docs.sh' "$PIPE_PATTERN" "$target" || true
    elif [ -d "$target" ]; then
        grep -rEn --include='*' "$PIPE_PATTERN_POSIX" "$target" || true
    else
        grep -nE "$PIPE_PATTERN_POSIX" "$target" || true
    fi
}

scan_bare_sha() {
    local target="$1"
    if [ "$have_rg" -eq 1 ]; then
        rg -n --glob '!scripts/test-no-pipe-to-shell-docs.sh' "$BARE_SHA_PATTERN" "$target" || true
    elif [ -d "$target" ]; then
        grep -rEn --include='*' "$BARE_SHA_PATTERN" "$target" || true
    else
        grep -nE "$BARE_SHA_PATTERN" "$target" || true
    fi
}

found_pipe_in() {
    local out
    out="$(scan_pipe "$1")"
    [ -n "$out" ]
}

found_bare_sha_in() {
    local out
    out="$(scan_bare_sha "$1")"
    [ -n "$out" ]
}

# Returns 0 if a ```bash block that runs bash install-*.sh is missing set -e
# (or && before the run), a signature check, or a portable checksum.
block_unchained() {
    local file="$1"
    python3 - "$file" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
blocks = re.findall(r"```bash\n(.*?)```", text, flags=re.S)
run = re.compile(r"bash\s+install-(?:shellsentry|sfetch)\.sh")
for block in blocks:
    if not run.search(block):
        continue
    chained = bool(re.search(r"set\s+-e", block)) or bool(
        re.search(r"&&\s*bash\s+install-(?:shellsentry|sfetch)\.sh", block)
    )
    signed = bool(re.search(r"minisign\s+-Vm", block)) or bool(
        re.search(r"gpg\s+--verify", block)
    )
    checksum = bool(re.search(r"sha256sum\s+-c\s+-", block)) or bool(
        re.search(r"shasum\s+-a\s+256\s+-c", block)
    )
    if not (chained and signed and checksum):
        sys.exit(0)
sys.exit(1)
PY
}

scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-nopipe-docs.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

# Revert proof: restoring the v0.1.8 curl|bash upgrade line must be caught.
printf '%s\n' \
    'curl -sSfL https://github.com/3leaps/shellsentry/releases/download/v0.1.8/install-shellsentry.sh | bash -s -- --tag v0.1.8' \
    >"$scratch/reverted.md"
if found_pipe_in "$scratch/reverted.md"; then
    pass "scanner catches a reverted curl | bash install line"
else
    fail "scanner missed a reverted curl | bash install line"
fi
printf '%s\n' 'curl -fsSL https://example.com/install.sh | shellsentry' >"$scratch/analyze.md"
if found_pipe_in "$scratch/analyze.md"; then
    fail "scanner must not flag curl piped to shellsentry"
fi
printf '%s\n' '- `curl | bash` / `wget | sh` patterns' >"$scratch/name.md"
if found_pipe_in "$scratch/name.md"; then
    fail "scanner must not flag a pattern name without a URL"
fi
pass "scanner allows curl | shellsentry and pattern-name mentions"

# Revert proof: bare sha256sum -c with no file must be caught.
printf '%s\n' "grep 'install-shellsentry.sh' SHA256SUMS | sha256sum -c" >"$scratch/bare-sha.md"
if found_bare_sha_in "$scratch/bare-sha.md"; then
    pass "scanner catches a reverted bare sha256sum -c"
else
    fail "scanner missed a reverted bare sha256sum -c"
fi
printf '%s\n' "grep 'install-shellsentry.sh' SHA256SUMS | sha256sum -c -" >"$scratch/ok-sha.md"
if found_bare_sha_in "$scratch/ok-sha.md"; then
    fail "scanner must not flag sha256sum -c -"
fi
pass "scanner allows sha256sum -c -"

# Revert proof: installer run without chained checks must be caught.
cat >"$scratch/unchained.md" <<'MD'
```bash
minisign -Vm SHA256SUMS -P RWTqUZ/PtmfAbQ3RKIlp/YTKT6zFeNMAZ8iAMelhlmqEsVqjKj3ctSA1
grep 'install-shellsentry.sh' SHA256SUMS | sha256sum -c -
bash install-shellsentry.sh --tag v0.1.8
```
MD
if block_unchained "$scratch/unchained.md"; then
    pass "scanner catches an unchained installer run"
else
    fail "scanner missed an unchained installer run"
fi
cat >"$scratch/chained.md" <<'MD'
```bash
set -euo pipefail
minisign -Vm SHA256SUMS -P RWTqUZ/PtmfAbQ3RKIlp/YTKT6zFeNMAZ8iAMelhlmqEsVqjKj3ctSA1
grep 'install-shellsentry.sh' SHA256SUMS | sha256sum -c -
bash install-shellsentry.sh --tag v0.1.8
```
MD
if block_unchained "$scratch/chained.md"; then
    fail "scanner must not flag a set -e install block"
fi
pass "scanner allows a set -e chained install block"

# Live tree must be clean.
pipe_hits=""
sha_hits=""
unchained_hits=""
for p in "${SCAN_PATHS[@]}"; do
    [ -e "$p" ] || fail "scan path missing: $p"
    chunk="$(scan_pipe "$p")"
    if [ -n "$chunk" ]; then
        pipe_hits="${pipe_hits}${chunk}"$'\n'
    fi
    chunk="$(scan_bare_sha "$p")"
    if [ -n "$chunk" ]; then
        sha_hits="${sha_hits}${chunk}"$'\n'
    fi
    if [ -d "$p" ]; then
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            if block_unchained "$f"; then
                unchained_hits="${unchained_hits}${f}"$'\n'
            fi
        done < <(find "$p" -type f -name '*.md' -print)
    elif [[ "$p" == *.md ]]; then
        if block_unchained "$p"; then
            unchained_hits="${unchained_hits}${p}"$'\n'
        fi
    fi
done
if [ -n "$pipe_hits" ]; then
    printf '%s' "$pipe_hits" >&2
    fail "docs must not recommend curl piped to a shell"
fi
pass "no curl | bash/sh install recipes in scanned docs"
if [ -n "$sha_hits" ]; then
    printf '%s' "$sha_hits" >&2
    fail "docs must not use sha256sum -c without a file or stdin token"
fi
pass "no bare sha256sum -c in scanned docs"
if [ -n "$unchained_hits" ]; then
    printf '%s' "$unchained_hits" >&2
    fail "install blocks must chain signature and checksum checks before the run"
fi
pass "install blocks chain signature, checksum, and run"

[[ ! -e configs/keys/release-signing-keys.asc ]] ||
    fail "configs/keys/release-signing-keys.asc must not exist; SSOT is docs/security/release-signing-keys.asc"
[[ ! -e configs/keys/shellsentry-minisign.pub ]] ||
    fail "configs/keys/shellsentry-minisign.pub must not exist; embed docs/security/shellsentry-minisign.pub"
pass "duplicate configs/keys pins are absent"
PINNED_PGP_PRIMARY='0CACA49B3119B6BC12B2CA11B9B485F294B9FE07'
pgp_recipe_ok() {
    local file="$1"
    grep -q 'curl -sSfLO "$BASE/shellsentry-release-signing-key.asc"' "$file" &&
        grep -q 'gpg --show-keys --with-fingerprint shellsentry-release-signing-key.asc' "$file" &&
        grep -q 'gpg --show-keys --with-colons shellsentry-release-signing-key.asc' "$file" &&
        grep -q "$PINNED_PGP_PRIMARY" "$file" &&
        grep -q "error: PGP key is not the pinned primary" "$file" &&
        grep -q 'gpg --import shellsentry-release-signing-key.asc' "$file" &&
        ! grep -q 'gpg --import docs/security/' "$file" &&
        ! grep -q 'gpg --import configs/keys/' "$file"
}
pgp_recipe_ok README.md || fail "README PGP step must fetch and pin-check the release key"
pgp_recipe_ok docs/releases/v0.1.8.md ||
    fail "v0.1.8 notes PGP step must fetch and pin-check the release key"
if grep -n 'gpg --import configs/keys/' README.md docs/releases/v0.1.8.md; then
    fail "current install docs must not import the GPG pin from configs/keys"
fi
# v0.1.8 section of RELEASE_NOTES (before ## v0.1.7) must match the fetch recipe.
python3 - "$ROOT/RELEASE_NOTES.md" "$PINNED_PGP_PRIMARY" <<'PY' || fail "RELEASE_NOTES v0.1.8 PGP step must fetch and pin-check the release key"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
pin = sys.argv[2]
start = text.find("## v0.1.8")
end = text.find("## v0.1.7")
if start < 0 or end < 0 or end <= start:
    raise SystemExit("RELEASE_NOTES.md missing v0.1.8 before v0.1.7")
sec = text[start:end]
if 'curl -sSfLO "$BASE/shellsentry-release-signing-key.asc"' not in sec:
    raise SystemExit("v0.1.8 section does not fetch the release key asset")
if "gpg --show-keys --with-fingerprint shellsentry-release-signing-key.asc" not in sec:
    raise SystemExit("v0.1.8 section does not show the fetched key fingerprint")
if "gpg --show-keys --with-colons shellsentry-release-signing-key.asc" not in sec:
    raise SystemExit("v0.1.8 section does not read the colon fingerprint")
if pin not in sec:
    raise SystemExit("v0.1.8 section does not pin the primary fingerprint")
if "error: PGP key is not the pinned primary" not in sec:
    raise SystemExit("v0.1.8 section does not refuse a fingerprint mismatch")
if "gpg --import shellsentry-release-signing-key.asc" not in sec:
    raise SystemExit("v0.1.8 section does not import the fetched key")
if "gpg --import docs/security/" in sec or "gpg --import configs/keys/" in sec:
    raise SystemExit("v0.1.8 section still imports a checkout path")
PY
pass "current PGP install steps fetch the release key and pin the primary"

python3 - "$ROOT/docs/releases/v0.1.8.md" "$scratch/checkout-import.md" <<'PY' || fail "checkout-import mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = '''# curl -sSfLO "$BASE/shellsentry-release-signing-key.asc"
# gpg --show-keys --with-fingerprint shellsentry-release-signing-key.asc
# fpr=$(gpg --show-keys --with-colons shellsentry-release-signing-key.asc | awk -F: '$1=="fpr" {print $10; exit}')
# [ "$fpr" = 0CACA49B3119B6BC12B2CA11B9B485F294B9FE07 ] || { echo 'error: PGP key is not the pinned primary' >&2; exit 1; }
# gpg --import shellsentry-release-signing-key.asc'''
new = "# gpg --import docs/security/release-signing-keys.asc"
if old not in text:
    raise SystemExit("live v0.1.8 notes are missing the pinned PGP fetch")
mut = text.replace(old, new, 1)
if "gpg --import docs/security/" not in mut:
    raise SystemExit("mutant did not restore a checkout import")
dest.write_text(mut)
PY
if pgp_recipe_ok "$scratch/checkout-import.md"; then
    fail "accepted v0.1.8 notes after restoring a checkout PGP import"
fi
pass "checkout PGP import mutant is distinguished"

python3 - "$ROOT/docs/releases/v0.1.8.md" "$scratch/tofu-import.md" <<'PY' || fail "trust-on-first-use PGP mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = '''# gpg --show-keys --with-fingerprint shellsentry-release-signing-key.asc
# fpr=$(gpg --show-keys --with-colons shellsentry-release-signing-key.asc | awk -F: '$1=="fpr" {print $10; exit}')
# [ "$fpr" = 0CACA49B3119B6BC12B2CA11B9B485F294B9FE07 ] || { echo 'error: PGP key is not the pinned primary' >&2; exit 1; }
# gpg --import shellsentry-release-signing-key.asc'''
new = "# gpg --import shellsentry-release-signing-key.asc"
if old not in text:
    raise SystemExit("live v0.1.8 notes are missing the fingerprint pin check")
mut = text.replace(old, new, 1)
if "error: PGP key is not the pinned primary" in mut:
    raise SystemExit("mutant still refuses a fingerprint mismatch")
if "gpg --show-keys --with-fingerprint" in mut:
    raise SystemExit("mutant still shows the fingerprint")
dest.write_text(mut)
PY
if pgp_recipe_ok "$scratch/tofu-import.md"; then
    fail "accepted v0.1.8 notes after dropping the fingerprint pin check"
fi
pass "trust-on-first-use PGP import mutant is distinguished"

echo "[ok] no pipe-to-shell install docs"
