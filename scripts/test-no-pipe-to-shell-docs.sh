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
    ) or bool(re.search(r"\bgpgv\b", block))
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
PINNED_PGP_SUBKEY='DAB70DD758911B26BB45A08C3B75AC591449DEBE'
pgp_recipe_ok() {
    local file="$1"
    grep -q 'curl -sSfLO "$BASE/shellsentry-release-signing-key.asc"' "$file" &&
        grep -q 'gpg --show-keys --with-fingerprint shellsentry-release-signing-key.asc' "$file" &&
        grep -q 'gpg --show-keys --with-colons shellsentry-release-signing-key.asc' "$file" &&
        grep -q '$1=="pub" || $1=="sec"' "$file" &&
        grep -q '\[ "$n" = 1 \]' "$file" &&
        grep -q "$PINNED_PGP_PRIMARY" "$file" &&
        grep -q "error: PGP key is not the pinned primary" "$file" &&
        grep -q 'gpgv --keyring ./shellsentry-release-signing-key.gpg' "$file" &&
        grep -q "VALIDSIG ${PINNED_PGP_SUBKEY} " "$file" &&
        grep -q "error: PGP signature is not from the pinned signing subkey" "$file" &&
        ! grep -q 'gpg --import shellsentry-release-signing-key.asc' "$file" &&
        ! grep -q 'gpg --import docs/security/' "$file" &&
        ! grep -q 'gpg --import configs/keys/' "$file"
}
pgp_recipe_ok README.md || fail "README PGP step must fetch, count primaries, and bind the signer"
pgp_recipe_ok docs/releases/v0.1.7.md || fail "v0.1.7 notes must bind the signer"
pgp_recipe_ok docs/releases/v0.1.8.md ||
    fail "v0.1.8 notes PGP step must fetch, count primaries, and bind the signer"
if grep -n 'gpg --import configs/keys/' README.md docs/releases/v0.1.8.md; then
    fail "current install docs must not import the GPG pin from configs/keys"
fi
# v0.1.8 section of RELEASE_NOTES (before ## v0.1.7) must match the fetch recipe.
python3 - "$ROOT/RELEASE_NOTES.md" "$PINNED_PGP_PRIMARY" "$PINNED_PGP_SUBKEY" <<'PY' || fail "RELEASE_NOTES v0.1.8 PGP step must fetch, count primaries, and bind the signer"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
pin, sub = sys.argv[2], sys.argv[3]
start = text.find("## v0.1.8")
end = text.find("## v0.1.7")
if start < 0 or end < 0 or end <= start:
    raise SystemExit("RELEASE_NOTES.md missing v0.1.8 before v0.1.7")
sec = text[start:end]
historical = text[end:text.find("## v0.1.6", end)]
need = [
    'curl -sSfLO "$BASE/shellsentry-release-signing-key.asc"',
    "gpg --show-keys --with-fingerprint shellsentry-release-signing-key.asc",
    "gpg --show-keys --with-colons shellsentry-release-signing-key.asc",
    '$1=="pub" || $1=="sec"',
    '[ "$n" = 1 ]',
    pin,
    "error: PGP key is not the pinned primary",
    "gpgv --keyring ./shellsentry-release-signing-key.gpg",
    f"VALIDSIG {sub} ",
    "error: PGP signature is not from the pinned signing subkey",
]
for item in need:
    if item not in historical:
        raise SystemExit(f"v0.1.7 section missing {item!r}")
    if item not in sec:
        raise SystemExit(f"v0.1.8 section missing {item!r}")
if "gpg --import shellsentry-release-signing-key.asc" in sec:
    raise SystemExit("v0.1.8 section still imports into the default keyring")
if "gpg --import docs/security/" in sec or "gpg --import configs/keys/" in sec:
    raise SystemExit("v0.1.8 section still imports a checkout path")
PY
pass "current PGP install steps fetch the release key, require one primary, and bind the signer"

python3 - "$ROOT/README.md" "$ROOT/docs/releases/v0.1.8.md" "$ROOT/RELEASE_NOTES.md" \
    "$scratch/pgp-diverge.md" <<'PY' || fail "PGP recipe copies are not byte-identical"
from pathlib import Path
import sys

def pgp_block(text, start=0):
    i = text.find("# PGP instead of minisign:", start)
    if i < 0:
        raise SystemExit("missing PGP recipe")
    lines = []
    for line in text[i:].splitlines():
        if line.startswith("# PGP") or line.startswith("# ") or line == "#":
            lines.append(line)
            continue
        break
    if not lines:
        raise SystemExit("empty PGP recipe")
    return "\n".join(lines) + "\n"

readme, notes, relnotes = (Path(p).read_text() for p in sys.argv[1:4])
r18_start, r18_end = relnotes.find("## v0.1.8"), relnotes.find("## v0.1.7")
if r18_start < 0 or r18_end <= r18_start:
    raise SystemExit("RELEASE_NOTES.md missing v0.1.8 before v0.1.7")
blocks = [
    pgp_block(readme),
    pgp_block(notes),
    pgp_block(relnotes, r18_start),
]
if len(set(blocks)) != 1:
    raise SystemExit("PGP recipe copies differ")
mut = notes.replace(blocks[1], blocks[1] + "# gpg --verify SHA256SUMS.asc SHA256SUMS\n", 1)
if pgp_block(mut) == blocks[1]:
    raise SystemExit("divergence mutant was not applied")
Path(sys.argv[4]).write_text(mut)
PY
pass "PGP recipe copies are byte-identical"
if python3 - "$scratch/pgp-diverge.md" "$ROOT/README.md" <<'PY'
from pathlib import Path
import sys

def pgp_block(text, start=0):
    i = text.find("# PGP instead of minisign:", start)
    if i < 0:
        raise SystemExit("missing PGP recipe")
    lines = []
    for line in text[i:].splitlines():
        if line.startswith("# PGP") or line.startswith("# ") or line == "#":
            lines.append(line)
            continue
        break
    return "\n".join(lines) + "\n"

if pgp_block(Path(sys.argv[1]).read_text()) == pgp_block(Path(sys.argv[2]).read_text()):
    raise SystemExit("divergence mutant still matches README")
PY
then
    pass "byte-identical mutant is distinguished"
else
    fail "accepted PGP recipes after diverging one copy"
fi

python3 - "$ROOT/docs/releases/v0.1.8.md" "$scratch/checkout-import.md" <<'PY' || fail "checkout-import mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = '''# curl -sSfLO "$BASE/shellsentry-release-signing-key.asc"
# gpg --show-keys --with-fingerprint shellsentry-release-signing-key.asc'''
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

python3 - "$ROOT/docs/releases/v0.1.8.md" "$scratch/first-fpr.md" <<'PY' || fail "first-fingerprint mutant was not distinguished"
from pathlib import Path
import sys
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
old = '''# listing=$(gpg --show-keys --with-colons shellsentry-release-signing-key.asc)
# n=$(printf '%s\\n' "$listing" | awk -F: '$1=="pub" || $1=="sec" {n++} END {print n+0}')
# fpr=$(printf '%s\\n' "$listing" | awk -F: '$1=="fpr" {print $10; exit}')
# [ "$n" = 1 ] && [ "$fpr" = 0CACA49B3119B6BC12B2CA11B9B485F294B9FE07 ] || { echo 'error: PGP key is not the pinned primary' >&2; exit 1; }'''
new = '''# fpr=$(gpg --show-keys --with-colons shellsentry-release-signing-key.asc | awk -F: '$1=="fpr" {print $10; exit}')
# [ "$fpr" = 0CACA49B3119B6BC12B2CA11B9B485F294B9FE07 ] || { echo 'error: PGP key is not the pinned primary' >&2; exit 1; }'''
if old not in text:
    raise SystemExit("live v0.1.8 notes are missing the one-primary check")
mut = text.replace(old, new, 1)
if '[ "$n" = 1 ]' in mut:
    raise SystemExit("mutant still requires exactly one primary")
dest.write_text(mut)
PY
if pgp_recipe_ok "$scratch/first-fpr.md"; then
    fail "accepted v0.1.8 notes after restoring a first-fingerprint-only check"
fi
pass "first-fingerprint-only mutant is distinguished"

command -v gpg >/dev/null 2>&1 || fail "gpg required for PGP recipe fixtures"
command -v gpgv >/dev/null 2>&1 || fail "gpgv required for PGP recipe fixtures"

gpghome="$scratch/gpg"
mkdir -m 700 "$gpghome"
printf 'allow-loopback-pinentry\ndisable-scdaemon\n' >"$gpghome/gpg-agent.conf"
printf 'pinentry-mode loopback\n' >"$gpghome/gpg.conf"
cleanup_docs() {
    env -u GNUPGHOME gpgconf --homedir "$gpghome" --kill all >/dev/null 2>&1 || true
    env -u GNUPGHOME gpgconf --homedir "$scratch/gpg-bad" --kill all >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup_docs EXIT
export GNUPGHOME="$gpghome"
gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase '' --quick-generate-key \
    'Pinned <pinned@example.invalid>' ed25519 cert 0 \
    || fail "gpg generate-key failed"
listing="$(gpg --batch --with-colons --fingerprint --list-keys)" || fail "gpg list-keys failed"
primary="$(awk -F: '$1=="fpr" {print $10; exit}' <<<"$listing")"
gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase '' --quick-add-key \
    "$primary" ed25519 sign 0 \
    || fail "gpg add signing subkey failed"
listing="$(gpg --batch --with-colons --with-subkey-fingerprint --list-keys "$primary")" ||
    fail "gpg list-subkeys failed"
subkey="$(awk -F: '$1=="sub" {s=1; next} s && $1=="fpr" {print $10; exit}' <<<"$listing")"
[[ "$primary" =~ ^[0-9A-F]{40}$ && "$subkey" =~ ^[0-9A-F]{40}$ ]] || fail "fixture signing key missing"
mkdir -m 700 "$scratch/gpg-bad"
printf 'allow-loopback-pinentry\ndisable-scdaemon\n' >"$scratch/gpg-bad/gpg-agent.conf"
printf 'pinentry-mode loopback\n' >"$scratch/gpg-bad/gpg.conf"
bad_gpg() { env -u GNUPGHOME gpg --homedir "$scratch/gpg-bad" "$@"; }
bad_gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase '' \
    --quick-generate-key 'Attacker <attacker@example.invalid>' ed25519 cert 0 \
    || fail "attacker gpg generate-key failed"
bad_listing="$(bad_gpg --batch --with-colons --fingerprint --list-keys)" ||
    fail "attacker list-keys failed"
bad_primary="$(awk -F: '$1=="fpr" {print $10; exit}' <<<"$bad_listing")"
bad_gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase '' \
    --quick-add-key "$bad_primary" ed25519 sign 0 \
    || fail "attacker add signing subkey failed"
bad_listing="$(bad_gpg --batch --with-colons --with-subkey-fingerprint --list-keys "$bad_primary")" ||
    fail "attacker list-subkeys failed"
bad_subkey="$(awk -F: '$1=="sub" {s=1; next} s && $1=="fpr" {print $10; exit}' <<<"$bad_listing")"
gpg --batch --armor --export "$primary" >"$scratch/good.asc"
bad_gpg --batch --armor --export "$bad_primary" >"$scratch/bad.asc"
printf 'fixture sums\n' >"$scratch/SHA256SUMS"
gpg --batch --yes --armor --local-user "$subkey!" --detach-sign \
    -o "$scratch/SHA256SUMS.good.asc" "$scratch/SHA256SUMS"
bad_gpg --batch --yes --armor --local-user "$bad_subkey!" --detach-sign \
    -o "$scratch/SHA256SUMS.bad.asc" "$scratch/SHA256SUMS"

recipe_body="$(python3 - "$ROOT/docs/releases/v0.1.8.md" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
i = text.find("# PGP instead of minisign:")
lines = []
for line in text[i:].splitlines():
    if line.startswith("# PGP") or line.startswith("# ") or line == "#":
        if line.startswith("# "):
            cmd = line[2:]
        else:
            continue
        if cmd.startswith("curl ") or cmd.startswith("PGP instead"):
            continue
        lines.append(cmd)
        continue
    break
print("set -euo pipefail")
print("\n".join(lines))
PY
)"

run_recipe() {
    local key="$1" sig="$2" work="$3"
    rm -rf "$work"
    mkdir -p "$work"
    cp "$key" "$work/shellsentry-release-signing-key.asc"
    cp "$scratch/SHA256SUMS" "$work/SHA256SUMS"
    cp "$sig" "$work/SHA256SUMS.asc"
    printf '%s\n' "$recipe_body" | sed \
        -e "s/${PINNED_PGP_PRIMARY}/${primary}/g" \
        -e "s/${PINNED_PGP_SUBKEY}/${subkey}/g" \
        >"$work/recipe.sh"
    (CDPATH= cd "$work" && bash "$work/recipe.sh")
}

if ! run_recipe "$scratch/good.asc" "$scratch/SHA256SUMS.good.asc" "$scratch/run-ok" \
    >/dev/null 2>"$scratch/run-ok.err"; then
    fail "live PGP recipe must accept the single pinned key (log: $(cat "$scratch/run-ok.err"))"
fi
pass "live PGP recipe accepts the single pinned key"

cat "$scratch/good.asc" "$scratch/bad.asc" >"$scratch/bundle-first.asc"
cat "$scratch/bad.asc" "$scratch/good.asc" >"$scratch/bundle-second.asc"

if run_recipe "$scratch/bundle-first.asc" "$scratch/SHA256SUMS.good.asc" "$scratch/run-first" \
    >/dev/null 2>"$scratch/run-first.err"; then
    fail "accepted a two-key bundle with the pin first"
fi
grep -q "error: PGP key is not the pinned primary" "$scratch/run-first.err" ||
    fail "two-key (pin first) must name the primary refusal (log: $(cat "$scratch/run-first.err"))"
pass "two-key bundle with the pin first is refused"

if run_recipe "$scratch/bundle-second.asc" "$scratch/SHA256SUMS.good.asc" "$scratch/run-second" \
    >/dev/null 2>"$scratch/run-second.err"; then
    fail "accepted a two-key bundle with the pin second"
fi
grep -q "error: PGP key is not the pinned primary" "$scratch/run-second.err" ||
    fail "two-key (pin second) must name the primary refusal (log: $(cat "$scratch/run-second.err"))"
pass "two-key bundle with the pin second is refused"

if run_recipe "$scratch/good.asc" "$scratch/SHA256SUMS.bad.asc" "$scratch/run-bad-sig" \
    >/dev/null 2>"$scratch/run-bad-sig.err"; then
    fail "accepted a signature from a non-pinned key"
fi
grep -Eq "error: PGP signature (verification failed|is not from the pinned signing subkey)" \
    "$scratch/run-bad-sig.err" ||
    fail "non-pinned signer must be refused (log: $(cat "$scratch/run-bad-sig.err"))"
pass "signature from a non-pinned key is refused"

# Revert: first fingerprint only plus gpg --import/--verify. A bundle with the
# pin first plus an attacker signature must then succeed.
python3 - "$ROOT/docs/releases/v0.1.8.md" "$scratch/old-recipe.sh" "$primary" <<'PY' || fail "old-recipe mutant was not built"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
pin = sys.argv[3]
body = f'''set -euo pipefail
gpg --show-keys --with-fingerprint shellsentry-release-signing-key.asc
fpr=$(gpg --show-keys --with-colons shellsentry-release-signing-key.asc | awk -F: '$1=="fpr" {{print $10; exit}}')
[ "$fpr" = {pin} ] || {{ echo 'error: PGP key is not the pinned primary' >&2; exit 1; }}
gpg --import shellsentry-release-signing-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
'''
Path(sys.argv[2]).write_text(body)
PY
old_work="$scratch/run-old"
rm -rf "$old_work"
mkdir -p "$old_work"
cp "$scratch/bundle-first.asc" "$old_work/shellsentry-release-signing-key.asc"
cp "$scratch/SHA256SUMS" "$old_work/SHA256SUMS"
cp "$scratch/SHA256SUMS.bad.asc" "$old_work/SHA256SUMS.asc"
if ! (CDPATH= cd "$old_work" && bash "$scratch/old-recipe.sh") >/dev/null 2>"$scratch/run-old.err"; then
    fail "first-fpr plus gpg --verify must accept pin-first bundle + attacker signature (log: $(cat "$scratch/run-old.err"))"
fi
pass "first-fingerprint plus gpg --verify mutant accepts a pin-first bundle"

echo "[ok] no pipe-to-shell install docs"
