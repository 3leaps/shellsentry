#!/usr/bin/env bash
# Exercise the real Makefile recipe after changing the working-tree installer.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
unset RELEASE_TAG || true
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-bootstrap-script.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

repo="$scratch/repo"
mkdir -p "$repo/scripts" "$scratch/home"
export HOME="$scratch/home" GIT_CONFIG_NOSYSTEM=1
git init -q -b main "$repo"
git -C "$repo" config user.name Fixture
git -C "$repo" config user.email fixture@example.invalid
git -C "$repo" config commit.gpgsign false
cp "$root/Makefile" "$repo/Makefile"
cp "$root/scripts/install-shellsentry.sh" "$repo/scripts/"
printf '1.2.3\n' >"$repo/VERSION"
git -C "$repo" add Makefile VERSION scripts
git -C "$repo" commit -qm fixture
git -C "$repo" -c tag.gpgsign=false tag -am fixture v1.2.3
git -C "$repo" show v1.2.3:scripts/install-shellsentry.sh >"$scratch/tagged-installer"
printf '\n# changed after tagging\n' >>"$repo/scripts/install-shellsentry.sh"
if cmp -s "$scratch/tagged-installer" "$repo/scripts/install-shellsentry.sh"; then
    fail 'fixture installer must differ from the tagged blob'
fi

stage_installer() {
    rm -rf "$repo/dist"
    make -C "$repo" bootstrap-script SHELLSENTRY_RELEASE_TAG=v1.2.3
}
assert_tagged_installer() {
    cmp -s "$scratch/tagged-installer" "$repo/dist/release/install-shellsentry.sh"
}
stage_installer
assert_tagged_installer || fail 'bootstrap-script staged working-tree bytes instead of the tagged blob'
pass 'bootstrap-script stages the tagged installer despite working-tree edits'

# Restore the old copy recipe and rerun the same byte comparison.
python3 - "$repo/Makefile" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
recipe = '\tgit show "$(SHELLSENTRY_RELEASE_TAG)^{commit}:scripts/install-shellsentry.sh" > $(DIST_RELEASE)/install-shellsentry.sh\n'
if text.count(recipe) != 1:
    raise SystemExit('expected exactly one tagged installer recipe')
path.write_text(text.replace(recipe, '\tcp scripts/install-shellsentry.sh $(DIST_RELEASE)/install-shellsentry.sh\n', 1))
PY
stage_installer
if assert_tagged_installer; then
    fail 'old working-tree copy recipe escaped the regression assertion'
fi
cmp -s "$repo/scripts/install-shellsentry.sh" "$repo/dist/release/install-shellsentry.sh" ||
    fail 'old copy recipe did not stage the changed working-tree installer'
pass 'old working-tree copy recipe fails the same tagged-blob assertion'
