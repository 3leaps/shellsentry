#!/usr/bin/env bash
# Public keys stage from git cat-file of the tagged commit, byte-exact.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
repo="$scratch/repo"
git init -q -b main "$repo"
git -C "$repo" config user.name Fixture
git -C "$repo" config user.email fixture@example.invalid
git -C "$repo" config commit.gpgsign false
mkdir -p "$repo/docs/security" "$repo/scripts" "$scratch/dest"
printf 'untrusted comment: fixture minisign\nRWTfixturekeyblobAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' \
	>"$repo/docs/security/shellsentry-minisign.pub"
cat >"$repo/docs/security/release-signing-keys.asc" <<'ASC'
-----BEGIN PGP PUBLIC KEY BLOCK-----

fixture
-----END PGP PUBLIC KEY BLOCK-----
ASC
cp "$root/scripts/release-stage-tagged-pubkeys.sh" "$repo/scripts/"
git -C "$repo" add docs/security scripts
git -C "$repo" commit -qm fixture
git -C "$repo" tag -am 'v1.2.3' v1.2.3
(cd "$repo" && ./scripts/release-stage-tagged-pubkeys.sh v1.2.3 "$scratch/dest")
cmp -s "$repo/docs/security/shellsentry-minisign.pub" "$scratch/dest/shellsentry-minisign.pub"
cmp -s "$repo/docs/security/release-signing-keys.asc" "$scratch/dest/shellsentry-release-signing-key.asc"
# A later working-tree edit must not change what a retag of the same name would
# stage: the command reads the tagged blob, not the dirty tree.
printf 'untrusted comment: dirty working tree\nRWTfixturekeyblobAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' \
	>"$repo/docs/security/shellsentry-minisign.pub"
(cd "$repo" && ./scripts/release-stage-tagged-pubkeys.sh v1.2.3 "$scratch/dest")
git -C "$repo" show v1.2.3:docs/security/shellsentry-minisign.pub >"$scratch/tagged.pub"
cmp -s "$scratch/tagged.pub" "$scratch/dest/shellsentry-minisign.pub" || {
	echo 'error: staging followed the dirty working tree' >&2
	exit 1
}
# Mutant: cp from the working tree instead of cat-file must fail this check.
if ! python3 - "$root/scripts/release-stage-tagged-pubkeys.sh" "$scratch/mutant.sh" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
if 'cat-file blob' not in text:
    raise SystemExit('live script does not read tagged blobs')
mut = text.replace('git -C "$root" cat-file blob "$commit:$path" >"$expected"',
                   'cp "$root/$path" "$expected"')
if 'cat-file blob' in mut:
    raise SystemExit('mutant still uses cat-file')
Path(sys.argv[2]).write_text(mut)
PY
then
	echo 'error: working-tree copy mutant was not distinguished' >&2
	exit 1
fi
chmod +x "$scratch/mutant.sh"
cp "$scratch/mutant.sh" "$repo/scripts/release-stage-tagged-pubkeys.sh"
(cd "$repo" && ./scripts/release-stage-tagged-pubkeys.sh v1.2.3 "$scratch/dest")
if cmp -s "$scratch/tagged.pub" "$scratch/dest/shellsentry-minisign.pub"; then
	echo 'error: working-tree copy mutant still staged the tagged blob' >&2
	exit 1
fi
echo '[ok] public keys stage byte-exact from the tagged commit'
