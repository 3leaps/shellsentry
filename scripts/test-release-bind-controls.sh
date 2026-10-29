#!/usr/bin/env bash
# Negative controls for the shared draft/publish artifact binding gate.
set -euo pipefail
repo="$1" src="$2"
work="$(mktemp -d "${TMPDIR:-/tmp}/shs-bind-controls.XXXXXX")"
trap 'rm -rf "$work"; git -C "$repo" show v1.2.3:scripts/install-shellsentry.sh >"$repo/scripts/install-shellsentry.sh"' EXIT
for mutant in installer swapped wrong-os extra; do
    rm -rf "$work/stage"
    cp -R "$src" "$work/stage"
    case "$mutant" in
        installer)
            printf '\n# changed after tagging\n' >>"$repo/scripts/install-shellsentry.sh"
            cp "$repo/scripts/install-shellsentry.sh" "$work/stage/install-shellsentry.sh"
            ;;
        swapped) cp "$work/stage/shellsentry_linux_arm64.tar.gz" "$work/stage/shellsentry_linux_amd64.tar.gz" ;;
        wrong-os) cp "$work/stage/shellsentry_darwin_arm64.tar.gz" "$work/stage/shellsentry_linux_arm64.tar.gz" ;;
        extra)
            python3 - "$work/stage/shellsentry_linux_amd64.tar.gz" <<'PY'
import io, pathlib, sys, tarfile
p = pathlib.Path(sys.argv[1])
with tarfile.open(p, 'r:gz') as tf:
    data = tf.extractfile(tf.getmember('shellsentry')).read()
with tarfile.open(p, 'w:gz') as tf:
    for name, content in [('shellsentry', data), ('extra', b'extra')]:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
PY
            ;;
    esac
    if "$repo/scripts/release-bind-archives.sh" v1.2.3 "$work/stage" >"$work/out" 2>&1; then
        echo "FAIL: artifact binding accepted $mutant" >&2
        exit 1
    fi
    case "$mutant" in
        installer) expected='staged installer does not match tagged installer' ;;
        swapped|wrong-os) expected='wrong executable format or architecture' ;;
        extra) expected='must contain exactly one shellsentry binary' ;;
    esac
    grep -q "$expected" "$work/out" || { cat "$work/out" >&2; exit 1; }
    echo "PASS: artifact binding rejects $mutant"
done
