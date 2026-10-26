#!/usr/bin/env bash
# Bind staged archives to the signed tag. vcs.revision must equal the tagged
# commit, vcs.modified must be false, and the ldflag version must be an exact
# delimited match (left not a digit, right NUL) so 11.2.3 does not satisfy 1.2.3.
# Usage: release-bind-archives.sh vX.Y.Z [source_dir]
set -euo pipefail
die() {
	echo "error: $*" >&2
	exit 1
}
tag="${1:-}"
src="${2:-dist/release}"
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
	die 'usage: release-bind-archives.sh vX.Y.Z [source_dir]'
version="${tag#v}"
command -v go >/dev/null 2>&1 || die 'go is required to bind archives to the signed tag'
command -v python3 >/dev/null 2>&1 || die 'python3 is required to bind archives to the signed tag'
[[ -d "$src" && ! -L "$src" ]] || die "source dir not found: $src"
root="$(cd "$(dirname "$0")/.." && pwd -P)"
commit="$(git -C "$root" rev-parse --verify --quiet "${tag}^{commit}")" || die "cannot peel tagged commit $tag"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die 'tagged commit is malformed'
# Short physical /tmp: macOS TMPDIR under /var/folders overflows nothing here,
# but keep the helper consistent with the other ceremony scripts.
work="$(mktemp -d /tmp/shs-ba.XXXXXX)"
work="$(CDPATH= cd -P -- "$work" && pwd -P)"
trap 'rm -rf "$work"' EXIT

bind_archive() {
	local archive="$1" dest="$work/extract"
	rm -rf "$dest"
	mkdir -p "$dest"
	if ! python3 - "$src/$archive" "$dest/shellsentry" <<'PY'
import pathlib
import sys
import tarfile
import zipfile

archive = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
wanted = {"shellsentry", "shellsentry.exe"}
data = None
if archive.name.endswith(".tar.gz"):
    with tarfile.open(archive, "r:gz") as tf:
        members = [m for m in tf.getmembers() if pathlib.Path(m.name).name in wanted and m.isfile()]
        if len(members) != 1:
            raise SystemExit(f"error: {archive.name} must contain exactly one shellsentry binary")
        extracted = tf.extractfile(members[0])
        if extracted is None:
            raise SystemExit(f"error: {archive.name} member is not readable")
        data = extracted.read()
elif archive.name.endswith(".zip"):
    with zipfile.ZipFile(archive) as zf:
        members = [n for n in zf.namelist() if pathlib.Path(n).name in wanted and not n.endswith("/")]
        if len(members) != 1:
            raise SystemExit(f"error: {archive.name} must contain exactly one shellsentry binary")
        data = zf.read(members[0])
else:
    raise SystemExit(f"error: unrecognized archive {archive.name}")
out.write_bytes(data)
PY
	then
		die "failed to extract $archive"
	fi
	bin="$dest/shellsentry"
	[[ -s "$bin" ]] || die "no shellsentry binary in $archive"
	# Prefer go version -m: vcs.revision is the full 40-char tag commit and
	# vcs.modified is false. Production ldflags still inject a short
	# gitCommit, and a 40-char hash in another -X (buildTime) is not a bind.
	# Version is matched as an exact delimited ldflag string (left and right
	# boundaries), so 11.2.3 does not satisfy tag 1.2.3.
	info="$(go version -m "$bin" 2>/dev/null)" || die "$archive is not a Go binary"
	if ! python3 - "$bin" "$version" "$commit" "$info" <<'PY'
from pathlib import Path
import sys

data = Path(sys.argv[1]).read_bytes()
version, full_commit, info = sys.argv[2], sys.argv[3], sys.argv[4]


def is_hex_digit(byte: int) -> bool:
    return 48 <= byte <= 57 or 65 <= byte <= 70 or 97 <= byte <= 102


def delimited(value: str) -> bool:
    needle = value.encode("ascii")
    n = len(needle)
    hex_token = len(value) == 40 and all(c in "0123456789abcdefABCDEF" for c in value)
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            return False
        if hex_token:
            left_ok = i == 0 or not is_hex_digit(data[i - 1])
            right_ok = i + n == len(data) or data[i + n] == 0 or not is_hex_digit(data[i + n])
        else:
            # Version ldflag is a Go string: right boundary is NUL, left is
            # not a digit, so 11.2.3 does not satisfy tag 1.2.3.
            left_ok = i == 0 or not (48 <= data[i - 1] <= 57)
            right_ok = i + n == len(data) or data[i + n] == 0
        if left_ok and right_ok:
            return True
        start = i + 1


vcs_revision = None
vcs_modified = None
for raw in info.splitlines():
    line = raw.strip()
    if line.startswith("build\tvcs.revision="):
        vcs_revision = line.split("=", 1)[1]
    elif line.startswith("build\tvcs.modified="):
        vcs_modified = line.split("=", 1)[1]

if not delimited(version):
    raise SystemExit("error: archive is not bound to tag version " + version)
if vcs_revision != full_commit:
    raise SystemExit("error: archive vcs.revision is not the tagged commit")
if vcs_modified != "false":
    raise SystemExit("error: archive vcs.modified is not false")
PY
	then
		die "archive $archive is not bound to signed tag $tag (version $version commit $commit)"
	fi
}
for archive in \
	shellsentry_linux_amd64.tar.gz \
	shellsentry_linux_arm64.tar.gz \
	shellsentry_windows_amd64.zip \
	shellsentry_windows_arm64.zip \
	shellsentry_darwin_arm64.tar.gz
do
	[[ -f "$src/$archive" && -s "$src/$archive" && ! -L "$src/$archive" ]] ||
		die "missing release file: $archive"
	bind_archive "$archive"
done
echo "[ok] archives bound to $tag (version $version commit $commit)"
