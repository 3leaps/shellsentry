#!/usr/bin/env bash
# Bind staged archives to the signed tag. vcs.revision must equal the tagged
# commit, vcs.modified must be false, and go version -m `mod` must equal the
# tag exactly (Go 1.24+ records vX.Y.Z for a clean tagged build).
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
command -v go >/dev/null 2>&1 || die 'go is required to bind archives to the signed tag'
command -v python3 >/dev/null 2>&1 || die 'python3 is required to bind archives to the signed tag'
[[ -d "$src" && ! -L "$src" ]] || die "source dir not found: $src"
root="$(cd "$(dirname "$0")/.." && pwd -P)"
commit="$(git -C "$root" rev-parse --verify --quiet "${tag}^{commit}")" || die "cannot peel tagged commit $tag"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die 'tagged commit is malformed'
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
	info="$(go version -m "$bin" 2>/dev/null)" || die "$archive is not a Go binary"
	if ! python3 - "$tag" "$commit" "$info" <<'PY'
import sys

tag, full_commit, info = sys.argv[1], sys.argv[2], sys.argv[3]
mod = None
vcs_revision = None
vcs_modified = None
for raw in info.splitlines():
    line = raw.strip()
    parts = line.split("\t")
    if parts and parts[0] == "mod" and len(parts) >= 3:
        mod = parts[2]
    elif line.startswith("build\tvcs.revision="):
        vcs_revision = line.split("=", 1)[1]
    elif line.startswith("build\tvcs.modified="):
        vcs_modified = line.split("=", 1)[1]

if mod != tag:
    raise SystemExit("error: archive mod version is not " + tag)
if vcs_revision != full_commit:
    raise SystemExit("error: archive vcs.revision is not the tagged commit")
if vcs_modified != "false":
    raise SystemExit("error: archive vcs.modified is not false")
PY
	then
		die "archive $archive is not bound to signed tag $tag (mod $tag commit $commit)"
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
echo "[ok] archives bound to $tag (mod $tag commit $commit)"
