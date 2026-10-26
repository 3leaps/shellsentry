#!/usr/bin/env bash
# Bind staged archives to the signed tag. vcs.revision must equal the tagged
# commit, vcs.modified must be false, and go version -m `mod` must equal the
# tag exactly (Go 1.24+ records vX.Y.Z for a clean tagged build). Those pin
# the source. A byte scan cannot tell which -X variable a string belongs to:
# exactly one delimited match for the tag without the leading v (left not
# alphanumeric, '-' or '_'; right NUL) so 9.9.9, x1.2.3, X1.2.3, 11.2.3,
# 1.2.30, pre-1.2.3, release_1.2.3, and the default "dev" do not satisfy
# 1.2.3; exactly one delimited RFC3339 UTC timestamp that is a real date;
# and exactly one delimited 40-hex tagged commit. Known limit: -X
# github.com/3leaps/shellsentry/internal/cli.Version=1.2.3 with
# -X main.version=9.9.9 still binds while `shellsentry version` prints
# 9.9.9 (self-verify and updates use that reported version). The same holds
# for cli.BuildTime, cli.GitCommit, and swapping buildTime with gitCommit.
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
	if ! python3 - "$bin" "$version" "$tag" "$commit" "$info" <<'PY'
from datetime import datetime
from pathlib import Path
import re
import sys

data = Path(sys.argv[1]).read_bytes()
version, tag, full_commit, info = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]


def version_hits(value: str) -> int:
    # A version label is a Go string: right boundary is NUL. Left must not be
    # alphanumeric, '-' or '_', so 11.2.3, x1.2.3, X1.2.3, pre-1.2.3 and
    # release_1.2.3 do not satisfy tag 1.2.3. Right NUL so 1.2.30 does not.
    # The buildinfo module version is v1.2.3 (left 'v', right TAB) and is not
    # this match. The scan cannot tell which -X variable owns the string.
    needle = value.encode("ascii")
    n = len(needle)
    hits = 0
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            return hits
        left = data[i - 1] if i else 0
        left_ok = i == 0 or not (
            48 <= left <= 57 or 65 <= left <= 90 or 97 <= left <= 122
            or left in (45, 95)
        )
        right_ok = i + n == len(data) or data[i + n] == 0
        if left_ok and right_ok:
            hits += 1
        start = i + 1


def go_string(value: str) -> bool:
    # Mach-O sometimes precedes a Go string with '<' rather than NUL.
    needle = value.encode("ascii")
    n = len(needle)
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            return False
        left_ok = i == 0 or data[i - 1] in (0, 0x3C)
        right_ok = i + n == len(data) or data[i + n] == 0
        if left_ok and right_ok:
            return True
        start = i + 1


def delimited_matches(pattern: bytes) -> list:
    found = []
    for match in re.finditer(pattern, data):
        i, j = match.start(), match.end()
        left_ok = i == 0 or data[i - 1] in (0, 0x3C)
        right_ok = j == len(data) or data[j] == 0
        if left_ok and right_ok:
            found.append(match.group())
    return found


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

hits = version_hits(version)
if hits == 0:
    raise SystemExit("error: archive is not bound to tag version " + version)
if hits != 1:
    raise SystemExit("error: archive version label is not unique")
rfc_hits = delimited_matches(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
if not rfc_hits:
    raise SystemExit("error: archive buildTime is not RFC3339")
if len(rfc_hits) > 1:
    raise SystemExit("error: archive buildTime is not unique")
if rfc_hits:
    try:
        datetime.strptime(rfc_hits[0].decode("ascii"), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise SystemExit("error: archive buildTime is not a real date")
if not go_string(full_commit):
    raise SystemExit("error: archive gitCommit is not the tagged commit")
if len(delimited_matches(rb"[0-9a-f]{40}")) > 1:
    raise SystemExit("error: archive gitCommit is not unique")
if mod != tag:
    raise SystemExit("error: archive mod version is not " + tag)
if vcs_revision != full_commit:
    raise SystemExit("error: archive vcs.revision is not the tagged commit")
if vcs_modified != "false":
    raise SystemExit("error: archive vcs.modified is not false")
PY
	then
		die "archive $archive is not bound to signed tag $tag (mod $tag version $version commit $commit)"
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
echo "[ok] archives bound to $tag (mod $tag version $version commit $commit)"
