#!/usr/bin/env bash
# Pack bin/shellsentry_${GOOS}_${GOARCH}.exe with a real python (not the
# Windows Store stub). Used by CI Windows jobs and the tag-build matrix.
set -euo pipefail

goos="${1:-$(go env GOOS)}"
goarch="${2:-$(go env GOARCH)}"
if [ "$goos" != "windows" ]; then
    echo "error: package-windows-zip.sh is windows-only (got ${goos}/${goarch})" >&2
    exit 1
fi

py="$(command -v python)"
case "$py" in
    *WindowsApps*) echo "error: Windows Store python stub at $py" >&2; exit 1 ;;
esac
test -s "$py"

ASSET="shellsentry_${goos}_${goarch}"
ARCHIVE="${ASSET}.zip"
test -s "bin/${ASSET}.exe"
(cd bin && mv "${ASSET}.exe" "shellsentry.exe")
"$py" -c 'import zipfile,sys; z=zipfile.ZipFile(sys.argv[1],"w",zipfile.ZIP_DEFLATED); z.write("bin/shellsentry.exe","shellsentry.exe")' "${ARCHIVE}"
(cd bin && mv "shellsentry.exe" "${ASSET}.exe")
test -s "${ARCHIVE}"
echo "packed ${ARCHIVE}"
if [ -n "${GITHUB_ENV:-}" ]; then
    echo "ASSET_FILE=${ARCHIVE}" >> "$GITHUB_ENV"
fi
