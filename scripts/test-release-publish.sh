#!/usr/bin/env bash
# Stub-gh: promote only when the draft is byte-identical to local SHA256SUMS.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
# CI sets GITHUB_ACTIONS; the real script refuses it. Tests unset it.
unset GITHUB_ACTIONS || true
for tool in jq cmp git; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: $tool is required for the publish controls" >&2
        exit 1
    }
done
scratch="$(mktemp -d "${TMPDIR:-/tmp}/shs-publish.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
repo="$scratch/repo"
mkdir -p "$repo/scripts" "$scratch/bin"
cp "$root/scripts/release-publish.sh" "$root/scripts/release-ci-refuse.sh" "$repo/scripts/"
chmod +x "$repo/scripts/"*.sh

d="$scratch/dist"
stage() {
    rm -rf "$d" "$scratch/draft"
    mkdir -p "$d" "$scratch/draft"
    for f in linux_amd64.tar.gz linux_arm64.tar.gz darwin_arm64.tar.gz windows_amd64.zip windows_arm64.zip; do
        printf 'pkg %s\n' "$f" >"$d/shellsentry_$f"
    done
    printf '#!/bin/sh\necho installer\n' >"$d/install-shellsentry.sh"
    (
        cd "$d"
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum shellsentry_linux_amd64.tar.gz shellsentry_linux_arm64.tar.gz \
                shellsentry_darwin_arm64.tar.gz shellsentry_windows_amd64.zip \
                shellsentry_windows_arm64.zip install-shellsentry.sh >SHA256SUMS
        else
            shasum -a 256 shellsentry_linux_amd64.tar.gz shellsentry_linux_arm64.tar.gz \
                shellsentry_darwin_arm64.tar.gz shellsentry_windows_amd64.zip \
                shellsentry_windows_arm64.zip install-shellsentry.sh >SHA256SUMS
        fi
    )
    cp "$d"/* "$scratch/draft/"
}

cat >"$scratch/bin/gh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FIXTURE_LOG"
case "$1 $2" in
"release view")
    names="$(cd "$FIXTURE_DRAFT" && ls -1 | jq -R . | jq -s 'map({name: .})')"
    jq -n --argjson a "$names" --argjson d "${FIXTURE_IS_DRAFT:-true}" '{isDraft: $d, assets: $a}'
    ;;
"release download")
    dir=""
    while [[ $# -gt 0 ]]; do
        [[ "$1" == --dir ]] && dir="$2"
        shift
    done
    cp "$FIXTURE_DRAFT"/* "$dir/"
    ;;
"release edit") ;;
*) exit 1 ;;
esac
SH
chmod +x "$scratch/bin/gh"
export PATH="$scratch/bin:$PATH" FIXTURE_LOG="$scratch/gh.log" FIXTURE_DRAFT="$scratch/draft"

refuse() {
    local reason="$1"
    : >"$FIXTURE_LOG"
    if (cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >"$scratch/out" 2>&1; then
        echo "error: expected rejection: $reason" >&2
        cat "$scratch/out" >&2
        exit 1
    fi
    grep -q "$reason" "$scratch/out" || {
        echo "error: missing named rejection: $reason" >&2
        cat "$scratch/out" >&2
        exit 1
    }
    ! grep -q '^release edit' "$FIXTURE_LOG" || {
        echo "error: promoted despite: $reason" >&2
        exit 1
    }
}

stage
FIXTURE_IS_DRAFT=false refuse 'is not a draft'
stage
printf 'tampered\n' >>"$d/shellsentry_linux_amd64.tar.gz"
refuse 'local files do not match SHA256SUMS'
stage
printf 'swapped on the server\n' >"$scratch/draft/shellsentry_darwin_arm64.tar.gz"
refuse 'draft asset differs from the verified local file'
stage
printf 'deadbeef  install-shellsentry.sh\n' >"$scratch/draft/SHA256SUMS"
refuse 'draft SHA256SUMS differs from the local file'
stage
rm -f "$scratch/draft/shellsentry_linux_arm64.tar.gz"
refuse 'draft missing asset listed in SHA256SUMS'
stage
rm -f "$d/SHA256SUMS"
refuse 'local SHA256SUMS required'

stage
: >"$FIXTURE_LOG"
(cd "$repo" && ./scripts/release-publish.sh v1.2.3 "$d") >/dev/null
[[ "$(grep -c '^release edit v1.2.3 .*--draft=false' "$FIXTURE_LOG")" == 1 ]]
[[ "$(grep -n '' "$FIXTURE_LOG" | grep -E 'release (download|edit)' | head -1)" == *'release download'* ]]
echo '[ok] publish promotes only a byte-verified draft'
