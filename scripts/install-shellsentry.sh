#!/usr/bin/env bash
#
# install-shellsentry.sh - Bootstrap installer for shellsentry
#
# Usage:
#   Download install-shellsentry.sh, SHA256SUMS, and SHA256SUMS.minisig (or
#   SHA256SUMS.asc) from the same GitHub release. Verify SHA256SUMS with
#   minisign or gpg, check the installer checksum, optionally run shellsentry
#   on the installer, then:
#     bash install-shellsentry.sh
#     bash install-shellsentry.sh --tag vX.Y.Z
#   Do not pipe curl to a shell.
#
# Options:
#   --tag vX.Y.Z         Install specific version (default: latest)
#   --dir PATH           Install directory (default: ~/.local/bin, or ~/bin on Windows)
#   --dest PATH          Alias for --dir
#   --yes                Skip confirmation prompts
#   --dry-run            Download and verify, but don't install
#   --require-signature    Require signature verification (default: true)
#   --help                 Show this help
#
# Verification:
#   Default: signature verification is REQUIRED.
#   - minisign: verifies SHA256SUMS.minisig using pinned key (preferred)
#   - gpg: alternative if fingerprint matches pinned FPR
#
# -----------------------------------------------------------------------------
# Provenance
# -----------------------------------------------------------------------------
# This script is distributed as a release asset and can be verified:
#   1. Download SHA256SUMS and SHA256SUMS.minisig from the same release
#   2. minisign -Vm SHA256SUMS -P RWTqUZ/PtmfAbQ3RKIlp/YTKT6zFeNMAZ8iAMelhlmqEsVqjKj3ctSA1
#      (tags <= v0.1.6 verify under the previous key: RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC)
#   3. grep install-shellsentry.sh SHA256SUMS | sha256sum -c -
#      (macOS without GNU sha256sum: shasum -a 256 -c)
#
# Repository: https://github.com/3leaps/shellsentry
# Trust anchor: RWTqUZ/PtmfAbQ3RKIlp/YTKT6zFeNMAZ8iAMelhlmqEsVqjKj3ctSA1
#

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SHELLSENTRY_REPO="3leaps/shellsentry"
SHELLSENTRY_API="https://api.github.com/repos/${SHELLSENTRY_REPO}/releases"

# Embedded trust anchor - minisign public key for verifying releases
# Must match configs/keys/shellsentry-minisign.pub (embedded in the binary).
SHELLSENTRY_MINISIGN_PUBKEY="${SHELLSENTRY_MINISIGN_PUBKEY:-RWTqUZ/PtmfAbQ3RKIlp/YTKT6zFeNMAZ8iAMelhlmqEsVqjKj3ctSA1}"
# Pinned PGP fingerprint (for optional fallback)
SHELLSENTRY_PGP_FPR="${SHELLSENTRY_PGP_FPR:-0CACA49B3119B6BC12B2CA11B9B485F294B9FE07}"
# Previous-key anchors, pin-scoped ONLY. SHELLSENTRY_PREVKEY_MAX is the last tag
# signed with the previous org keys (historical fact, never advance it): tags at
# or below it verify against the LEGACY anchors; tags above verify against the
# current ones. Never try both generations for one tag.
SHELLSENTRY_PREVKEY_MAX="v0.1.6"
SHELLSENTRY_MINISIGN_PUBKEY_LEGACY="RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC"
SHELLSENTRY_PGP_FPR_LEGACY="94BB7811D4AD49B2310E0C08FA0651DE91B828ED"
TRUST_LEVEL="unknown"

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

log() { echo "==> $*" >&2; }
warn() { echo "warning: $*" >&2; }
err() {
    echo "error: $*" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "required command not found: $1"
    fi
}

is_exact_semver_tag() {
    [[ "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

# semver_le_tag: true if tag a <= tag b (exact vX.Y.Z inputs, no leading zeros).
# Length-then-lexical per component under C locale: no machine arithmetic, so no
# wraparound on huge components.
semver_le_tag() {
    local LC_ALL=C
    local a="${1#v}" b="${2#v}"
    local a1 a2 a3 b1 b2 b3
    IFS=. read -r a1 a2 a3 <<<"$a"
    IFS=. read -r b1 b2 b3 <<<"$b"
    local x y
    for pair in "$a1:$b1" "$a2:$b2" "$a3:$b3"; do
        x="${pair%%:*}"
        y="${pair##*:}"
        if [ "${#x}" -lt "${#y}" ]; then return 0; fi
        if [ "${#x}" -gt "${#y}" ]; then return 1; fi
        if [[ "$x" < "$y" ]]; then return 0; fi
        if [[ "$x" > "$y" ]]; then return 1; fi
    done
    return 0
}

# select_trust_anchor TAG: set ACTIVE_MINISIGN_PUBKEY, ACTIVE_PGP_FPR and
# ANCHOR_GEN for the resolved tag. The tag selects exactly one key generation:
# tags at or below SHELLSENTRY_PREVKEY_MAX are previous-key-signed; tags above
# are current-key-signed. Refuse non-semver tags rather than guess a key.
select_trust_anchor() {
    local version="$1"
    if ! is_exact_semver_tag "$version"; then
        err "cannot select trust anchor for non-semver tag: ${version:-<empty>}"
    fi
    ACTIVE_MINISIGN_PUBKEY="$SHELLSENTRY_MINISIGN_PUBKEY"
    ACTIVE_PGP_FPR="$SHELLSENTRY_PGP_FPR"
    ANCHOR_GEN="current"
    if semver_le_tag "$version" "$SHELLSENTRY_PREVKEY_MAX"; then
        ANCHOR_GEN="legacy"
        ACTIVE_MINISIGN_PUBKEY="$SHELLSENTRY_MINISIGN_PUBKEY_LEGACY"
        ACTIVE_PGP_FPR="$SHELLSENTRY_PGP_FPR_LEGACY"
    fi
    log "trust anchor: ${ANCHOR_GEN} (pin ${version})"
}

read_release_tag_name() {
    local release_json_file="$1"
    local version=""

    # Prefer jq when available (more robust than grep on JSON), but keep a
    # dependency-free fallback for minimal bootstrap environments.
    if command -v jq >/dev/null 2>&1; then
        version=$(jq -r '.tag_name // empty' "$release_json_file" 2>/dev/null || true)
    fi

    if [ -z "$version" ]; then
        version=$(grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$release_json_file" | head -1 | cut -d'"' -f4 || true)
    fi

    if [ -z "$version" ]; then
        err "failed to parse release tag from GitHub API response"
    fi

    echo "$version"
}

print_verifier_help() {
    echo "To verify signatures, install one of:"
    case "$(uname -s)" in
        Darwin*)
            echo "  minisign (recommended): brew install minisign"
            echo "  gpg (fallback):        brew install gnupg"
            ;;
        Linux*)
            echo "  minisign (recommended): apt install minisign    # Debian/Ubuntu"
            echo "                          brew install minisign   # if using Homebrew"
            echo "  gpg (fallback):        apt install gnupg"
            ;;
        MINGW* | MSYS* | CYGWIN*)
            echo "  minisign (recommended): scoop bucket add main && scoop install main/minisign"
            echo "  gpg (fallback):         scoop install gpg"
            ;;
    esac
    echo "If you cannot install a verifier here, verify on a trusted machine and copy the binary."
}

# -----------------------------------------------------------------------------
# Platform detection
# -----------------------------------------------------------------------------

# Windows ARM64 detection with three-tier fallback.
#
# Git Bash on Windows ARM64 runs under x64 (WoW64) emulation, so uname -m and
# PROCESSOR_ARCHITECTURE can both report amd64. This function queries three
# sources to find the real host architecture:
#   1. RUNNER_ARCH env var (GitHub Actions runners set this to the native arch)
#   2. PowerShell RuntimeInformation.OSArchitecture (bypasses emulation)
#   3. PROCESSOR_ARCHITEW6432 (Windows env var for native arch from WoW64)
detect_windows_arch() {
    local arch_hint

    # Tier 1: GitHub Actions runners expose the native architecture via RUNNER_ARCH
    arch_hint=$(printf '%s' "${RUNNER_ARCH:-}" | tr '[:upper:]' '[:lower:]')
    case "$arch_hint" in
        amd64 | x64 | x86_64)
            echo "amd64"
            return 0
            ;;
        arm64 | aarch64)
            echo "arm64"
            return 0
            ;;
    esac

    # Tier 2: Ask native PowerShell for the host OS architecture
    if command -v powershell.exe >/dev/null 2>&1; then
        arch_hint=$(powershell.exe -NoProfile -NonInteractive -Command "[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture" 2>/dev/null | tr -d '\r' | tr '[:upper:]' '[:lower:]' | head -n1)
        case "$arch_hint" in
            amd64 | x64 | x86_64)
                echo "amd64"
                return 0
                ;;
            arm64 | aarch64)
                echo "arm64"
                return 0
                ;;
        esac
    fi

    # Tier 3: PROCESSOR_ARCHITEW6432 reports native arch even from WoW64
    arch_hint=$(printf '%s' "${PROCESSOR_ARCHITEW6432:-${PROCESSOR_ARCHITECTURE:-}}" | tr '[:upper:]' '[:lower:]')
    case "$arch_hint" in
        amd64 | x64 | x86_64)
            echo "amd64"
            return 0
            ;;
        arm64 | aarch64)
            echo "arm64"
            return 0
            ;;
    esac

    return 1
}

detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux*) os="linux" ;;
        Darwin*) os="darwin" ;;
        MINGW* | MSYS* | CYGWIN*) os="windows" ;;
        *) err "unsupported OS: $(uname -s)" ;;
    esac

    # Windows needs special handling: Git Bash under WoW64 emulation reports
    # x86_64 even on ARM64 hardware. Use detect_windows_arch() for accuracy.
    if [ "$os" = "windows" ]; then
        if arch=$(detect_windows_arch); then
            echo "${os}_${arch}"
            return
        fi
    fi

    case "$(uname -m)" in
        x86_64 | amd64) arch="amd64" ;;
        arm64 | aarch64) arch="arm64" ;;
        *) err "unsupported architecture: $(uname -m)" ;;
    esac

    echo "${os}_${arch}"
}

# -----------------------------------------------------------------------------
# Verification tool detection
# -----------------------------------------------------------------------------

check_verification_tools() {
    local has_minisign=false
    local has_gpg=false

    if command -v minisign >/dev/null 2>&1; then
        has_minisign=true
    fi

    if command -v gpg >/dev/null 2>&1; then
        has_gpg=true
    fi

    if [ "$has_minisign" = false ] && [ "$has_gpg" = false ]; then
        warn "no signature verification tools found"
        echo ""
        echo "For signature verification, install one of:"
        echo ""
        case "$(uname -s)" in
            Darwin*)
                echo "  minisign (recommended):"
                echo "    brew install minisign"
                echo ""
                echo "  gpg:"
                echo "    brew install gnupg"
                ;;
            Linux*)
                echo "  minisign (recommended):"
                echo "    brew install minisign        # if using Homebrew"
                echo "    apt install minisign         # Debian/Ubuntu"
                echo ""
                echo "  gpg:"
                echo "    apt install gnupg            # Debian/Ubuntu"
                ;;
            MINGW* | MSYS* | CYGWIN*)
                echo "  minisign (recommended):"
                echo "    scoop bucket add main"
                echo "    scoop install main/minisign"
                echo ""
                echo "  gpg:"
                echo "    scoop install gpg"
                ;;
        esac
        echo ""
    fi

    VERIFY_MINISIGN=$has_minisign
    VERIFY_GPG=$has_gpg
}

# -----------------------------------------------------------------------------
# Download helpers
# -----------------------------------------------------------------------------

fetch() {
    local url="$1"
    local dest="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -sSfL -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url"
    else
        err "curl or wget required"
    fi
}

fetch_json() {
    local url="$1"

    if command -v curl >/dev/null 2>&1; then
        curl -sSfL -H "Accept: application/vnd.github.v3+json" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O - --header="Accept: application/vnd.github.v3+json" "$url"
    else
        err "curl or wget required"
    fi
}

# -----------------------------------------------------------------------------
# Checksum verification
# -----------------------------------------------------------------------------

verify_checksum() {
    local file="$1"
    local expected="$2"
    local actual

    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$file" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$file" | cut -d' ' -f1)
    else
        err "sha256sum or shasum required"
    fi

    if [ "$actual" != "$expected" ]; then
        err "checksum mismatch for $(basename "$file")"
    fi
}

# -----------------------------------------------------------------------------
# Signature verification
# -----------------------------------------------------------------------------

# gpg_cleanup: stop any agent started for the isolated GnuPG home, then
# remove it. Safe to call more than once.
GPG_HOME=""
gpg_cleanup() {
    if [ -n "$GPG_HOME" ] && [ -d "$GPG_HOME" ]; then
        gpgconf --homedir "$GPG_HOME" --kill all >/dev/null 2>&1 || true
        rm -rf "$GPG_HOME"
    fi
    GPG_HOME=""
}

verify_signature() {
    local sums_file="$1"
    local tmpdir="$2"
    local verified=false
    TRUST_LEVEL="unverified"

    # Try minisign first (preferred - uses embedded trust anchor)
    if [ "$VERIFY_MINISIGN" = true ] && [ -f "${sums_file}.minisig" ]; then
        local pubkey_file="${tmpdir}/shellsentry-minisign.pub"
        echo "untrusted comment: shellsentry release signing key" >"$pubkey_file"
        echo "$ACTIVE_MINISIGN_PUBKEY" >>"$pubkey_file"

        log "Verifying signature with minisign (embedded trust anchor)..."
        if minisign -Vm "$sums_file" -p "$pubkey_file" >/dev/null 2>&1; then
            log "Minisign signature verified"
            verified=true
            TRUST_LEVEL="high (minisign)"
        else
            err "minisign signature verification failed"
        fi
    fi

    if [ "$verified" = false ] && [ "$REQUIRE_MINISIGN" = true ]; then
        if [ "$VERIFY_MINISIGN" = false ]; then
            err "minisign is required; install minisign to continue"
        fi
        if [ ! -f "${sums_file}.minisig" ]; then
            err "SHA256SUMS.minisig missing; cannot verify"
        fi
    fi

    # Try GPG if minisign didn't verify and minisign is not required
    if [ "$verified" = false ] && [ "$REQUIRE_MINISIGN" = false ] && [ "$VERIFY_GPG" = true ] && [ -f "${sums_file}.asc" ]; then
        local gpg_key="${tmpdir}/shellsentry-release-signing-key.asc"
        if [ -f "$gpg_key" ]; then
            # Isolated home inside tmpdir, so the EXIT trap removes it on every
            # path; gpg_cleanup also stops the agent gpg may start for it.
            GPG_HOME="${tmpdir}/gnupg"
            mkdir -m 700 "$GPG_HOME" || err "cannot create GnuPG home"
            # The key file must hold exactly one primary key, public only, equal
            # to the pin. Count every primary record (pub and sec) so no extra
            # key can ride along; VALIDSIG below independently pins the signer.
            local listing fprs _f
            if ! listing=$(gpg --homedir "$GPG_HOME" --batch --no-tty --with-colons \
                --import-options show-only --import "$gpg_key" 2>/dev/null); then
                gpg_cleanup
                err "GPG key file could not be read"
            fi
            # Parse the whole listing in the shell (no pipes: an early-exiting
            # reader under pipefail could otherwise skip a check).
            local line rec want=false has_sec=false nprimary=0
            fprs=""
            while IFS= read -r line; do
                rec="${line%%:*}"
                case "$rec" in
                    sec) has_sec=true want=true nprimary=$((nprimary + 1)) ;;
                    pub) want=true nprimary=$((nprimary + 1)) ;;
                    fpr)
                        if [ "$want" = true ]; then
                            IFS=: read -r -a _f <<<"$line"
                            fprs="${fprs}${fprs:+ }${_f[9]:-}"
                            want=false
                        fi
                        ;;
                esac
            done <<<"$listing"
            if [ "$has_sec" = true ]; then
                gpg_cleanup
                err "GPG key file must not contain secret keys"
            fi
            if [ "$nprimary" -ne 1 ]; then
                gpg_cleanup
                err "GPG key file must contain exactly one primary key"
            fi
            if [ "$fprs" != "$ACTIVE_PGP_FPR" ]; then
                gpg_cleanup
                err "GPG key fingerprint mismatch (expected ${ACTIVE_PGP_FPR}, got ${fprs:-unknown})"
            fi
            log "Verifying signature with gpg (pinned fingerprint)..."
            # Accept only a VALIDSIG whose primary-key fingerprint is the pin.
            local status sig_primary
            if gpg --batch --no-tty --homedir "$GPG_HOME" --import "$gpg_key" 2>/dev/null &&
                status=$(gpg --batch --no-tty --homedir "$GPG_HOME" --trust-model always \
                    --status-fd 1 --verify "${sums_file}.asc" "$sums_file" 2>/dev/null); then
                sig_primary=""
                while IFS= read -r line; do
                    case "$line" in
                        "[GNUPG:] VALIDSIG "*)
                            sig_primary="${line##* }"
                            break
                            ;;
                    esac
                done <<<"$status"
                if [ "$sig_primary" != "$ACTIVE_PGP_FPR" ]; then
                    gpg_cleanup
                    err "GPG signature is not from the pinned key (got ${sig_primary:-none})"
                fi
                log "GPG signature verified"
                verified=true
                TRUST_LEVEL="medium (gpg, pinned key)"
            else
                gpg_cleanup
                err "GPG signature verification failed"
            fi
            gpg_cleanup
        else
            warn "GPG public key not found in release"
        fi
    fi

    if [ "$verified" = false ]; then
        if [ "$REQUIRE_SIGNATURE" = true ]; then
            err "signature verification required; install minisign (recommended) or gpg"
        fi
        err "signature verification required; no valid signature found"
    fi
}

# -----------------------------------------------------------------------------
# Installation
# -----------------------------------------------------------------------------

install_binary() {
    local src="$1"
    local dest_dir="$2"
    local platform="$3"
    local binary_name="shellsentry"

    # Windows needs .exe extension
    if [[ "$platform" == windows_* ]]; then
        binary_name="shellsentry.exe"
    fi

    local dest="${dest_dir}/${binary_name}"

    # Create destination directory
    mkdir -p "$dest_dir"

    # Copy binary
    cp "$src" "$dest"
    chmod +x "$dest"

    log "Installed ${binary_name} to ${dest}"
    log "Trust: ${TRUST_LEVEL}"

    # Path advice
    case ":$PATH:" in
        *":${dest_dir}:"*) ;;
        *)
            echo ""
            echo "Add to your PATH:"
            if [[ "$platform" == windows_* ]]; then
                echo "  setx PATH \"%PATH%;${dest_dir}\""
            else
                echo "  export PATH=\"${dest_dir}:\$PATH\""
            fi
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    local tag="latest"
    local install_dir=""
    local dry_run=false
    local yes=false
    local require_signature=true
    local require_minisign=false

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --tag)
                tag="$2"
                shift 2
                ;;
            --dir | --dest)
                install_dir="$2"
                shift 2
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            --yes)
                yes=true
                shift
                ;;
            --require-signature)
                require_signature=true
                shift
                ;;
            --require-minisign)
                require_minisign=true
                shift
                ;;
            --no-require-minisign)
                require_minisign=false
                shift
                ;;
            --help | -h)
                head -25 "$0" | tail -20
                exit 0
                ;;
            *)
                err "unknown option: $1"
                ;;
        esac
    done

    REQUIRE_SIGNATURE=$require_signature
    REQUIRE_MINISIGN=$require_minisign

    # Detect platform
    local platform
    platform=$(detect_platform)
    log "Detected platform: ${platform}"

    # macOS Intel (darwin/amd64) artifacts end at v0.1.4. Block unversioned
    # installs — which default to "latest" and would 404 on the missing
    # asset — but honor an explicit --tag so the documented recovery path
    # (--tag v0.1.4) actually works. An invalid tag on Intel Mac still
    # 404s with its own error rather than being masked by this guard.
    if [ "$platform" = "darwin_amd64" ] && [ "$tag" = "latest" ]; then
        err "darwin/amd64 (Intel Mac) is no longer supported as of shellsentry v0.1.5. Pin an explicit --tag v0.1.4 to install the last supporting release, or use Apple Silicon."
    fi

    # Set default install directory
    if [ -z "$install_dir" ]; then
        if [[ "$platform" == windows_* ]]; then
            install_dir="${USERPROFILE:-$HOME}/bin"
        else
            install_dir="${HOME}/.local/bin"
        fi
    fi

    # Check verification tools
    check_verification_tools
    if [ "$REQUIRE_MINISIGN" = true ] && [ "${VERIFY_MINISIGN:-false}" = false ]; then
        print_verifier_help
        err "minisign is required; install minisign to continue"
    fi
    if [ "$REQUIRE_SIGNATURE" = true ] && [ "${VERIFY_MINISIGN:-false}" = false ] && [ "${VERIFY_GPG:-false}" = false ]; then
        print_verifier_help
        err "signature verification required; install minisign (recommended) or gpg"
    fi

    # Create temp directory (not local - needed for EXIT trap)
    tmpdir=$(mktemp -d)
    trap 'gpg_cleanup; rm -rf "$tmpdir"' EXIT

    # Fetch release info
    local release_url
    if [ "$tag" = "latest" ]; then
        release_url="${SHELLSENTRY_API}/latest"
    else
        release_url="${SHELLSENTRY_API}/tags/${tag}"
    fi

    log "Fetching release info..."
    local release_json="${tmpdir}/release.json"
    fetch_json "$release_url" >"$release_json"

    local version
    version=$(read_release_tag_name "$release_json")
    log "Installing shellsentry ${version}"

    select_trust_anchor "$version"

    # Determine archive name
    local archive_name="shellsentry_${platform}"
    if [[ "$platform" == windows_* ]]; then
        archive_name="${archive_name}.zip"
    else
        archive_name="${archive_name}.tar.gz"
    fi

    # Download assets
    local base_url="https://github.com/${SHELLSENTRY_REPO}/releases/download/${version}"

    log "Downloading assets..."
    fetch "${base_url}/SHA256SUMS" "${tmpdir}/SHA256SUMS"
    fetch "${base_url}/${archive_name}" "${tmpdir}/${archive_name}"

    # Download signature files (optional)
    fetch "${base_url}/SHA256SUMS.minisig" "${tmpdir}/SHA256SUMS.minisig" 2>/dev/null || true
    fetch "${base_url}/SHA256SUMS.asc" "${tmpdir}/SHA256SUMS.asc" 2>/dev/null || true
    fetch "${base_url}/shellsentry-release-signing-key.asc" "${tmpdir}/shellsentry-release-signing-key.asc" 2>/dev/null || true

    # Verify signature on SHA256SUMS
    verify_signature "${tmpdir}/SHA256SUMS" "$tmpdir"

    # Verify archive checksum
    log "Verifying checksum..."
    local expected_hash
    expected_hash=$(grep "${archive_name}" "${tmpdir}/SHA256SUMS" | cut -d' ' -f1)
    if [ -z "$expected_hash" ]; then
        err "archive not found in SHA256SUMS: ${archive_name}"
    fi
    verify_checksum "${tmpdir}/${archive_name}" "$expected_hash"
    log "Checksum verified"

    # Dry run stops here
    if [ "$dry_run" = true ]; then
        log "Dry run complete - verification passed"
        exit 0
    fi

    # Extract
    log "Extracting..."
    local extract_dir="${tmpdir}/extract"
    mkdir -p "$extract_dir"

    # List archive entries to guard against zip-slip/path traversal.
    # Reject absolute paths, Windows drive-letter paths, and parent-dir traversal segments.
    local entry
    local list_cmd=()

    if [[ "$archive_name" == *.zip ]]; then
        need_cmd unzip
        if unzip -Z1 "${tmpdir}/${archive_name}" >/dev/null 2>&1; then
            list_cmd=(unzip -Z1 "${tmpdir}/${archive_name}")
        else
            list_cmd=(sh -c "unzip -l \"${tmpdir}/${archive_name}\" | awk 'NR>3 {print \$NF}' | sed '/^$/d'")
        fi
    else
        need_cmd tar
        list_cmd=(tar -tzf "${tmpdir}/${archive_name}")
    fi

    while IFS= read -r entry; do
        while [[ "$entry" == ./* ]]; do
            entry="${entry#./}"
        done
        if [[ -z "$entry" ]]; then
            continue
        fi

        if [[ "$entry" == /* ]] || [[ "$entry" == \\* ]] || [[ "$entry" =~ ^[A-Za-z]: ]]; then
            err "unsafe path in archive entry: $entry"
        fi

        if [[ "$entry" == ".." ]] || [[ "$entry" == ../* ]] || [[ "$entry" == */../* ]] || [[ "$entry" == */.. ]]; then
            err "unsafe path in archive entry: $entry"
        fi

        if [[ "$entry" == ..\\* ]] || [[ "$entry" == *"\\..\\"* ]] || [[ "$entry" == *"\\.." ]]; then
            err "unsafe path in archive entry: $entry"
        fi
    done < <("${list_cmd[@]}")

    if [[ "$archive_name" == *.zip ]]; then
        unzip -q "${tmpdir}/${archive_name}" -d "$extract_dir"
    else
        tar -xzf "${tmpdir}/${archive_name}" -C "$extract_dir"
    fi

    # Find binary
    local binary
    binary=$(find "$extract_dir" -type f -name "shellsentry*" | head -1)
    if [ -z "$binary" ]; then
        err "binary not found in archive"
    fi

    # Confirm installation
    if [ "$yes" = false ] && [ -t 0 ]; then
        echo ""
        echo "Ready to install shellsentry ${version} to ${install_dir}"
        echo "Verification: ${TRUST_LEVEL}"
        printf "Continue? [Y/n] "
        read -r confirm
        case "$confirm" in
            [nN]*)
                echo "Aborted."
                exit 1
                ;;
        esac
    fi

    # Install
    install_binary "$binary" "$install_dir" "$platform"

    echo ""
    log "Done! Run 'shellsentry --help' to get started."
    echo ""
    echo "Tip: For secure installs of other tools, use sfetch with a pinned tag"
    echo "  (see https://github.com/3leaps/sfetch — verified bootstrap / setup-sfetch action)."
}

main "$@"
