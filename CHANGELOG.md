# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to
Semantic Versioning.

## [Unreleased]

## [0.1.8] - 2026-10-26

### Fixed

- **Pinned gosec in CI.** `gosec` is pinned to v2.29.0 (`go install` into
  `bin/`). `make gosec-high` fails closed if `gosec` is missing, instead of
  exiting 127 when goneat cooling skips a newer `@latest` build. It also
  asserts the binary on PATH matches `GOSEC_VERSION`.
- **Tag workflow is read-only.** Tag-push CI verifies committed public
  anchors, builds five native platforms, and uploads archives as artifacts.
  It never creates a GitHub Release, never signs, and never requests
  `contents: write`. Drafting and publishing stay on the operator machine.
- **Workflow actions are SHA-pinned.** Every `uses:` in `.github/workflows`
  is a 40-character commit SHA with a version comment, including
  `actions/checkout` and `actions/setup-go`. `download-artifact` is v7.0.0 to
  match `upload-artifact` v7. `scripts/test-workflow-action-pins.py` fails if
  a pin is reverted to a tag.
- **Pin assertion does not SIGPIPE.** `make assert-tool-pins` takes the first
  version line without piping through `head`, so extra output cannot exit 141
  under `set -o pipefail`. `scripts/test-assert-tool-pins.sh` fails if the
  piped-head path is restored.
- **Operator-home agent kill via `GNUPGHOME`.** The smartcard fixture refuses
  a bare `gpgconf --kill` while `GNUPGHOME` is the operator home, not only
  an explicit `--homedir`.
- **Install docs do not pipe curl to a shell.** Upgrade and install examples
  download the installer, verify `SHA256SUMS` plus minisign or PGP, optionally
  run shellsentry on it, then execute. Checksums use `sha256sum -c -` or
  `shasum -a 256 -c`, and `set -e` stops the run if a check fails.
  PGP examples fetch `shellsentry-release-signing-key.asc` from the release
  instead of importing a checkout path, print the fingerprint with
  `gpg --show-keys --with-fingerprint`, and refuse a mismatch against the
  pinned primary `0CACA49B3119B6BC12B2CA11B9B485F294B9FE07`.
  `scripts/test-no-pipe-to-shell-docs.sh` fails if a `curl ... | bash`
  recipe, a bare `sha256sum -c`, an unchained installer run, a checkout
  PGP import, or a trust-on-first-use PGP import is restored.
- **Draft notes asset matches the tagged notes.** `make release-upload`
  attaches `release-notes-<tag>.md`. `make release-publish` byte-compares
  that asset to `docs/releases/<tag>.md` at the tagged commit. GitHub
  release titles drop a leading `# ` from that heading.
- **Release archives bind to the tagged version.** Packaged binaries carry a
  unique delimited version label, a real-date `buildTime`, and the tagged
  `gitCommit`. A byte scan cannot attribute those strings to a specific `-X`
  variable, so the source is pinned by `mod`, `vcs.revision`, and
  `vcs.modified`. The publish path refuses a draft whose version does not
  match the tag.
- **Installer previous-key cutoff ignores the environment.**
  `SHELLSENTRY_PREVKEY_MAX` is the quoted literal `v0.1.6`. Exporting a
  larger value before loading the installer does not make v0.1.7 verify
  under the previous key.

### Added

- **Signed-tag release ceremony.** `make release-tag` creates a local signed
  annotated tag from `SHELLSENTRY_RELEASE_TAG` and verifies it against the
  committed public pin (`docs/security/release-signing-keys.asc`,
  `keys/expected-fingerprints.txt`). `make release-create-draft` opens the
  GitHub draft from locally staged packages. `make release-publish`
  re-downloads the draft, byte-compares `SHA256SUMS` and every listed asset,
  then publishes. Tagging, upload, and publish scripts refuse
  `GITHUB_ACTIONS` and do not run in CI.
- **Committed public identity.** Release preflight binds
  `SHELLSENTRY_DECERNOR_BIN` and checks GPG and minisign exports against the
  fingerprint anchors in the tagged commit. Staged keys come from that
  commit, not the working tree. CI installs Decernor from a digest pin.
- **Native five-platform CI.** Pull requests and tag builds run on
  linux/amd64, linux/arm64, darwin/arm64, windows/amd64, and windows/arm64
  with a matching `GOHOSTOS`/`GOHOSTARCH` check. Platform steps refuse the
  common soft-fail forms (`continue-on-error`, `if: false`, and `|| true`).
  Windows archives are packed
  with `scripts/package-windows-zip.sh` and a SHA-pinned `actions/setup-python`.

### Changed

- **Tag signing uses the operator GPG home.** `make release-tag` binds
  `GNUPGHOME` to `SHELLSENTRY_GPG_HOMEDIR` and does not export secret keys
  into a throwaway keyring, so hardware-backed subkeys can sign. Cleanup
  never `gpgconf --kill`s the operator agent. Public-pin verification stays
  on a disposable keyring.
- **Verified bootstrap pin.** sfetch v0.4.15, engine and action commit
  `c44577261902c848119d3c89b0138becb613b158` (peeled signed tag). goneat
  stays v0.6.6.
- **Parser and lint pins.** `mvdan.cc/sh/v3` v3.14.1, staticcheck v0.8.2,
  govulncheck v1.9.0.
- **Installer previous-key map is frozen.** Tags at or below v0.1.6 keep the
  previous keys; v0.1.7 and later stay on the current keys. The cutoff is
  not raised to retire historical installs.

## [0.1.7] - 2026-10-21

### Security

- Built with Go 1.26.10, resolving GO-2026-5026, GO-2026-5972, GO-2026-6090,
  GO-2026-6218, GO-2026-6603, GO-2026-6605, GO-2026-6607, GO-2026-6608,
  GO-2026-6610, GO-2026-6611, GO-2026-6612, GO-2026-6613, GO-2026-6617, and
  GO-2026-6809, which were reachable when built with Go 1.26.5.
- `golang.org/x/crypto` v0.58.0 (GO-2026-6303, GO-2026-6354, GO-2026-6355;
  not called).

### Changed

- Go toolchain: `go 1.26.0` with `toolchain go1.26.10`; CI and release use Go 1.26.10.
- Dependencies: `golang.org/x/crypto` v0.58.0, `golang.org/x/sys` v0.49.0.
- Release signing anchors rotated to the current organization keys. The installer
  selects the key by tag (v0.1.6 and earlier: previous keys; later: current keys)
  with no fallback. Self-update from v0.1.6 or earlier requires a one-time reinstall.
- Bootstrap pins: sfetch v0.4.13 with its engine/action commit, engine SHA-256 and
  current anchor; goneat v0.6.6; golangci-lint v2.14.0 (was unpinned).

### Fixed

- `install-shellsentry.sh` GPG route now reads the release key file's fingerprint;
  previously it failed closed with a fingerprint mismatch. The key file must
  contain exactly one primary key equal to the pinned fingerprint, and the
  signature must come from that key. Key files with secret-key
  packets are refused.

### Added

- `make test-install-anchor-select` installer key-selection regression (runs in
  `make prepush`), covering selection through minisign and GPG verification.

## [0.1.6] - 2026-07-31

### Added

- Verified sfetch bootstrap via `3leaps/sfetch` setup-sfetch action (CI) and digest-pinned `scripts/install-sfetch-verified.sh` (Makefile).
- Fail-closed assert against pipe-to-bash for `install-sfetch.sh` (`make assert-no-pipe-install-sfetch`).
- Soft-only sfetch pin freshness probe (`make check-sfetch-pin-freshness`); authenticity remains fail-closed.
- macOS Makefile bootstrap smoke job; dogfood job analyzes install-sfetch.sh after verified fetch.

### Changed

- Bootstrap pin **sfetch v0.4.11** (minisig installer path); goneat remains v0.5.15 with `--require-minisign`.
- Removed Chocolatey/winget minisign installs from Windows CI (pinned minisign 0.12 via setup-sfetch).
- Activated `make dogfood` in Linux CI quality job.

## [0.1.5] - 2026-07-30

### Added

- Pull-request and main-branch CI workflow with Linux amd64/arm64 and Windows amd64/arm64 coverage.
- Fail-closed `make release-verify-checksums` regression harness (`scripts/test-release-verify-checksums.sh`).
- Pinned `govulncheck@v1.6.0` quality gate in precommit and CI.

### Changed

- Go toolchain: `go 1.25.12` with `toolchain go1.26.5`; CI and release use Go 1.26.5.
- Dependencies: go-minisign tip, mvdan.cc/sh/v3 v3.13.1, golang.org/x/crypto v0.54.0, golang.org/x/sys v0.47.0.
- Bootstrap pins: sfetch v0.4.9 and goneat v0.5.15 installed into repo-local `bin/` with `--tag` and `--require-minisign`.
- Release workflow: replace archived Node12 create/upload actions with `softprops/action-gh-release@v3`; checkout@v5 and setup-go@v6.
- License check pins `go-licenses@v1.5.0` (no floating `@latest` on the release path).
- `make release-upload` now depends on the full `release-verify` chain.
- Supported release matrix is five targets; darwin/amd64 is no longer published.

### Fixed

- `release-verify-checksums` failed open: a failing `shasum -c` could still exit 0. Both SHA256SUMS and SHA512SUMS must now exist, be non-empty, and verify successfully.
- Bootstrap used invalid sfetch installer flag `--dest` and omitted `--tag` / minisign requirements, so pins were not enforced.

### Removed

- darwin/amd64 (Intel Mac) release artifacts. Last supporting release is v0.1.4. The install script and self-update path surface recovery guidance (`--tag v0.1.4` or build from source).

## [0.1.4] - 2026-03-11

### Added

- Composite release verification targets: `release-verify`, `release-verify-signatures`, `release-verify-keys`, `release-export-keys`.
- `scripts/verify-signatures.sh` for automated minisign and PGP signature verification.
- `release-verify-minisign-pubkey` target to validate exported key matches embedded trust anchor.

### Changed

- Renamed `SHA2-512SUMS` to `SHA512SUMS` across all code and scripts (aligned with sfetch and `sha512sum` convention).
- Reordered RELEASE_CHECKLIST.md: verify checksums before signing, verify signatures after.

### Fixed

- Windows ARM64 platform detection in install script: Git Bash under WoW64 emulation reported `x86_64`, causing wrong binary download. Added three-tier `detect_windows_arch()` fallback (RUNNER_ARCH, PowerShell OSArchitecture, PROCESSOR_ARCHITEW6432).
- `release-verify-minisign-pubkey` grep pattern now handles pretty-printed JSON output from `--self-verify --json`.
- Added `windows/arm64` to `build-all` and `package-all` Makefile targets (was already in CI matrix).

## [0.1.3] - 2026-03-10

### Changed

- **Go toolchain**: 1.25.1 -> 1.26.1 (resolves 1 critical, 10 high, 11 medium stdlib CVEs).
- **mvdan.cc/sh/v3**: 3.12.0 -> 3.13.0 (shell parser, direct dependency).
- **golang.org/x/crypto**: 0.31.0 -> 0.48.0 (resolves 3 advisories including GHSA-hcg3-q754-cr77).
- **golang.org/x/sys**: 0.33.0 -> 0.42.0.
- **github.com/spf13/pflag**: 1.0.9 -> 1.0.10.
- Pinned tool minimums: sfetch v0.4.5 and goneat v0.5.7.
- Commit attribution updated to precise provenance chain format with model/tool URLs and `Role:` trailer.
- Role catalog reorganized into categorized tables (Development & Engineering, Documentation & Governance).

### Added

- `.goneat/dependencies.yaml` for vulnerability scanning (`fail_on: high`), license compliance, and package cooling policy.

### Security

- All known stdlib and x/crypto CVEs resolved (0 findings on `goneat dependencies --vuln`).
- Vulnerability gating enforced at `high` severity via goneat dependency protection.

## [0.1.2] - 2026-01-10

### Added

- SDR documentation for gosec suppressions (G304, G302).
- Test coverage improvements for output and selfupdate packages.

### Security

- Suppressed gosec G302 false positive for executable permissions on self-update binary.

## [0.1.1] - 2026-01-02

### Added

- `--self-verify` flag to display verification instructions and embedded trust anchors.
- `--self-update` flag for cryptographically verified self-updates from GitHub releases.
- Embedded minisign public key as build-time trust anchor.
- SHA2-512SUMS support with automatic fallback to SHA256SUMS.
- Dev build guard preventing accidental self-update without `--self-update-force`.

### Security

- Minisign signature verification is mandatory before any checksum is trusted.
- Atomic binary replacement during self-update with rollback on failure.
- Major version jump protection requires explicit `--self-update-force`.

## [0.1.0] - 2026-01-01

### Added

- SARIF schema validation targets (`schema-validate`, `schema-meta`, `sarif-validate`).
- Goneat hook configuration with guardian-enabled pre-commit and pre-push hooks.
- Vendored SARIF 2.1.0 JSON schema for offline validation.
- Pre-commit and pre-push Make targets for local validation flows.
- Heredoc-aware comment stripping to preserve heredoc content in Level 1 analysis.

### Changed

- Pinned tool minimums: sfetch v0.3.1 and goneat v0.4.0 (existing installs respected).
- Normalized formatting across docs, schemas, and testdata with goneat format.

[Unreleased]: https://github.com/3leaps/shellsentry/compare/v0.1.8...HEAD
[0.1.8]: https://github.com/3leaps/shellsentry/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/3leaps/shellsentry/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/3leaps/shellsentry/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/3leaps/shellsentry/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/3leaps/shellsentry/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/3leaps/shellsentry/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/3leaps/shellsentry/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/3leaps/shellsentry/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/3leaps/shellsentry/releases/tag/v0.1.0
