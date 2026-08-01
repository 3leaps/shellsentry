# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to
Semantic Versioning.

## [Unreleased]

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

[Unreleased]: https://github.com/3leaps/shellsentry/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/3leaps/shellsentry/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/3leaps/shellsentry/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/3leaps/shellsentry/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/3leaps/shellsentry/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/3leaps/shellsentry/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/3leaps/shellsentry/releases/tag/v0.1.0
