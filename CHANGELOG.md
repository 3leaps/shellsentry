# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to
Semantic Versioning.

## [Unreleased]

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
