# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to
Semantic Versioning.

## [Unreleased]

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
