# Release Notes

Note: Keep only the latest three releases here, in newest-to-oldest order.

## v0.1.3

### Highlights

- Security dependency sweep: all known stdlib and x/crypto CVEs resolved.
- Go toolchain bumped to 1.26.1; shell parser (mvdan.cc/sh) updated to v3.13.0.
- Goneat dependency protection added with vulnerability gating at `high` severity.
- Agentic attribution hardened against email squatting with full provenance chain format.

### Changed

- Go toolchain: 1.25.1 -> 1.26.1 (resolves 1 critical, 10 high, 11 medium stdlib CVEs).
- mvdan.cc/sh/v3: 3.12.0 -> 3.13.0 (shell parser, direct dependency).
- golang.org/x/crypto: 0.31.0 -> 0.48.0 (resolves 3 advisories).
- golang.org/x/sys: 0.33.0 -> 0.42.0.
- github.com/spf13/pflag: 1.0.9 -> 1.0.10.
- Pinned tool minimums: sfetch v0.4.5, goneat v0.5.7.
- Commit attribution now requires model vendor URL, tool URL, Role trailer, and full Committer-of-Record identity.
- Role catalog reorganized into categorized tables.

### Added

- `.goneat/dependencies.yaml` with vulnerability scanning, license compliance, and package cooling policy.

### Security

- Zero vulnerability findings after upgrades (was 1 critical, 10 high, 11 medium).
- Vulnerability gating enforced at `high` severity via goneat dependency protection.

---

## v0.1.2

### Highlights

- SDR documentation for gosec suppressions.
- Test coverage improvements for output and selfupdate packages.

### Security

- Suppressed gosec G302 false positive for executable permissions on self-update binary.
- Added SDR documentation for G304 (file inclusion) and G302 (file permissions) suppressions.

---

## v0.1.1

### Highlights

- Self-verification and self-update capabilities with cryptographic verification.
- Embedded minisign public key as build-time trust anchor.
- Follows sfetch patterns for secure update workflow.

### Added

- `--self-verify` flag displays verification instructions and embedded trust anchors.
- `--self-update` flag performs cryptographically verified updates from GitHub releases.
- `--self-update-force` allows major version jumps and dev build updates.
- `--self-update-dir` specifies custom install directory.
- `--json` flag for machine-readable `--self-verify` output.
- SHA2-512SUMS support with automatic fallback to SHA256SUMS.

### Security

- Minisign signature verification is mandatory before trusting any checksum.
- Atomic binary replacement with rollback on failure.
- Dev builds blocked from self-update unless `--self-update-force` is used.
- Major version jumps require explicit `--self-update-force` confirmation.
