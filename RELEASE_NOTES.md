# Release Notes

Note: Keep only the latest three releases here, in newest-to-oldest order.

## v0.1.5

### Highlights

- Package and CI/CD hygiene: PR CI, modern Node 24-era Actions, verified bootstrap pins.
- Release verification is fail-closed; upload requires the full verify chain.
- darwin/amd64 (Intel Mac) artifacts dropped; last supporting release is v0.1.4.

### Added

- PR/main CI covering Linux amd64/arm64 and Windows amd64/arm64 (org named runners for ARM64).
- Fail-closed checksum verification regression harness.
- Pinned govulncheck v1.6.0 in local and CI quality gates.

### Changed

- Go 1.25.12 / toolchain 1.26.5; module bumps for go-minisign, mvdan/sh, x/crypto, x/sys.
- Bootstrap: sfetch v0.4.9 + goneat v0.5.15 into repo-local `bin/` with minisign and exact tags.
- Release workflow uses softprops/action-gh-release@v3 (replaces archived Node12 create/upload actions).
- go-licenses pinned to v1.5.0 on the release path.

### Removed

- `shellsentry_darwin_amd64.tar.gz` is no longer published.
- Intel Mac recovery:

```bash
curl -sSfL https://github.com/3leaps/shellsentry/releases/download/v0.1.4/install-shellsentry.sh | bash -s -- --tag v0.1.4
```

### Supported platforms from v0.1.5

| OS      | Architectures   |
| ------- | --------------- |
| Linux   | amd64, arm64    |
| macOS   | arm64           |
| Windows | amd64, arm64    |

---

## v0.1.4

### Highlights

- Release verification aligned to sfetch pattern with composite `make release-verify` gate.
- Checksum manifest naming aligned to `SHA512SUMS` (convention match with sfetch and `sha512sum`).
- Windows ARM64 install script fix: correct binary now downloaded on ARM64 hardware.

### Added

- `release-verify` composite target runs checksums, signatures, and key verification in one step.
- `release-verify-signatures` + `scripts/verify-signatures.sh` for automated signature validation.
- `release-verify-keys` validates both PGP and minisign public keys.
- `release-export-keys` exports both key types in one command.
- `release-verify-minisign-pubkey` validates exported key matches embedded trust anchor.

### Changed

- Renamed `SHA2-512SUMS` -> `SHA512SUMS` across Go source, scripts, and Makefile. Self-update falls back to SHA256SUMS for older releases.
- RELEASE_CHECKLIST.md reordered: verify checksums before signing, verify signatures after.

### Fixed

- Windows ARM64 platform detection: `detect_windows_arch()` with three-tier fallback (RUNNER_ARCH, PowerShell OSArchitecture, PROCESSOR_ARCHITEW6432) prevents WoW64 emulation from selecting wrong binary.
- `release-verify-minisign-pubkey` grep pattern for pretty-printed JSON output.
- `build-all` and `package-all` now include `windows/arm64` (aligned with CI matrix).

---

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

### Security

- Zero vulnerability findings after upgrades (was 1 critical, 10 high, 11 medium).
- Vulnerability gating enforced at `high` severity via goneat dependency protection.
