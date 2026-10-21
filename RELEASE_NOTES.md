# Release Notes

Note: Keep only the latest three releases here, in newest-to-oldest order.

## v0.1.7

### Highlights

- Built with Go 1.26.10. Resolves standard library vulnerabilities reachable
  from shellsentry when built with Go 1.26.5.
- Release signing keys rotated to the current organization keys.
- Dependency and development tooling refresh.

### Security

- Go 1.26.10 resolves GO-2026-5026, GO-2026-5972, GO-2026-6090,
  GO-2026-6218, GO-2026-6603, GO-2026-6605, GO-2026-6607, GO-2026-6608,
  GO-2026-6610, GO-2026-6611, GO-2026-6612, GO-2026-6613, GO-2026-6617, and
  GO-2026-6809 (`net/http`, `net/url`, `net/textproto`, `crypto/tls`,
  `crypto/x509`, `encoding/asn1`). `govulncheck` reports no called
  vulnerabilities.
- `golang.org/x/crypto` v0.58.0 (GO-2026-6303, GO-2026-6354, GO-2026-6355 in
  `x/crypto/ssh`; not called by shellsentry).

### Changed

- `go.mod`: `go 1.26.0` with `toolchain go1.26.10`; CI and release use Go
  1.26.10.
- `golang.org/x/crypto` v0.58.0 and `golang.org/x/sys` v0.49.0.
- Release signing: the embedded self-update anchor and the installer's
  minisign and GPG pins move to the current organization keys. The installer
  selects one key generation per tag: v0.1.6 and earlier verify under the
  previous keys, v0.1.7 and later under the current keys, with no fallback.
- Verified bootstrap: sfetch v0.4.13 (engine and action commit, engine
  SHA-256, and consumer trust anchor) and goneat v0.6.6; golangci-lint pinned
  to v2.14.0 (was unpinned).

### Fixed

- `install-shellsentry.sh` GPG route reads the release key file's fingerprint
  correctly; it previously failed closed with a fingerprint mismatch. The key
  file must contain exactly one primary key equal to the pinned fingerprint,
  and the signature must come from that key. Key files with secret-key
  packets are refused.

### Upgrading

Self-update in v0.1.6 and earlier embeds the previous key and rejects v0.1.7.
Reinstall once with `install-shellsentry.sh` or sfetch:

```bash
curl -sSfL https://github.com/3leaps/shellsentry/releases/download/v0.1.7/install-shellsentry.sh | bash -s -- --tag v0.1.7
```

Self-update works again from v0.1.7 onward.

---

## v0.1.6

### Highlights

- CI installs sfetch via the `3leaps/sfetch` `setup-sfetch` action (SHA-pinned); no pipe-to-bash.
- Makefile bootstrap uses the digest-pinned `bootstrap-sfetch-verified` engine.
- Windows CI drops choco/winget minisign (pinned 0.12 via setup-sfetch).
- Soft-only pin freshness probe; fail-closed pipe-to-bash assert; dogfood and macOS bootstrap smoke.

### Pins

- sfetch v0.4.11, goneat v0.5.15.

---

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
