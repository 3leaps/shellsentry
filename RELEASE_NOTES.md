# Release Notes

Note: Keep only the latest three releases here, in newest-to-oldest order.

## v0.1.8

### Highlights

- Tag-push CI only creates a draft GitHub release.
- `make release-tag` signs a local annotated tag from the operator GPG home
  (smartcard / non-exportable subkeys). `make release-publish` promotes only
  after a byte-for-byte draft check.
- Every GitHub Actions `uses:` is a commit SHA with a version comment.
- `gosec` is pinned to v2.29.0 and fails closed when missing or mismatched.
- Verified bootstrap consumes sfetch v0.4.15.

### Changed

- Tag signing binds `GNUPGHOME` to `SHELLSENTRY_GPG_HOMEDIR` and does not
  export secret keys or `gpgconf --kill` the operator agent. Public-pin
  verification stays on a disposable keyring.
- Bootstrap: sfetch v0.4.15, engine and action
  `c44577261902c848119d3c89b0138becb613b158`. goneat stays v0.6.6.

### Fixed

- `gosec` is installed at v2.29.0 into `bin/`. `make gosec-high` fails closed
  if it is missing or if the binary on PATH does not match `GOSEC_VERSION`.
- Release workflow: `draft: true` on every `action-gh-release` step; build is
  `contents: read` and only uploads artifacts; a separate upload job with
  `contents: write` attaches them to the draft.
- Workflow actions, including `actions/checkout` and `actions/setup-go`, are
  40-character commit SHAs. Artifact actions are both v7.
  `scripts/test-workflow-action-pins.py` fails if a pin is reverted to a tag.
- `make assert-tool-pins` takes the first version line without piping through
  `head`, so extra output cannot SIGPIPE the pin check.
- The smartcard fixture refuses a bare `gpgconf --kill` while `GNUPGHOME` is
  the operator home.

### Added

- `make release-tag` creates a local signed annotated tag and verifies it
  against the committed public pin. `make release-publish` re-downloads the
  draft, byte-compares `SHA256SUMS` and every listed asset, then publishes.
  Tagging, upload, and publish scripts refuse `GITHUB_ACTIONS`.

### Upgrading

Self-update from v0.1.7 works. Binaries through v0.1.6 still need a one-time
reinstall under the current keys:

```bash
curl -sSfL https://github.com/3leaps/shellsentry/releases/download/v0.1.8/install-shellsentry.sh | bash -s -- --tag v0.1.8
```

---

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
