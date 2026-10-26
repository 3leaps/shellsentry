# Release Notes

Note: Keep only the latest three releases here, in newest-to-oldest order.

## v0.1.8

### Highlights

- Tag-push CI is read-only: it verifies committed public anchors, builds five
  native platforms, and uploads archives as artifacts. It does not create a
  GitHub Release and does not sign.
- `make release-tag` signs a local annotated tag from the operator GPG home
  (smartcard / non-exportable subkeys). `make release-create-draft` opens the
  draft from local packages. `make release-publish` promotes only after a
  byte-for-byte draft check.
- Every GitHub Actions `uses:` is a commit SHA with a version comment.
- `gosec` is pinned to v2.29.0 and fails closed when missing or mismatched.
- Verified bootstrap consumes sfetch v0.4.15.
- Parser is `mvdan.cc/sh/v3` v3.14.1; staticcheck v0.8.2; govulncheck v1.9.0.

### Changed

- Tag signing binds `GNUPGHOME` to `SHELLSENTRY_GPG_HOMEDIR` and does not
  export secret keys or `gpgconf --kill` the operator agent. Public-pin
  verification stays on a disposable keyring.
- Bootstrap: sfetch v0.4.15, engine and action
  `c44577261902c848119d3c89b0138becb613b158`. goneat stays v0.6.6.
- The installer previous-key cutoff stays at v0.1.6 as a quoted literal.
  Ambient `SHELLSENTRY_PREVKEY_MAX` cannot move it.

### Fixed

- `gosec` is installed at v2.29.0 into `bin/`. `make gosec-high` fails closed
  if it is missing or if the binary on PATH does not match `GOSEC_VERSION`.
- Tag workflow: `contents: read` only; no GitHub Release; no signing.
  Drafting and publishing stay on the operator machine.
- Workflow actions, including `actions/checkout` and `actions/setup-go`, are
  40-character commit SHAs. Artifact actions are both v7.
  `scripts/test-workflow-action-pins.py` fails if a pin is reverted to a tag.
- `make assert-tool-pins` takes the first version line without piping through
  `head`, so extra output cannot SIGPIPE the pin check.
- The smartcard fixture refuses a bare `gpgconf --kill` while `GNUPGHOME` is
  the operator home.
- Upgrade and install examples download the installer, verify `SHA256SUMS`
  plus minisign or PGP, optionally run shellsentry on it, then execute. They
  do not pipe curl to a shell. Checksums use `sha256sum -c -` or
  `shasum -a 256 -c`, and `set -e` stops the run if a check fails. PGP
  recipes fetch `shellsentry-release-signing-key.asc`, require exactly one
  primary matching the pinned fingerprint, and verify with `gpgv --keyring`
  plus `[GNUPG:] VALIDSIG` for the pinned signing subkey.
- `make release-upload` attaches `release-notes-<tag>.md`. `make
  release-publish` byte-compares that asset to `docs/releases/<tag>.md` at
  the tagged commit. GitHub release titles drop a leading `# ` from that
  heading.
- Release archives bind to a unique delimited version label, a real-date
  `buildTime`, and the tagged `gitCommit`. A byte scan cannot attribute
  those strings to a specific `-X` variable, so the source is pinned by
  `mod`, `vcs.revision`, and `vcs.modified`.
- Platform CI steps refuse the common soft-fail forms (`continue-on-error`,
  `if: false`, and `|| true`).

### Added

- `make release-tag` creates a local signed annotated tag from
  `SHELLSENTRY_RELEASE_TAG` and verifies it against the committed public pin.
  `make release-create-draft` opens the GitHub draft from locally staged
  packages. `make release-publish` re-downloads the draft, byte-compares
  `SHA256SUMS` and every listed asset, then publishes. Tagging, upload, and
  publish scripts refuse `GITHUB_ACTIONS`.
- Release preflight binds `SHELLSENTRY_DECERNOR_BIN` and checks GPG and
  minisign exports against the fingerprint anchors in the tagged commit.
  Staged keys come from that commit. CI installs Decernor from a digest pin.
- Pull requests and tag builds run natively on linux/amd64, linux/arm64,
  darwin/arm64, windows/amd64, and windows/arm64. Windows archives are packed
  with `scripts/package-windows-zip.sh` and a SHA-pinned `actions/setup-python`.

### Upgrading

Self-update from v0.1.7 works. Binaries through v0.1.6 still need a one-time
reinstall under the current keys. Download the installer, verify it, then run
it — do not pipe curl to a shell.

```bash
set -euo pipefail
BASE=https://github.com/3leaps/shellsentry/releases/download/v0.1.8
curl -sSfLO "$BASE/install-shellsentry.sh"
curl -sSfLO "$BASE/SHA256SUMS"
curl -sSfLO "$BASE/SHA256SUMS.minisig"
minisign -Vm SHA256SUMS -P RWTqUZ/PtmfAbQ3RKIlp/YTKT6zFeNMAZ8iAMelhlmqEsVqjKj3ctSA1
# PGP instead of minisign:
# curl -sSfLO "$BASE/SHA256SUMS.asc"
# curl -sSfLO "$BASE/shellsentry-release-signing-key.asc"
# gpg --show-keys --with-fingerprint shellsentry-release-signing-key.asc
# listing=$(gpg --show-keys --with-colons shellsentry-release-signing-key.asc)
# n=$(printf '%s\n' "$listing" | awk -F: '$1=="pub" || $1=="sec" {n++} END {print n+0}')
# fpr=$(printf '%s\n' "$listing" | awk -F: '$1=="fpr" {print $10; exit}')
# [ "$n" = 1 ] && [ "$fpr" = 0CACA49B3119B6BC12B2CA11B9B485F294B9FE07 ] || { echo 'error: PGP key is not the pinned primary' >&2; exit 1; }
# gpg --dearmor --output shellsentry-release-signing-key.gpg shellsentry-release-signing-key.asc
# status=$(gpgv --keyring ./shellsentry-release-signing-key.gpg --status-fd 1 SHA256SUMS.asc SHA256SUMS) || { echo 'error: PGP signature verification failed' >&2; exit 1; }
# printf '%s\n' "$status" | grep -q '^\[GNUPG:\] VALIDSIG DAB70DD758911B26BB45A08C3B75AC591449DEBE ' || { echo 'error: PGP signature is not from the pinned signing subkey' >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  grep 'install-shellsentry.sh' SHA256SUMS | sha256sum -c -
else
  grep 'install-shellsentry.sh' SHA256SUMS | shasum -a 256 -c
fi
# optional: shellsentry --exit-on-danger install-shellsentry.sh
bash install-shellsentry.sh --tag v0.1.8
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
Reinstall once with `install-shellsentry.sh` or sfetch. Download the installer,
verify it, then run it — do not pipe curl to a shell.

```bash
set -euo pipefail
BASE=https://github.com/3leaps/shellsentry/releases/download/v0.1.7
curl -sSfLO "$BASE/install-shellsentry.sh"
curl -sSfLO "$BASE/SHA256SUMS"
curl -sSfLO "$BASE/SHA256SUMS.minisig"
minisign -Vm SHA256SUMS -P RWTqUZ/PtmfAbQ3RKIlp/YTKT6zFeNMAZ8iAMelhlmqEsVqjKj3ctSA1
# PGP instead of minisign:
# curl -sSfLO "$BASE/SHA256SUMS.asc"
# gpg --import docs/security/release-signing-keys.asc
# signing subkey DAB70DD758911B26BB45A08C3B75AC591449DEBE
# gpg --verify SHA256SUMS.asc SHA256SUMS
if command -v sha256sum >/dev/null 2>&1; then
  grep 'install-shellsentry.sh' SHA256SUMS | sha256sum -c -
else
  grep 'install-shellsentry.sh' SHA256SUMS | shasum -a 256 -c
fi
# optional: shellsentry --exit-on-danger install-shellsentry.sh
bash install-shellsentry.sh --tag v0.1.7
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
