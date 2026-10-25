# Release Checklist

This document walks maintainers through the signed-tag, build, sign, and publish flow for each shellsentry release.

> **Naming note:** Starting with v0.1.4, checksum manifests use `SHA512SUMS`
> (aligned with sfetch and conventional `sha512sum` naming). Releases v0.1.3 and
> earlier used `SHA2-512SUMS`. The self-update code falls back gracefully.

Signing and publish scripts run on the maintainer's machine only. They refuse
`GITHUB_ACTIONS`. CI builds unsigned archives and attaches them to a **draft**
GitHub release; it never tags, signs, or publishes.

Set the canonical tag (must equal `v$(cat VERSION)`):

```bash
export SHELLSENTRY_RELEASE_TAG=v$(cat VERSION)
```

Bare `RELEASE_TAG` is not accepted.

## 1. Prepare & signed tag (local)

- [ ] Ensure `main` is clean and `make prepush` passes
- [ ] Update `VERSION` file with new semver (e.g., `0.1.0`)
- [ ] Update `CHANGELOG.md` (move Unreleased to new version section)
- [ ] Update `RELEASE_NOTES.md`
- [ ] Create `docs/releases/vX.Y.Z.md`
- [ ] Commit: `git add -A && git commit -m "release: prepare vX.Y.Z"`
- [ ] Push `main`
- [ ] Create the signed annotated tag locally (does not push):

  ```bash
  export SHELLSENTRY_RELEASE_TAG=v$(cat VERSION)
  export SHELLSENTRY_PGP_KEY_ID=<40-hex-signing-subkey>!
  export SHELLSENTRY_GPG_HOMEDIR=/path/to/isolated/gpg/homedir   # not ~/.gnupg, not inside the repo
  make release-tag
  ```

  `make release-tag` imports the signing subkey into a throwaway GNUPGHOME,
  creates an annotated signed tag, and verifies it against the public pin
  committed in the tagged commit (`docs/security/release-signing-keys.asc` and
  `keys/expected-fingerprints.txt`). Re-check with `make release-verify-tag`.

- [ ] Push the already-signed tag: `git push origin "$SHELLSENTRY_RELEASE_TAG"`
- [ ] Wait for GitHub Actions release workflow to complete
  - CI validates VERSION file matches tag
  - The `build` job (contents: read) builds unsigned archives for the five
    platform matrix and uploads them as artifacts
  - The `upload` job (contents: write) attaches those archives plus
    `install-shellsentry.sh` to a **draft** GitHub release
  - CI cannot publish; the draft stays unpublished until after signing

## 2. Manual Signing (local machine)

```bash
export SHELLSENTRY_RELEASE_TAG=v$(cat VERSION)
export SHELLSENTRY_MINISIGN_KEY=/path/to/shellsentry.key
export SHELLSENTRY_MINISIGN_PUB=/path/to/shellsentry.pub
export SHELLSENTRY_PGP_KEY_ID=<40-hex-signing-subkey>!
export SHELLSENTRY_GPG_HOMEDIR=/path/to/isolated/gpg/homedir
```

### Steps

1. **Clean previous release artifacts**

   ```bash
   make release-clean
   ```

2. **Download draft artifacts**

   ```bash
   make release-download
   ```

3. **Generate checksum manifests** (`SHA256SUMS`, `SHA512SUMS`)

   ```bash
   make release-checksums
   ```

4. **Verify checksums**

   ```bash
   make release-verify-checksums
   ```

5. **Sign checksum manifests** with minisign + PGP

   ```bash
   make release-sign
   ```

   Produces: `SHA256SUMS`, `SHA512SUMS` plus `.minisig`/`.asc`

6. **Verify signatures**

   ```bash
   make release-verify-signatures
   ```

7. **Export public keys**

   ```bash
   make release-export-keys
   ```

8. **Verify exported keys**

   ```bash
   make release-verify-keys
   ```

   Or run all verification in one step:

   ```bash
   make release-verify
   ```

9. **Copy release notes** (requires `docs/releases/$SHELLSENTRY_RELEASE_TAG.md`)

   ```bash
   make release-notes
   ```

10. **Upload signatures and keys** (draft is preserved)

    ```bash
    make release-upload
    ```

    Uploads assets with `--clobber` and edits notes with `--draft=true`.
    Promotion is the next step, after byte verification.

## 3. Publish (byte-verified)

- [ ] Promote only after the draft matches local `SHA256SUMS` byte-for-byte:

  ```bash
  make release-publish
  ```

  `release-publish` refuses a non-draft release, re-downloads the draft,
  `cmp`s `SHA256SUMS` and every listed file against the local tree, then
  runs `gh release edit --draft=false`.

- [ ] Verify release: `gh release view "$SHELLSENTRY_RELEASE_TAG"`
- [ ] Test install script: `curl -sSfL .../install-shellsentry.sh | bash -s -- --dry-run`
- [ ] Verify binary version: `shellsentry --version` shows correct version
- [ ] Announce release

## 4. Post-Release Version Bump (optional)

After release, bump VERSION for next development cycle:

```bash
make version-patch   # 0.1.0 -> 0.1.1 (bugfix prep)
# or: make version-minor  # 0.1.0 -> 0.2.0 (feature prep)
# or: make version-major  # 0.1.0 -> 1.0.0 (breaking change prep)
# or: make version-set V=1.2.3  # explicit version

git add VERSION
git commit -m "chore: bump version to $(cat VERSION)-dev"
```

Check current version anytime with `make version-check`.

## Key Rotation Reminder

If rotating signing keys, also update:

- [ ] `docs/security/release-signing-keys.asc` - committed GPG public pin
- [ ] `docs/security/shellsentry-minisign.pub` and `configs/keys/shellsentry-minisign.pub`
- [ ] `keys/expected-fingerprints.txt` - GPG primary fingerprint and minisign key SHA-256
- [ ] `scripts/install-shellsentry.sh` - embedded `SHELLSENTRY_MINISIGN_PUBKEY` and `SHELLSENTRY_PGP_FPR`
- [ ] `README.md` - verification snippet public key
- [ ] Any external documentation referencing shellsentry signing keys

## Versioning Reference

- **Patch** (0.1.5): Bug fixes, security patches
- **Minor** (0.2.0): New features, backward-compatible
- **Major** (1.0.0): Breaking changes
