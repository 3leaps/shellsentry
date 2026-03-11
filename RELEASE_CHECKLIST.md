# Release Checklist

This document walks maintainers through the build/sign/upload flow for each shellsentry release.

> **Naming note:** Starting with v0.1.4, checksum manifests use `SHA512SUMS`
> (aligned with sfetch and conventional `sha512sum` naming). Releases v0.1.3 and
> earlier used `SHA2-512SUMS`. The self-update code falls back gracefully.

## 1. Prepare & Tag

- [ ] Ensure `main` is clean and `make prepush` passes
- [ ] Update `VERSION` file with new semver (e.g., `0.1.0`)
- [ ] Update `CHANGELOG.md` (move Unreleased to new version section)
- [ ] Update `RELEASE_NOTES.md`
- [ ] Create `docs/releases/vX.Y.Z.md`
- [ ] Commit: `git add -A && git commit -m "release: prepare vX.Y.Z"`
- [ ] Push and tag:
  ```bash
  git push origin main
  git tag v$(cat VERSION)
  git push origin v$(cat VERSION)
  ```
- [ ] Wait for GitHub Actions release workflow to complete
  - CI validates VERSION file matches tag
  - Builds unsigned archives
  - Uploads install-shellsentry.sh

## 2. Manual Signing (local machine)

Set environment variables:

```bash
export SHELLSENTRY_RELEASE_TAG=v$(cat VERSION)
export SHELLSENTRY_MINISIGN_KEY=/path/to/shellsentry.key
export SHELLSENTRY_MINISIGN_PUB=/path/to/shellsentry.pub
export SHELLSENTRY_PGP_KEY_ID="security@3leaps.net"        # or your-subkey-id!
export SHELLSENTRY_GPG_HOMEDIR=/path/to/custom/gpg/homedir   # optional, defaults to ~/.gnupg
```

### Steps

1. **Clean previous release artifacts**

   ```bash
   make release-clean
   ```

2. **Download artifacts**

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

10. **Upload signatures and keys**

    ```bash
    make release-upload
    ```

    > **Note:** This uploads ALL assets with `--clobber`, including binaries CI already uploaded.
    > This is intentional for idempotency - rerun safely to fix any mistakes.

## 3. Post-Release

- [ ] Verify release: `gh release view v$(cat VERSION)`
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

- [ ] `scripts/install-shellsentry.sh` - embedded `SHELLSENTRY_MINISIGN_PUBKEY`
- [ ] `README.md` - verification snippet public key
- [ ] Any external documentation referencing shellsentry signing keys

## Versioning Reference

- **Patch** (0.1.5): Bug fixes, security patches
- **Minor** (0.2.0): New features, backward-compatible
- **Major** (1.0.0): Breaking changes
