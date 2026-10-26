# Release Checklist

This document walks maintainers through the signed-tag, build, sign, and publish flow for each shellsentry release.

> **Naming note:** Starting with v0.1.4, checksum manifests use `SHA512SUMS`
> (aligned with sfetch and conventional `sha512sum` naming). Releases v0.1.3 and
> earlier used `SHA2-512SUMS`. The self-update code falls back gracefully.

Signing and publish scripts run on the maintainer's machine only. They refuse
`GITHUB_ACTIONS`. CI builds unsigned archives and uploads them as workflow
artifacts; it never tags, signs, creates a GitHub Release, or publishes. The
maintainer signs the manifests, then opens the draft locally with
`make release-create-draft`.

For v0.1.8, `VERSION`, `CHANGELOG.md`, `RELEASE_NOTES.md`, and
`docs/releases/v0.1.8.md` are already on `main`. Start at the signed-tag step
below. Do not retag or bump `VERSION` again.

Set the canonical tag (must equal `v$(cat VERSION)`). Bare `RELEASE_TAG` is
not accepted from the environment or the command line.

```bash
export SHELLSENTRY_RELEASE_TAG=v$(cat VERSION)
export SHELLSENTRY_TAG_MESSAGE_DIR="$HOME/devsecops/releases/github/3leaps/shellsentry/$SHELLSENTRY_RELEASE_TAG"
export SHELLSENTRY_TAGGER_NAME='3 Leaps Infosec Team'
export SHELLSENTRY_TAGGER_EMAIL='infosec@3leaps.net'
export SHELLSENTRY_GPG_SIGNING_FINGERPRINT=<40-hex-primary>
export SHELLSENTRY_PGP_KEY_ID=<40-hex-signing-subkey>!
export SHELLSENTRY_GPG_HOMEDIR=/path/to/operator/gpg/homedir   # outside repo; not ~/.gnupg; mode 0700
export SHELLSENTRY_DECERNOR_BIN=/absolute/path/to/decernor     # regular executable; no symlink; no PATH fallback
```

The tagger string must equal `config/release/tagger-identity.txt`
(`3 Leaps Infosec Team <infosec@3leaps.net>`), not the first GPG UID.
Sign with the exact subkey (`SHELLSENTRY_PGP_KEY_ID=<subkey>!`).

## 1. Prepare & signed tag (local)

- [ ] Ensure `main` is clean and `make prepush` passes
- [ ] Update `VERSION` file with new semver (e.g., `0.1.0`)
- [ ] Update `CHANGELOG.md` (move Unreleased to new version section)
- [ ] Update `RELEASE_NOTES.md`
- [ ] Create `docs/releases/vX.Y.Z.md`
- [ ] Commit: `git add -A && git commit -m "release: prepare vX.Y.Z"`
- [ ] Push `main`
- [ ] Confirm committed anchors: `make release-verify-committed-anchors`
- [ ] Run the pre-tag gate: `make release-preflight`
- [ ] Prepare the public tag message (creates `$SHELLSENTRY_TAG_MESSAGE_DIR/message.txt` if missing; does not overwrite): `make release-prepare-tag-message`
- [ ] Create the signed annotated tag locally (does not push): `make release-tag`

  Tag signing uses `SHELLSENTRY_GPG_HOMEDIR` and its existing agent/smartcard
  setup directly; it does not export secret keys. The primary secret key may
  remain offline. Public verification uses only the committed pin in a
  temporary keyring (`docs/security/release-signing-keys.asc`,
  `docs/security/shellsentry-minisign.pub`, and
  `keys/expected-fingerprints.{txt,ndjson}`), separate from the operator home.
  Re-check with `make release-verify-tag`.

- [ ] Push only the tag and confirm it is unchanged: `make release-push-tag`
- [ ] Confirm the remote object equals the local one and GitHub reports Verified with reason `valid`: `make release-verify-remote-tag`
- [ ] Wait for GitHub Actions release workflow to complete
  - CI validates VERSION file matches tag
  - The `verify-anchors` job installs digest-pinned Decernor and checks the
    committed public anchors
  - The `build` job (`contents: read`, `ubuntu-24.04`, `needs: verify-anchors`)
    builds unsigned archives for the five-platform matrix
  - `collect-packages` uploads a single `release-packages-$TAG` artifact
  - CI never creates a GitHub Release and never requests `contents: write`
  - A green tag run is a consistency signal, not release authorization
  - Record the successful Release workflow run id and attempt for staging

## 2. Stage packages, sign, then open the draft (local machine)

```bash
export SHELLSENTRY_RELEASE_TAG=v$(cat VERSION)
export SHELLSENTRY_MINISIGN_KEY=/path/to/shellsentry.key
export SHELLSENTRY_PGP_KEY_ID=<40-hex-signing-subkey>!
export SHELLSENTRY_GPG_HOMEDIR=/path/to/operator/gpg/homedir   # outside repo; not ~/.gnupg
```

### Steps

1. **Clean previous release artifacts**

   ```bash
   make release-clean
   ```

2. **Fetch the tag-workflow packages** bound to that run, attempt, and digest

   ```bash
   export RELEASE_RUN_ID=<run-id>
   export RELEASE_RUN_ATTEMPT=<attempt>
   make release-download
   ```

   `release-download` verifies the published tag, downloads the combined
   `release-packages-$TAG` artifact by id, and checks the zip digest.
   Local `make package-all` is not a substitute: the signed bytes must be
   the archives CI produced for that tagged commit.

   Expected names: `shellsentry_linux_amd64.tar.gz`,
   `shellsentry_linux_arm64.tar.gz`, `shellsentry_windows_amd64.zip`,
   `shellsentry_windows_arm64.zip`, `shellsentry_darwin_arm64.tar.gz`.

3. **Generate checksum manifests** (`SHA256SUMS`, `SHA512SUMS`)

   ```bash
   make release-checksums
   ```

   Also copies `scripts/install-shellsentry.sh` into `dist/release/`.

4. **Verify checksums**

   ```bash
   make release-verify-checksums
   ```

5. **Sign checksum manifests** with minisign + PGP

   ```bash
   make release-sign
   ```

   Produces: `SHA256SUMS`, `SHA512SUMS` plus `.minisig`/`.asc`. Signatures
   must exist before the draft is opened.

6. **Verify signatures**

   ```bash
   make release-verify-signatures
   ```

   Reads the minisign and GPG public keys from the tagged commit only.
   Both signatures must verify on both manifests. Env-named key files
   are not used.

7. **Create the draft GitHub release** from the staged packages

   ```bash
   make release-create-draft
   ```

   Runs `gh release create --verify-tag --draft`. Refuses GitHub Actions
   and refuses if a release for the tag already exists. Before trusting
   the tag, confirms the local tag object equals origin, GitHub reports
   it verified/valid, the tagged commit is an ancestor of `origin/main`,
   and identity files are byte-identical to `origin/main`. Checks that
   both manifests list exactly the staged archives with matching hashes,
   verifies minisign and GPG signatures with the keys from the tagged
   commit, binds each archive via `go version -m` (`mod` equals the tag,
   `vcs.revision` equals the tagged commit, `vcs.modified` is false)
   plus exactly one delimited version label, one real RFC3339 UTC date,
   and one 40-hex tagged commit. Known limit: a byte scan cannot tell
   which `-X` variable a string belongs to, so `internal/cli` ldflags
   (or swapped buildTime/gitCommit) can satisfy the labels while
   `shellsentry version` reports `main.version`. Release notes come
   from the tagged commit
   (`git cat-file blob <commit>:docs/releases/<tag>.md`), not the
   working tree. Also refuses extra files and a tag that no longer
   matches the staging anchor.

8. **Export public keys**

   ```bash
   make release-export-keys
   ```

9. **Verify exported keys**

   ```bash
   make release-verify-keys
   ```

   Requires both staged public keys and `SHELLSENTRY_RELEASE_TAG`.
   Decernor checks them against the fingerprint anchors in the tagged
   commit (PDR-0008 §2.1); the primary fingerprint, signing-subkey id,
   and minisign blob are compared explicitly. Working-tree identity
   files are not used as the pin.

   Or run all verification in one step:

   ```bash
   make release-verify
   ```

10. **Copy release notes** (requires `docs/releases/$SHELLSENTRY_RELEASE_TAG.md`)

    ```bash
    make release-notes
    ```

11. **Upload remaining keys** (draft is preserved)

    ```bash
    make release-upload
    ```

    Uploads assets with `--clobber` and edits notes with `--draft=true`.
    Promotion is the next step, after byte verification.

## 3. Publish (byte-verified)

- [ ] Promote only after the draft is the locally verified set:

  ```bash
  make release-publish
  ```

  `release-publish` re-verifies the staged tag through the shared tag-anchor
  (fetches `origin/main` first), requires the GitHub release `tagName`,
  title, and body to match the signed tag and tagged notes, requires an
  exact draft asset set, checks both manifests and their minisign/PGP
  signatures against pins in the tagged commit, binds each archive so
  `go version -m` `mod` equals the tag, there is exactly one delimited
  version label for the tag without the leading v, exactly one real
  RFC3339 UTC date, and exactly one 40-hex tagged commit. Known limit:
  a byte scan cannot tell which `-X` variable a string belongs to, so
  `internal/cli` ldflags (or swapped buildTime/gitCommit) can satisfy
  the labels while `shellsentry version` reports `main.version`. Then
  re-downloads the draft, `cmp`s every asset, re-verifies the tag
  immediately before promotion, then runs `gh release edit --draft=false`.
  It targets `3leaps/shellsentry` only. It refuses GitHub Actions, an
  edited body, and a non-draft release. Do not run
  `gh release edit --draft=false` by hand.

- [ ] Verify release: `gh release view "$SHELLSENTRY_RELEASE_TAG"`
- [ ] Test install script: download `install-shellsentry.sh`, verify it against
      `SHA256SUMS` plus minisign or PGP, optionally run shellsentry on it, then
      `bash install-shellsentry.sh --dry-run`
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
- [ ] `docs/security/shellsentry-minisign.pub` - committed minisign pin (also `go:embed`)
- [ ] `docs/security/sfetch-minisign.pub` - third-party sfetch pin
- [ ] `keys/expected-fingerprints.txt` and `keys/expected-fingerprints.ndjson` - derived by Decernor, never typed
- [ ] `config/release/decernor-ci-sha256.txt` - digest of the Decernor archive CI downloads
- [ ] `scripts/install-shellsentry.sh` - embedded `SHELLSENTRY_MINISIGN_PUBKEY` and `SHELLSENTRY_PGP_FPR` (equality-tested against the committed files)
- [ ] `README.md` - verification snippet public key
- [ ] Any external documentation referencing shellsentry signing keys

## Versioning Reference

- **Patch** (0.1.5): Bug fixes, security patches
- **Minor** (0.2.0): New features, backward-compatible
- **Major** (1.0.0): Breaking changes
