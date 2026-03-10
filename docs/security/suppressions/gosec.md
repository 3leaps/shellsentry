# Gosec Suppression Decisions

This document records Security Decision Records (SDRs) for gosec static analysis suppressions in shellsentry.

## SDR-001: CLI File Path Inputs (G304)

**Rule:** G304 - Potential file inclusion via variable
**Severity:** Medium
**Instances:** 4
**Decision:** Suppress with `#nosec G304 -- SDR-001`

### Context

G304 flags `os.ReadFile(path)`, `os.Open(path)`, and `os.Create(path)` where `path` is a variable, warning of potential path traversal attacks.

### Threat Model Consideration

This rule protects against attacks where:

1. Untrusted remote input becomes a file path
2. The application has higher privileges than the input source
3. Attackers could read/write sensitive files they shouldn't access

### Why Suppression is Appropriate

shellsentry is a CLI tool where:

1. **No privilege escalation**: shellsentry runs with the invoking user's permissions. A user who runs `shellsentry /etc/shadow` could also run `cat /etc/shadow`.

2. **Local user = trusted input**: Command-line arguments come from a local user with shell access. The "attacker" would need local access, at which point they have equivalent capabilities without shellsentry.

3. **Intended functionality**: Reading user-specified scripts for analysis and writing to user-specified output files is core functionality.

4. **No network exposure**: These code paths are only reachable from CLI argument parsing, not from network input.

### Affected Locations

| File                            | Function        | Purpose                                 |
| ------------------------------- | --------------- | --------------------------------------- |
| internal/cli/root.go            | runAnalysis     | User-specified script file for analysis |
| internal/cli/root.go            | runAnalysis     | User-specified output file path         |
| scripts/cmd/generate-checksums/ | writeChecksums  | Build tool output path                  |
| scripts/cmd/generate-checksums/ | computeFileHash | Build tool reading release assets       |

---

## SDR-002: File Permissions (G302)

**Rule:** G302 - Expect file permissions to be 0600 or less
**Severity:** Medium
**Instances:** 1
**Decision:** Suppress with `#nosec G302 -- SDR-002`

### Context

G302 flags `os.Chmod` with permissions greater than 0600.

### Why Suppression is Appropriate

shellsentry sets 0755 permissions for:

1. **Self-updated binary**: The downloaded shellsentry binary must be executable. This is the tool's self-update functionality.

### Security Consideration

- 0755 for executables is standard Unix practice
- No secrets or credentials are written with these permissions
- User explicitly initiated the self-update

### Affected Location

| File                          | Function      | Purpose                                    |
| ----------------------------- | ------------- | ------------------------------------------ |
| internal/selfupdate/update.go | performUpdate | Downloaded binary needs execute permission |

---

## Suppression Audit Log

| Date       | SDR     | Action  | Author          |
| ---------- | ------- | ------- | --------------- |
| 2026-01-10 | SDR-001 | Created | Claude Opus 4.5 |
| 2026-01-10 | SDR-002 | Created | Claude Opus 4.5 |
