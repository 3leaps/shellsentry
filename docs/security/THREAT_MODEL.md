# Threat Model

## Overview

shellsentry is a CLI tool that analyzes shell scripts for security issues. This document describes trust boundaries, attack surface, and security controls.

## Trust Boundaries

### Local User (Trusted)
- Command-line arguments are trusted input
- The user running shellsentry has equivalent filesystem access to the shellsentry process
- No privilege escalation occurs - shellsentry runs with user permissions

### Input Scripts (Semi-trusted)
- Scripts provided for analysis may contain malicious content
- shellsentry parses but does not execute scripts
- Analysis is read-only; no modifications to input files

### Network (Untrusted)
- Self-update downloads are verified via checksums and signatures
- HTTPS provides transport security

## Attack Surface

| Surface | Threats | Mitigations |
|---------|---------|-------------|
| CLI arguments | Path traversal | Paths resolved; user already has shell access |
| Script parsing | Malformed input, DoS | Parser limits; no code execution |
| Self-update | Malicious binary | Checksum + signature verification |
| Output files | Path injection | User-controlled paths; no escalation |

## Security Controls

### Analysis Safety
- Scripts are parsed, never executed
- Memory-safe Go implementation
- No shell-out to interpreters

### Self-Update Security
- Checksums verified before installation
- Minisign signature verification
- Atomic file replacement

## Out of Scope

The following are explicitly out of scope for shellsentry's threat model:

1. **Malicious local user**: If the user running shellsentry is malicious, they already have shell access
2. **Compromised signing keys**: shellsentry verifies signatures but cannot detect key compromise
3. **Kernel/OS vulnerabilities**: shellsentry assumes the underlying OS is not compromised

## Related Documents

- [suppressions/gosec.md](suppressions/gosec.md) - Static analysis suppression decisions
