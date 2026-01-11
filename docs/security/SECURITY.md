# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in shellsentry, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email security concerns to: security@3leaps.net
3. Include: description, reproduction steps, affected versions, potential impact

We aim to respond within 48 hours and will coordinate disclosure timing with you.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Security Model

shellsentry is a CLI tool for analyzing shell scripts for security issues. See [THREAT_MODEL.md](THREAT_MODEL.md) for:
- Trust boundaries
- Attack surface analysis
- Security controls

## Static Analysis

We use gosec for static security analysis. Suppressions are documented in [suppressions/gosec.md](suppressions/gosec.md) with Security Decision Records (SDRs).

## Verification

shellsentry releases include:
- SHA-256 and SHA-512 checksums
- Minisign signatures (Ed25519)
