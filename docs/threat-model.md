# Threat Model

**Status:** Contract (stable from v0.1.0)

This document defines what shellsentry detects, what it doesn't detect, and the boundaries of its security claims.

## What shellsentry Is

A **static risk assessment tool** that identifies patterns in shell scripts commonly associated with:

- Malicious behavior
- Risky operations
- Privilege escalation
- Data exfiltration
- Obfuscation

## What shellsentry Is NOT

| Not This                      | Why                                                                       |
| ----------------------------- | ------------------------------------------------------------------------- |
| A sandbox                     | Does not execute scripts or contain runtime behavior                      |
| A guarantee of safety         | Static analysis has inherent limitations                                  |
| An antivirus                  | Not signature-based malware detection                                     |
| A linter                      | Use [shellcheck](https://github.com/koalaman/shellcheck) for code quality |
| A replacement for code review | Provides a starting point, not a final verdict                            |

## Detection Categories

### High Risk (Exit Code 3)

Patterns that are almost always malicious or extremely dangerous in install scripts:

| Pattern                       | Rationale                                    |
| ----------------------------- | -------------------------------------------- |
| `curl \| bash` / `wget \| sh` | Remote code execution without inspection     |
| `eval` with external input    | Arbitrary code execution                     |
| Base64 decode + execute       | Obfuscation of payload                       |
| `/dev/tcp` or `/dev/udp`      | Network sockets (data exfiltration)          |
| Hidden unicode                | Zero-width chars, RTL override (obfuscation) |
| Known malware signatures      | Cryptocurrency miners, backdoors             |
| `rm -rf /` patterns           | Destructive operations                       |

### Medium Risk (Exit Code 2)

Patterns that are common in legitimate scripts but warrant review:

| Pattern                      | Rationale                     |
| ---------------------------- | ----------------------------- |
| `sudo` without confirmation  | Privilege escalation          |
| Downloads from variable URLs | Unverified remote content     |
| PATH modification            | Hijacking potential           |
| `/etc/` file writes          | System configuration changes  |
| Cron/systemd installation    | Persistence mechanism         |
| SSH key operations           | Credential access             |
| `chmod 777`                  | Overly permissive permissions |

### Low Risk / Informational (Exit Code 1)

Patterns that are normal but provide context for review:

| Pattern                      | Rationale                 |
| ---------------------------- | ------------------------- |
| External command invocations | Awareness of dependencies |
| Network operations           | Connectivity requirements |
| File system writes           | Installation footprint    |
| Package manager calls        | Dependency installation   |
| Environment variable reads   | Configuration sources     |

## What We Cannot Detect

### Fundamental Limitations

1. **Semantic intent** - We detect patterns, not meaning. A script that downloads and executes code is flagged whether it's malicious or a legitimate installer.

2. **Runtime behavior** - Static analysis sees code, not execution. Conditional branches, environment-dependent behavior, and dynamic code generation are partially or fully opaque.

3. **Novel malware** - Pattern-based detection requires known signatures. Zero-day attacks using new techniques will not be caught.

4. **Obfuscation beyond patterns** - We detect common obfuscation (base64, unicode tricks), but sophisticated encoding schemes may evade detection.

5. **External dependencies** - We analyze the script, not what it downloads or executes.

### Specific Gaps

| Gap                  | Example                                                   |
| -------------------- | --------------------------------------------------------- |
| Polyglot files       | Script that's also valid in another language              |
| Steganography        | Payload hidden in comments or whitespace                  |
| Time bombs           | Malicious behavior triggered by date/time                 |
| Environment checks   | Behaves differently on analysis vs target                 |
| Multi-stage payloads | Initial script is clean, downloads malicious second stage |

## Trust Model

### What We Trust

- **The shell parser** (`mvdan/sh`) - Assumed to correctly parse shell syntax
- **Pattern definitions** - Embedded patterns are assumed accurate
- **Local filesystem** - Input files are read as-is

### What We Don't Trust

- **Input scripts** - The entire point is to assess untrusted input
- **Network sources** - shellsentry makes no network calls by default
- **External tools** - shellcheck integration is optional and isolated

## Security Properties

### Confidentiality

- No network calls by default
- Scripts are analyzed locally
- No telemetry or data collection

### Integrity

- Single static binary
- Embedded patterns (no external pattern files by default)
- Reproducible builds

### Availability

- Fast analysis (<500ms for typical scripts)
- No external dependencies required
- Graceful degradation on parse errors

## Recommended Usage

### Do

- Use as a first-pass filter before human review
- Combine with sfetch for secure acquisition
- Integrate into CI pipelines
- Use JSON output for audit trails

### Don't

- Rely solely on shellsentry for security decisions
- Assume clean output means safe script
- Skip review for scripts from untrusted sources
- Ignore medium-risk findings in production

## Reporting Security Issues

If you discover a bypass, false negative on malicious patterns, or vulnerability in shellsentry itself:

**Email:** security@3leaps.net

Do not open public issues for security vulnerabilities.
