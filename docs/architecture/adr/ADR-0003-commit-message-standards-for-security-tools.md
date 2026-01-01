# ADR-0003: Commit Message Standards for Security Tools

**Status:** Accepted  
**Date:** 2025-12-25  
**Author:** 3leaps-agent-devlead  
**Supersedes:** None

## Context

shellsentry is a security-focused static analyzer. Its effectiveness depends partly on
attackers not knowing exactly what patterns are detected and what bypasses exist.

During v0.1.1 development, we wrote detailed commit messages that included:

- Specific detection patterns (`env | curl`, `printenv | nc`)
- Exact evasion techniques ("here-docs not handled")
- Implementation details ("tracks escape sequences, parameter expansion braces")
- Bypass hints ("require sudo to appear at command boundaries")

**Problem:** This level of detail in public git history functions as a bypass manual.
An attacker reading our commits learns exactly what we detect and how to evade it.

## Decision

Adopt a **minimal public detail** policy for commit messages:

### Public Commits (git history)

| Element     | Guideline                       | Example                                        |
| ----------- | ------------------------------- | ---------------------------------------------- |
| Subject     | Generic improvement description | `fix(patterns): reduce false positives`        |
| Body        | High-level what, not how        | `Improve pattern accuracy for sudo detection.` |
| Limitations | Never document in commits       | (keep in .plans/)                              |
| Patterns    | Never list specific patterns    | (keep in .plans/)                              |
| Evasions    | Never mention bypass techniques | (keep in .plans/)                              |

### Private Documentation

Detailed implementation notes, limitation documentation, and bypass analysis
belong in private project planning files accessible to the team only.

### Tag Messages

Release tags should summarize user-facing improvements without revealing
detection internals:

```
v0.1.1: Improved detection accuracy and reduced false positives

- Better comment handling
- Improved pattern precision
- Expanded threat coverage
```

## Rationale

**Security through obscurity is not security** - but there's no reason to
hand attackers a roadmap. The detection logic is open source and auditable,
but we don't need to highlight every limitation in the commit log.

**Defense in depth applies to documentation too:**

- Source code: available for audit (unavoidable)
- Commit messages: minimal operational detail (this ADR)
- Internal docs: full detail for maintainers (private planning files)

## Consequences

### Positive

- Commits don't serve as evasion documentation
- Attackers must read source code to find bypasses (higher bar)
- Public history remains useful for understanding changes at high level

### Negative

- Contributors must understand the policy
- Detailed rationale requires reading private docs or source
- May frustrate external contributors wanting context

### Neutral

- Source code still reveals implementation (as expected for OSS)
- Security researchers can still audit fully

## Compliance

Before pushing commits that touch detection logic:

1. Review commit message for pattern specifics - remove them
2. Review for limitation mentions - move to private docs
3. Review for bypass hints - remove entirely
4. Ask: "Would this help an attacker evade detection?" If yes, rewrite.

## References

- OWASP guidance on security documentation
- Prior art: many security tools use generic commit messages
- Internal: detailed notes maintained in private project planning files
