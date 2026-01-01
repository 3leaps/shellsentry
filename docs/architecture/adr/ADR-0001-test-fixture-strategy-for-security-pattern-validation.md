# ADR-0001: Test Fixture Strategy for Security Pattern Validation

**Status:** Accepted  
**Date:** 2025-12-25  
**Author:** 3leaps-agent-devlead  
**Supersedes:** None

## Context

shellsentry is a static analyzer that detects risky patterns in shell scripts. To validate
that detection works correctly, we need test fixtures containing patterns like:

- `curl | bash` (remote code execution)
- `base64 -d | eval` (obfuscated execution)
- `/dev/tcp` connections (reverse shells)
- `rm -rf /` (destructive operations)

**Problem:** Storing these patterns in the repository creates risks:

1. Security scanners (GitHub, Snyk, goneat) may flag the repository
2. Raw dangerous scripts could be downloaded and executed by bad actors
3. CI/CD systems may block or quarantine the repository
4. The patterns could trigger endpoint security tools

## Decision

We adopt a **hybrid testing approach** with three tiers:

### Tier 1: Benign Fixtures (stored in repo)

Real-world install scripts from trusted sources (bun, nvm) stored in `testdata/benign/`.
These contain legitimate patterns and establish a regression baseline.

### Tier 2: Programmatic Generation (in test code)

Test files generate risky patterns at runtime using helper functions:

```go
func generateCurlPipeBash(url, shell string) string {
    return fmt.Sprintf("curl -fsSL %s | %s", url, shell)
}
```

**Benefits:**

- No stored dangerous content
- Patterns are clearly intentional (in test code)
- Easy to parameterize for edge cases
- Security scanners don't flag Go code

### Tier 3: ScriptBuilder API (future)

A fluent API for generating complex multi-pattern scripts:

```go
script := testutil.NewScript().
    WithStrictMode().
    WithCurlPipeBash("https://example.com/install.sh").
    WithPathModification("/opt/bin").
    Build()

expected := script.ExpectedPatterns() // ["SS001", "SS012"]
```

Design assets for the ScriptBuilder API are maintained separately during development.

## Alternatives Considered

### A. Plain Text Fixtures

Store all patterns in `.sh` files.

**Rejected:** Too risky for security scanners and could enable misuse.

### B. Encrypted Archives

Store fixtures in age-encrypted archives.

**Deferred:** Adds complexity (key management, decryption step). Consider for v0.2
if we need actual malware signatures.

### C. Private Fixture Repository

Keep fixtures in a separate private repo.

**Deferred:** Adds CI complexity and local dev friction. May revisit if we need
actual malware samples.

### D. Container Isolation

Run tests with dangerous fixtures only inside ephemeral containers.

**Deferred:** Not needed for programmatic generation. Consider for v0.2 if we
add real malware corpus testing.

## Consequences

### Positive

- Repository stays clean for security scanners
- Tests are self-documenting (patterns in code with test names)
- Easy to add new pattern variants
- Known regex limitations are documented inline

### Negative

- Some test boilerplate for pattern generation
- Benign fixtures may still trigger low-severity scanner warnings
- More complex test infrastructure than simple file fixtures

### Neutral

- Regex-based detection has known limitations (can't distinguish comments/strings)
- Tests document these limitations explicitly

## Implementation

### Current State (v0.1.0)

- `testdata/benign/` contains bun and nvm install scripts
- `testdata/benign/expected/` contains expected findings per script
- `internal/patterns/patterns_test.go` uses programmatic generation
- Tests document known regex limitations inline

### Future Work (v0.2.0+)

- Implement ScriptBuilder fluent API for complex test scenarios
- Consider embedded test fixtures in pattern YAML definitions
- Add container-isolated testing for real malware signatures
- Integrate with CI/CD test matrix

## References

- `testdata/README.md` - Fixture handling documentation
- `internal/patterns/patterns_test.go` - Programmatic generation examples
