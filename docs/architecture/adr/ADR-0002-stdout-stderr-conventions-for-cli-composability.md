# ADR-0002: Stdout/Stderr Conventions for CLI Composability

**Status:** Accepted  
**Date:** 2025-12-25  
**Author:** 3leaps-agent-devlead  
**Supersedes:** None

## Context

shellsentry is designed to be composable in Unix pipelines:

```bash
curl -fsSL https://example.com/install.sh | shellsentry --format json | jq '.findings'
```

For this to work correctly, we must be disciplined about what goes to stdout vs stderr.

## Decision

### Stdout (parseable output only)

Stdout is reserved for **analysis output** that downstream tools can parse:

- Human-formatted findings (default)
- JSON reports (`--format json`)
- SARIF reports (`--format sarif`)

Stdout should be empty when using `--quiet` mode.

### Stderr (metadata and diagnostics)

Stderr is used for **everything else**:

- Version information (`--version`, `--version-extended`)
- Error messages
- Warnings and diagnostics
- Progress indicators (if added in future)

This ensures that piping shellsentry output to another tool (e.g., `jq`, `grep`)
never includes version strings or error messages in the parsed data.

### Exit Codes

Exit codes are part of the API and documented in `docs/exit-codes.md`:

| Code | Meaning                              |
| ---- | ------------------------------------ |
| 0    | Clean - no issues found              |
| 1    | Info - informational findings only   |
| 2    | Warning - medium-risk patterns found |
| 3    | Danger - high-risk patterns found    |
| 4    | Error - analysis failed              |

## Consequences

### Positive

- Clean pipeline composition: `shellsentry script.sh | jq '.findings[]'`
- Version checks don't pollute redirected output
- Errors are visible even when stdout is redirected to a file

### Negative

- Users must use `2>&1` to capture version output: `shellsentry --version 2>&1`
- Slightly more complex output handling in code

### Implementation Notes

```go
// Version output goes to stderr
fmt.Fprintf(os.Stderr, "shellsentry %s\n", Version)

// Analysis output goes to stdout (via formatter)
formatter.Format(os.Stdout, report)

// Errors go to stderr
fmt.Fprintf(os.Stderr, "Error: %v\n", err)
```

## References

- [Exit Codes Documentation](/docs/exit-codes.md)
- [Unix Philosophy](https://en.wikipedia.org/wiki/Unix_philosophy) - "Write programs that do one thing and do it well"
