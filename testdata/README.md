# Test Fixtures

This directory contains test fixtures for shellsentry.

## Directory Structure

```
testdata/
├── benign/           # Real-world legitimate install scripts
│   ├── bun-install.sh
│   ├── nvm-install.sh
│   ├── heredoc/      # Benign heredoc syntax fixtures
│   │   └── expected/ # Expected findings (clean) in JSON
│   └── expected/     # Expected findings in JSON format
├── malicious/        # Reserved; do not commit executable payloads
└── generated/        # .gitignored, created at test time
```

## Benign Fixtures

Real-world install scripts from well-known projects. These scripts are
**not malicious** - they are used to:

1. Verify shellsentry correctly identifies patterns in legitimate scripts
2. Establish a regression baseline (findings count should not change unexpectedly)
3. Demonstrate that "findings" != "malicious" - even trusted scripts have patterns

### Sources

| Script         | Source                                                          | Retrieved  |
| -------------- | --------------------------------------------------------------- | ---------- |
| bun-install.sh | https://bun.sh/install                                          | 2025-12-25 |
| nvm-install.sh | https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | 2025-12-25 |

### Expected Findings

Each script has a corresponding `.expected.json` file in `benign/expected/` that
documents the expected findings count by severity. Tests verify that actual
findings match expected counts.

**Important:** These scripts may trigger scanner warnings in CI/CD. The patterns
detected (PATH modification, network downloads, etc.) are legitimate for install
scripts but worth reviewing.

## Malicious Fixtures

The `malicious/` directory is reserved for testing risky patterns, but we
generally keep it empty.

We use **programmatic generation** in Go tests for risky patterns rather than
storing executable dangerous code. See `docs/architecture/adr/ADR-0001-test-fixture-strategy-for-security-pattern-validation.md` for the full rationale.

If you need a larger "dogfood" corpus (e.g. heredoc-heavy installer scripts),
keep it outside the repo (e.g. in a local `~/dev/playground/...` folder) and
record results in `.plans/` artifacts rather than committing the scripts.

See `internal/patterns/patterns_test.go` for how patterns are tested using
generated input at runtime.

## Adding New Fixtures

When adding benign fixtures:

1. Download from the official source
2. Document the source URL and date
3. Run shellsentry and capture expected findings
4. Create `expected/<name>.expected.json`
5. Add to the table above

When adding risky pattern tests:

1. Use programmatic generation in test code
2. See existing tests in `internal/patterns/patterns_test.go`
3. Do NOT commit executable dangerous scripts
