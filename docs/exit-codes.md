# Exit Codes

**Status:** Contract (stable from v0.1.0)

shellsentry uses exit codes as a primary API for automation and scripting. These codes are part of the public contract and will not change without a major version bump.

## Exit Code Table

| Code | Name    | Meaning                           | Use Case                      |
| ---- | ------- | --------------------------------- | ----------------------------- |
| 0    | Clean   | No findings at or above threshold | Script passed analysis        |
| 1    | Info    | Informational findings only       | Low-risk patterns detected    |
| 2    | Warning | Medium-risk patterns found        | Review recommended            |
| 3    | Danger  | High-risk patterns found          | Do not execute without review |
| 4    | Error   | Analysis failed                   | I/O error, bad arguments      |

## Behavior by Flag

### Default Mode

Exit code reflects the highest severity finding:

- High-risk finding → exit 3
- Medium-risk finding (no high) → exit 2
- Low-risk finding only → exit 1
- No findings → exit 0

### `--exit-on-danger`

Only exit non-zero (3) for high-risk patterns. Medium and low findings produce exit 0.

```bash
# Execute only if no high-risk patterns
shellsentry --exit-on-danger script.sh && bash script.sh
```

### `--strict`

Exit non-zero on any finding, including informational:

- Any finding → exit code per severity
- No findings → exit 0

### `--lenient`

Only exit non-zero on high-risk patterns (alias for `--exit-on-danger`).

## Usage Examples

### CI Pipeline

```bash
# Fail build on medium+ risk
shellsentry install.sh
if [ $? -ge 2 ]; then
    echo "Script failed safety check"
    exit 1
fi
```

### Conditional Execution

```bash
# Run only if safe
shellsentry --exit-on-danger install.sh && bash install.sh
```

### Severity-Based Routing

```bash
shellsentry script.sh
case $? in
    0) echo "Clean" ;;
    1) echo "Info only - proceeding" ;;
    2) echo "Warning - review recommended" ;;
    3) echo "Danger - blocked" && exit 1 ;;
    4) echo "Error - analysis failed" && exit 1 ;;
esac
```

## Design Rationale

### Why Not Boolean (0/1)?

Binary pass/fail doesn't capture the nuance of risk assessment. A script with informational findings is different from one with high-risk patterns. The graduated scale enables:

- Flexible thresholds per environment
- Audit trails with severity context
- Progressive rollout (strict in prod, lenient in dev)

### Why 4 for Error?

Reserving 4 (not 1) for errors distinguishes "analysis found low-risk patterns" from "analysis failed to run." This prevents false positives when shellsentry itself has problems.

### Parse Errors vs I/O Errors

Parse errors (invalid shell syntax) do **not** return exit code 4. Instead:

- Parse errors generate an SS000 finding (INFO severity)
- Level1 regex analysis still runs on the raw content
- Exit code reflects the highest severity finding as normal

This design allows shellsentry to provide useful analysis even for syntactically invalid scripts. Only true failures (file not found, permission denied, invalid arguments) return exit code 4.

### Alignment with Unix Conventions

- 0 = success (clean)
- 1-3 = success with findings (graduated severity)
- 4+ = failure (error conditions)

This follows the principle that non-zero indicates "something to report" while higher values indicate more severe conditions.

## Stability Promise

Exit codes 0-4 are frozen from v0.1.0. Future versions may add codes 5+ for new error conditions, but existing codes will not change meaning.
