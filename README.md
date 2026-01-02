# shellsentry

**The pause before the pipe.**

Static risk assessment for shell scripts you're about to trust.

---

**shellsentry** is a lightweight static analyzer that assesses shell scripts for risky patterns before you execute them. The companion to [sfetch](https://github.com/3leaps/sfetch): where sfetch handles secure acquisition with signature verification, shellsentry handles content assessment--when verification isn't available, or when you want to know what that install script actually does.

A tiny, statically-linked Go binary with no runtime dependencies. Detects curl-pipe-bash inception, base64 obfuscation, hidden unicode, privilege escalation, and other patterns commonly found in malicious scripts. Outputs human-readable reports, structured JSON, or SARIF for CI integration.

Not a sandbox, not a guarantee--just a fast, honest starting point for review.

## Quick Start

```bash
# Analyze a script
shellsentry install.sh

# Analyze from stdin
curl -fsSL https://example.com/install.sh | shellsentry

# JSON output for automation
shellsentry --format json install.sh

# Exit non-zero only on high-risk patterns
shellsentry --exit-on-danger install.sh && bash install.sh
```

## With sfetch

The complete secure bootstrap pipeline:

```bash
# Download with verification, analyze, then execute
SCRIPT=$(mktemp)
sfetch --repo 3leaps/shellsentry --latest --asset-match "install-shellsentry.sh" --output "$SCRIPT"

if shellsentry --exit-on-danger "$SCRIPT"; then
    bash "$SCRIPT"
else
    echo "Script failed safety analysis"
    shellsentry "$SCRIPT"
fi
rm "$SCRIPT"
```

## Exit Codes

| Code | Meaning | Use Case                                 |
| ---- | ------- | ---------------------------------------- |
| 0    | Clean   | No findings at or above threshold        |
| 1    | Info    | Informational findings only              |
| 2    | Warning | Medium-risk patterns found               |
| 3    | Danger  | High-risk patterns found                 |
| 4    | Error   | Analysis failed (parse error, I/O error) |

## What It Detects

### High Risk

- `curl | bash` / `wget | sh` patterns (yes, the irony)
- `eval` with external input
- Base64 decode + execute
- `/dev/tcp` and `/dev/udp` usage
- Hidden unicode characters (zero-width, RTL override)
- Known malware signatures

### Medium Risk

- `sudo` without user confirmation
- Downloads from variable URLs
- PATH modification
- `/etc/` file writes
- Cron/systemd installation
- SSH key operations

### Low Risk (Informational)

- External command invocations
- Network operations
- File system writes
- Package manager calls

## Output Formats

```bash
shellsentry --format text script.sh    # Default: human-readable text
shellsentry --format json script.sh    # Structured JSON
shellsentry --format sarif script.sh   # SARIF for GitHub Code Scanning
```

## What shellsentry Is NOT

- A sandbox or runtime protection
- A replacement for code review
- A guarantee of safety
- An antivirus or malware scanner
- A linter (use [shellcheck](https://github.com/koalaman/shellcheck) for that)

## Installation

### Recommended: install sfetch, then fetch shellsentry

```bash
curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash
sfetch --repo 3leaps/shellsentry --latest --dest-dir ~/.local/bin
```

### Alternative: verified bootstrap installer

```bash
curl -sSfL https://github.com/3leaps/shellsentry/releases/latest/download/install-shellsentry.sh | bash
```

### From source

```bash
git clone https://github.com/3leaps/shellsentry
cd shellsentry
make build
make install  # installs to ~/.local/bin
```

### Verification

Verify your installed binary against release trust anchors:

```bash
shellsentry --self-verify        # Show verification instructions
shellsentry --self-verify --json # Machine-readable output
```

### Self-Update

Update to the latest release with cryptographic verification:

```bash
shellsentry --self-update --yes  # Update with confirmation
```

The update process:
1. Fetches latest release from GitHub
2. Verifies minisign signature on checksums (mandatory)
3. Verifies archive checksum
4. Atomically replaces the binary

Additional flags:
- `--self-update-force` -- Allow major version jumps or update dev builds
- `--self-update-dir DIR` -- Install to custom directory

## Build

```bash
make build      # Build for current platform
make test       # Run tests
make lint       # Run linters
make check-all  # All quality checks
```

## Philosophy

shellsentry follows the 3leaps principles:

- **Small and auditable** -- Single binary, minimal dependencies, readable source
- **No network by default** -- All analysis is local
- **Composable** -- Stdin/stdout, JSON output, Unix exit codes
- **Honest about limitations** -- Static analysis can't catch everything; we say so

## Related Projects

- [sfetch](https://github.com/3leaps/sfetch) -- Secure, verifiable, zero-trust downloader
- [shellcheck](https://github.com/koalaman/shellcheck) -- Shell script linter (complementary)

## License

Apache 2.0. See [LICENSE](LICENSE) for details.

---

_Part of the [3leaps](https://github.com/3leaps) ecosystem._
