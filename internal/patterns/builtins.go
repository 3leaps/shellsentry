// Package patterns provides pattern matching for shell script analysis.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package patterns

import "github.com/3leaps/shellsentry/internal/types"

// BuiltinPatterns returns the embedded pattern set.
// These patterns are compiled into the binary.
func BuiltinPatterns() *PatternSet {
	ps := NewPatternSet()

	// High-risk patterns
	for _, p := range highRiskPatterns() {
		_ = ps.Add(p) // Builtins should never fail to compile
	}

	// Medium-risk patterns
	for _, p := range mediumRiskPatterns() {
		_ = ps.Add(p)
	}

	// Low-risk patterns
	for _, p := range lowRiskPatterns() {
		_ = ps.Add(p)
	}

	return ps
}

func highRiskPatterns() []*Pattern {
	return []*Pattern{
		{
			ID:          "SS001",
			Name:        "curl-pipe-shell",
			Severity:    types.SeverityHigh,
			Category:    types.CategoryExecution,
			Description: "Detects curl/wget output piped directly to shell",
			Patterns: []PatternMatch{
				{Regex: `curl\s+[^|]*\|\s*(bash|sh|zsh|dash)`},
				{Regex: `wget\s+[^|]*-O\s*-\s*\|\s*(bash|sh|zsh|dash)`},
				{Regex: `wget\s+[^|]*\|\s*(bash|sh|zsh|dash)`},
			},
			Message:        "Piping download directly to shell interpreter",
			Detail:         "This pattern downloads and executes code in a single step, bypassing any opportunity for review. If the remote source is compromised, malicious code executes immediately.",
			Recommendation: "Download to a file first, review the contents, then execute.",
		},
		{
			ID:          "SS002",
			Name:        "base64-decode-exec",
			Severity:    types.SeverityHigh,
			Category:    types.CategoryObfuscation,
			Description: "Detects base64 decode piped to execution",
			Patterns: []PatternMatch{
				{Regex: `base64\s+(-d|--decode)[^|]*\|\s*(bash|sh|eval)`},
				{Regex: `\|\s*base64\s+(-d|--decode)[^|]*\|\s*(bash|sh|eval)`},
				{Regex: `echo\s+[^|]+\|\s*base64\s+(-d|--decode)[^|]*\|\s*(bash|sh)`},
			},
			Message:        "Base64-encoded content decoded and executed",
			Detail:         "Base64 encoding is commonly used to obfuscate malicious payloads. The encoded content cannot be reviewed without decoding first.",
			Recommendation: "Decode the base64 content and review before execution.",
		},
		{
			ID:          "SS003",
			Name:        "eval-variable",
			Severity:    types.SeverityHigh,
			Category:    types.CategoryExecution,
			Description: "Detects eval with variable input",
			Patterns: []PatternMatch{
				{Regex: `eval\s+"\$`},
				{Regex: `eval\s+'\$`},
				{Regex: `eval\s+\$\{`},
				{Regex: `eval\s+\$[A-Za-z_]`},
			},
			Message:        "eval with variable input enables arbitrary code execution",
			Detail:         "Using eval with variable content allows the variable's value to be executed as code. If an attacker controls the variable, they control execution.",
			Recommendation: "Avoid eval with untrusted input. Consider safer alternatives.",
		},
		{
			ID:          "SS004",
			Name:        "dev-tcp-udp",
			Severity:    types.SeverityHigh,
			Category:    types.CategoryNetwork,
			Description: "Detects /dev/tcp or /dev/udp usage",
			Patterns: []PatternMatch{
				{Regex: `/dev/tcp/`},
				{Regex: `/dev/udp/`},
			},
			Message:        "Bash network socket detected (/dev/tcp or /dev/udp)",
			Detail:         "Bash's /dev/tcp and /dev/udp are commonly used in reverse shells and data exfiltration. Legitimate install scripts rarely need raw socket access.",
			Recommendation: "Review the network destination and purpose carefully.",
		},
		{
			ID:          "SS005",
			Name:        "hidden-unicode",
			Severity:    types.SeverityHigh,
			Category:    types.CategoryObfuscation,
			Description: "Detects hidden unicode characters",
			Patterns: []PatternMatch{
				// Zero-width characters
				{Regex: `\x{200B}`}, // Zero-width space
				{Regex: `\x{200C}`}, // Zero-width non-joiner
				{Regex: `\x{200D}`}, // Zero-width joiner
				{Regex: `\x{FEFF}`}, // BOM / zero-width no-break space
				// RTL override (can hide malicious code direction)
				{Regex: `\x{202E}`}, // Right-to-left override
				{Regex: `\x{202D}`}, // Left-to-right override
			},
			Message:        "Hidden unicode characters detected",
			Detail:         "Zero-width and bidirectional override characters can hide malicious code or make code appear different than it executes.",
			Recommendation: "Remove hidden unicode and review the actual content.",
		},
		{
			ID:          "SS006",
			Name:        "rm-rf-root",
			Severity:    types.SeverityHigh,
			Category:    types.CategoryDestructive,
			Description: "Detects dangerous rm -rf patterns",
			Patterns: []PatternMatch{
				{Regex: `(?m)rm\s+(-rf|-fr|--recursive\s+--force|-r\s+-f|-f\s+-r)\s+/\s*$`},
				{Regex: `rm\s+(-rf|-fr)\s+/\*`},
				{Regex: `rm\s+(-rf|-fr)\s+"\$\{?[^}]*:-/\}?"`}, // Variable with / default
			},
			Message:        "Potentially destructive rm -rf pattern",
			Detail:         "This pattern could delete critical system files. Even with variable expansion, if the variable is empty or unset, this could be catastrophic.",
			Recommendation: "Ensure variables are validated before use in rm commands.",
		},
		{
			ID:          "SS007",
			Name:        "chmod-777",
			Severity:    types.SeverityHigh,
			Category:    types.CategoryPrivilege,
			Description: "Detects chmod 777 patterns",
			Patterns: []PatternMatch{
				{Regex: `chmod\s+777\s`},
				{Regex: `chmod\s+a\+rwx\s`},
			},
			Message:        "World-writable permissions (chmod 777)",
			Detail:         "Setting 777 permissions allows any user to read, write, and execute the file. This is almost never appropriate and creates security vulnerabilities.",
			Recommendation: "Use minimal necessary permissions (e.g., 755 for executables).",
		},
		{
			ID:          "SS008",
			Name:        "hex-decode-exec",
			Severity:    types.SeverityHigh,
			Category:    types.CategoryObfuscation,
			Description: "Detects hex-encoded payload execution",
			Patterns: []PatternMatch{
				{Regex: `xxd\s+[^|]*-r[^|]*\|\s*(bash|sh|eval)`},
				{Regex: `xxd\s+[^|]*-p[^|]*-r[^|]*\|\s*(bash|sh|eval)`},
			},
			Message:        "Hex-encoded content decoded and executed",
			Detail:         "Hex encoding via xxd is used to obfuscate payloads. The encoded content cannot be reviewed without decoding.",
			Recommendation: "Decode the hex content and review before execution.",
		},
		{
			ID:          "SS009",
			Name:        "arithmetic-command-exec",
			Severity:    types.SeverityHigh,
			Category:    types.CategoryObfuscation,
			Description: "Detects command execution in arithmetic expansion",
			Patterns: []PatternMatch{
				{Regex: `\$\(\([^)]*\$\([^)]+\)[^)]*\)\)`},
			},
			Message:        "Command substitution inside arithmetic expansion",
			Detail:         "Embedding command substitution in arithmetic contexts can hide malicious execution and data exfiltration.",
			Recommendation: "Review the nested command and its purpose.",
		},
	}
}

func mediumRiskPatterns() []*Pattern {
	return []*Pattern{
		{
			ID:          "SS010",
			Name:        "sudo-command",
			Severity:    types.SeverityMedium,
			Category:    types.CategoryPrivilege,
			Description: "Detects sudo usage patterns",
			Patterns: []PatternMatch{
				// sudo at line start (possibly indented) followed by command
				// (?m) enables multiline mode so ^ matches start of each line
				{Regex: `(?m)^\s*sudo\s+(-[A-Za-z]+\s+)*[A-Za-z./]`},
				// sudo after command separator (;, &&, ||, |) followed by command
				{Regex: `[;&|]\s*sudo\s+(-[A-Za-z]+\s+)*[A-Za-z./]`},
				// sudo in subshell or command substitution
				{Regex: `\(\s*sudo\s+`},
				{Regex: `\$\(\s*sudo\s+`},
			},
			Message:        "sudo command detected",
			Detail:         "This script uses sudo for privilege escalation. Review what operations require elevated privileges.",
			Recommendation: "Verify that sudo is necessary and understand what elevated operations are performed.",
		},
		{
			ID:          "SS011",
			Name:        "curl-download",
			Severity:    types.SeverityMedium,
			Category:    types.CategoryDownload,
			Description: "Detects downloads from variable URLs",
			Patterns: []PatternMatch{
				{Regex: `curl\s+[^"'\s]*\$[A-Za-z_]`},
				{Regex: `wget\s+[^"'\s]*\$[A-Za-z_]`},
				{Regex: `curl\s+[^"'\s]*"\$\{`},
				{Regex: `wget\s+[^"'\s]*"\$\{`},
			},
			Message:        "Download from URL containing variable",
			Detail:         "The download URL is not hardcoded, making it harder to verify the source. The actual URL depends on runtime values.",
			Recommendation: "Review how the URL variable is set and whether the source is trusted.",
		},
		{
			ID:          "SS012",
			Name:        "path-modification",
			Severity:    types.SeverityMedium,
			Category:    types.CategoryPrivilege,
			Description: "Detects PATH modification",
			Patterns: []PatternMatch{
				{Regex: `export\s+PATH=`},
				{Regex: `PATH=.*:\$PATH`},
				{Regex: `PATH=\$PATH:`},
			},
			Message:        "PATH environment variable modification",
			Detail:         "Modifying PATH can affect which executables are run. Prepending to PATH can hijack system commands.",
			Recommendation: "Review the PATH modification to ensure it doesn't introduce hijacking risks.",
		},
		{
			ID:          "SS013",
			Name:        "etc-write",
			Severity:    types.SeverityMedium,
			Category:    types.CategoryFilesystem,
			Description: "Detects writes to /etc",
			Patterns: []PatternMatch{
				{Regex: `>\s*/etc/`},
				{Regex: `>>\s*/etc/`},
				{Regex: `tee\s+[^|]*\s+/etc/`},
				{Regex: `cp\s+[^/]*/etc/`},
				{Regex: `mv\s+[^/]*/etc/`},
			},
			Message:        "System configuration file write detected",
			Detail:         "Writing to /etc modifies system configuration. This can affect system behavior for all users.",
			Recommendation: "Review what configuration changes are made and whether they're appropriate.",
		},
		{
			ID:          "SS014",
			Name:        "cron-systemd-install",
			Severity:    types.SeverityMedium,
			Category:    types.CategoryPersistence,
			Description: "Detects cron or systemd installation",
			Patterns: []PatternMatch{
				{Regex: `crontab\s+`},
				{Regex: `/etc/cron`},
				{Regex: `systemctl\s+(enable|start|daemon-reload)`},
				{Regex: `/etc/systemd/system/`},
				{Regex: `/lib/systemd/system/`},
			},
			Message:        "System service or scheduled task installation",
			Detail:         "Installing cron jobs or systemd services creates persistent execution. The installed service will run even after this script completes.",
			Recommendation: "Review what is being installed for persistent execution.",
		},
		{
			ID:          "SS015",
			Name:        "ssh-key-ops",
			Severity:    types.SeverityMedium,
			Category:    types.CategoryCredential,
			Description: "Detects SSH key operations",
			Patterns: []PatternMatch{
				{Regex: `\.ssh/authorized_keys`},
				{Regex: `ssh-keygen`},
				{Regex: `\.ssh/id_`},
				{Regex: `\.ssh/known_hosts`},
			},
			Message:        "SSH key operation detected",
			Detail:         "This script accesses or modifies SSH keys or authorized_keys. This could grant persistent remote access.",
			Recommendation: "Review what SSH operations are performed and whether they're expected.",
		},
	}
}

func lowRiskPatterns() []*Pattern {
	return []*Pattern{
		{
			ID:          "SS020",
			Name:        "network-download",
			Severity:    types.SeverityLow,
			Category:    types.CategoryNetwork,
			Description: "Detects network download operations",
			Patterns: []PatternMatch{
				{Regex: `curl\s+`},
				{Regex: `wget\s+`},
				{Regex: `fetch\s+`},
			},
			Message:        "Network download operation",
			Detail:         "This script downloads content from the network. This is common in install scripts but worth noting.",
			Recommendation: "Verify the download sources are trusted.",
		},
		{
			ID:          "SS021",
			Name:        "package-manager",
			Severity:    types.SeverityInfo,
			Category:    types.CategoryInformational,
			Description: "Detects package manager usage",
			Patterns: []PatternMatch{
				{Regex: `apt(-get)?\s+(install|update|upgrade)`},
				{Regex: `yum\s+(install|update)`},
				{Regex: `dnf\s+(install|update)`},
				{Regex: `brew\s+(install|upgrade)`},
				{Regex: `pacman\s+-S`},
				{Regex: `apk\s+add`},
			},
			Message:        "Package manager operation",
			Detail:         "This script uses a package manager to install software.",
			Recommendation: "Review what packages are being installed.",
		},
		{
			ID:          "SS022",
			Name:        "file-write",
			Severity:    types.SeverityInfo,
			Category:    types.CategoryFilesystem,
			Description: "Detects file write operations",
			Patterns: []PatternMatch{
				{Regex: `>\s*/`},
				{Regex: `>>\s*/`},
				{Regex: `tee\s+`},
			},
			Message:        "File write operation",
			Detail:         "This script writes to the filesystem.",
			Recommendation: "Review what files are written and their contents.",
		},
	}
}
