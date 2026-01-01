// Package analyzer provides the core analysis engine for shellsentry.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package analyzer

import (
	"context"
	"strings"

	"github.com/3leaps/shellsentry/internal/parser"
	"github.com/3leaps/shellsentry/internal/types"
)

// Level0Analyzer performs AST-based structural analysis.
// This analyzer uses the parsed AST to detect patterns that regex cannot,
// such as pipelines, command context, and structural risks.
type Level0Analyzer struct {
	parserOpts parser.Options
}

// NewLevel0Analyzer creates a new Level 0 analyzer.
func NewLevel0Analyzer() *Level0Analyzer {
	return &Level0Analyzer{
		parserOpts: parser.DefaultOptions(),
	}
}

// Name returns the analyzer identifier.
func (a *Level0Analyzer) Name() string {
	return "level0-ast"
}

// Analyze performs AST-based analysis on the script content.
func (a *Level0Analyzer) Analyze(ctx context.Context, content []byte, filename string) ([]types.Finding, error) {
	result, err := parser.Parse(content, filename, a.parserOpts)

	var findings []types.Finding

	// Report parse errors as findings
	for _, parseErr := range result.Errors {
		findings = append(findings, types.Finding{
			ID:             "SS000",
			Severity:       types.SeverityInfo,
			Category:       types.CategoryExecution,
			Line:           parseErr.Line,
			Column:         parseErr.Column,
			Message:        "Parse error: " + parseErr.Message,
			Detail:         "The script contains syntax errors that may indicate issues.",
			Recommendation: "Review the script for syntax errors.",
		})
	}

	// If parsing failed completely, return what we have
	if result.File == nil {
		return findings, err
	}

	// Analyze pipelines for dangerous patterns
	pipelineFindings := a.analyzePipelines(result)
	findings = append(findings, pipelineFindings...)

	// Analyze variable flow for indirect execution
	varFlowFindings := a.analyzeVariableFlow(result)
	findings = append(findings, varFlowFindings...)

	return findings, nil
}

// analyzePipelines detects dangerous pipeline patterns using AST.
func (a *Level0Analyzer) analyzePipelines(result *parser.Result) []types.Finding {
	var findings []types.Finding

	pipelines := parser.FindPipelines(result.File)

	for _, pipeline := range pipelines {
		// Check for download-to-shell patterns
		if finding := a.checkDownloadToShell(pipeline); finding != nil {
			findings = append(findings, *finding)
		}

		// Check for data exfiltration patterns
		if finding := a.checkDataExfiltration(pipeline); finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings
}

// downloadCommands are commands that fetch remote content.
var downloadCommands = map[string]bool{
	"curl":  true,
	"wget":  true,
	"fetch": true, // FreeBSD
}

// shellCommands are shell interpreters.
var shellCommands = map[string]bool{
	"sh":      true,
	"bash":    true,
	"zsh":     true,
	"ksh":     true,
	"dash":    true,
	"ash":     true,
	"fish":    true,
	"python":  true,
	"python3": true,
	"python2": true,
	"perl":    true,
	"ruby":    true,
	"node":    true,
}

// checkDownloadToShell detects curl|bash style patterns.
func (a *Level0Analyzer) checkDownloadToShell(pipeline *parser.Pipeline) *types.Finding {
	if len(pipeline.Commands) < 2 {
		return nil
	}

	// Check if first command is a downloader
	firstCmd := pipeline.Commands[0]
	if !downloadCommands[firstCmd.Name] {
		return nil
	}

	// Check if last command is a shell interpreter
	lastCmd := pipeline.Commands[len(pipeline.Commands)-1]
	if !shellCommands[lastCmd.Name] {
		return nil
	}

	// This is a download-to-shell pattern
	return &types.Finding{
		ID:       "SS001",
		Severity: types.SeverityHigh,
		Category: types.CategoryExecution,
		Line:     pipeline.Line,
		Column:   pipeline.Column,
		Code:     formatPipelineCode(pipeline),
		Message:  "Piping download directly to shell interpreter",
		Detail: "This pattern downloads and executes code in a single step, bypassing " +
			"any opportunity for review. If the remote source is compromised, " +
			"malicious code executes immediately.",
		Recommendation: "Download to a file first, review the contents, then execute.",
	}
}

// exfilCommands are commands commonly used for data exfiltration.
var exfilCommands = map[string]bool{
	"curl":    true,
	"wget":    true,
	"nc":      true,
	"netcat":  true,
	"ncat":    true, // nmap's netcat
	"socat":   true,
	"telnet":  true,
	"openssl": true, // s_client can send data
}

// sensitiveDataCommands produce sensitive data without arguments.
// These commands output environment variables or shell state.
var sensitiveDataCommands = map[string]bool{
	"env":      true, // Environment variables
	"printenv": true, // Environment variables
	"set":      true, // Shell variables (includes env)
	"export":   true, // Exported variables (with -p flag, but often used)
	"declare":  true, // Bash variable declarations (with -p)
	"compgen":  true, // Bash completion - can leak function names
	"typeset":  true, // ksh/zsh variable declarations
	"history":  true, // Command history
	"fc":       true, // Fix command - accesses history
}

// sensitiveFileCommands read files and need path checking.
var sensitiveFileCommands = map[string]bool{
	"cat":     true,
	"head":    true,
	"tail":    true,
	"less":    true,
	"more":    true,
	"tac":     true,
	"nl":      true,
	"xxd":     true,
	"od":      true,
	"strings": true,
}

// archiveCommands can bundle sensitive directories for exfiltration.
var archiveCommands = map[string]bool{
	"tar": true,
	"zip": true,
}

// checkDataExfiltration detects patterns like `cat /etc/passwd | curl` or `env | curl`.
func (a *Level0Analyzer) checkDataExfiltration(pipeline *parser.Pipeline) *types.Finding {
	if len(pipeline.Commands) < 2 {
		return nil
	}

	// Look for sensitive command piped to network command
	var hasSensitive bool
	var sensitiveReason string
	var hasNetwork bool

	for i, cmd := range pipeline.Commands {
		// Commands that produce sensitive data without arguments
		if sensitiveDataCommands[cmd.Name] {
			hasSensitive = true
			sensitiveReason = cmd.Name + " outputs sensitive data"
		}

		// Commands that need sensitive path checking
		if sensitiveFileCommands[cmd.Name] {
			for _, arg := range cmd.Args {
				if isSensitivePath(arg) {
					hasSensitive = true
					sensitiveReason = "reads sensitive file: " + arg
					break
				}
			}
		}

		// Archive commands bundling sensitive directories
		if archiveCommands[cmd.Name] && isArchiveToStdout(cmd) {
			for _, arg := range cmd.Args {
				if isSensitivePath(arg) {
					hasSensitive = true
					sensitiveReason = "archives sensitive path: " + arg
					break
				}
			}
		}

		// Network command later in pipeline
		if i > 0 && exfilCommands[cmd.Name] {
			hasNetwork = true
		}

		// wget with POST flags is an exfil sink
		if i > 0 && cmd.Name == "wget" && hasPostFlags(cmd) {
			hasNetwork = true
		}
	}

	if hasSensitive && hasNetwork {
		return &types.Finding{
			ID:       "SS030",
			Severity: types.SeverityHigh,
			Category: types.CategoryExfiltration,
			Line:     pipeline.Line,
			Column:   pipeline.Column,
			Code:     formatPipelineCode(pipeline),
			Message:  "Potential data exfiltration: " + sensitiveReason,
			Detail: "This pipeline reads sensitive data and pipes it to a network command, " +
				"which could exfiltrate credentials, environment variables, or system information.",
			Recommendation: "Review what data is being sent and to where.",
		}
	}

	return nil
}

// isArchiveToStdout checks if an archive command outputs to stdout.
func isArchiveToStdout(cmd *parser.Command) bool {
	// tar: look for 'c' (create) in flags and '-' as output target
	// Examples: tar czf - dir, tar -czf - dir, tar cf - dir
	if cmd.Name == "tar" {
		hasCreate := false
		hasStdoutFile := false
		for _, arg := range cmd.Args {
			// Check for create flag - can be in various forms
			// -c, -czf, czf, -cf, cf all contain 'c' as a flag
			if !strings.HasPrefix(arg, "/") && !strings.HasPrefix(arg, ".") && !strings.HasPrefix(arg, "~") {
				// This looks like a flag or flag bundle
				if strings.Contains(arg, "c") {
					hasCreate = true
				}
			}
			if arg == "-" {
				hasStdoutFile = true
			}
		}
		return hasCreate && hasStdoutFile
	}

	// zip: zip -r - dir sends to stdout
	if cmd.Name == "zip" {
		for _, arg := range cmd.Args {
			if arg == "-" {
				return true
			}
		}
	}

	return false
}

// hasPostFlags checks if wget has POST-related flags.
func hasPostFlags(cmd *parser.Command) bool {
	for _, arg := range cmd.Args {
		if strings.HasPrefix(arg, "--post-data") ||
			strings.HasPrefix(arg, "--post-file") {
			return true
		}
	}
	return false
}

// isSensitivePath checks if a path might contain sensitive data.
func isSensitivePath(path string) bool {
	sensitivePaths := []string{
		// System files
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/etc/hosts",
		"/etc/hostname",
		// SSH keys and config
		".ssh",
		"id_rsa",
		"id_ed25519",
		"id_ecdsa",
		"id_dsa",
		"authorized_keys",
		"known_hosts",
		// Cloud credentials
		".aws",
		".azure",
		".config/gcloud",
		".kube/config",
		".docker/config",
		// Secrets and tokens
		".gnupg",
		".env",
		".netrc",
		".git-credentials",
		".npmrc",
		".pypirc",
		// Process and runtime
		"/proc/self/environ",
		"/proc/self/cmdline",
	}

	for _, sensitive := range sensitivePaths {
		if strings.Contains(path, sensitive) {
			return true
		}
	}

	return false
}

// formatPipelineCode creates a readable representation of a pipeline.
func formatPipelineCode(pipeline *parser.Pipeline) string {
	var parts []string
	for _, cmd := range pipeline.Commands {
		parts = append(parts, cmd.String())
	}
	return strings.Join(parts, " | ")
}

// riskyPatterns are patterns that indicate dangerous content in variable values.
var riskyPatterns = []string{
	"| bash",
	"| sh",
	"|bash",
	"|sh",
	"eval ",
	"curl ",
	"wget ",
	"$(curl",
	"$(wget",
	"`curl",
	"`wget",
}

// analyzeVariableFlow detects risky variable assignments being executed.
func (a *Level0Analyzer) analyzeVariableFlow(result *parser.Result) []types.Finding {
	var findings []types.Finding

	// Get all variable assignments
	assignments := parser.FindAssignments(result.File)

	// Build map of risky variables
	riskyVars := make(map[string]string) // varname -> why it's risky
	for _, assign := range assignments {
		for _, pattern := range riskyPatterns {
			if strings.Contains(assign.Value, pattern) {
				riskyVars[assign.Name] = assign.Value
				break
			}
		}
	}

	// If no risky variables, nothing to check
	if len(riskyVars) == 0 {
		return findings
	}

	// Find variable executions
	executions := parser.FindVariableExecutions(result.File)

	for _, exec := range executions {
		if value, risky := riskyVars[exec.VarName]; risky {
			findings = append(findings, types.Finding{
				ID:       "SS031",
				Severity: types.SeverityHigh,
				Category: types.CategoryExecution,
				Line:     exec.Line,
				Column:   exec.Column,
				Code:     "$" + exec.VarName,
				Message:  "Execution of variable containing risky content",
				Detail: "The variable $" + exec.VarName + " was assigned a value containing " +
					"potentially dangerous commands and is being executed directly. " +
					"Assigned value: " + truncateValue(value, 60),
				Recommendation: "Avoid storing executable commands in variables. " +
					"If necessary, validate the content before execution.",
			})
		}
	}

	return findings
}

// truncateValue truncates a string to maxLen with ellipsis.
func truncateValue(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
