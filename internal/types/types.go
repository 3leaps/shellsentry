// Package types defines core types for shellsentry.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package types

import (
	"fmt"
	"time"
)

// Severity levels for findings, aligned with exit codes.
type Severity string

const (
	SeverityHigh   Severity = "high"   // Exit code 3
	SeverityMedium Severity = "medium" // Exit code 2
	SeverityLow    Severity = "low"    // Exit code 1
	SeverityInfo   Severity = "info"   // Exit code 1
)

// Category classifies the type of risk a finding represents.
type Category string

const (
	CategoryExecution     Category = "execution"     // Code execution patterns
	CategoryDownload      Category = "download"      // Remote content fetching
	CategoryPrivilege     Category = "privilege"     // Privilege escalation
	CategoryObfuscation   Category = "obfuscation"   // Code hiding techniques
	CategoryPersistence   Category = "persistence"   // System persistence (cron, systemd)
	CategoryNetwork       Category = "network"       // Network operations
	CategoryFilesystem    Category = "filesystem"    // File system operations
	CategoryCredential    Category = "credential"    // Credential/key access
	CategoryDestructive   Category = "destructive"   // Destructive operations
	CategoryExfiltration  Category = "exfiltration"  // Data exfiltration patterns
	CategoryInformational Category = "informational" // General information
)

// RiskLevel represents the overall risk assessment of a script.
type RiskLevel string

const (
	RiskClean   RiskLevel = "clean"   // No findings
	RiskInfo    RiskLevel = "info"    // Informational only
	RiskWarning RiskLevel = "warning" // Medium-risk patterns
	RiskDanger  RiskLevel = "danger"  // High-risk patterns
	RiskError   RiskLevel = "error"   // Analysis failed
)

// Shell types that can be detected.
type Shell string

const (
	ShellBash    Shell = "bash"
	ShellSh      Shell = "sh"
	ShellZsh     Shell = "zsh"
	ShellUnknown Shell = "unknown"
)

// Finding represents a single detected pattern or issue.
type Finding struct {
	// ID is the finding identifier (e.g., "SS001").
	ID string `json:"id"`

	// Severity indicates the risk level.
	Severity Severity `json:"severity"`

	// Category classifies the type of risk.
	Category Category `json:"category"`

	// Line is the 1-based line number where the pattern was found.
	Line int `json:"line,omitempty"`

	// Column is the 1-based column number where the pattern starts.
	Column int `json:"column,omitempty"`

	// EndLine is the end line for multi-line patterns.
	EndLine int `json:"end_line,omitempty"`

	// EndColumn is the end column for multi-line patterns.
	EndColumn int `json:"end_column,omitempty"`

	// Code is the matched code snippet.
	Code string `json:"code,omitempty"`

	// Message is a human-readable description.
	Message string `json:"message"`

	// Detail provides extended explanation of the risk.
	Detail string `json:"detail,omitempty"`

	// Recommendation suggests remediation or review action.
	Recommendation string `json:"recommendation,omitempty"`
}

// Summary counts findings by severity.
type Summary struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

// Metrics provides script statistics.
type Metrics struct {
	// ExternalCommands lists external commands invoked.
	ExternalCommands []string `json:"external_commands,omitempty"`

	// NetworkOperations counts network-related operations.
	NetworkOperations int `json:"network_operations"`

	// FilesystemWrites counts filesystem write operations.
	FilesystemWrites int `json:"filesystem_writes"`

	// PrivilegeEscalations counts sudo/privilege operations.
	PrivilegeEscalations int `json:"privilege_escalations"`
}

// ShellcheckStatus reports shellcheck integration status.
type ShellcheckStatus struct {
	// Available indicates whether shellcheck was found.
	Available bool `json:"available"`

	// FindingsMerged counts shellcheck findings incorporated.
	FindingsMerged int `json:"findings_merged"`
}

// Source provides optional provenance metadata.
type Source struct {
	// URL is where the script was fetched from.
	URL string `json:"url,omitempty"`

	// Repo is the repository identifier (e.g., "owner/repo").
	Repo string `json:"repo,omitempty"`
}

// ParseError represents a parse error encountered.
type ParseError struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

// Report is the complete analysis output.
type Report struct {
	// SchemaVersion is the schema version (e.g., "0.1").
	SchemaVersion string `json:"schema_version"`

	// SchemaStability indicates schema stability level.
	SchemaStability string `json:"schema_stability"`

	// ToolVersion is the shellsentry version that produced this report.
	ToolVersion string `json:"tool_version"`

	// File is the name of the analyzed file (omitted for stdin).
	File string `json:"file,omitempty"`

	// Source provides optional provenance metadata.
	Source *Source `json:"source,omitempty"`

	// AnalyzedAt is the ISO 8601 timestamp of analysis.
	AnalyzedAt time.Time `json:"analyzed_at"`

	// Shell is the detected shell type.
	Shell Shell `json:"shell,omitempty"`

	// Lines is the total line count.
	Lines int `json:"lines,omitempty"`

	// RiskLevel is the overall risk assessment.
	RiskLevel RiskLevel `json:"risk_level"`

	// RiskScore is a numeric risk score (0-100).
	RiskScore int `json:"risk_score,omitempty"`

	// Summary counts findings by severity.
	Summary Summary `json:"summary"`

	// Findings lists detected patterns/issues.
	Findings []Finding `json:"findings"`

	// seenFindingKeys tracks findings already added.
	// This prevents double-counting the same detection emitted by multiple analyzers.
	seenFindingKeys map[string]struct{}

	// Metrics provides script statistics.
	Metrics *Metrics `json:"metrics,omitempty"`

	// Shellcheck reports shellcheck integration status.
	Shellcheck *ShellcheckStatus `json:"shellcheck,omitempty"`

	// ParseErrors lists any parse errors encountered.
	ParseErrors []ParseError `json:"parse_errors,omitempty"`
}

// NewReport creates a new report with default values.
func NewReport(toolVersion string) *Report {
	return &Report{
		SchemaVersion:   "0.1",
		SchemaStability: "experimental",
		ToolVersion:     toolVersion,
		AnalyzedAt:      time.Now().UTC(),
		RiskLevel:       RiskClean,
		Summary:         Summary{},
		Findings:        []Finding{},
		seenFindingKeys: make(map[string]struct{}),
	}
}

// AddFinding adds a finding and updates the summary.
func (r *Report) AddFinding(f Finding) {
	if r.seenFindingKeys == nil {
		r.seenFindingKeys = make(map[string]struct{})
	}

	key := fmt.Sprintf("%s|%s|%d|%d", f.ID, f.Category, f.Line, f.Column)
	if _, ok := r.seenFindingKeys[key]; ok {
		return
	}

	r.seenFindingKeys[key] = struct{}{}
	r.Findings = append(r.Findings, f)

	switch f.Severity {
	case SeverityHigh:
		r.Summary.High++
	case SeverityMedium:
		r.Summary.Medium++
	case SeverityLow:
		r.Summary.Low++
	case SeverityInfo:
		r.Summary.Info++
	}

	// Update risk level to highest severity found
	r.updateRiskLevel()
}

// updateRiskLevel sets RiskLevel based on highest severity finding.
func (r *Report) updateRiskLevel() {
	switch {
	case r.Summary.High > 0:
		r.RiskLevel = RiskDanger
	case r.Summary.Medium > 0:
		r.RiskLevel = RiskWarning
	case r.Summary.Low > 0 || r.Summary.Info > 0:
		r.RiskLevel = RiskInfo
	default:
		r.RiskLevel = RiskClean
	}
}

// ExitCode returns the appropriate exit code for this report.
func (r *Report) ExitCode() int {
	switch r.RiskLevel {
	case RiskClean:
		return 0
	case RiskInfo:
		return 1
	case RiskWarning:
		return 2
	case RiskDanger:
		return 3
	case RiskError:
		return 4
	default:
		return 0
	}
}
