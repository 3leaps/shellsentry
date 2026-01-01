// Package output provides formatters for shellsentry analysis reports.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/3leaps/shellsentry/internal/types"
)

// TextFormatter formats reports as human-readable text.
type TextFormatter struct{}

// NewTextFormatter creates a new text formatter.
func NewTextFormatter() *TextFormatter {
	return &TextFormatter{}
}

// Format writes a human-readable text report.
func (f *TextFormatter) Format(w io.Writer, report *types.Report) error {
	var err error
	writef := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(w, format, args...)
	}
	writeln := func(args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintln(w, args...)
	}

	// Header
	writef("shellsentry analysis: %s\n", riskIcon(report.RiskLevel))
	writef("─────────────────────────────────────────\n")

	if report.File != "" {
		writef("File: %s\n", report.File)
	}
	if report.Lines > 0 {
		writef("Lines: %d\n", report.Lines)
	}
	if report.Shell != "" && report.Shell != types.ShellUnknown {
		writef("Shell: %s\n", report.Shell)
	}
	writef("Risk Level: %s\n", formatRiskLevel(report.RiskLevel))
	writef("Risk Score: %d/100\n", report.RiskScore)
	writeln()

	// Summary
	writef("Summary: %d high, %d medium, %d low, %d info\n",
		report.Summary.High, report.Summary.Medium, report.Summary.Low, report.Summary.Info)
	writeln()

	// Findings
	if len(report.Findings) == 0 {
		writeln("No issues found.")
		return err
	}

	writef("Findings (%d):\n", len(report.Findings))
	writeln()

	for i, finding := range report.Findings {
		writef("%d. [%s] %s (%s)\n",
			i+1,
			severityIcon(finding.Severity),
			finding.Message,
			finding.ID)

		if finding.Line > 0 {
			writef("   Location: line %d", finding.Line)
			if finding.Column > 0 {
				writef(", column %d", finding.Column)
			}
			writeln()
		}

		if finding.Code != "" {
			// Indent and truncate code
			code := finding.Code
			if len(code) > 80 {
				code = code[:77] + "..."
			}
			writef("   Code: %s\n", code)
		}

		if finding.Detail != "" {
			// Wrap detail text
			wrapped := wrapText(finding.Detail, 70)
			for _, line := range wrapped {
				writef("   %s\n", line)
			}
		}

		if finding.Recommendation != "" {
			writef("   Recommendation: %s\n", finding.Recommendation)
		}

		writeln()
	}

	// Parse errors
	if len(report.ParseErrors) > 0 {
		writeln("Parse Errors:")
		for _, pe := range report.ParseErrors {
			if pe.Line > 0 {
				writef("  - Line %d: %s\n", pe.Line, pe.Message)
			} else {
				writef("  - %s\n", pe.Message)
			}
		}
		writeln()
	}

	return err
}

func riskIcon(level types.RiskLevel) string {
	switch level {
	case types.RiskClean:
		return "CLEAN"
	case types.RiskInfo:
		return "INFO"
	case types.RiskWarning:
		return "WARNING"
	case types.RiskDanger:
		return "DANGER"
	case types.RiskError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

func formatRiskLevel(level types.RiskLevel) string {
	switch level {
	case types.RiskClean:
		return "Clean - no issues found"
	case types.RiskInfo:
		return "Info - informational findings only"
	case types.RiskWarning:
		return "Warning - medium-risk patterns found"
	case types.RiskDanger:
		return "Danger - high-risk patterns found"
	case types.RiskError:
		return "Error - analysis failed"
	default:
		return string(level)
	}
}

func severityIcon(s types.Severity) string {
	switch s {
	case types.SeverityHigh:
		return "HIGH"
	case types.SeverityMedium:
		return "MEDIUM"
	case types.SeverityLow:
		return "LOW"
	case types.SeverityInfo:
		return "INFO"
	default:
		return string(s)
	}
}

func wrapText(text string, width int) []string {
	if len(text) <= width {
		return []string{text}
	}

	var lines []string
	words := strings.Fields(text)
	var current strings.Builder

	for _, word := range words {
		if current.Len()+len(word)+1 > width {
			if current.Len() > 0 {
				lines = append(lines, current.String())
				current.Reset()
			}
		}
		if current.Len() > 0 {
			current.WriteString(" ")
		}
		current.WriteString(word)
	}

	if current.Len() > 0 {
		lines = append(lines, current.String())
	}

	return lines
}
