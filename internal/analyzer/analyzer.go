// Package analyzer provides the core analysis engine for shellsentry.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package analyzer

import (
	"context"
	"io"

	"github.com/3leaps/shellsentry/internal/types"
)

// Analyzer is the interface for script analysis engines.
type Analyzer interface {
	// Analyze performs analysis on the given script content.
	// Returns findings discovered by this analyzer.
	Analyze(ctx context.Context, content []byte, filename string) ([]types.Finding, error)

	// Name returns the analyzer's identifier.
	Name() string
}

// Options configures the analysis engine.
type Options struct {
	// ToolVersion is injected for report generation.
	ToolVersion string

	// SourceURL is optional provenance metadata.
	SourceURL string

	// SourceRepo is optional provenance metadata.
	SourceRepo string

	// Filename is the name of the file being analyzed.
	Filename string

	// DisableShellcheck skips shellcheck integration.
	DisableShellcheck bool

	// StrictMode exits non-zero on any finding.
	StrictMode bool

	// ExitOnDanger only exits non-zero on high-risk patterns.
	ExitOnDanger bool
}

// Engine orchestrates multiple analyzers and produces reports.
type Engine struct {
	analyzers []Analyzer
	opts      Options
}

// NewEngine creates a new analysis engine with the given options.
func NewEngine(opts Options) *Engine {
	return &Engine{
		analyzers: []Analyzer{},
		opts:      opts,
	}
}

// RegisterAnalyzer adds an analyzer to the engine.
func (e *Engine) RegisterAnalyzer(a Analyzer) {
	e.analyzers = append(e.analyzers, a)
}

// Analyze runs all registered analyzers and produces a report.
func (e *Engine) Analyze(ctx context.Context, r io.Reader) (*types.Report, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		report := types.NewReport(e.opts.ToolVersion)
		report.RiskLevel = types.RiskError
		report.ParseErrors = append(report.ParseErrors, types.ParseError{
			Message: "failed to read input: " + err.Error(),
		})
		return report, err
	}

	report := types.NewReport(e.opts.ToolVersion)
	report.File = e.opts.Filename
	report.Lines = countLines(content)

	// Set source provenance if provided
	if e.opts.SourceURL != "" || e.opts.SourceRepo != "" {
		report.Source = &types.Source{
			URL:  e.opts.SourceURL,
			Repo: e.opts.SourceRepo,
		}
	}

	// Run each analyzer
	for _, analyzer := range e.analyzers {
		findings, err := analyzer.Analyze(ctx, content, e.opts.Filename)
		if err != nil {
			// Record parse errors but continue with other analyzers
			report.ParseErrors = append(report.ParseErrors, types.ParseError{
				Message: analyzer.Name() + ": " + err.Error(),
			})
			continue
		}

		for _, f := range findings {
			report.AddFinding(f)
		}
	}

	// Calculate risk score
	report.RiskScore = calculateRiskScore(report)

	return report, nil
}

// ExitCode returns the appropriate exit code based on options.
func (e *Engine) ExitCode(report *types.Report) int {
	if e.opts.ExitOnDanger {
		// Only exit non-zero for high-risk patterns
		if report.Summary.High > 0 {
			return 3
		}
		return 0
	}

	if e.opts.StrictMode {
		// Exit non-zero on any finding
		if len(report.Findings) > 0 {
			return report.ExitCode()
		}
		return 0
	}

	// Default: exit code based on highest severity
	return report.ExitCode()
}

// countLines counts newlines in content.
func countLines(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	count := 1
	for _, b := range content {
		if b == '\n' {
			count++
		}
	}
	// Don't count trailing newline as extra line
	if len(content) > 0 && content[len(content)-1] == '\n' {
		count--
	}
	return count
}

// calculateRiskScore produces a 0-100 score based on findings.
func calculateRiskScore(report *types.Report) int {
	// Simple weighted scoring
	score := 0
	score += report.Summary.High * 25
	score += report.Summary.Medium * 10
	score += report.Summary.Low * 3
	score += report.Summary.Info * 1

	if score > 100 {
		score = 100
	}
	return score
}
