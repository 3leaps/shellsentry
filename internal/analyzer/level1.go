// Package analyzer provides the core analysis engine for shellsentry.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package analyzer

import (
	"context"

	"github.com/3leaps/shellsentry/internal/parser"
	"github.com/3leaps/shellsentry/internal/patterns"
	"github.com/3leaps/shellsentry/internal/types"
)

// Level1Analyzer performs pattern-based risk detection.
type Level1Analyzer struct {
	patterns         *patterns.PatternSet
	filterStringLits bool
	parserOpts       parser.Options
}

// NewLevel1Analyzer creates a new Level 1 analyzer with builtin patterns.
func NewLevel1Analyzer() *Level1Analyzer {
	return &Level1Analyzer{
		patterns:         patterns.BuiltinPatterns(),
		filterStringLits: true, // Enable string literal filtering by default
		parserOpts:       parser.DefaultOptions(),
	}
}

// NewLevel1AnalyzerWithPatterns creates a Level 1 analyzer with custom patterns.
func NewLevel1AnalyzerWithPatterns(ps *patterns.PatternSet) *Level1Analyzer {
	return &Level1Analyzer{
		patterns:         ps,
		filterStringLits: true,
		parserOpts:       parser.DefaultOptions(),
	}
}

// Name returns the analyzer identifier.
func (a *Level1Analyzer) Name() string {
	return "level1-patterns"
}

// Analyze runs pattern matching against the script content.
func (a *Level1Analyzer) Analyze(ctx context.Context, content []byte, filename string) ([]types.Finding, error) {
	var (
		stringRegions []parser.StringRegion
		heredocRanges []patterns.LineRange
	)

	// Parse once for region-based filtering.
	result, _ := parser.Parse(content, filename, a.parserOpts)
	if result != nil && result.File != nil {
		if a.filterStringLits {
			stringRegions = parser.FindStringLiterals(result.File)
		}

		for _, r := range parser.FindHeredocs(result.File) {
			heredocRanges = append(heredocRanges, patterns.LineRange{
				StartLine: r.StartLine,
				EndLine:   r.EndLine,
			})
		}
	}

	matches := a.patterns.MatchAllWithProtectedLines(content, heredocRanges)

	// Note: findings within string literals are still filtered below.

	findings := make([]types.Finding, 0, len(matches))
	for _, m := range matches {
		finding := m.ToFinding()

		// Skip findings that fall entirely within string literals
		if a.filterStringLits && isInsideStringLiteral(finding, stringRegions) {
			continue
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// isInsideStringLiteral checks if a finding is inside a quoted string.
func isInsideStringLiteral(f types.Finding, regions []parser.StringRegion) bool {
	for _, r := range regions {
		if r.Contains(f.Line, f.Column) {
			return true
		}
	}
	return false
}
