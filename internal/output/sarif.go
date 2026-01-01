// Package output provides formatters for shellsentry analysis reports.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package output

import (
	"encoding/json"
	"io"

	"github.com/3leaps/shellsentry/internal/types"
)

// SARIF output types per SARIF 2.1.0 spec
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifMessage      `json:"shortDescription,omitempty"`
	FullDescription  sarifMessage      `json:"fullDescription,omitempty"`
	DefaultConfig    sarifRuleConfig   `json:"defaultConfiguration,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// SARIFFormatter formats reports in SARIF format.
type SARIFFormatter struct{}

// NewSARIFFormatter creates a new SARIF formatter.
func NewSARIFFormatter() *SARIFFormatter {
	return &SARIFFormatter{}
}

// Format writes a SARIF report.
func (f *SARIFFormatter) Format(w io.Writer, report *types.Report) error {
	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "shellsentry",
						Version:         report.ToolVersion,
						InformationURI:  "https://github.com/3leaps/shellsentry",
						SemanticVersion: report.ToolVersion,
					},
				},
				Results: f.convertFindings(report),
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

func (f *SARIFFormatter) convertFindings(report *types.Report) []sarifResult {
	results := make([]sarifResult, 0, len(report.Findings))

	for _, finding := range report.Findings {
		result := sarifResult{
			RuleID:  finding.ID,
			Level:   severityToLevel(finding.Severity),
			Message: sarifMessage{Text: finding.Message},
		}

		// Add location if available
		if report.File != "" && finding.Line > 0 {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{
						URI: report.File,
					},
					Region: &sarifRegion{
						StartLine:   finding.Line,
						StartColumn: finding.Column,
						EndLine:     finding.EndLine,
						EndColumn:   finding.EndColumn,
					},
				},
			}
			result.Locations = []sarifLocation{loc}
		}

		results = append(results, result)
	}

	return results
}

func severityToLevel(s types.Severity) string {
	switch s {
	case types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	case types.SeverityLow:
		return "note"
	case types.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}
