// Package output provides formatters for shellsentry analysis reports.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/3leaps/shellsentry/internal/types"
)

func createTestReport() *types.Report {
	report := types.NewReport("0.1.0")
	report.File = "test.sh"
	report.Lines = 10
	report.RiskLevel = types.RiskWarning
	report.RiskScore = 35
	report.Summary.High = 0
	report.Summary.Medium = 2
	report.Summary.Low = 1
	report.Summary.Info = 0

	report.AddFinding(types.Finding{
		ID:             "SS010",
		Severity:       types.SeverityMedium,
		Category:       types.CategoryPrivilege,
		Line:           5,
		Column:         1,
		EndLine:        5,
		EndColumn:      25,
		Code:           "sudo apt-get install pkg",
		Message:        "sudo command detected",
		Detail:         "This script uses sudo.",
		Recommendation: "Review sudo usage.",
	})

	return report
}

func TestJSONFormatter_Format(t *testing.T) {
	formatter := NewJSONFormatter()
	report := createTestReport()

	var buf bytes.Buffer
	err := formatter.Format(&buf, report)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check expected fields
	if parsed["file"] != "test.sh" {
		t.Errorf("expected file=test.sh, got %v", parsed["file"])
	}
	if parsed["risk_level"] != "warning" {
		t.Errorf("expected risk_level=warning, got %v", parsed["risk_level"])
	}
	if parsed["tool_version"] != "0.1.0" {
		t.Errorf("expected tool_version=0.1.0, got %v", parsed["tool_version"])
	}
}

func TestJSONFormatter_NoIndent(t *testing.T) {
	formatter := &JSONFormatter{Indent: false}
	report := createTestReport()

	var buf bytes.Buffer
	err := formatter.Format(&buf, report)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Without indent, should be compact (single line)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 1 {
		t.Errorf("expected single-line output without indent, got %d lines", len(lines))
	}
}

func TestTextFormatter_Format(t *testing.T) {
	formatter := NewTextFormatter()
	report := createTestReport()

	var buf bytes.Buffer
	err := formatter.Format(&buf, report)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Check for expected content
	if !strings.Contains(output, "WARNING") {
		t.Error("expected 'WARNING' in output")
	}
	if !strings.Contains(output, "test.sh") {
		t.Error("expected filename in output")
	}
	if !strings.Contains(output, "MEDIUM") || !strings.Contains(output, "SS010") {
		t.Error("expected finding details in output")
	}
}

func TestTextFormatter_CleanReport(t *testing.T) {
	formatter := NewTextFormatter()
	report := types.NewReport("0.1.0")
	report.File = "safe.sh"
	report.Lines = 5
	report.RiskLevel = types.RiskClean
	report.RiskScore = 0

	var buf bytes.Buffer
	err := formatter.Format(&buf, report)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Clean reports should indicate no issues
	if !strings.Contains(strings.ToLower(output), "clean") {
		t.Error("expected 'clean' indicator in output")
	}
}

func TestSARIFFormatter_Format(t *testing.T) {
	formatter := NewSARIFFormatter()
	report := createTestReport()

	var buf bytes.Buffer
	err := formatter.Format(&buf, report)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Verify it's valid JSON (SARIF is JSON)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check SARIF structure
	if parsed["$schema"] == nil {
		t.Error("expected $schema field in SARIF output")
	}
	if parsed["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", parsed["version"])
	}

	runs, ok := parsed["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Error("expected runs array in SARIF output")
	}
}

func TestSARIFFormatter_EmptyReport(t *testing.T) {
	formatter := NewSARIFFormatter()
	report := types.NewReport("0.1.0")
	report.File = "empty.sh"
	report.Lines = 1

	var buf bytes.Buffer
	err := formatter.Format(&buf, report)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should still produce valid SARIF
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestFormatterInterface(t *testing.T) {
	// Verify all formatters implement the interface
	var _ Formatter = NewJSONFormatter()
	var _ Formatter = NewTextFormatter()
	var _ Formatter = NewSARIFFormatter()
}

func TestSARIFFormatter_FullValidation(t *testing.T) {
	formatter := NewSARIFFormatter()
	report := createTestReport()

	var buf bytes.Buffer
	err := formatter.Format(&buf, report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Validate SARIF schema URL
	schema, ok := sarif["$schema"].(string)
	if !ok || !strings.Contains(schema, "sarif") {
		t.Error("expected valid SARIF schema URL")
	}

	// Validate runs array
	runs, ok := sarif["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatal("expected exactly one run")
	}

	run := runs[0].(map[string]interface{})

	// Validate tool section
	tool, ok := run["tool"].(map[string]interface{})
	if !ok {
		t.Fatal("expected tool section")
	}

	driver, ok := tool["driver"].(map[string]interface{})
	if !ok {
		t.Fatal("expected driver section")
	}

	if driver["name"] != "shellsentry" {
		t.Errorf("expected tool name 'shellsentry', got %v", driver["name"])
	}

	// Validate results array exists
	results, ok := run["results"].([]interface{})
	if !ok {
		t.Fatal("expected results array")
	}

	// Test report has 1 finding (createTestReport adds 1)
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}

	// Validate first result structure
	if len(results) > 0 {
		result := results[0].(map[string]interface{})

		// Check ruleId
		if _, ok := result["ruleId"].(string); !ok {
			t.Error("expected ruleId in result")
		}

		// Check level
		if _, ok := result["level"].(string); !ok {
			t.Error("expected level in result")
		}

		// Check message
		msg, ok := result["message"].(map[string]interface{})
		if !ok {
			t.Error("expected message object in result")
		}
		if _, ok := msg["text"].(string); !ok {
			t.Error("expected text in message")
		}

		// Check locations
		locations, ok := result["locations"].([]interface{})
		if !ok || len(locations) == 0 {
			t.Error("expected locations array with at least one entry")
		}
	}
}

func TestSARIFFormatter_SeverityMapping(t *testing.T) {
	formatter := NewSARIFFormatter()

	testCases := []struct {
		severity types.Severity
		expected string
	}{
		{types.SeverityHigh, "error"},
		{types.SeverityMedium, "warning"},
		{types.SeverityLow, "note"},
		{types.SeverityInfo, "note"},
	}

	for _, tc := range testCases {
		t.Run(string(tc.severity), func(t *testing.T) {
			report := types.NewReport("0.1.0")
			report.File = "test.sh"
			report.Lines = 1
			report.AddFinding(types.Finding{
				ID:       "SS999",
				Severity: tc.severity,
				Message:  "Test finding",
				Line:     1,
				Column:   1,
			})

			var buf bytes.Buffer
			if err := formatter.Format(&buf, report); err != nil {
				t.Fatalf("format error: %v", err)
			}

			var sarif map[string]interface{}
			if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
				t.Fatalf("unmarshal sarif: %v", err)
			}

			runs := sarif["runs"].([]interface{})
			run := runs[0].(map[string]interface{})
			results := run["results"].([]interface{})

			if len(results) != 1 {
				t.Fatal("expected 1 result")
			}

			result := results[0].(map[string]interface{})
			level := result["level"].(string)

			if level != tc.expected {
				t.Errorf("severity %s: expected SARIF level %q, got %q",
					tc.severity, tc.expected, level)
			}
		})
	}
}
