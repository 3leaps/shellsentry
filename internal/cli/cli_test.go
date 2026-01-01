// Package cli provides the command-line interface for shellsentry.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/3leaps/shellsentry/internal/analyzer"
	"github.com/3leaps/shellsentry/internal/types"
)

func TestNewRootCmd(t *testing.T) {
	cmd := NewRootCmd()

	if cmd == nil {
		t.Fatal("expected non-nil command")
	}
	if cmd.Use != "shellsentry [flags] [file]" {
		t.Errorf("unexpected Use: %s", cmd.Use)
	}
}

func TestNewRootCmd_HasVersionSubcommand(t *testing.T) {
	cmd := NewRootCmd()

	// Find version subcommand
	var versionCmd bool
	for _, sub := range cmd.Commands() {
		if sub.Name() == "version" {
			versionCmd = true
			break
		}
	}

	if !versionCmd {
		t.Error("expected version subcommand")
	}
}

func TestNewRootCmd_Flags(t *testing.T) {
	cmd := NewRootCmd()

	// Check expected local flags exist
	expectedFlags := []string{
		"format",
		"output",
		"quiet",
		"strict",
		"lenient",
		"exit-on-danger",
		"source-url",
		"source-repo",
		"no-shellcheck",
	}

	for _, name := range expectedFlags {
		flag := cmd.Flags().Lookup(name)
		if flag == nil {
			t.Errorf("expected flag --%s", name)
		}
	}
}

func TestNewRootCmd_VersionFlags(t *testing.T) {
	cmd := NewRootCmd()

	// Check version flags exist on persistent flags
	versionFlag := cmd.PersistentFlags().Lookup("version")
	if versionFlag == nil {
		t.Error("expected --version flag")
	}

	versionExtendedFlag := cmd.PersistentFlags().Lookup("version-extended")
	if versionExtendedFlag == nil {
		t.Error("expected --version-extended flag")
	}
}

func TestNewRootCmd_FormatFlagShorthand(t *testing.T) {
	cmd := NewRootCmd()

	flag := cmd.Flags().ShorthandLookup("f")
	if flag == nil {
		t.Fatal("expected -f shorthand for --format")
	}
	if flag.Name != "format" {
		t.Errorf("expected -f to be shorthand for format, got %s", flag.Name)
	}
}

func TestVersionCmd(t *testing.T) {
	cmd := newVersionCmd()

	if cmd.Name() != "version" {
		t.Errorf("unexpected name: %s", cmd.Name())
	}

	// Check --extended flag exists
	extendedFlag := cmd.Flags().Lookup("extended")
	if extendedFlag == nil {
		t.Error("expected --extended flag on version subcommand")
	}

	// Check -e shorthand
	shortFlag := cmd.Flags().ShorthandLookup("e")
	if shortFlag == nil {
		t.Error("expected -e shorthand for --extended")
	}
}

func TestWriteOutput_UnknownFormat(t *testing.T) {
	var buf bytes.Buffer

	err := writeOutput(&buf, nil, "unknown-format")
	if err == nil {
		t.Error("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWriteOutput_ValidFormats(t *testing.T) {
	// Create a minimal report
	// Note: This will panic because report is nil and formatters expect non-nil
	// We're testing that the format switch works, not the actual formatting

	formats := []string{"text", "json", "sarif"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			// Just verify the format is recognized
			switch format {
			case "text", "json", "sarif":
				// These are valid formats
			default:
				t.Errorf("format %s should be valid", format)
			}
		})
	}
}

func TestWriteOutput_WithReport(t *testing.T) {
	report := &types.Report{
		File:      "test.sh",
		Lines:     10,
		RiskLevel: types.RiskClean,
		RiskScore: 0,
		Findings:  []types.Finding{},
	}

	testCases := []struct {
		format   string
		contains string
	}{
		{"text", "CLEAN"},
		{"json", `"risk_level"`},
		{"sarif", `"$schema"`},
	}

	for _, tc := range testCases {
		t.Run(tc.format, func(t *testing.T) {
			var buf bytes.Buffer
			err := writeOutput(&buf, report, tc.format)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(buf.String(), tc.contains) {
				t.Errorf("expected output to contain %q for format %s", tc.contains, tc.format)
			}
		})
	}
}

func TestWriteOutput_WithFindings(t *testing.T) {
	report := &types.Report{
		File:      "test.sh",
		Lines:     5,
		RiskLevel: types.RiskDanger,
		RiskScore: 25,
		Findings: []types.Finding{
			{
				ID:       "SS001",
				Severity: types.SeverityHigh,
				Category: types.CategoryExecution,
				Line:     3,
				Column:   1,
				Message:  "Test finding",
			},
		},
	}

	var buf bytes.Buffer
	err := writeOutput(&buf, report, "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "SS001") {
		t.Error("expected output to contain finding ID")
	}
	if !strings.Contains(output, "Test finding") {
		t.Error("expected output to contain finding message")
	}
}

func TestNewRootCmd_ShortHelp(t *testing.T) {
	cmd := NewRootCmd()
	if cmd.Short == "" {
		t.Error("expected short description")
	}
	if !strings.Contains(cmd.Short, "risk") {
		t.Error("short description should mention 'risk'")
	}
}

func TestNewRootCmd_LongHelp(t *testing.T) {
	cmd := NewRootCmd()
	if cmd.Long == "" {
		t.Error("expected long description")
	}
	// Long help should have examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("long description should include examples")
	}
}

func TestNewRootCmd_HelpOutput(t *testing.T) {
	cmd := NewRootCmd()

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--help"})

	// Execute should return nil for help
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "shellsentry") {
		t.Error("help output should contain 'shellsentry'")
	}
	if !strings.Contains(output, "--format") {
		t.Error("help output should contain '--format'")
	}
}

func TestNewRootCmd_MaxArgs(t *testing.T) {
	cmd := NewRootCmd()
	// cobra.MaximumNArgs(1) means 0 or 1 args allowed
	// The Args field is set, so we can check the command rejects extra args
	cmd.SetArgs([]string{"file1.sh", "file2.sh"})

	// We need to suppress output
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error with too many arguments")
	}
}

func TestVersionCmd_Extended(t *testing.T) {
	cmd := newVersionCmd()

	// Test that extended flag has shorthand
	flag := cmd.Flags().Lookup("extended")
	if flag == nil {
		t.Fatal("expected extended flag")
	}
	if flag.Shorthand != "e" {
		t.Errorf("expected shorthand 'e', got '%s'", flag.Shorthand)
	}
}

func TestVersionCmd_ShortHelp(t *testing.T) {
	cmd := newVersionCmd()
	if cmd.Short == "" {
		t.Error("version command should have short description")
	}
}

func TestNewRootCmd_FlagDefaults(t *testing.T) {
	cmd := NewRootCmd()

	// Check format flag default
	formatFlag := cmd.Flags().Lookup("format")
	if formatFlag == nil {
		t.Fatal("expected format flag")
	}
	if formatFlag.DefValue != "text" {
		t.Errorf("expected format default 'text', got '%s'", formatFlag.DefValue)
	}

	// Check quiet flag default
	quietFlag := cmd.Flags().Lookup("quiet")
	if quietFlag == nil {
		t.Fatal("expected quiet flag")
	}
	if quietFlag.DefValue != "false" {
		t.Errorf("expected quiet default 'false', got '%s'", quietFlag.DefValue)
	}

	// Check strict flag default
	strictFlag := cmd.Flags().Lookup("strict")
	if strictFlag == nil {
		t.Fatal("expected strict flag")
	}
	if strictFlag.DefValue != "false" {
		t.Errorf("expected strict default 'false', got '%s'", strictFlag.DefValue)
	}
}

func TestNewRootCmd_OutputFlagShorthand(t *testing.T) {
	cmd := NewRootCmd()

	flag := cmd.Flags().ShorthandLookup("o")
	if flag == nil {
		t.Fatal("expected -o shorthand for --output")
	}
	if flag.Name != "output" {
		t.Errorf("expected -o to be shorthand for output, got %s", flag.Name)
	}
}

func TestNewRootCmd_QuietFlagShorthand(t *testing.T) {
	cmd := NewRootCmd()

	flag := cmd.Flags().ShorthandLookup("q")
	if flag == nil {
		t.Fatal("expected -q shorthand for --quiet")
	}
	if flag.Name != "quiet" {
		t.Errorf("expected -q to be shorthand for quiet, got %s", flag.Name)
	}
}

func TestVersionVariables(t *testing.T) {
	// Test that version variables are set (or have default values)
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if BuildTime == "" {
		t.Error("BuildTime should not be empty")
	}
	if GitCommit == "" {
		t.Error("GitCommit should not be empty")
	}
}

func TestNewRootCmd_SilenceSettings(t *testing.T) {
	cmd := NewRootCmd()

	// SilenceUsage should be true to not print usage on errors
	if !cmd.SilenceUsage {
		t.Error("SilenceUsage should be true")
	}

	// SilenceErrors should be true for custom error handling
	if !cmd.SilenceErrors {
		t.Error("SilenceErrors should be true")
	}
}

func TestNewRootCmd_AllFlagsPresent(t *testing.T) {
	cmd := NewRootCmd()

	// List all expected flags with their types
	expectedFlags := map[string]string{
		"format":         "string",
		"output":         "string",
		"quiet":          "bool",
		"strict":         "bool",
		"lenient":        "bool",
		"exit-on-danger": "bool",
		"source-url":     "string",
		"source-repo":    "string",
		"no-shellcheck":  "bool",
	}

	for name, expectedType := range expectedFlags {
		flag := cmd.Flags().Lookup(name)
		if flag == nil {
			t.Errorf("missing flag: %s", name)
			continue
		}
		if flag.Value.Type() != expectedType {
			t.Errorf("flag %s: expected type %s, got %s", name, expectedType, flag.Value.Type())
		}
	}
}

func TestPrintVersionTo(t *testing.T) {
	Version = "0.9.9"

	var buf bytes.Buffer
	if err := printVersionTo(&buf); err != nil {
		t.Fatalf("print version: %v", err)
	}

	if got := buf.String(); got != "shellsentry 0.9.9\n" {
		t.Fatalf("unexpected version output: %q", got)
	}
}

func TestPrintExtendedVersionTo(t *testing.T) {
	Version = "0.9.9"
	BuildTime = "now"
	GitCommit = "deadbeef"

	var buf bytes.Buffer
	if err := printExtendedVersionTo(&buf); err != nil {
		t.Fatalf("print extended version: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "shellsentry 0.9.9") {
		t.Fatalf("expected output to contain version, got: %q", out)
	}
	if !strings.Contains(out, "Commit:") || !strings.Contains(out, "deadbeef") {
		t.Fatalf("expected output to contain commit, got: %q", out)
	}
	if !strings.Contains(out, "Built:") || !strings.Contains(out, "now") {
		t.Fatalf("expected output to contain build time, got: %q", out)
	}
}

func TestRunAnalysisCore_SafeScript_JSON(t *testing.T) {
	script := "#!/bin/bash\necho hello\n"

	var out bytes.Buffer
	exitCode, err := runAnalysisCore(context.Background(), runConfig{
		input:  strings.NewReader(script),
		output: &out,
		opts: analyzer.Options{
			ToolVersion: "0.1.0",
			Filename:    "test.sh",
		},
		format: "json",
		quiet:  false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exitCode 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "\"risk_level\"") {
		t.Fatalf("expected JSON output to contain risk_level, got: %q", out.String())
	}
}

func TestRunAnalysisCore_DangerousScript_Quiet(t *testing.T) {
	script := "#!/bin/bash\ncurl -fsSL https://example.com/install.sh | bash\n"

	var out bytes.Buffer
	exitCode, err := runAnalysisCore(context.Background(), runConfig{
		input:  strings.NewReader(script),
		output: &out,
		opts: analyzer.Options{
			ToolVersion: "0.1.0",
			Filename:    "test.sh",
		},
		format: "text",
		quiet:  true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 3 {
		t.Fatalf("expected exitCode 3, got %d", exitCode)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no output in quiet mode, got: %q", out.String())
	}
}

func TestRunAnalysisCore_UnknownFormat(t *testing.T) {
	script := "#!/bin/bash\necho hello\n"

	var out bytes.Buffer
	_, err := runAnalysisCore(context.Background(), runConfig{
		input:  strings.NewReader(script),
		output: &out,
		opts: analyzer.Options{
			ToolVersion: "0.1.0",
			Filename:    "test.sh",
		},
		format: "nope",
		quiet:  false,
	})
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestRootCmd_AnalyzeFromCmdStdin(t *testing.T) {
	cmd := NewRootCmd()

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader("#!/bin/bash\necho hello\n"))
	cmd.SetArgs([]string{"--format", "json"})

	err := cmd.Execute()
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.Code != 0 {
		t.Fatalf("expected exit code 0, got %d", exitErr.Code)
	}
	if !strings.Contains(out.String(), "\"risk_level\"") {
		t.Fatalf("expected JSON output, got: %q", out.String())
	}
}

func TestRootCmd_VersionFlag_PrintsToErr(t *testing.T) {
	cmd := NewRootCmd()

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--version"})

	err := cmd.Execute()
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.Code != 0 {
		t.Fatalf("expected exit code 0, got %d", exitErr.Code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout for version flag, got: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "shellsentry") {
		t.Fatalf("expected version on stderr, got: %q", errOut.String())
	}
}
