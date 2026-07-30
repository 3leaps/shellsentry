// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestInstallScriptDarwinAMD64GuardHonorsExplicitTag exercises the Intel Mac
// retirement guard in scripts/install-shellsentry.sh. The guard fires only when
// tag is "latest"; an explicit --tag (e.g. v0.1.4 recovery) must bypass it.
func TestInstallScriptDarwinAMD64GuardHonorsExplicitTag(t *testing.T) {
	scriptBytes, err := os.ReadFile("scripts/install-shellsentry.sh")
	if err != nil {
		t.Fatalf("read install script: %v", err)
	}
	// Normalize line endings so Windows checkouts (CRLF) match the harness.
	normalized := strings.ReplaceAll(string(scriptBytes), "\r\n", "\n")
	// Strip `main "$@"` so the harness can call main() with controlled argv.
	script := strings.TrimSuffix(normalized, "main \"$@\"\n")
	if script == normalized {
		script = strings.TrimSuffix(normalized, "main \"$@\"")
	}
	if script == normalized {
		t.Fatal("install script missing main invocation suffix")
	}

	scriptPath := filepath.Join(t.TempDir(), "install-shellsentry-lib.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write temp script: %v", err)
	}

	tests := []struct {
		name         string
		args         string
		wantExit     bool
		wantContains string
	}{
		{
			name:         "no --tag on Intel Mac fires the guard",
			args:         "",
			wantExit:     true,
			wantContains: "darwin/amd64 (Intel Mac) is no longer supported",
		},
		{
			name:         "--tag v0.1.4 on Intel Mac bypasses the guard",
			args:         "--tag v0.1.4",
			wantExit:     false,
			wantContains: "",
		},
		{
			name:         "--tag v0.1.0 on Intel Mac bypasses the guard",
			args:         "--tag v0.1.0",
			wantExit:     false,
			wantContains: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Stub uname to Darwin/x86_64; redefine err(); stub post-guard
			// helpers so a bypassed guard exits cleanly without network.
			harness := `
set -u
uname() {
	case "$1" in
		-s) printf 'Darwin\n' ;;
		-m) printf 'x86_64\n' ;;
		*) command uname "$@" ;;
	esac
}
source "$1"
err() {
	printf 'ERR: %s\n' "$*" >&2
	exit 42
}
check_verification_tools() { VERIFY_MINISIGN=true; VERIFY_GPG=false; }
fetch_json() { exit 0; }
main ` + tc.args + `
echo "GUARD_SKIPPED"
`
			cmd := exec.Command("bash", "-c", harness, "bash", scriptPath)
			cmd.Env = filteredEnv(os.Environ(), "PATH")
			cmd.Env = append(cmd.Env, "PATH=/usr/bin:/bin")

			out, _ := cmd.CombinedOutput()
			exitCode := cmd.ProcessState.ExitCode()

			if tc.wantExit {
				if exitCode != 42 {
					t.Fatalf("expected guard exit (42), got %d\noutput:\n%s", exitCode, out)
				}
				if !strings.Contains(string(out), tc.wantContains) {
					t.Errorf("output should contain %q, got:\n%s", tc.wantContains, out)
				}
			} else {
				if strings.Contains(string(out), "darwin/amd64 (Intel Mac) is no longer supported") {
					t.Errorf("guard fired unexpectedly on %q; output:\n%s", tc.args, out)
				}
				if exitCode != 0 {
					t.Fatalf("expected exit 0 after guard bypass, got %d\noutput:\n%s", exitCode, out)
				}
			}
		})
	}
}

func filteredEnv(env []string, dropKeys ...string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if ok && slices.Contains(dropKeys, key) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}
