package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_GeneratesChecksums(t *testing.T) {
	dir := t.TempDir()

	artifacts := []string{
		"shellsentry_linux_amd64.tar.gz",
		"shellsentry_darwin_arm64.tar.gz",
		"install-shellsentry.sh",
	}
	for _, name := range artifacts {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("write artifact: %v", err)
		}
	}

	if err := run(dir, "sha256,sha512"); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	sha256Path := filepath.Join(dir, "SHA256SUMS")
	sha512Path := filepath.Join(dir, "SHA2-512SUMS")
	if _, err := os.Stat(sha256Path); err != nil {
		t.Fatalf("SHA256SUMS not created: %v", err)
	}
	if _, err := os.Stat(sha512Path); err != nil {
		t.Fatalf("SHA2-512SUMS not created: %v", err)
	}

	content, err := os.ReadFile(sha256Path)
	if err != nil {
		t.Fatalf("read SHA256SUMS: %v", err)
	}
	for _, name := range artifacts {
		if !strings.Contains(string(content), name) {
			t.Fatalf("SHA256SUMS missing %s", name)
		}
	}
}
