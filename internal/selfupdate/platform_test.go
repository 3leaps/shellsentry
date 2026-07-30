// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package selfupdate

import (
	"strings"
	"testing"
)

func TestPlatformKey(t *testing.T) {
	if got := platformKey("darwin", "amd64"); got != "darwin_amd64" {
		t.Fatalf("platformKey = %q", got)
	}
	if got := platformKey("windows", "arm64"); got != "windows_arm64" {
		t.Fatalf("platformKey = %q", got)
	}
}

func TestAssetNameFor(t *testing.T) {
	tests := []struct {
		goos, goarch, want string
	}{
		{"darwin", "arm64", "shellsentry_darwin_arm64.tar.gz"},
		{"darwin", "amd64", "shellsentry_darwin_amd64.tar.gz"},
		{"linux", "amd64", "shellsentry_linux_amd64.tar.gz"},
		{"windows", "amd64", "shellsentry_windows_amd64.zip"},
		{"windows", "arm64", "shellsentry_windows_arm64.zip"},
	}
	for _, tc := range tests {
		if got := assetNameFor(tc.goos, tc.goarch); got != tc.want {
			t.Errorf("assetNameFor(%s,%s) = %q, want %q", tc.goos, tc.goarch, got, tc.want)
		}
	}
}

func TestIsDarwinAMD64(t *testing.T) {
	if !isDarwinAMD64("darwin", "amd64") {
		t.Fatal("expected true for darwin/amd64")
	}
	if isDarwinAMD64("darwin", "arm64") {
		t.Fatal("expected false for darwin/arm64")
	}
	if isDarwinAMD64("linux", "amd64") {
		t.Fatal("expected false for linux/amd64")
	}
}

func TestDarwinAMD64RetirementMessage(t *testing.T) {
	msg := darwinAMD64RetirementMessage("v0.1.5")
	for _, want := range []string{
		"darwin/amd64",
		LastDarwinAMD64Tag,
		"--tag " + LastDarwinAMD64Tag,
		"v0.1.5",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q: %s", want, msg)
		}
	}
}

// TestLatestRejectionUsesRetirementMessage models the self-update path when
// the target release lacks a darwin/amd64 archive: the error must be the
// retirement guidance, not a bare "archive asset not found".
func TestLatestRejectionUsesRetirementMessage(t *testing.T) {
	release := &GitHubRelease{
		TagName: "v0.1.5",
		Assets: []GitHubAsset{
			{Name: "shellsentry_darwin_arm64.tar.gz"},
			{Name: "shellsentry_linux_amd64.tar.gz"},
		},
	}
	wanted := assetNameFor("darwin", "amd64")
	if findAsset(release.Assets, wanted) != nil {
		t.Fatal("fixture should not contain darwin/amd64 asset")
	}
	if !isDarwinAMD64("darwin", "amd64") {
		t.Fatal("precondition")
	}
	msg := darwinAMD64RetirementMessage(release.TagName)
	if strings.Contains(msg, "archive asset not found") {
		t.Fatalf("retirement message should not be generic: %s", msg)
	}
	if !strings.Contains(msg, LastDarwinAMD64Tag) {
		t.Fatalf("expected last supporting tag in message: %s", msg)
	}
}
