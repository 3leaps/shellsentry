// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package selfupdate

import (
	"runtime"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{
			name:     "v1 less than v2",
			v1:       "1.0.0",
			v2:       "1.0.1",
			expected: -1,
		},
		{
			name:     "v1 greater than v2",
			v1:       "2.0.0",
			v2:       "1.9.9",
			expected: 1,
		},
		{
			name:     "equal versions",
			v1:       "1.0.0",
			v2:       "1.0.0",
			expected: 0,
		},
		{
			name:     "handles v prefix on first",
			v1:       "v1.0.0",
			v2:       "1.0.1",
			expected: -1,
		},
		{
			name:     "handles v prefix on second",
			v1:       "1.0.1",
			v2:       "v1.0.0",
			expected: 1,
		},
		{
			name:     "handles v prefix on both",
			v1:       "v1.0.0",
			v2:       "v1.0.0",
			expected: 0,
		},
		{
			name:     "major version difference",
			v1:       "1.5.3",
			v2:       "2.0.0",
			expected: -1,
		},
		{
			name:     "minor version difference",
			v1:       "1.1.0",
			v2:       "1.2.0",
			expected: -1,
		},
		{
			name:     "patch version difference",
			v1:       "1.0.1",
			v2:       "1.0.2",
			expected: -1,
		},
		{
			name:     "short version v1",
			v1:       "1.0",
			v2:       "1.0.1",
			expected: -1,
		},
		{
			name:     "short version v2",
			v1:       "1.0.1",
			v2:       "1.0",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compareVersions(tt.v1, tt.v2)
			if err != nil {
				t.Errorf("compareVersions(%q, %q) unexpected error: %v", tt.v1, tt.v2, err)
				return
			}
			if got != tt.expected {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.expected)
			}
		})
	}
}

func TestIsMajorJump(t *testing.T) {
	tests := []struct {
		name     string
		old      string
		new      string
		expected bool
	}{
		{
			name:     "major version jump 0 to 1",
			old:      "0.1.0",
			new:      "1.0.0",
			expected: true,
		},
		{
			name:     "minor version change",
			old:      "1.0.0",
			new:      "1.1.0",
			expected: false,
		},
		{
			name:     "patch version change",
			old:      "1.0.0",
			new:      "1.0.1",
			expected: false,
		},
		{
			name:     "major version jump 1 to 2",
			old:      "1.9.9",
			new:      "2.0.0",
			expected: true,
		},
		{
			name:     "same major version",
			old:      "1.0.0",
			new:      "1.0.0",
			expected: false,
		},
		{
			name:     "handles v prefix",
			old:      "v0.5.0",
			new:      "v1.0.0",
			expected: true,
		},
		{
			name:     "downgrade same major",
			old:      "1.5.0",
			new:      "1.4.0",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMajorJump(tt.old, tt.new)
			if got != tt.expected {
				t.Errorf("isMajorJump(%q, %q) = %v, want %v", tt.old, tt.new, got, tt.expected)
			}
		})
	}
}

func TestParseChecksumFor(t *testing.T) {
	tests := []struct {
		name          string
		checksums     string
		filename      string
		expected      string
		expectError   bool
		errorContains string
	}{
		{
			name:      "finds checksum in multi-line file",
			checksums: "abc123def456  myfile.tar.gz\nghijkl789012  other.zip",
			filename:  "myfile.tar.gz",
			expected:  "abc123def456",
		},
		{
			name:      "finds checksum for second file",
			checksums: "abc123def456  myfile.tar.gz\nghijkl789012  other.zip",
			filename:  "other.zip",
			expected:  "ghijkl789012",
		},
		{
			name:          "returns error when file not found",
			checksums:     "abc123def456  myfile.tar.gz\nghijkl789012  other.zip",
			filename:      "notfound.tar.gz",
			expectError:   true,
			errorContains: "checksum not found",
		},
		{
			name:      "handles empty lines",
			checksums: "\nabc123def456  myfile.tar.gz\n\nghijkl789012  other.zip\n\n",
			filename:  "other.zip",
			expected:  "ghijkl789012",
		},
		{
			name:      "handles whitespace",
			checksums: "  abc123def456  myfile.tar.gz  \n",
			filename:  "myfile.tar.gz",
			expected:  "abc123def456",
		},
		{
			name:          "empty checksums file",
			checksums:     "",
			filename:      "myfile.tar.gz",
			expectError:   true,
			errorContains: "checksum not found",
		},
		{
			name:      "sha512 length hash",
			checksums: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e  shellsentry_linux_amd64.tar.gz",
			filename:  "shellsentry_linux_amd64.tar.gz",
			expected:  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseChecksumFor([]byte(tt.checksums), tt.filename)
			if tt.expectError {
				if err == nil {
					t.Errorf("parseChecksumFor() expected error, got nil")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("parseChecksumFor() error = %q, want error containing %q", err.Error(), tt.errorContains)
				}
				return
			}
			if err != nil {
				t.Errorf("parseChecksumFor() unexpected error: %v", err)
				return
			}
			if got != tt.expected {
				t.Errorf("parseChecksumFor() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestComputeHash(t *testing.T) {
	testData := []byte("test data for hashing")

	// Known hashes for "test data for hashing"
	expectedSHA256 := "f7eb7961d8a233e6256d3a6257548bbb9293c3a08fb3574c88c7d6b429dbb9f5"
	expectedSHA512 := "1ef4f53766489878e6f1fccd8cac73101ca8ca3017d5c3f2d5042fc93793e90b35613b003728a76871a8b6abe96842ac68bcdb764eaaa8e1b2ba6d01d2e45ee3"

	tests := []struct {
		name         string
		checksumFile string
		useSHA512    bool
	}{
		{
			name:         "SHA512 from SHA2-512SUMS",
			checksumFile: "SHA2-512SUMS",
			useSHA512:    true,
		},
		{
			name:         "SHA512 from filename with 512",
			checksumFile: "checksums-512.txt",
			useSHA512:    true,
		},
		{
			name:         "SHA256 from SHA256SUMS",
			checksumFile: "SHA256SUMS",
			useSHA512:    false,
		},
		{
			name:         "SHA256 default",
			checksumFile: "checksums.txt",
			useSHA512:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeHash(testData, tt.checksumFile)

			// Verify hash length and value
			if tt.useSHA512 {
				if len(got) != 128 {
					t.Errorf("computeHash() for SHA512 returned hash of length %d, want 128", len(got))
				}
				if got != expectedSHA512 {
					t.Errorf("computeHash() SHA512 = %q, want %q", got, expectedSHA512)
				}
			} else {
				if len(got) != 64 {
					t.Errorf("computeHash() for SHA256 returned hash of length %d, want 64", len(got))
				}
				if got != expectedSHA256 {
					t.Errorf("computeHash() SHA256 = %q, want %q", got, expectedSHA256)
				}
			}

			// Verify determinism
			got2 := computeHash(testData, tt.checksumFile)
			if got != got2 {
				t.Errorf("computeHash() not deterministic: %q != %q", got, got2)
			}
		})
	}
}

func TestAssetName(t *testing.T) {
	got := assetName()

	// Verify it contains the platform info
	if !strings.Contains(got, runtime.GOOS) {
		t.Errorf("assetName() = %q, should contain GOOS %q", got, runtime.GOOS)
	}
	if !strings.Contains(got, runtime.GOARCH) {
		t.Errorf("assetName() = %q, should contain GOARCH %q", got, runtime.GOARCH)
	}

	// Verify correct extension
	if runtime.GOOS == "windows" {
		if !strings.HasSuffix(got, ".zip") {
			t.Errorf("assetName() on Windows = %q, should end with .zip", got)
		}
	} else {
		if !strings.HasSuffix(got, ".tar.gz") {
			t.Errorf("assetName() on non-Windows = %q, should end with .tar.gz", got)
		}
	}

	// Verify starts with shellsentry
	if !strings.HasPrefix(got, "shellsentry_") {
		t.Errorf("assetName() = %q, should start with shellsentry_", got)
	}
}

func TestChecksumCommand(t *testing.T) {
	tests := []struct {
		name     string
		hashAlgo string
	}{
		{
			name:     "sha512 algorithm",
			hashAlgo: "sha512",
		},
		{
			name:     "sha256 algorithm",
			hashAlgo: "sha256",
		},
		{
			name:     "empty defaults to sha256",
			hashAlgo: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checksumCommand(tt.hashAlgo)

			// Should always return a non-empty command
			if got == "" {
				t.Errorf("checksumCommand(%q) returned empty string", tt.hashAlgo)
			}

			// Should contain appropriate algorithm reference
			if tt.hashAlgo == "sha512" {
				if !strings.Contains(strings.ToLower(got), "512") {
					t.Errorf("checksumCommand(%q) = %q, should contain 512", tt.hashAlgo, got)
				}
			} else {
				if !strings.Contains(strings.ToLower(got), "256") {
					t.Errorf("checksumCommand(%q) = %q, should contain 256", tt.hashAlgo, got)
				}
			}

			// Should reference shellsentry
			if !strings.Contains(got, "shellsentry") {
				t.Errorf("checksumCommand(%q) = %q, should reference shellsentry", tt.hashAlgo, got)
			}
		})
	}
}

func TestFindAsset(t *testing.T) {
	assets := []GitHubAsset{
		{Name: "shellsentry_linux_amd64.tar.gz", BrowserDownloadURL: "https://example.com/linux"},
		{Name: "shellsentry_darwin_arm64.tar.gz", BrowserDownloadURL: "https://example.com/darwin"},
		{Name: "SHA256SUMS", BrowserDownloadURL: "https://example.com/sums"},
	}

	tests := []struct {
		name      string
		assetName string
		wantFound bool
		wantURL   string
	}{
		{
			name:      "finds existing asset",
			assetName: "SHA256SUMS",
			wantFound: true,
			wantURL:   "https://example.com/sums",
		},
		{
			name:      "finds platform asset",
			assetName: "shellsentry_darwin_arm64.tar.gz",
			wantFound: true,
			wantURL:   "https://example.com/darwin",
		},
		{
			name:      "returns nil for missing asset",
			assetName: "notfound.txt",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findAsset(assets, tt.assetName)
			if tt.wantFound {
				if got == nil {
					t.Errorf("findAsset() returned nil, want asset %q", tt.assetName)
					return
				}
				if got.BrowserDownloadURL != tt.wantURL {
					t.Errorf("findAsset() URL = %q, want %q", got.BrowserDownloadURL, tt.wantURL)
				}
			} else {
				if got != nil {
					t.Errorf("findAsset() = %+v, want nil", got)
				}
			}
		})
	}
}
