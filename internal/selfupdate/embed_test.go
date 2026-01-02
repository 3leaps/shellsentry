// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package selfupdate

import "testing"

func TestEmbeddedMinisignPubkey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "extracts base64 key line",
			input:    "untrusted comment: minisign public key DE44B5D37442A1C0\nRWTdRLXTdEKhwFNzVN2VGxfIb5djqGpY3x9eVIwPfKCqVlPqKfIZVFEL",
			expected: "RWTdRLXTdEKhwFNzVN2VGxfIb5djqGpY3x9eVIwPfKCqVlPqKfIZVFEL",
		},
		{
			name:     "returns empty string when not set",
			input:    "",
			expected: "",
		},
		{
			name:     "skips empty lines",
			input:    "\n\nuntrusted comment: test key 12345\n\nABC123DEF456GHI789\n",
			expected: "ABC123DEF456GHI789",
		},
		{
			name:     "handles whitespace around key",
			input:    "untrusted comment: test\n  KEYDATA123  \n",
			expected: "KEYDATA123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore original value
			original := embeddedMinisignPubkeyRaw
			defer func() { embeddedMinisignPubkeyRaw = original }()

			SetEmbeddedMinisignPubkey(tt.input)
			got := EmbeddedMinisignPubkey()

			if got != tt.expected {
				t.Errorf("EmbeddedMinisignPubkey() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestEmbeddedMinisignKeyID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "extracts key ID from standard comment",
			input:    "untrusted comment: minisign public key DE44B5D37442A1C0\nRWTdRLXTdEKhwFNzVN2VGxfIb5djqGpY3x9eVIwPfKCqVlPqKfIZVFEL",
			expected: "DE44B5D37442A1C0",
		},
		{
			name:     "returns empty string when no comment present",
			input:    "RWTdRLXTdEKhwFNzVN2VGxfIb5djqGpY3x9eVIwPfKCqVlPqKfIZVFEL",
			expected: "",
		},
		{
			name:     "returns empty string when not set",
			input:    "",
			expected: "",
		},
		{
			name:     "returns empty string when comment too short",
			input:    "untrusted comment: short\nKEYDATA",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore original value
			original := embeddedMinisignPubkeyRaw
			defer func() { embeddedMinisignPubkeyRaw = original }()

			SetEmbeddedMinisignPubkey(tt.input)
			got := EmbeddedMinisignKeyID()

			if got != tt.expected {
				t.Errorf("EmbeddedMinisignKeyID() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestSetEmbeddedMinisignPubkey(t *testing.T) {
	// Save and restore original value
	original := embeddedMinisignPubkeyRaw
	defer func() { embeddedMinisignPubkeyRaw = original }()

	testValue := "test-pubkey-value"
	SetEmbeddedMinisignPubkey(testValue)

	if embeddedMinisignPubkeyRaw != testValue {
		t.Errorf("SetEmbeddedMinisignPubkey() did not set value correctly, got %q, want %q",
			embeddedMinisignPubkeyRaw, testValue)
	}
}
