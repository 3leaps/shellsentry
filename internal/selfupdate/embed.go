// Package selfupdate provides self-verification and self-update capabilities.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package selfupdate

import (
	"strings"
)

// Embedded trust anchor set by main package
var embeddedMinisignPubkeyRaw string

// SetEmbeddedMinisignPubkey sets the embedded minisign public key from the main package.
// This must be called before using any selfupdate functions.
func SetEmbeddedMinisignPubkey(pubkey string) {
	embeddedMinisignPubkeyRaw = pubkey
}

// EmbeddedMinisignPubkey returns the minisign public key embedded at build time.
func EmbeddedMinisignPubkey() string {
	lines := strings.Split(strings.TrimSpace(embeddedMinisignPubkeyRaw), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "untrusted comment:") {
			continue
		}
		return line
	}
	return ""
}

// EmbeddedMinisignKeyID returns the key ID from the embedded public key comment.
func EmbeddedMinisignKeyID() string {
	lines := strings.Split(embeddedMinisignPubkeyRaw, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "untrusted comment:") {
			// Extract key ID from comment like "untrusted comment: minisign public key DE44B5D37442A1C0"
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				return parts[len(parts)-1]
			}
		}
	}
	return ""
}
