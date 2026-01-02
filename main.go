// shellsentry - Static risk assessment for shell scripts
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package main

import (
	_ "embed"
	"errors"
	"fmt"
	"os"

	"github.com/3leaps/shellsentry/internal/cli"
	"github.com/3leaps/shellsentry/internal/selfupdate"
)

// Build-time variables (injected via ldflags)
var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

// Embedded trust anchor (minisign public key)
//
//go:embed configs/keys/shellsentry-minisign.pub
var embeddedMinisignPubkey string

func main() {
	// Inject build info into CLI package
	cli.Version = version
	cli.BuildTime = buildTime
	cli.GitCommit = gitCommit

	// Inject embedded trust anchor into selfupdate package
	selfupdate.SetEmbeddedMinisignPubkey(embeddedMinisignPubkey)

	if err := cli.Execute(); err != nil {
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}

		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(4) // ExitError
	}
}
