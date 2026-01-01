// shellsentry - Static risk assessment for shell scripts
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/3leaps/shellsentry/internal/cli"
)

// Build-time variables (injected via ldflags)
var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

func main() {
	// Inject build info into CLI package
	cli.Version = version
	cli.BuildTime = buildTime
	cli.GitCommit = gitCommit

	if err := cli.Execute(); err != nil {
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}

		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(4) // ExitError
	}
}
