// Package output provides formatters for shellsentry analysis reports.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package output

import (
	"io"

	"github.com/3leaps/shellsentry/internal/types"
)

// Formatter formats a report for output.
type Formatter interface {
	Format(w io.Writer, report *types.Report) error
}
