// Package output provides formatters for shellsentry analysis reports.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package output

import (
	"encoding/json"
	"io"

	"github.com/3leaps/shellsentry/internal/types"
)

// JSONFormatter formats reports as JSON.
type JSONFormatter struct {
	Indent bool
}

// NewJSONFormatter creates a new JSON formatter.
func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{Indent: true}
}

// Format writes a JSON report.
func (f *JSONFormatter) Format(w io.Writer, report *types.Report) error {
	encoder := json.NewEncoder(w)
	if f.Indent {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(report)
}
