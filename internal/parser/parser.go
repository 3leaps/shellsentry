// Package parser provides shell script parsing using mvdan/sh.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package parser

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func uintToInt(u uint) int {
	if u > uint(math.MaxInt) {
		return math.MaxInt
	}
	return int(u)
}

func posLine(p syntax.Pos) int {
	return uintToInt(p.Line())
}

func posCol(p syntax.Pos) int {
	return uintToInt(p.Col())
}

// Result contains the parsed AST and any errors encountered.
type Result struct {
	// File is the parsed AST (nil if parsing failed completely).
	File *syntax.File

	// Errors contains any parse errors encountered.
	// Scripts may still have a partial AST even with errors.
	Errors []ParseError

	// Dialect is the detected or specified shell dialect.
	Dialect Dialect
}

// ParseError represents a parsing error with location information.
type ParseError struct {
	Line    int
	Column  int
	Message string
}

// Dialect represents a shell dialect.
type Dialect int

const (
	// DialectAuto attempts to detect the dialect from shebang.
	DialectAuto Dialect = iota
	// DialectBash is GNU Bash.
	DialectBash
	// DialectPOSIX is POSIX sh.
	DialectPOSIX
	// DialectMirBSDKorn is MirBSD Korn shell.
	DialectMirBSDKorn
	// DialectBats is Bash Automated Testing System.
	DialectBats
)

// Options configures the parser behavior.
type Options struct {
	// Dialect specifies the shell dialect. Default is DialectAuto.
	Dialect Dialect

	// KeepComments preserves comments in the AST.
	KeepComments bool
}

// DefaultOptions returns default parser options.
func DefaultOptions() Options {
	return Options{
		Dialect:      DialectAuto,
		KeepComments: true,
	}
}

// Parse parses shell script content and returns the AST.
func Parse(content []byte, filename string, opts Options) (*Result, error) {
	reader := bytes.NewReader(content)
	return ParseReader(reader, filename, opts)
}

// ParseReader parses shell script content from a reader.
func ParseReader(r io.Reader, filename string, opts Options) (*Result, error) {
	result := &Result{
		Dialect: opts.Dialect,
	}

	// Configure parser options
	parserOpts := []syntax.ParserOption{
		syntax.KeepComments(opts.KeepComments),
	}

	// Set dialect variant
	switch opts.Dialect {
	case DialectBash:
		parserOpts = append(parserOpts, syntax.Variant(syntax.LangBash))
	case DialectPOSIX:
		parserOpts = append(parserOpts, syntax.Variant(syntax.LangPOSIX))
	case DialectMirBSDKorn:
		parserOpts = append(parserOpts, syntax.Variant(syntax.LangMirBSDKorn))
	case DialectBats:
		parserOpts = append(parserOpts, syntax.Variant(syntax.LangBats))
	default:
		// Auto-detect from shebang - use Bash as fallback (most permissive)
		parserOpts = append(parserOpts, syntax.Variant(syntax.LangBash))
	}

	parser := syntax.NewParser(parserOpts...)

	file, err := parser.Parse(r, filename)
	if err != nil {
		// Try to extract structured error information
		if parseErr, ok := err.(syntax.ParseError); ok {
			result.Errors = append(result.Errors, ParseError{
				Line:    posLine(parseErr.Pos),
				Column:  posCol(parseErr.Pos),
				Message: parseErr.Text,
			})
		} else {
			result.Errors = append(result.Errors, ParseError{
				Line:    1,
				Column:  1,
				Message: err.Error(),
			})
		}
		// Parser may still have returned a partial AST
		result.File = file
		return result, err
	}

	result.File = file
	return result, nil
}

// DetectDialect attempts to detect the shell dialect from a shebang line.
func DetectDialect(content []byte) Dialect {
	// Look for shebang on first line
	idx := bytes.IndexByte(content, '\n')
	var firstLine []byte
	if idx >= 0 {
		firstLine = content[:idx]
	} else {
		firstLine = content
	}

	line := string(firstLine)
	if !strings.HasPrefix(line, "#!") {
		return DialectAuto
	}

	// Extract interpreter path
	shebang := strings.TrimPrefix(line, "#!")
	shebang = strings.TrimSpace(shebang)

	// Handle "#!/usr/bin/env bash" style
	if strings.HasPrefix(shebang, "/usr/bin/env ") {
		shebang = strings.TrimPrefix(shebang, "/usr/bin/env ")
		shebang = strings.Fields(shebang)[0]
	} else {
		// Extract basename from path
		parts := strings.Split(shebang, "/")
		shebang = parts[len(parts)-1]
		// Remove any arguments
		shebang = strings.Fields(shebang)[0]
	}

	switch shebang {
	case "bash":
		return DialectBash
	case "sh", "dash":
		return DialectPOSIX
	case "ksh", "mksh":
		return DialectMirBSDKorn
	case "bats":
		return DialectBats
	default:
		return DialectAuto
	}
}

// WalkFunc is called for each node during AST traversal.
type WalkFunc func(node syntax.Node) bool

// Walk traverses the AST in depth-first order.
// If walkFn returns false, children of the current node are not visited.
func Walk(file *syntax.File, walkFn WalkFunc) {
	if file == nil {
		return
	}

	syntax.Walk(file, func(node syntax.Node) bool {
		return walkFn(node)
	})
}

// FindCommands extracts all command calls from the AST.
func FindCommands(file *syntax.File) []*Command {
	if file == nil {
		return nil
	}

	var commands []*Command

	syntax.Walk(file, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok {
			cmd := extractCommand(call)
			if cmd != nil {
				commands = append(commands, cmd)
			}
		}
		return true
	})

	return commands
}

// Command represents an extracted command call.
type Command struct {
	// Name is the command name (first word).
	Name string

	// Args are the command arguments.
	Args []string

	// Line is the line number where the command starts.
	Line int

	// Column is the column where the command starts.
	Column int

	// InPipeline indicates if this command is part of a pipeline.
	InPipeline bool

	// PipelinePosition is the position in the pipeline (0-indexed).
	PipelinePosition int

	// IsBackgrounded indicates if the command runs in background (&).
	IsBackgrounded bool

	// Node is the underlying syntax node.
	Node *syntax.CallExpr
}

// extractCommand extracts command information from a CallExpr.
func extractCommand(call *syntax.CallExpr) *Command {
	if len(call.Args) == 0 {
		return nil
	}

	// Get command name from first word
	firstArg := call.Args[0]
	name := wordToString(firstArg)
	if name == "" {
		return nil
	}

	cmd := &Command{
		Name:   name,
		Line:   posLine(call.Pos()),
		Column: posCol(call.Pos()),
		Node:   call,
	}

	// Extract arguments
	for i := 1; i < len(call.Args); i++ {
		arg := wordToString(call.Args[i])
		cmd.Args = append(cmd.Args, arg)
	}

	return cmd
}

// wordToString converts a syntax.Word to a string.
// Returns empty string if the word contains complex expansions.
func wordToString(word *syntax.Word) string {
	if word == nil || len(word.Parts) == 0 {
		return ""
	}

	var result strings.Builder
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			result.WriteString(p.Value)
		case *syntax.SglQuoted:
			result.WriteString(p.Value)
		case *syntax.DblQuoted:
			// For double quotes, try to extract literal content
			for _, qpart := range p.Parts {
				if lit, ok := qpart.(*syntax.Lit); ok {
					result.WriteString(lit.Value)
				} else {
					// Contains variable expansion or other complexity
					result.WriteString("$")
				}
			}
		default:
			// Complex expansion - mark it
			result.WriteString("$")
		}
	}

	return result.String()
}

// FindPipelines extracts all pipelines from the AST.
func FindPipelines(file *syntax.File) []*Pipeline {
	if file == nil {
		return nil
	}

	var pipelines []*Pipeline

	syntax.Walk(file, func(node syntax.Node) bool {
		if bin, ok := node.(*syntax.BinaryCmd); ok && bin.Op == syntax.Pipe {
			pipeline := extractPipeline(bin)
			if pipeline != nil {
				pipelines = append(pipelines, pipeline)
			}
			return false // Don't descend into pipeline components
		}
		return true
	})

	return pipelines
}

// Pipeline represents a shell pipeline (cmd1 | cmd2 | ...).
type Pipeline struct {
	// Commands in the pipeline, in order.
	Commands []*Command

	// Line is the line number where the pipeline starts.
	Line int

	// Column is the column where the pipeline starts.
	Column int
}

// extractPipeline recursively extracts commands from a pipeline.
func extractPipeline(bin *syntax.BinaryCmd) *Pipeline {
	if bin.Op != syntax.Pipe {
		return nil
	}

	pipeline := &Pipeline{
		Line:   posLine(bin.Pos()),
		Column: posCol(bin.Pos()),
	}

	// Recursively extract left side
	extractPipelineCommands(bin, pipeline)

	// Set pipeline position for each command
	for i, cmd := range pipeline.Commands {
		cmd.InPipeline = true
		cmd.PipelinePosition = i
	}

	return pipeline
}

// extractPipelineCommands recursively extracts commands from pipeline nodes.
func extractPipelineCommands(node syntax.Node, pipeline *Pipeline) {
	switch n := node.(type) {
	case *syntax.BinaryCmd:
		if n.Op == syntax.Pipe {
			extractPipelineCommands(n.X, pipeline)
			extractPipelineCommands(n.Y, pipeline)
		}
	case *syntax.Stmt:
		extractPipelineCommands(n.Cmd, pipeline)
	case *syntax.CallExpr:
		cmd := extractCommand(n)
		if cmd != nil {
			pipeline.Commands = append(pipeline.Commands, cmd)
		}
	case *syntax.Subshell:
		// Subshell in pipeline - note but don't extract inner commands
		pipeline.Commands = append(pipeline.Commands, &Command{
			Name:   "(subshell)",
			Line:   posLine(n.Pos()),
			Column: posCol(n.Pos()),
		})
	}
}

// String returns a human-readable representation of the command.
func (c *Command) String() string {
	if len(c.Args) == 0 {
		return c.Name
	}
	return fmt.Sprintf("%s %s", c.Name, strings.Join(c.Args, " "))
}

// StringRegion represents a quoted string literal in the script.
type StringRegion struct {
	StartLine   int
	StartColumn int
	EndLine     int
	EndColumn   int
}

// Contains checks if a position falls within this string region.
func (r *StringRegion) Contains(line, column int) bool {
	// Before start
	if line < r.StartLine || (line == r.StartLine && column < r.StartColumn) {
		return false
	}
	// After end
	if line > r.EndLine || (line == r.EndLine && column > r.EndColumn) {
		return false
	}
	return true
}

// Assignment represents a variable assignment in the script.
type Assignment struct {
	// Name is the variable name.
	Name string

	// Value is the raw assigned value as a string.
	Value string

	// Line is the line number where the assignment occurs.
	Line int

	// Column is the column where the assignment starts.
	Column int
}

// FindAssignments extracts all variable assignments from the AST.
func FindAssignments(file *syntax.File) []Assignment {
	if file == nil {
		return nil
	}

	var assignments []Assignment

	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Assign:
			if n.Name != nil && n.Value != nil {
				assignments = append(assignments, Assignment{
					Name:   n.Name.Value,
					Value:  wordToString(n.Value),
					Line:   posLine(n.Pos()),
					Column: posCol(n.Pos()),
				})
			}
		}
		return true
	})

	return assignments
}

// VariableExecution represents a bare variable used as a command.
type VariableExecution struct {
	// VarName is the variable being executed.
	VarName string

	// Line is the line number.
	Line int

	// Column is the column.
	Column int
}

// FindVariableExecutions finds bare variable executions like `$cmd`.
func FindVariableExecutions(file *syntax.File) []VariableExecution {
	if file == nil {
		return nil
	}

	var executions []VariableExecution

	syntax.Walk(file, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			first := call.Args[0]
			// Check if first arg is a bare variable expansion
			if len(first.Parts) == 1 {
				if pe, ok := first.Parts[0].(*syntax.ParamExp); ok {
					// This is $var being used as a command
					executions = append(executions, VariableExecution{
						VarName: pe.Param.Value,
						Line:    posLine(call.Pos()),
						Column:  posCol(call.Pos()),
					})
				}
			}
		}
		return true
	})

	return executions
}

// FindStringLiterals extracts all quoted string regions from the AST.
// This includes both single-quoted and double-quoted strings.
func FindStringLiterals(file *syntax.File) []StringRegion {
	if file == nil {
		return nil
	}

	var regions []StringRegion

	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.SglQuoted:
			regions = append(regions, StringRegion{
				StartLine:   posLine(n.Pos()),
				StartColumn: posCol(n.Pos()),
				EndLine:     posLine(n.End()),
				EndColumn:   posCol(n.End()),
			})
		case *syntax.DblQuoted:
			regions = append(regions, StringRegion{
				StartLine:   posLine(n.Pos()),
				StartColumn: posCol(n.Pos()),
				EndLine:     posLine(n.End()),
				EndColumn:   posCol(n.End()),
			})
		}
		return true
	})

	return regions
}

// HeredocRegion represents the body region of a heredoc.
// The region covers only the heredoc body lines (not the introducer line).
type HeredocRegion struct {
	StartLine int
	EndLine   int
}

// FindHeredocs finds heredoc body regions in the AST.
//
// Note: The returned regions are best-effort and depend on successful parsing.
func FindHeredocs(file *syntax.File) []HeredocRegion {
	if file == nil {
		return nil
	}

	var regions []HeredocRegion

	syntax.Walk(file, func(node syntax.Node) bool {
		redir, ok := node.(*syntax.Redirect)
		if !ok || redir.Hdoc == nil {
			return true
		}

		start := posLine(redir.Hdoc.Pos())
		end := posLine(redir.Hdoc.End())
		if start == 0 || end == 0 {
			return true
		}
		if end < start {
			start, end = end, start
		}

		regions = append(regions, HeredocRegion{
			StartLine: start,
			EndLine:   end,
		})

		return true
	})

	return regions
}
