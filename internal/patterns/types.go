// Package patterns provides pattern matching for shell script analysis.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package patterns

import (
	"bytes"
	"regexp"

	"github.com/3leaps/shellsentry/internal/types"
)

// Pattern defines a detection rule.
type Pattern struct {
	// ID is the unique identifier (e.g., "SS001").
	ID string `yaml:"id"`

	// Name is a short name for the pattern.
	Name string `yaml:"name"`

	// Severity is the risk level.
	Severity types.Severity `yaml:"severity"`

	// Category classifies the type of risk.
	Category types.Category `yaml:"category"`

	// Description explains what this pattern detects.
	Description string `yaml:"description"`

	// Patterns contains the regex patterns to match.
	Patterns []PatternMatch `yaml:"patterns"`

	// Message is the human-readable finding message.
	Message string `yaml:"message"`

	// Detail provides extended explanation.
	Detail string `yaml:"detail"`

	// Recommendation suggests remediation.
	Recommendation string `yaml:"recommendation"`

	// compiled holds compiled regex patterns (not serialized).
	compiled []*regexp.Regexp
}

// PatternMatch defines a single regex pattern.
type PatternMatch struct {
	// Regex is the regular expression to match.
	Regex string `yaml:"regex"`

	// Flags are optional regex flags (not currently used).
	Flags string `yaml:"flags,omitempty"`
}

// Compile compiles all regex patterns. Returns error if any fail.
func (p *Pattern) Compile() error {
	p.compiled = make([]*regexp.Regexp, 0, len(p.Patterns))
	for _, pm := range p.Patterns {
		re, err := regexp.Compile(pm.Regex)
		if err != nil {
			return err
		}
		p.compiled = append(p.compiled, re)
	}
	return nil
}

// Match checks if content matches any of the pattern's regexes.
// Returns all matches with their positions.
func (p *Pattern) Match(content []byte) []Match {
	var matches []Match

	for _, re := range p.compiled {
		locs := re.FindAllIndex(content, -1)
		for _, loc := range locs {
			line, col := positionToLineCol(content, loc[0])
			endLine, endCol := positionToLineCol(content, loc[1])

			matches = append(matches, Match{
				Pattern:   p,
				Start:     loc[0],
				End:       loc[1],
				Line:      line,
				Column:    col,
				EndLine:   endLine,
				EndColumn: endCol,
				Code:      string(content[loc[0]:loc[1]]),
			})
		}
	}

	return matches
}

// Match represents a pattern match in the content.
type Match struct {
	Pattern   *Pattern
	Start     int
	End       int
	Line      int
	Column    int
	EndLine   int
	EndColumn int
	Code      string
}

// ToFinding converts a match to a Finding.
func (m *Match) ToFinding() types.Finding {
	return types.Finding{
		ID:             m.Pattern.ID,
		Severity:       m.Pattern.Severity,
		Category:       m.Pattern.Category,
		Line:           m.Line,
		Column:         m.Column,
		EndLine:        m.EndLine,
		EndColumn:      m.EndColumn,
		Code:           truncateCode(m.Code, 100),
		Message:        m.Pattern.Message,
		Detail:         m.Pattern.Detail,
		Recommendation: m.Pattern.Recommendation,
	}
}

// positionToLineCol converts byte offset to 1-based line and column.
func positionToLineCol(content []byte, pos int) (line, col int) {
	line = 1
	col = 1
	for i := 0; i < pos && i < len(content); i++ {
		if content[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

// truncateCode limits code snippet length.
func truncateCode(code string, maxLen int) string {
	if len(code) <= maxLen {
		return code
	}
	return code[:maxLen-3] + "..."
}

// LineRange represents a 1-based inclusive line range.
type LineRange struct {
	StartLine int
	EndLine   int
}

// PatternSet is a collection of patterns.
type PatternSet struct {
	Patterns []*Pattern
}

// NewPatternSet creates an empty pattern set.
func NewPatternSet() *PatternSet {
	return &PatternSet{
		Patterns: []*Pattern{},
	}
}

// Add adds a pattern to the set.
func (ps *PatternSet) Add(p *Pattern) error {
	if err := p.Compile(); err != nil {
		return err
	}
	ps.Patterns = append(ps.Patterns, p)
	return nil
}

// MatchAll runs all patterns against content and returns matches.
// Full-line comments (lines starting with #) are excluded from matching
// to reduce false positives from documentation text.
func (ps *PatternSet) MatchAll(content []byte) []Match {
	return ps.MatchAllWithProtectedLines(content, nil)
}

// MatchAllWithProtectedLines runs all patterns against content and returns matches.
// Lines inside any protected range are excluded from comment stripping.
func (ps *PatternSet) MatchAllWithProtectedLines(content []byte, protected []LineRange) []Match {
	filtered := stripCommentsWithProtectedLines(content, protected)

	var matches []Match
	for _, p := range ps.Patterns {
		matches = append(matches, p.Match(filtered)...)
	}
	return matches
}

// stripComments replaces comments with spaces to preserve byte positions.
// Handles both full-line comments and inline comments.
//
// Full-line comment: line where first non-whitespace is #
// Inline comment: # that appears outside of quotes
//
// Known limitations:
// - Does not handle $'...' ANSI-C quoting
// - Escaped quotes inside same-type quotes may confuse the parser
func stripComments(content []byte) []byte {
	return stripCommentsWithProtectedLines(content, nil)
}

func stripCommentsWithProtectedLines(content []byte, protected []LineRange) []byte {
	lines := bytes.Split(content, []byte("\n"))
	result := make([][]byte, len(lines))

	protectedLines := make(map[int]struct{})
	for _, r := range protected {
		start := r.StartLine
		end := r.EndLine
		if start <= 0 || end <= 0 {
			continue
		}
		if end < start {
			start, end = end, start
		}
		for line := start; line <= end; line++ {
			protectedLines[line] = struct{}{}
		}
	}

	for i, line := range lines {
		lineNum := i + 1
		if _, ok := protectedLines[lineNum]; ok {
			result[i] = line
			continue
		}
		result[i] = stripLineComments(line)
	}

	return bytes.Join(result, []byte("\n"))
}

// stripLineComments removes comments from a single line.
// Returns the line with comment portions replaced by spaces.
func stripLineComments(line []byte) []byte {
	// Quick check: if no #, nothing to do
	if !bytes.Contains(line, []byte("#")) {
		return line
	}

	// Check for full-line comment first (optimization)
	trimmed := bytes.TrimLeft(line, " \t")
	if len(trimmed) > 0 && trimmed[0] == '#' {
		return bytes.Repeat([]byte(" "), len(line))
	}

	// Scan for inline comment
	result := make([]byte, len(line))
	copy(result, line)

	inSingle := false
	inDouble := false
	braceDepth := 0 // Track ${...} nesting
	i := 0

	for i < len(line) {
		c := line[i]

		// Handle escape sequences (only outside single quotes)
		if c == '\\' && !inSingle && i+1 < len(line) {
			// Skip escaped character
			i += 2
			continue
		}

		// Track quote state
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			i++
			continue
		}

		if c == '"' && !inSingle {
			inDouble = !inDouble
			i++
			continue
		}

		// Track ${...} parameter expansion (can contain #)
		if c == '$' && i+1 < len(line) && line[i+1] == '{' && !inSingle {
			braceDepth++
			i += 2
			continue
		}

		if c == '}' && braceDepth > 0 && !inSingle {
			braceDepth--
			i++
			continue
		}

		// Found comment start outside quotes and outside ${...}
		if c == '#' && !inSingle && !inDouble && braceDepth == 0 {
			// Replace from here to end of line with spaces
			for j := i; j < len(result); j++ {
				result[j] = ' '
			}
			break
		}

		i++
	}

	return result
}
