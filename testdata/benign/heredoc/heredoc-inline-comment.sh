#!/bin/bash
# Test fixture: heredoc opener with inline comment
# Purpose: Verify inline comment on heredoc line IS stripped, but content is not

# The inline comment after <<EOF should be stripped
cat <<EOF  # this is a real inline comment
# This hash line is inside the heredoc
Content line
# Another heredoc line with hash
EOF

# Redirect with heredoc and inline comment
cat >&2 <<-MESSAGE  # redirect to stderr
	# Error message header
	Something went wrong
	# Error message footer
MESSAGE

echo "Inline comment test complete"
