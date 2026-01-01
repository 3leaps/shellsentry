#!/bin/bash
# Test fixture: basic heredoc syntax
# Purpose: Verify heredoc content is preserved (not stripped as comments)

# This IS a comment and should be stripped
echo "Starting heredoc test"

cat <<EOF
# This line starts with hash but is heredoc content
# It should NOT be stripped by the comment stripper
Line without hash
# Another hash-prefixed line in heredoc
EOF

# This IS a comment (outside heredoc)
echo "Done"
