#!/bin/bash
# Test fixture: heredoc in subshell and command substitution
# Purpose: Verify nested heredoc detection

# Heredoc in command substitution
MESSAGE=$(cat <<INNER
# Hash line in command substitution heredoc
Captured message
# Another hash line
INNER
)

echo "$MESSAGE"

# Heredoc in subshell
(
    cat <<SUBSHELL
# Hash line in subshell heredoc
Subshell output
# Footer
SUBSHELL
)

# Heredoc assigned via process substitution pattern
while read -r line; do
    echo "Read: $line"
done <<WHILE
# First item
# Second item
# Third item
WHILE
