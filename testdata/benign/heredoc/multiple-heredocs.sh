#!/bin/bash
# Test fixture: multiple heredocs in one script
# Purpose: Verify all heredoc regions are identified

# First heredoc
cat <<FIRST
# Content in first heredoc
Message one
FIRST

# Real comment between heredocs

# Second heredoc with different delimiter
cat <<SECOND
# Content in second heredoc
Message two
SECOND

# Heredoc in a function
print_help() {
    cat <<HELP
# Help header (heredoc content)
This is the help message.
# Help footer (heredoc content)
HELP
}

print_help
