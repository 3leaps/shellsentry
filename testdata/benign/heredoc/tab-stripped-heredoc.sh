#!/bin/bash
# Test fixture: tab-stripped heredoc (<<-)
# Purpose: Verify <<- syntax with indented content and delimiter

setup() {
	# This is a real comment
	cat <<-USAGE
		# This hash line is heredoc content
		Usage: command [options]
		  -h    Show help
		  -v    Verbose mode
		# End of usage text
	USAGE
}

setup
