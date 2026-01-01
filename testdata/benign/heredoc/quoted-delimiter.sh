#!/bin/bash
# Test fixture: quoted heredoc delimiter
# Purpose: Verify <<'EOF' and <<"EOF" preserve content literally

# Single-quoted delimiter (no variable expansion)
cat <<'LITERAL'
# Hash-prefixed content
$HOME is literal, not expanded
`command` is literal too
# More hash content
LITERAL

# Double-quoted delimiter (same behavior as unquoted for our purposes)
cat <<"QUOTED"
# This is also heredoc content
Variables like $PATH would expand here
# But this line still looks like a comment
QUOTED

echo "Delimiter quoting test complete"
