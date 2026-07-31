#!/bin/sh
# version-matches-pin.sh VERSION_LINE PIN
#
# Exit 0 if VERSION_LINE contains a version token that exactly equals the
# normalized pin (leading "v" stripped from both). Substring matches are
# rejected (e.g. "0.4.90" does not satisfy pin "v0.4.9"). Empty pins never
# match. Portable /bin/sh.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: version-matches-pin.sh VERSION_LINE PIN" >&2
    exit 2
fi

line=$1
pin=$2

case "$pin" in
    v*) pin_nov=${pin#v} ;;
    *) pin_nov=$pin ;;
esac

# Empty pin must not match.
if [ -z "$pin_nov" ]; then
    exit 1
fi

# Disable pathname expansion so unquoted $line cannot expand globs against CWD
# (e.g. "sfetch *" with a file named like the pin must not fail-open).
set -f

# Walk whitespace-separated tokens; compare each version-like token exactly.
# A token is version-like if, after optional leading "v", it starts with a digit.
for word in $line; do
    case "$word" in
        v*) cand=${word#v} ;;
        *) cand=$word ;;
    esac
    case "$cand" in
        [0-9]*)
            if [ "$cand" = "$pin_nov" ]; then
                exit 0
            fi
            ;;
    esac
done

exit 1
