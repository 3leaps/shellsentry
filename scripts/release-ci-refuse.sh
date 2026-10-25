#!/usr/bin/env bash
# Shared guard: maintainer signing/publish scripts never run under GitHub Actions.
# Tests unset GITHUB_ACTIONS when they exercise the scripts in a fixture.
if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "error: maintainer-only; refuse GitHub Actions" >&2
    exit 1
fi
