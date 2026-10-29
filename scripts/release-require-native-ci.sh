#!/usr/bin/env bash
# Require a successful push CI run and native macOS job for the exact commit.
set -euo pipefail
commit="${1:?commit required}"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo 'error: invalid commit' >&2; exit 1; }
runs="$(gh run list --repo 3leaps/shellsentry --workflow ci.yml --commit "$commit" --event push --json databaseId,headSha,event,status,conclusion --limit 100)" || {
    echo 'error: cannot query CI runs' >&2; exit 1;
}
run="$(printf '%s' "$runs" | python3 -c 'import json,sys
sha=sys.argv[1]
runs=json.load(sys.stdin)
ids=[r["databaseId"] for r in runs if r.get("headSha")==sha and r.get("event")=="push" and r.get("status")=="completed" and r.get("conclusion")=="success"]
if not ids: sys.exit("error: no successful push CI for commit")
print(ids[0])' "$commit")" || exit 1
jobs="$(gh run view "$run" --repo 3leaps/shellsentry --json jobs)" || { echo 'error: cannot query CI jobs' >&2; exit 1; }
printf '%s' "$jobs" | python3 -c 'import json,sys
jobs=json.load(sys.stdin)["jobs"]
matched=[j for j in jobs if j.get("name")=="macOS bootstrap smoke (Makefile path)"]
if len(matched)!=1 or matched[0].get("status")!="completed" or matched[0].get("conclusion")!="success":
    sys.exit("error: native macOS CI job did not succeed")'
echo '[ok] native macOS CI passed for the tagged commit'
