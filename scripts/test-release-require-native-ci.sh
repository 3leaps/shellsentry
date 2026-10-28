#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
work="$(mktemp -d "${TMPDIR:-/tmp}/shs-ci.XXXXXX")"
trap 'rm -rf "$work"' EXIT
cat >"$work/gh" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
  'run list') cat "$FIXTURE_RUNS" ;;
  'run view') cat "$FIXTURE_JOBS" ;;
  *) exit 1 ;;
esac
SH
chmod +x "$work/gh"
export PATH="$work:$PATH" FIXTURE_RUNS="$work/runs" FIXTURE_JOBS="$work/jobs"
sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
printf '[{"databaseId":1,"headSha":"%s","event":"push","status":"completed","conclusion":"success"}]' "$sha" >"$FIXTURE_RUNS"
printf '{"jobs":[{"name":"macOS bootstrap smoke (Makefile path)","status":"completed","conclusion":"success"}]}' >"$FIXTURE_JOBS"
"$root/scripts/release-require-native-ci.sh" "$sha"
for mutant in wrong-sha pending failed missing-job failed-job; do
    cp "$FIXTURE_RUNS" "$work/runs.good"
    cp "$FIXTURE_JOBS" "$work/jobs.good"
    case "$mutant" in
        wrong-sha) sed 's/aaaaaaaa/bbbbbbbb/g' "$work/runs.good" >"$FIXTURE_RUNS" ;;
        pending) sed 's/completed/in_progress/' "$work/runs.good" >"$FIXTURE_RUNS" ;;
        failed) sed 's/success/failure/' "$work/runs.good" >"$FIXTURE_RUNS" ;;
        missing-job) printf '{"jobs":[]}' >"$FIXTURE_JOBS" ;;
        failed-job) sed 's/success/failure/' "$work/jobs.good" >"$FIXTURE_JOBS" ;;
    esac
    if "$root/scripts/release-require-native-ci.sh" "$sha" >/dev/null 2>&1; then
        echo "FAIL: native CI gate accepted $mutant" >&2; exit 1
    fi
    mv "$work/runs.good" "$FIXTURE_RUNS"
    mv "$work/jobs.good" "$FIXTURE_JOBS"
    echo "PASS: native CI gate rejects $mutant"
done
