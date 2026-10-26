#!/usr/bin/env python3
"""Live checks for native-platform CI and tag-build jobs.

Mutants in test-release-ci-hygiene.sh and test-release-workflow-draft.py must
call these functions rather than a copied regex. Skip/soft-fail is refused
except for two named exemptions, each exactly once, with an exact run body:

- continue-on-error on "sfetch pin freshness (informational soft-warn only)"
  in the linux/amd64 CI job, run: make check-sfetch-pin-freshness
- if: matrix.goos == 'linux' && matrix.goarch == 'amd64' on "License check"
  in the tag build job, run: the pinned go-licenses block
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ZIP_SCRIPT = ROOT / "scripts" / "package-windows-zip.sh"

FLOATING_LABEL_RE = re.compile(
    r"(?m)^\s+(?:runs-on|runner):\s*(ubuntu-latest|macos-latest|windows-latest)\s*$"
)
SETUP_PYTHON_RE = re.compile(
    r"uses:\s*actions/setup-python@([0-9a-f]{40})\s+#\s*(\S+)"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"v[0-9]")
OR_TRUE_RE = re.compile(r"\|\|\s*(?:true\b|:)")
EXIT_ZERO_RE = re.compile(r"(?m)\bexit\s+0\b")

CI_JOBS = {
    "test": ("ubuntu-24.04", "linux/amd64"),
    "test-linux-arm64": ("ubuntu-latest-arm64-s", "linux/arm64"),
    "macos-bootstrap-smoke": ("macos-15", "darwin/arm64"),
    "windows-dogfood-x64": ("windows-2022", "windows/amd64"),
    "windows-dogfood-arm64": ("windows-latest-arm64-s", "windows/arm64"),
}
WINDOWS_CI_JOBS = ("windows-dogfood-x64", "windows-dogfood-arm64")
RELEASE_BUILD_JOB = "build"
WINDOWS_ZIP_RUN = "./scripts/package-windows-zip.sh"

FRESHNESS_STEP = "sfetch pin freshness (informational soft-warn only)"
FRESHNESS_RUN = "make check-sfetch-pin-freshness"
LICENSE_STEP = "License check"
LICENSE_IF = "matrix.goos == 'linux' && matrix.goarch == 'amd64'"
LICENSE_RUN = """go install github.com/google/go-licenses@v1.5.0
REPORT=$(go-licenses csv ./...)
echo "$REPORT"
if echo "$REPORT" | grep -E "(GPL|AGPL)" >/dev/null 2>&1; then
  echo "GPL/AGPL detected—blocked"
  exit 1
fi"""
HOST_STEP = "Assert native host"


def parse_jobs(text: str) -> dict[str, str]:
    match = re.search(r"(?m)^jobs:\n", text)
    if not match:
        return {}
    parts = re.split(r"(?m)^  ([A-Za-z0-9_-]+):\n", text[match.end() :])
    jobs: dict[str, str] = {}
    iterator = iter(parts[1:])
    for name in iterator:
        jobs[name] = next(iterator, "")
    return jobs


def split_header_steps(body: str) -> tuple[str, list[str]]:
    match = re.search(r"(?m)^    steps:\s*\n", body)
    if not match:
        return body, []
    header = body[: match.start()]
    rest = body[match.end() :]
    parts = re.split(r"(?m)^      - ", rest)
    return header, [part for part in parts if part.strip()]


def step_meta(step: str, field: str) -> str | None:
    match = re.search(
        rf"(?m)^(?:{re.escape(field)}|        {re.escape(field)}):\s*(.*)$",
        step,
    )
    if not match:
        return None
    return match.group(1).strip()


def extract_run_body(step: str) -> str:
    capturing = False
    lines: list[str] = []
    for line in step.splitlines():
        if not capturing:
            block = re.match(r"^(?:run: \||        run: \|)\s*$", line)
            if block:
                capturing = True
                continue
            inline = re.match(r"^(?:run: |        run: )(.+)$", line)
            if inline:
                return inline.group(1)
            continue
        if line.startswith("          "):
            lines.append(line[10:])
            continue
        if line == "":
            lines.append("")
            continue
        break
    return "\n".join(lines)


def significant_run_lines(run: str) -> list[str]:
    lines: list[str] = []
    for raw in run.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def validate_windows_zip_script(text: str) -> list[str]:
    failures: list[str] = []
    if "zipfile" not in text:
        failures.append("package-windows-zip.sh must pack with python zipfile")
    if "WindowsApps" not in text:
        failures.append("package-windows-zip.sh must refuse the Windows Store python stub")
    return failures


def check_skippable_guards(
    job_name: str,
    body: str,
    *,
    allow_freshness_continue: bool = False,
    allow_license_if: bool = False,
) -> list[str]:
    failures: list[str] = []
    header, steps = split_header_steps(body)
    if re.search(r"(?m)^    if:", header):
        failures.append(f"{job_name} must not set job-level if:")
    if re.search(r"(?m)^    continue-on-error:", header):
        failures.append(f"{job_name} must not set job-level continue-on-error")

    freshness_steps: list[str] = []
    license_steps: list[str] = []
    saw_host = False
    parsed: list[tuple[str, str, str | None, str | None, str]] = []
    for step in steps:
        name = step_meta(step, "name") or ""
        if_val = step_meta(step, "if")
        continue_on_error = step_meta(step, "continue-on-error")
        run = extract_run_body(step)
        parsed.append((name, run, if_val, continue_on_error, step))
        if name == FRESHNESS_STEP:
            freshness_steps.append(step)
        if name == LICENSE_STEP:
            license_steps.append(step)

    if allow_freshness_continue:
        if len(freshness_steps) != 1:
            failures.append(
                f"{job_name} must contain exactly one {FRESHNESS_STEP} step"
            )
        else:
            run = extract_run_body(freshness_steps[0]).strip()
            if run != FRESHNESS_RUN:
                failures.append(
                    f"{job_name} sfetch pin-freshness run must be exactly {FRESHNESS_RUN}"
                )
    elif freshness_steps:
        failures.append(f"{job_name} must not claim the sfetch pin-freshness exemption")

    if allow_license_if:
        if len(license_steps) != 1:
            failures.append(f"{job_name} must contain exactly one {LICENSE_STEP} step")
        else:
            run = extract_run_body(license_steps[0]).strip()
            if run != LICENSE_RUN:
                failures.append(
                    f"{job_name} license-check run must be exactly the pinned go-licenses block"
                )
    elif license_steps:
        failures.append(f"{job_name} must not claim the license-check exemption")

    for name, run, if_val, continue_on_error, step in parsed:
        if OR_TRUE_RE.search(run):
            failures.append(
                f"{job_name} step {name or '(unnamed)'} must not use || true or || :"
            )

        freshness_ok = (
            allow_freshness_continue
            and name == FRESHNESS_STEP
            and len(freshness_steps) == 1
            and run.strip() == FRESHNESS_RUN
            and continue_on_error == "true"
            and job_name == "test"
        )
        license_ok = (
            allow_license_if
            and name == LICENSE_STEP
            and len(license_steps) == 1
            and run.strip() == LICENSE_RUN
            and if_val == LICENSE_IF
            and job_name == RELEASE_BUILD_JOB
        )

        if continue_on_error is not None and not freshness_ok:
            failures.append(
                f"{job_name} step {name or '(unnamed)'} must not set continue-on-error"
            )
        if if_val is not None and not license_ok:
            failures.append(
                f"{job_name} step {name or '(unnamed)'} must not set if:"
            )

        if name == HOST_STEP:
            saw_host = True
            if step_meta(step, "shell") is not None:
                failures.append(f"{job_name} host check must not set a custom shell:")
            if EXIT_ZERO_RE.search(run):
                failures.append(f"{job_name} host check must not exit 0")
            if re.search(r"(?m)^if\s+false\b", run):
                failures.append(f"{job_name} host check must not wrap in if false")
            lines = significant_run_lines(run)
            if not lines or not lines[-1].startswith("test "):
                failures.append(
                    f"{job_name} host check must end with a test that exits non-zero"
                )

    if not saw_host:
        failures.append(f"{job_name} must contain an Assert native host step")
    return failures


def check_setup_python(job_name: str, body: str) -> list[str]:
    failures: list[str] = []
    match = SETUP_PYTHON_RE.search(body)
    if not match:
        failures.append(f"{job_name} must pin actions/setup-python by SHA")
        return failures
    sha, comment = match.group(1), match.group(2)
    if not SHA_RE.fullmatch(sha):
        failures.append(f"{job_name} setup-python pin is not a 40-character SHA")
    if not VERSION_RE.search(comment):
        failures.append(f"{job_name} setup-python pin must have a version comment")
    if not re.search(r"(?m)^\s+python-version:", body):
        failures.append(f"{job_name} must set setup-python python-version")
    pack_at = body.find("package-windows-zip.sh")
    if pack_at >= 0 and match.start() > pack_at:
        failures.append(
            f"{job_name} must install setup-python before package-windows-zip.sh"
        )
    return failures


def check_windows_packaging(job_name: str, body: str) -> list[str]:
    failures = check_setup_python(job_name, body)
    runs: list[str] = []
    _, steps = split_header_steps(body)
    for step in steps:
        if step_meta(step, "name") != "Package Windows zip":
            continue
        runs.append(extract_run_body(step).strip())
    if runs != [WINDOWS_ZIP_RUN]:
        failures.append(
            f"{job_name} must pack Windows zips via {WINDOWS_ZIP_RUN}"
        )
    return failures


def validate_ci_text(text: str) -> tuple[bool, str]:
    failures: list[str] = []
    if FLOATING_LABEL_RE.search(text):
        failures.append(
            "ci.yml must not use ubuntu-latest, macos-latest, or windows-latest"
        )
    jobs = parse_jobs(text)
    zip_runs: list[str] = []
    for name, (runner, host) in CI_JOBS.items():
        body = jobs.get(name)
        if body is None:
            failures.append(f"missing job {name}")
            continue
        if not re.search(rf"(?m)^    runs-on:\s*{re.escape(runner)}\s*$", body):
            failures.append(f"{name} must run on {runner}")
        if f'= "{host}"' not in body:
            failures.append(f"{name} must assert native host {host}")
        failures.extend(
            check_skippable_guards(
                name,
                body,
                allow_freshness_continue=(name == "test"),
            )
        )
        if name in WINDOWS_CI_JOBS:
            failures.extend(check_windows_packaging(name, body))
            _, steps = split_header_steps(body)
            for step in steps:
                if step_meta(step, "name") == "Package Windows zip":
                    zip_runs.append(extract_run_body(step).strip())
    if len(zip_runs) != 2 or zip_runs[0] != zip_runs[1] or zip_runs[0] != WINDOWS_ZIP_RUN:
        failures.append("windows CI zip steps must be identical calls to package-windows-zip.sh")
    if ZIP_SCRIPT.is_file():
        failures.extend(validate_windows_zip_script(ZIP_SCRIPT.read_text(encoding="utf-8")))
    else:
        failures.append("scripts/package-windows-zip.sh is missing")
    if failures:
        return False, "; ".join(failures)
    return True, "ci.yml pins five native runners, refuses skippable build steps, and packs Windows zips with setup-python"


def validate_release_guards(text: str) -> list[str]:
    failures: list[str] = []
    jobs = parse_jobs(text)
    body = jobs.get(RELEASE_BUILD_JOB)
    if body is None:
        failures.append("missing build job")
        return failures
    failures.extend(
        check_skippable_guards(
            RELEASE_BUILD_JOB,
            body,
            allow_license_if=True,
        )
    )
    failures.extend(check_setup_python(RELEASE_BUILD_JOB, body))
    if WINDOWS_ZIP_RUN not in body:
        failures.append("build must pack Windows zips via scripts/package-windows-zip.sh")
    if ZIP_SCRIPT.is_file():
        failures.extend(validate_windows_zip_script(ZIP_SCRIPT.read_text(encoding="utf-8")))
    else:
        failures.append("scripts/package-windows-zip.sh is missing")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci", metavar="PATH", help="validate a ci.yml file")
    args = parser.parse_args(argv)
    if not args.ci:
        parser.error("pass --ci PATH")
    text = Path(args.ci).read_text(encoding="utf-8")
    ok, message = validate_ci_text(text)
    if not ok:
        print(message, file=sys.stderr)
        return 1
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
