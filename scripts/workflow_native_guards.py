#!/usr/bin/env python3
"""Live checks for native-platform CI and tag-build jobs.

Mutants in test-release-ci-hygiene.sh and test-release-workflow-draft.py must
call these functions rather than a copied regex. Skip/soft-fail is refused
except for two named exemptions:

- continue-on-error on "sfetch pin freshness (informational soft-warn only)"
  in the linux/amd64 CI job
- if: matrix.goos == 'linux' && matrix.goarch == 'amd64' on "License check"
  in the tag build job
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


FLOATING_LABEL_RE = re.compile(
    r"(?m)^\s+(?:runs-on|runner):\s*(ubuntu-latest|macos-latest|windows-latest)\s*$"
)
SETUP_PYTHON_RE = re.compile(
    r"uses:\s*actions/setup-python@([0-9a-f]{40})\s+#\s*(\S+)"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"v[0-9]")

CI_JOBS = {
    "test": ("ubuntu-24.04", "linux/amd64"),
    "test-linux-arm64": ("ubuntu-latest-arm64-s", "linux/arm64"),
    "macos-bootstrap-smoke": ("macos-15", "darwin/arm64"),
    "windows-dogfood-x64": ("windows-2022", "windows/amd64"),
    "windows-dogfood-arm64": ("windows-latest-arm64-s", "windows/arm64"),
}
WINDOWS_CI_JOBS = ("windows-dogfood-x64", "windows-dogfood-arm64")
RELEASE_BUILD_JOB = "build"

FRESHNESS_STEP = "sfetch pin freshness (informational soft-warn only)"
LICENSE_STEP = "License check"
LICENSE_IF = "matrix.goos == 'linux' && matrix.goarch == 'amd64'"
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

    saw_host = False
    for step in steps:
        name = step_meta(step, "name") or ""
        if_val = step_meta(step, "if")
        continue_on_error = step_meta(step, "continue-on-error")
        run = extract_run_body(step)

        if continue_on_error is not None:
            allowed = (
                allow_freshness_continue
                and name == FRESHNESS_STEP
                and continue_on_error == "true"
                and job_name == "test"
            )
            if not allowed:
                failures.append(
                    f"{job_name} step {name or '(unnamed)'} must not set continue-on-error"
                )

        if if_val is not None:
            allowed = (
                allow_license_if
                and name == LICENSE_STEP
                and if_val == LICENSE_IF
                and job_name == RELEASE_BUILD_JOB
            )
            if not allowed:
                failures.append(
                    f"{job_name} step {name or '(unnamed)'} must not set if:"
                )

        if name == HOST_STEP:
            saw_host = True
            if re.search(r"\|\|\s*true\b", run):
                failures.append(f"{job_name} host check must not use || true")
            if re.search(r"(?m)^if\s+false\b", run):
                failures.append(f"{job_name} host check must not wrap in if false")

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
    zip_at = body.find("zipfile")
    if zip_at >= 0 and match.start() > zip_at:
        failures.append(f"{job_name} must install setup-python before zipfile packaging")
    return failures


def check_windows_packaging(job_name: str, body: str) -> list[str]:
    failures = check_setup_python(job_name, body)
    if "zipfile" not in body:
        failures.append(f"{job_name} must pack with python zipfile")
    if "WindowsApps" not in body:
        failures.append(f"{job_name} must refuse the Windows Store python stub")
    return failures


def validate_ci_text(text: str) -> tuple[bool, str]:
    failures: list[str] = []
    if FLOATING_LABEL_RE.search(text):
        failures.append(
            "ci.yml must not use ubuntu-latest, macos-latest, or windows-latest"
        )
    jobs = parse_jobs(text)
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
    if "WindowsApps" not in body:
        failures.append("build must refuse the Windows Store python stub")
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
