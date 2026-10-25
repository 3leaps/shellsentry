#!/usr/bin/env python3
"""Regression: every workflow's action-gh-release stays draft and SHA-pinned.

Also: the build job is contents:read and never writes a GitHub release; upload
is the only contents:write job and is the only action-gh-release caller.
"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = ROOT / ".github" / "workflows"
ACTION_RE = re.compile(
    r"^(\s*)uses:\s*softprops/action-gh-release@(\S+)\s*(?:#.*)?$"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")


def workflow_files() -> list[Path]:
    files = sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml"))
    if not files:
        raise SystemExit("FAIL: no GitHub workflow files")
    return files


def action_blocks(text: str) -> list[tuple[int, int, int, str]]:
    lines = text.splitlines()
    blocks: list[tuple[int, int, int, str]] = []
    for uses_index, line in enumerate(lines):
        match = ACTION_RE.match(line)
        if not match:
            continue
        uses_indent = len(match.group(1))
        ref = match.group(2)
        step_indent = uses_indent - 2
        start = uses_index
        while start >= 0 and not re.match(rf"^ {{{step_indent}}}-\s+", lines[start]):
            start -= 1
        if start < 0:
            raise ValueError(
                f"release action at line {uses_index + 1} has no step boundary"
            )
        end = uses_index + 1
        while end < len(lines) and not re.match(
            rf"^ {{{step_indent}}}-\s+", lines[end]
        ):
            end += 1
        blocks.append((start, end, uses_indent + 2, ref))
    return blocks


def job_bodies(text: str) -> dict[str, str]:
    lines = text.splitlines(keepends=True)
    jobs: dict[str, str] = {}
    current = None
    buf: list[str] = []
    for line in lines:
        match = JOB_RE.match(line.rstrip("\n"))
        if match and not line.startswith("   "):
            if current is not None:
                jobs[current] = "".join(buf)
            current = match.group(1)
            buf = [line]
            continue
        if current is not None:
            buf.append(line)
    if current is not None:
        jobs[current] = "".join(buf)
    return jobs


def validate_files(files: dict[Path, str]) -> tuple[bool, str]:
    failures: list[str] = []
    total_blocks = 0
    release_text = files.get(WORKFLOWS_DIR / "release.yml", "")
    for path, text in files.items():
        try:
            blocks = action_blocks(text)
        except ValueError as error:
            return False, f"{path.name}: {error}"
        lines = text.splitlines()
        for start, end, child_indent, ref in blocks:
            total_blocks += 1
            if not SHA_RE.fullmatch(ref):
                failures.append(
                    f"{path.name}:{start + 1} must pin action-gh-release to a 40-character SHA (have: {ref})"
                )
            drafts = [
                line.strip()
                for line in lines[start:end]
                if re.match(rf"^ {{{child_indent}}}draft:\s*", line)
            ]
            if drafts != ["draft: true"]:
                failures.append(
                    f"{path.name}:{start + 1} requires exactly one literal draft: true"
                )
        if path.name != "release.yml" and blocks:
            failures.append(f"{path.name} must not create GitHub releases")

    if total_blocks == 0:
        return False, "no workflow contains a softprops/action-gh-release step"

    if not release_text:
        failures.append("release.yml missing")
    else:
        jobs = job_bodies(release_text)
        build = jobs.get("build", "")
        upload = jobs.get("upload", "")
        if not build:
            failures.append("release.yml must have a build job")
        if not upload:
            failures.append("release.yml must have an upload job")
        if re.search(r"^\s+contents:\s*write\b", build, re.M):
            failures.append("build job must not have contents: write")
        if not re.search(r"^\s+contents:\s*read\b", build, re.M):
            failures.append("build job must have contents: read")
        if "action-gh-release" in build:
            failures.append("build job must not use action-gh-release")
        if not re.search(r"^\s+contents:\s*write\b", upload, re.M):
            failures.append("upload job must have contents: write")
        if "action-gh-release" not in upload:
            failures.append("upload job must use action-gh-release")

    if failures:
        return False, "; ".join(failures)
    return True, f"{total_blocks} release-writing action step(s) across {len(files)} workflow file(s)"


def mutate_action_draft(text: str, block_index: int, replacement: str | None) -> str:
    lines = text.splitlines()
    blocks = action_blocks(text)
    start, end, child_indent, _ref = blocks[block_index]
    draft_indexes = [
        index
        for index in range(start, end)
        if re.match(rf"^ {{{child_indent}}}draft:\s*", lines[index])
    ]
    if len(draft_indexes) != 1:
        raise ValueError("action must contain exactly one draft setting")
    index = draft_indexes[0]
    if replacement is None:
        del lines[index]
    else:
        lines[index] = " " * child_indent + replacement
    return "\n".join(lines) + "\n"


def mutate_unpin(text: str) -> str:
    return re.sub(
        r"softprops/action-gh-release@[0-9a-f]{40}",
        "softprops/action-gh-release@v3",
        text,
        count=1,
    )


on_disk = workflow_files()
files = {path: path.read_text(encoding="utf-8") for path in on_disk}
if (WORKFLOWS_DIR / "ci.yml") not in files:
    raise SystemExit("FAIL: draft check did not load ci.yml (must scan every workflow)")
if (WORKFLOWS_DIR / "release.yml") not in files:
    raise SystemExit("FAIL: draft check did not load release.yml")
valid, message = validate_files(files)
if not valid:
    raise SystemExit(f"FAIL: committed workflows rejected: {message}")
print(f"PASS: {message}")

release_path = WORKFLOWS_DIR / "release.yml"
release = files[release_path]

for label, replacement in (("missing draft", None), ("draft false", "draft: false")):
    mutated = dict(files)
    mutated[release_path] = mutate_action_draft(release, -1, replacement)
    valid, _ = validate_files(mutated)
    if valid:
        raise SystemExit(f"FAIL: validator accepted fixture with {label}")
    print(f"PASS: validator rejects {label}")

mutated = dict(files)
mutated[release_path] = mutate_unpin(release)
valid, _ = validate_files(mutated)
if valid:
    raise SystemExit("FAIL: validator accepted unpinned @v3")
print("PASS: validator rejects unpinned @v3")

def mutate_build_contents_write(text: str) -> str:
    jobs = job_bodies(text)
    build = jobs["build"]
    if "contents: read" not in build:
        raise ValueError("build job has no contents: read to mutate")
    return text.replace(build, build.replace("contents: read", "contents: write", 1), 1)


mutated = dict(files)
mutated[release_path] = mutate_build_contents_write(release)
valid, _ = validate_files(mutated)
if valid:
    raise SystemExit("FAIL: validator accepted build job contents: write")
print("PASS: validator rejects write permission on build")

mutated = dict(files)
# Splice action-gh-release into the build job body.
mutated[release_path] = release.replace(
    "      - name: Upload packaged archive\n",
    "      - name: sneaky publish\n"
    "        uses: softprops/action-gh-release@efb35369e0ad2afab669f228072c1b0d510eae64  # v3.0.3\n"
    "        with:\n"
    "          draft: true\n"
    "      - name: Upload packaged archive\n",
    1,
)
valid, _ = validate_files(mutated)
if valid:
    raise SystemExit("FAIL: validator accepted action-gh-release in build")
print("PASS: validator rejects action-gh-release in build")

rogue = """---
name: Rogue
on: push
jobs:
  leak:
    runs-on: ubuntu-latest
    steps:
      - name: Publish
        uses: softprops/action-gh-release@efb35369e0ad2afab669f228072c1b0d510eae64
        with:
          draft: false
"""
mutated = dict(files)
mutated[WORKFLOWS_DIR / "rogue.yml"] = rogue
valid, _ = validate_files(mutated)
if valid:
    raise SystemExit("FAIL: validator accepted extra workflow with draft: false")
print("PASS: validator rejects action-gh-release in a second workflow")
