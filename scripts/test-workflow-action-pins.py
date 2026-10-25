#!/usr/bin/env python3
"""Regression: every workflow uses: is pinned to a 40-character commit SHA.

A floating tag (@v5, @v6, @main, @latest) or a SHA without a version comment
must fail this check. Mutating one pin back to a tag must fail.
"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = ROOT / ".github" / "workflows"
USES_RE = re.compile(
    r"^(\s*)(?:-\s+)?uses:\s*([^@\s#]+)@(\S+?)(?:\s+#\s*(\S.*))?\s*$"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"v[0-9]")


def workflow_files() -> list[Path]:
    files = sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml"))
    if not files:
        raise SystemExit("FAIL: no GitHub workflow files")
    return files


def uses_matches(text: str) -> list[tuple[int, re.Match[str]]]:
    matches: list[tuple[int, re.Match[str]]] = []
    for index, line in enumerate(text.splitlines()):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        match = USES_RE.match(line)
        if match:
            matches.append((index, match))
    return matches


def validate_files(files: dict[Path, str]) -> tuple[bool, str]:
    failures: list[str] = []
    total = 0
    for path, text in files.items():
        matches = uses_matches(text)
        total += len(matches)
        if not matches and path.suffix in {".yml", ".yaml"}:
            failures.append(f"{path.name}: no uses: steps")
        for index, match in matches:
            action, ref, comment = match.group(2), match.group(3), match.group(4)
            line_no = index + 1
            if not SHA_RE.fullmatch(ref):
                failures.append(
                    f"{path.name}:{line_no} {action} must pin to a 40-character SHA (have: {ref})"
                )
                continue
            if not comment or not VERSION_RE.search(comment):
                failures.append(
                    f"{path.name}:{line_no} {action}@{ref} must have a trailing version comment"
                )
    if total < 15:
        return False, (
            f"only {total} uses: step(s); anonymous '- uses:' lines may be unparsed"
        )
    if failures:
        return False, "; ".join(failures)
    return True, f"{total} uses: step(s) SHA-pinned across {len(files)} workflow file(s)"


def mutate_first_ref(text: str, new_ref: str, strip_comment: bool = False) -> str:
    lines = text.splitlines()
    for index, match in uses_matches(text):
        prefix = lines[index][: match.start(2)]
        comment = match.group(4)
        action = match.group(2)
        if strip_comment:
            lines[index] = f"{prefix}{action}@{new_ref}"
        elif comment:
            lines[index] = f"{prefix}{action}@{new_ref}  # {comment}"
        else:
            lines[index] = f"{prefix}{action}@{new_ref}"
        return "\n".join(lines) + "\n"
    raise ValueError("no uses: line to mutate")


makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
if "test-workflow-action-pins" not in makefile:
    raise SystemExit("FAIL: Makefile missing test-workflow-action-pins")
if not re.search(
    r"^release-tag-tests:.*\n(?:\t.*\n)*\t@\$\(MAKE\) test-workflow-action-pins$",
    makefile,
    re.M,
):
    raise SystemExit("FAIL: release-tag-tests must run test-workflow-action-pins")
if not re.search(
    r"^precommit:.*\n(?:\t.*\n)*\t\$\(MAKE\) release-tag-tests$",
    makefile,
    re.M,
):
    raise SystemExit("FAIL: precommit must run release-tag-tests")

files = {path: path.read_text(encoding="utf-8") for path in workflow_files()}
if (WORKFLOWS_DIR / "ci.yml") not in files or (WORKFLOWS_DIR / "release.yml") not in files:
    raise SystemExit("FAIL: pin check did not load ci.yml and release.yml")
valid, message = validate_files(files)
if not valid:
    raise SystemExit(f"FAIL: committed workflows rejected: {message}")
print(f"PASS: {message}")

# Mutant: revert one pin to a floating tag.
ci_path = WORKFLOWS_DIR / "ci.yml"
mutated = dict(files)
mutated[ci_path] = mutate_first_ref(files[ci_path], "v5")
valid, _ = validate_files(mutated)
if valid:
    raise SystemExit("FAIL: validator accepted a uses: pin reverted to a tag")
print("PASS: validator rejects a uses: pin reverted to a tag")

# Mutant: SHA without a version comment.
mutated = dict(files)
sha_line = uses_matches(files[ci_path])[0][1]
mutated[ci_path] = mutate_first_ref(
    files[ci_path], sha_line.group(3), strip_comment=True
)
valid, _ = validate_files(mutated)
if valid:
    raise SystemExit("FAIL: validator accepted a SHA pin with no version comment")
print("PASS: validator rejects a SHA pin with no version comment")
