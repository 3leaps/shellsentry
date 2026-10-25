#!/usr/bin/env python3
"""Regression checks for draft-preserving, SHA-pinned release action steps.

Every softprops/action-gh-release step must set draft: true (so a tag push
cannot publish) and pin the action to a 40-character commit SHA.
"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
ACTION_RE = re.compile(
    r"^(\s*)uses:\s*softprops/action-gh-release@(\S+)\s*(?:#.*)?$"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def action_blocks(text: str) -> list[tuple[int, int, int, str]]:
    """Return start, end, child indentation, and ref for each release action step."""
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


def validate(text: str) -> tuple[bool, str]:
    lines = text.splitlines()
    try:
        blocks = action_blocks(text)
    except ValueError as error:
        return False, str(error)
    if not blocks:
        return False, "release workflow has no softprops/action-gh-release steps"

    failures: list[str] = []
    for start, end, child_indent, ref in blocks:
        if not SHA_RE.fullmatch(ref):
            failures.append(
                f"release action step at line {start + 1} must pin "
                f"softprops/action-gh-release to a 40-character commit SHA "
                f"(have: {ref})"
            )
        drafts = [
            line.strip()
            for line in lines[start:end]
            if re.match(rf"^ {{{child_indent}}}draft:\s*", line)
        ]
        if drafts != ["draft: true"]:
            failures.append(
                f"release action step at line {start + 1} requires exactly one literal draft: true"
            )
    if failures:
        return False, "; ".join(failures)
    return True, f"{len(blocks)} release-writing action steps preserve draft state and SHA pin"


def mutate_action_draft(text: str, block_index: int, replacement: str | None) -> str:
    lines = text.splitlines()
    blocks = action_blocks(text)
    if not blocks:
        raise ValueError("cannot mutate workflow without a release action")
    start, end, child_indent, _ref = blocks[block_index]
    draft_indexes = [
        index
        for index in range(start, end)
        if re.match(rf"^ {{{child_indent}}}draft:\s*", lines[index])
    ]
    if len(draft_indexes) != 1:
        raise ValueError("last release action must contain exactly one draft setting")
    index = draft_indexes[0]
    if replacement is None:
        del lines[index]
    else:
        lines[index] = " " * child_indent + replacement
    return "\n".join(lines) + "\n"


def mutate_last_action_unpin(text: str) -> str:
    lines = text.splitlines()
    blocks = action_blocks(text)
    if not blocks:
        raise ValueError("cannot mutate workflow without a release action")
    start, end, _child_indent, _ref = blocks[-1]
    for index in range(start, end):
        match = ACTION_RE.match(lines[index])
        if match:
            lines[index] = re.sub(
                r"softprops/action-gh-release@[0-9a-f]{40}",
                "softprops/action-gh-release@v3",
                lines[index],
                count=1,
            )
            return "\n".join(lines) + "\n"
    raise ValueError("last release action has no uses line")


workflow = WORKFLOW.read_text(encoding="utf-8")
valid, message = validate(workflow)
if not valid:
    raise SystemExit(f"FAIL: fixed workflow rejected: {message}")
print(f"PASS: {message}")

for label, replacement in (("missing draft", None), ("draft false", "draft: false")):
    fixture = mutate_action_draft(workflow, -1, replacement)
    valid, _ = validate(fixture)
    if valid:
        raise SystemExit(f"FAIL: validator accepted fixture with {label}")
    print(f"PASS: validator rejects {label}")

first_false = mutate_action_draft(workflow, 0, "draft: false")
valid, _ = validate(first_false)
if valid:
    raise SystemExit("FAIL: validator accepted fixture with first-step draft false")
print("PASS: validator rejects first-step draft false")

unpin = mutate_last_action_unpin(workflow)
valid, _ = validate(unpin)
if valid:
    raise SystemExit("FAIL: validator accepted fixture with unpinned @v3")
print("PASS: validator rejects unpinned @v3")
