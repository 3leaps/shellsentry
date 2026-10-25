#!/usr/bin/env python3
"""Regression checks for the read-only tag workflow.

The tag workflow is artifacts-only: it must not create a GitHub Release, must
not request contents: write, must not use action-gh-release, and must pin a
fixed runner label. Publication stays on the maintainer machine.
"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
WRITE_PERM_RE = re.compile(r"^\s*([a-z-]+):\s*write\b", re.MULTILINE)
WRITE_ALL_RE = re.compile(r"^\s*permissions:\s*write-all\b", re.MULTILINE)
CONTENTS_READ_RE = re.compile(
    r"^permissions:\s*\n\s+contents:\s*read\b", re.MULTILINE
)
BANNED = (
    "action-gh-release",
    "gh release ",
    "contents: write",
    "GITHUB_TOKEN: ${{ secrets",
)


def validate(text: str) -> tuple[bool, str]:
    failures: list[str] = []
    if WRITE_ALL_RE.search(text):
        failures.append("write-all permissions granted")
    for match in WRITE_PERM_RE.finditer(text):
        failures.append(f"write permission granted: {match.group(1)}")
    if not CONTENTS_READ_RE.search(text):
        failures.append("workflow-level permissions must be contents: read")
    for banned in BANNED:
        if banned in text:
            failures.append(f"release-creating construct present: {banned!r}")
    if "upload-artifact" not in text:
        failures.append("tag workflow must upload artifacts (no GitHub Release)")
    if re.search(r"runs-on:\s*ubuntu-latest\b", text):
        failures.append("tag workflow must not use ubuntu-latest")
    if not re.search(r"runs-on:\s*ubuntu-24\.04\b", text):
        failures.append("tag workflow must use ubuntu-24.04")
    install = text.find("ci-install-decernor.sh")
    verify = text.find("release-verify-committed-anchors.sh")
    if install < 0 or verify < 0:
        failures.append("tag workflow must install Decernor and verify committed anchors")
    elif install > verify:
        failures.append("tag workflow must install Decernor before verifying anchors")
    if failures:
        return False, "; ".join(failures)
    return True, "tag workflow is read-only and never creates a release"


def mutate_insert_action(text: str) -> str:
    return text.replace(
        "uses: actions/upload-artifact@",
        "uses: softprops/action-gh-release@deadbeef\n"
        "        with:\n"
        "          draft: true\n"
        "      - uses: actions/upload-artifact@",
        1,
    )


def mutate_contents_write(text: str) -> str:
    return text.replace("contents: read", "contents: write", 1)


def mutate_floating_runner(text: str) -> str:
    return text.replace("ubuntu-24.04", "ubuntu-latest", 1)


def mutate_drop_anchor_verify(text: str) -> str:
    return text.replace(
        "./scripts/release-verify-committed-anchors.sh",
        "./scripts/release-preflight.sh",
        1,
    )


workflow = WORKFLOW.read_text(encoding="utf-8")
valid, message = validate(workflow)
if not valid:
    raise SystemExit(f"FAIL: fixed workflow rejected: {message}")
print(f"PASS: {message}")

for label, mutator in (
    ("action-gh-release restored", mutate_insert_action),
    ("contents write", mutate_contents_write),
    ("ubuntu-latest runner", mutate_floating_runner),
    ("anchor verify removed", mutate_drop_anchor_verify),
):
    fixture = mutator(workflow)
    valid, _ = validate(fixture)
    if valid:
        raise SystemExit(f"FAIL: validator accepted fixture with {label}")
    print(f"PASS: validator rejects {label}")
