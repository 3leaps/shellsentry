#!/usr/bin/env python3
"""Regression checks for the read-only tag workflow.

The tag workflow is artifacts-only: it must not create a GitHub Release, must
not request contents: write, must not use action-gh-release, and must build
on five native runners with fixed labels. Publication stays on the
maintainer machine.
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
SECRETS_RE = re.compile(r"secrets\.|secrets:\s*inherit")
GH_API_WRITE_RE = re.compile(
    r"gh\s+api\s+[^\n]*(?:--method|-X)\s+(?:POST|PATCH|PUT|DELETE)|"
    r"gh\s+api\s+[^\n]*/releases",
    re.IGNORECASE,
)
BANNED = (
    "action-gh-release",
    "gh release ",
    "contents: write",
    "GITHUB_TOKEN: ${{ secrets",
)
FLOATING_LABEL_RE = re.compile(
    r"(?m)^\s+(?:runs-on|runner):\s*(ubuntu-latest|macos-latest|windows-latest)\s*$"
)
NATIVE_CELLS = (
    ("ubuntu-24.04", "linux", "amd64"),
    ("ubuntu-latest-arm64-s", "linux", "arm64"),
    ("macos-15", "darwin", "arm64"),
    ("windows-2022", "windows", "amd64"),
    ("windows-latest-arm64-s", "windows", "arm64"),
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
    if SECRETS_RE.search(text):
        failures.append("tag workflow must not reference secrets.* or secrets: inherit")
    if GH_API_WRITE_RE.search(text):
        failures.append("tag workflow must not use gh api to write releases")
    if re.search(r"persist-credentials:\s*true\b", text):
        failures.append("tag workflow must not set persist-credentials: true")
    if "upload-artifact" not in text:
        failures.append("tag workflow must upload artifacts (no GitHub Release)")
    if "release-packages-" not in text:
        failures.append("tag workflow must upload a combined release-packages artifact")
    if FLOATING_LABEL_RE.search(text):
        failures.append("tag workflow must not use ubuntu-latest, macos-latest, or windows-latest")
    if not re.search(r"(?m)^\s+runs-on:\s*ubuntu-24\.04\s*$", text):
        failures.append("tag workflow must pin ubuntu-24.04 for non-matrix jobs")
    if not re.search(r"(?m)^  build:\n(?:.*\n)*?    runs-on:\s*\$\{\{\s*matrix\.runner\s*\}\}\s*$", text):
        failures.append("build must run on matrix.runner")
    for runner, goos, goarch in NATIVE_CELLS:
        cell = re.compile(
            rf"- runner:\s*{re.escape(runner)}\n\s+goos:\s*{re.escape(goos)}\n\s+goarch:\s*{re.escape(goarch)}\b"
        )
        if not cell.search(text):
            failures.append(f"build matrix missing native cell {goos}/{goarch} on {runner}")
    if 'host="$(go env GOHOSTOS)/$(go env GOHOSTARCH)"' not in text:
        failures.append("build must assert GOHOSTOS/GOHOSTARCH")
    if 'want="${{ matrix.goos }}/${{ matrix.goarch }}"' not in text:
        failures.append("build must compare the host to matrix.goos/goarch")
    if 'test "$host" = "$want"' not in text:
        failures.append("build must require the runner host to match the matrix cell")
    if re.search(r"apt-get install[^\n]*\bzip\b", text):
        failures.append("tag build must not apt-get zip")
    if "zipfile" not in text:
        failures.append("windows archives must be packed with python zipfile")
    if not re.search(r"(?m)^  build:\n(?:.*\n)*?    needs: verify-anchors\b", text):
        failures.append("build must need verify-anchors")
    install = text.find("ci-install-decernor.sh")
    verify = text.find("release-verify-committed-anchors.sh")
    if install < 0 or verify < 0:
        failures.append("tag workflow must install Decernor and verify committed anchors")
    elif install > verify:
        failures.append("tag workflow must install Decernor before verifying anchors")
    if failures:
        return False, "; ".join(failures)
    return True, "tag workflow is read-only and builds on five native runners"


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


def mutate_drop_needs(text: str) -> str:
    mut = text.replace("    needs: verify-anchors\n", "", 1)
    if "needs: verify-anchors" in mut:
        raise SystemExit("mutant still has needs: verify-anchors")
    return mut


def mutate_secrets(text: str) -> str:
    return text.replace(
        "permissions:\n  contents: read\n",
        "permissions:\n  contents: read\n  secrets: inherit\n",
        1,
    )


def mutate_persist_credentials(text: str) -> str:
    return text.replace("persist-credentials: false", "persist-credentials: true", 1)


def mutate_gh_api_write(text: str) -> str:
    return text + "\n      - run: gh api --method POST repos/3leaps/shellsentry/releases\n"


def mutate_drop_combined_artifact(text: str) -> str:
    return text.replace("release-packages-", "platform-packages-", 1)


def mutate_cross_compile(text: str) -> str:
    mut = text.replace("runs-on: ${{ matrix.runner }}", "runs-on: ubuntu-24.04", 1)
    if "matrix.runner" in mut.split("  build:", 1)[1].split("  collect-packages:", 1)[0]:
        raise SystemExit("cross-compile mutant still uses matrix.runner")
    return mut


def mutate_drop_host_assert(text: str) -> str:
    old = 'host="$(go env GOHOSTOS)/$(go env GOHOSTARCH)"'
    if old not in text:
        raise SystemExit("live workflow is missing the native host assert")
    return text.replace(old, 'host="linux/amd64"', 1)


def mutate_macos_latest(text: str) -> str:
    mut = text.replace("macos-15", "macos-latest", 1)
    if "macos-15" in mut:
        raise SystemExit("macos-latest mutant still has macos-15")
    return mut


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
    ("build needs verify-anchors dropped", mutate_drop_needs),
    ("secrets inherit", mutate_secrets),
    ("persist-credentials true", mutate_persist_credentials),
    ("gh api release write", mutate_gh_api_write),
    ("combined release-packages artifact removed", mutate_drop_combined_artifact),
    ("cross-compile on ubuntu-24.04", mutate_cross_compile),
    ("native host assert dropped", mutate_drop_host_assert),
    ("macos-latest runner", mutate_macos_latest),
):
    fixture = mutator(workflow)
    valid, _ = validate(fixture)
    if valid:
        raise SystemExit(f"FAIL: validator accepted fixture with {label}")
    print(f"PASS: validator rejects {label}")
