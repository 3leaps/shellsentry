#!/usr/bin/env python3
"""Regression checks for the read-only tag workflow.

The tag workflow is artifacts-only: it must not create a GitHub Release, must
not request contents: write, must not use action-gh-release, and must build
on five native runners with fixed labels. Publication stays on the
maintainer machine.
"""

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from workflow_native_guards import (  # noqa: E402
    PINNED_SELF_HOSTED_LABELS,
    contains_retired_runner_labels,
    uses_floating_runner_label,
    validate_release_guards,
    validate_windows_zip_script,
)
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
NATIVE_CELLS = (
    ("ubuntu-24.04", "linux", "amd64"),
    ("ubuntu-24.04-arm64-s", "linux", "arm64"),
    ("macos-15", "darwin", "arm64"),
    ("windows-2022", "windows", "amd64"),
    ("windows-11-arm64-s", "windows", "arm64"),
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
    if uses_floating_runner_label(text):
        failures.append("tag workflow must not use ubuntu-latest, macos-latest, or windows-latest")
    retired = contains_retired_runner_labels(text)
    if retired:
        failures.append(
            "tag workflow must not use retired runner labels: " + ", ".join(retired)
        )
    if not re.search(r"(?m)^\s+runs-on:\s*ubuntu-24\.04\s*$", text):
        failures.append("tag workflow must pin ubuntu-24.04 for non-matrix jobs")
    if not re.search(r"(?m)^  build:\n(?:.*\n)*?    runs-on:\s*\$\{\{\s*matrix\.runner\s*\}\}\s*$", text):
        failures.append("build must run on matrix.runner")
    for runner, goos, goarch in NATIVE_CELLS:
        if goos != "darwin" and goarch == "arm64" and runner not in PINNED_SELF_HOSTED_LABELS:
            failures.append(
                f"native cell {goos}/{goarch} runner {runner} must be a pinned self-hosted label"
            )
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
    if "package-windows-zip.sh" not in text:
        failures.append("windows archives must be packed by scripts/package-windows-zip.sh")
    if not re.search(r"(?m)^  build:\n(?:.*\n)*?    needs: verify-anchors\b", text):
        failures.append("build must need verify-anchors")
    install = text.find("ci-install-decernor.sh")
    verify = text.find("release-verify-committed-anchors.sh")
    if install < 0 or verify < 0:
        failures.append("tag workflow must install Decernor and verify committed anchors")
    elif install > verify:
        failures.append("tag workflow must install Decernor before verifying anchors")
    failures.extend(validate_release_guards(text))
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


def mutate_linux_arm64_retired(text: str) -> str:
    old = "ubuntu-24.04-arm64-s"
    new = "ubuntu-" + "latest" + "-arm64-s"
    if old not in text:
        raise SystemExit("live workflow is missing ubuntu-24.04-arm64-s")
    mut = text.replace(old, new, 1)
    if old in mut:
        raise SystemExit("linux arm64 retired-label mutant still has ubuntu-24.04-arm64-s")
    return mut


def mutate_windows_arm64_retired(text: str) -> str:
    old = "windows-11-arm64-s"
    new = "windows-" + "latest" + "-arm64-s"
    if old not in text:
        raise SystemExit("live workflow is missing windows-11-arm64-s")
    mut = text.replace(old, new, 1)
    if old in mut:
        raise SystemExit("windows arm64 retired-label mutant still has windows-11-arm64-s")
    return mut


def mutate_linux_arm64_wrong_runner(text: str) -> str:
    old = "          - runner: ubuntu-24.04-arm64-s\n            goos: linux\n            goarch: arm64"
    new = "          - runner: ubuntu-24.04\n            goos: linux\n            goarch: arm64"
    if old not in text:
        raise SystemExit("live workflow is missing the linux/arm64 native cell")
    mut = text.replace(old, new, 1)
    if old in mut:
        raise SystemExit("linux arm64 wrong-runner mutant still uses ubuntu-24.04-arm64-s")
    return mut


def mutate_build_job_if(text: str) -> str:
    old = "  build:\n    needs: verify-anchors\n"
    new = "  build:\n    if: startsWith(github.ref, 'refs/tags/v')\n    needs: verify-anchors\n"
    if old not in text:
        raise SystemExit("live workflow is missing the unguarded build job header")
    mut = text.replace(old, new, 1)
    if "  build:\n    if:" not in mut:
        raise SystemExit("build-job if: mutant did not set job-level if:")
    return mut


def mutate_host_step_if_false(text: str) -> str:
    old = "      - name: Assert native host\n"
    new = "      - name: Assert native host\n        if: false\n"
    if old not in text:
        raise SystemExit("live workflow is missing Assert native host")
    mut = text.replace(old, new, 1)
    if "        if: false\n" not in mut:
        raise SystemExit("host if: false mutant did not set if: false")
    return mut


def mutate_host_or_true(text: str) -> str:
    old = '          test "$host" = "$want"'
    new = '          test "$host" = "$want" || true'
    if old not in text:
        raise SystemExit("live workflow is missing the host equality test")
    mut = text.replace(old, new, 1)
    if old + "\n" in mut:
        raise SystemExit("host || true mutant still has the live host test")
    return mut


def mutate_build_continue_on_error(text: str) -> str:
    old = "      - name: Build\n"
    new = "      - name: Build\n        continue-on-error: true\n"
    if old not in text:
        raise SystemExit("live workflow is missing the Build step")
    mut = text.replace(old, new, 1)
    if "continue-on-error: true" not in mut.split("      - name: Build\n", 1)[1][:80]:
        raise SystemExit("Build continue-on-error mutant did not set continue-on-error")
    return mut


def mutate_license_if_false(text: str) -> str:
    old = "        if: matrix.goos == 'linux' && matrix.goarch == 'amd64'"
    new = "        if: false"
    if old not in text:
        raise SystemExit("live workflow is missing the linux/amd64 license if:")
    mut = text.replace(old, new, 1)
    if old in mut:
        raise SystemExit("license if: mutant still has the allowed predicate")
    return mut


def mutate_drop_setup_python(text: str) -> str:
    old = (
        "      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0  # v7.1.0\n"
        "        with:\n"
        "          python-version: '3.12'\n\n"
    )
    if old not in text:
        raise SystemExit("live workflow is missing the setup-python pin")
    mut = text.replace(old, "", 1)
    if "actions/setup-python@" in mut:
        raise SystemExit("setup-python mutant still pins setup-python")
    return mut


def mutate_drop_windows_zip_script(text: str) -> str:
    old = './scripts/package-windows-zip.sh "${{ matrix.goos }}" "${{ matrix.goarch }}"'
    new = 'python -c "pass"'
    if old not in text:
        raise SystemExit("live workflow is missing package-windows-zip.sh")
    mut = text.replace(old, new, 1)
    if "package-windows-zip.sh" in mut:
        raise SystemExit("zip-script mutant still calls package-windows-zip.sh")
    return mut


def mutate_license_swap(text: str) -> str:
    license_block = (
        "      - name: License check\n"
        "        if: matrix.goos == 'linux' && matrix.goarch == 'amd64'\n"
        "        # Pin go-licenses; do not use @latest on the release path.\n"
        "        run: |\n"
        "          go install github.com/google/go-licenses@v1.5.0\n"
        "          REPORT=$(go-licenses csv ./...)\n"
        '          echo "$REPORT"\n'
        '          if echo "$REPORT" | grep -E "(GPL|AGPL)" >/dev/null 2>&1; then\n'
        '            echo "GPL/AGPL detected—blocked"\n'
        "            exit 1\n"
        "          fi\n\n"
    )
    if license_block not in text:
        raise SystemExit("live workflow is missing the license step")
    mut = text.replace(license_block, "", 1)
    old = "      - name: Build\n        run: make build\n"
    new = (
        "      - name: License check\n"
        "        if: matrix.goos == 'linux' && matrix.goarch == 'amd64'\n"
        "        run: make build\n"
    )
    if old not in mut:
        raise SystemExit("license-swap mutant could not retarget Build")
    mut = mut.replace(old, new, 1)
    if mut.count("name: License check") != 1:
        raise SystemExit("license-swap mutant must keep exactly one License check name")
    return mut


def mutate_license_append(text: str) -> str:
    old = (
        '            echo "GPL/AGPL detected—blocked"\n'
        "            exit 1\n"
        "          fi\n"
    )
    new = old + "          true\n"
    if old not in text:
        raise SystemExit("live workflow is missing the license run tail")
    mut = text.replace(old, new, 1)
    if mut.count("          true\n") < 1:
        raise SystemExit("license-append mutant did not append a command")
    return mut


def mutate_host_exit_zero(text: str) -> str:
    old = '          test "$host" = "$want"'
    new = '          test "$host" = "$want"\n          exit 0'
    if old not in text:
        raise SystemExit("live workflow is missing the host equality test")
    mut = text.replace(old, new, 1)
    if "exit 0" not in mut:
        raise SystemExit("host exit 0 mutant did not append exit 0")
    return mut


def mutate_host_custom_shell(text: str) -> str:
    old = "      - name: Assert native host\n        run: |"
    new = "      - name: Assert native host\n        shell: bash {0}\n        run: |"
    if old not in text:
        raise SystemExit("live workflow is missing Assert native host")
    mut = text.replace(old, new, 1)
    if "shell: bash {0}" not in mut:
        raise SystemExit("host shell mutant did not set a custom shell:")
    return mut


def mutate_build_or_colon(text: str) -> str:
    old = "        run: make build\n"
    new = "        run: make build || :\n"
    if old not in text:
        raise SystemExit("live workflow is missing run: make build")
    mut = text.replace(old, new, 1)
    if "make build || :" not in mut:
        raise SystemExit("|| : mutant did not append || :")
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
    ("linux arm64 retired runner", mutate_linux_arm64_retired),
    ("windows arm64 retired runner", mutate_windows_arm64_retired),
    ("linux arm64 runner off table", mutate_linux_arm64_wrong_runner),
    ("build job-level if:", mutate_build_job_if),
    ("host-check if: false", mutate_host_step_if_false),
    ("host-check || true", mutate_host_or_true),
    ("Build continue-on-error", mutate_build_continue_on_error),
    ("license if: false", mutate_license_if_false),
    ("setup-python pin dropped", mutate_drop_setup_python),
    ("package-windows-zip.sh dropped", mutate_drop_windows_zip_script),
    ("license step swapped onto Build", mutate_license_swap),
    ("license run command appended", mutate_license_append),
    ("host-check exit 0", mutate_host_exit_zero),
    ("host-check custom shell:", mutate_host_custom_shell),
    ("Build || :", mutate_build_or_colon),
):
    fixture = mutator(workflow)
    valid, _ = validate(fixture)
    if valid:
        raise SystemExit(f"FAIL: validator accepted fixture with {label}")
    print(f"PASS: validator rejects {label}")

zip_script = (ROOT / "scripts" / "package-windows-zip.sh").read_text(encoding="utf-8")
zip_fails = validate_windows_zip_script(zip_script)
if zip_fails:
    raise SystemExit(f"FAIL: live package-windows-zip.sh rejected: {'; '.join(zip_fails)}")
print("PASS: package-windows-zip.sh packs with zipfile and refuses the Store stub")
gutted = zip_script.replace("WindowsApps", "System32")
if not validate_windows_zip_script(gutted):
    raise SystemExit("FAIL: validator accepted package-windows-zip.sh without WindowsApps")
print("PASS: validator rejects package-windows-zip.sh without the Store stub refusal")
no_zipfile = zip_script.replace("zipfile", "tarfile")
if not validate_windows_zip_script(no_zipfile):
    raise SystemExit("FAIL: validator accepted package-windows-zip.sh without zipfile")
print("PASS: validator rejects package-windows-zip.sh without zipfile")
