#!/usr/bin/env python3
"""Fail closed on GitHub Actions workflow authority drift.

The repository intentionally treats workflow token authority as a closed allowlist.
Every workflow, trigger, job, and permissions block must be reviewed here before it
can be introduced or changed. This prevents a future workflow from silently acquiring
repository-write, PR-write, OIDC, attestation, package, Actions, or security-event
authority merely because it is new and therefore outside a workflow-specific validator.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"

WORKFLOW_SCOPE = "__workflow__"

EXPECTED = {
    "codeql.yml": {
        "triggers": {"pull_request", "push", "schedule", "workflow_dispatch"},
        "jobs": {"analyze"},
        "permissions": {
            WORKFLOW_SCOPE: {"contents": "read"},
            "analyze": {"contents": "read", "security-events": "write"},
        },
    },
    "dependency-review.yml": {
        "triggers": {"pull_request"},
        "jobs": {"dependency-review"},
        "permissions": {
            WORKFLOW_SCOPE: {"contents": "read"},
            "dependency-review": {"contents": "read"},
        },
    },
    "profile-quality.yml": {
        "triggers": {"pull_request", "push"},
        "jobs": {"validate", "integration"},
        "permissions": {
            WORKFLOW_SCOPE: {"contents": "read"},
            "validate": {"contents": "read"},
            "integration": {"contents": "read"},
        },
    },
    "profile-stats.yml": {
        "triggers": {"workflow_dispatch", "push", "schedule"},
        "jobs": {"generate", "attest", "publish"},
        "permissions": {
            WORKFLOW_SCOPE: {"contents": "read"},
            "generate": {"contents": "read"},
            "attest": {
                "contents": "read",
                "id-token": "write",
                "attestations": "write",
            },
            "publish": {"contents": "write"},
        },
    },
}

JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
PERMISSIONS_KEY = re.compile(r"^(\s*)permissions:\s*(.*)$")
PERMISSION_ENTRY = re.compile(r"^([A-Za-z0-9-]+):\s*(read|write|none)\s*$")
TRIGGER_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):(?:\s.*)?$")


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def parse_triggers(text: str, label: str) -> set[str]:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line == "on:"]
    require(len(starts) == 1, f"{label}: workflow must use exactly one mapping-style on: block")
    start = starts[0]
    triggers: set[str] = set()
    for line in lines[start + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indentation(line) == 0:
            break
        match = TRIGGER_KEY.match(line)
        if match:
            triggers.add(match.group(1))
    require(triggers, f"{label}: workflow trigger set is empty")
    return triggers


def parse_jobs(text: str, label: str) -> set[str]:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line == "jobs:"]
    require(len(starts) == 1, f"{label}: workflow must contain exactly one jobs: block")
    jobs: set[str] = set()
    for line in lines[starts[0] + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indentation(line) == 0:
            break
        match = JOB_KEY.match(line)
        if match:
            jobs.add(match.group(1))
    require(jobs, f"{label}: workflow job set is empty")
    return jobs


def parse_permissions(text: str, label: str) -> dict[str, dict[str, str]]:
    lines = text.splitlines()
    result: dict[str, dict[str, str]] = {}
    in_jobs = False
    current_job: str | None = None

    for index, line in enumerate(lines):
        if line == "jobs:":
            in_jobs = True
            current_job = None
            continue
        if in_jobs:
            job = JOB_KEY.match(line)
            if job:
                current_job = job.group(1)

        match = PERMISSIONS_KEY.match(line)
        if not match:
            continue

        indent = len(match.group(1))
        require(not match.group(2).strip(), f"{label}:{index + 1}: scalar/inline permissions are forbidden")
        if indent == 0:
            scope = WORKFLOW_SCOPE
        elif indent == 4 and current_job is not None:
            scope = current_job
        else:
            fail(f"{label}:{index + 1}: permissions block appears at an unreviewed scope")
        require(scope not in result, f"{label}: duplicate permissions block for {scope}")

        entries: dict[str, str] = {}
        cursor = index + 1
        while cursor < len(lines):
            candidate = lines[cursor]
            if not candidate.strip() or candidate.lstrip().startswith("#"):
                cursor += 1
                continue
            candidate_indent = indentation(candidate)
            if candidate_indent <= indent:
                break
            require(
                candidate_indent == indent + 2,
                f"{label}:{cursor + 1}: nested/indirect permissions syntax is forbidden",
            )
            stripped = candidate.strip()
            entry = PERMISSION_ENTRY.fullmatch(stripped)
            require(entry is not None, f"{label}:{cursor + 1}: unsupported permissions entry: {stripped}")
            key, value = entry.groups()
            require(key not in entries, f"{label}:{cursor + 1}: duplicate permission key: {key}")
            entries[key] = value
            cursor += 1
        require(entries, f"{label}: empty permissions block for {scope}")
        result[scope] = entries

    return result


def validate_workflow_text(filename: str, text: str, spec: dict[str, object]) -> None:
    triggers = parse_triggers(text, filename)
    jobs = parse_jobs(text, filename)
    permissions = parse_permissions(text, filename)
    require(triggers == spec["triggers"], f"{filename}: trigger authority changed: {sorted(triggers)}")
    require(jobs == spec["jobs"], f"{filename}: job inventory changed: {sorted(jobs)}")
    require(
        permissions == spec["permissions"],
        f"{filename}: token authority changed: {permissions!r}",
    )


def validate_inventory() -> None:
    require(WORKFLOWS.is_dir(), ".github/workflows is missing")
    paths = sorted({*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")})
    observed = {path.name for path in paths}
    expected = set(EXPECTED)
    require(
        observed == expected,
        "Workflow inventory changed without authority review; "
        f"expected={sorted(expected)} observed={sorted(observed)}",
    )
    for path in paths:
        validate_workflow_text(path.name, path.read_text(encoding="utf-8"), EXPECTED[path.name])


def validate_quality_contract(text: str) -> None:
    require(
        "python3 scripts/validate-workflow-authority-contract.py" in text,
        "Profile Quality must execute the workflow authority firewall",
    )
    require(
        '- ".github/workflows/**"' in text,
        "Profile Quality push paths must cover every workflow authority change",
    )


def validate_governance(text: str) -> None:
    for phrase in (
        "## Workflow authority firewall",
        "closed allowlist",
        "security-events: write",
        "id-token: write",
        "attestations: write",
        "contents: write",
        "pull_request_target",
        "new workflow",
    ):
        require(phrase in text, f"Workflow authority governance documentation is missing: {phrase}")


def expect_failure(text: str, expected_fragment: str) -> None:
    spec = {
        "triggers": {"pull_request"},
        "jobs": {"scan"},
        "permissions": {
            WORKFLOW_SCOPE: {"contents": "read"},
            "scan": {"contents": "read"},
        },
    }
    try:
        validate_workflow_text("self-test.yml", text, spec)
    except ValueError as exc:
        require(expected_fragment in str(exc), f"self-test failed for wrong reason: {exc}")
    else:
        fail(f"self-test accepted forbidden workflow drift: {expected_fragment}")


def self_test() -> None:
    good = """name: Self test
on:
  pull_request:
permissions:
  contents: read
jobs:
  scan:
    permissions:
      contents: read
    runs-on: ubuntu-24.04
"""
    validate_workflow_text(
        "self-test.yml",
        good,
        {
            "triggers": {"pull_request"},
            "jobs": {"scan"},
            "permissions": {
                WORKFLOW_SCOPE: {"contents": "read"},
                "scan": {"contents": "read"},
            },
        },
    )
    expect_failure(good.replace("  contents: read", "  contents: write", 1), "token authority changed")
    expect_failure(good.replace("  pull_request:\n", "  pull_request:\n  pull_request_target:\n"), "trigger authority changed")
    expect_failure(good.replace("jobs:\n", "jobs:\n  publish:\n    runs-on: ubuntu-24.04\n"), "job inventory changed")
    expect_failure(good.replace("permissions:\n  contents: read", "permissions: write-all", 1), "scalar/inline permissions")
    expect_failure(good.replace("      contents: read", "      contents: read\n      actions: write"), "token authority changed")


def main() -> int:
    try:
        for path in (QUALITY, GOVERNANCE):
            require(path.is_file(), f"Workflow authority input is missing: {path.relative_to(ROOT)}")
        self_test()
        validate_inventory()
        validate_quality_contract(QUALITY.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))
        print(
            "Workflow authority validation passed: the workflow/trigger/job inventory is closed, "
            "read-only is the default authority, and every write-capable permission remains isolated "
            "to an explicitly reviewed job."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
