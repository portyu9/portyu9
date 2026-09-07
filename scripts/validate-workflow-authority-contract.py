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

import spotlight_profile_links as spotlight_links

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"
SYNC = WORKFLOWS / "spotlight-link-sync.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"
README = ROOT / "README.md"

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
    "spotlight-link-sync.yml": {
        "triggers": {"workflow_dispatch", "schedule"},
        "jobs": {"plan", "propose", "approve", "merge"},
        "permissions": {
            WORKFLOW_SCOPE: {"contents": "read"},
            "plan": {"contents": "read"},
            "propose": {"contents": "write", "pull-requests": "write"},
            "approve": {"actions": "write"},
            "merge": {"contents": "write", "pull-requests": "write", "checks": "read"},
        },
    },
}

JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
PERMISSIONS_KEY = re.compile(r"^(\s*)permissions:\s*(.*)$")
PERMISSION_ENTRY = re.compile(r"^([A-Za-z0-9-]+):\s*(read|write|none)\s*$")
TRIGGER_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):(?:\s.*)?$")
SHA40 = re.compile(r"[0-9a-f]{40}")


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
            require(candidate_indent == indent + 2,
                    f"{label}:{cursor + 1}: nested/indirect permissions syntax is forbidden")
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
    require(permissions == spec["permissions"], f"{filename}: token authority changed: {permissions!r}")


def job_block(text: str, key: str, next_key: str | None) -> str:
    start = re.search(rf"(?m)^  {re.escape(key)}:\s*$", text)
    require(start is not None, f"workflow job is missing: {key}")
    if next_key is None:
        return text[start.start():]
    end = re.search(rf"(?m)^  {re.escape(next_key)}:\s*$", text[start.end():])
    require(end is not None, f"workflow job boundary is missing after {key}: {next_key}")
    return text[start.start(): start.end() + end.start()]


def validate_inventory() -> None:
    require(WORKFLOWS.is_dir(), ".github/workflows is missing")
    paths = sorted({*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")})
    observed = {path.name for path in paths}
    expected = set(EXPECTED)
    require(observed == expected,
            "Workflow inventory changed without authority review; "
            f"expected={sorted(expected)} observed={sorted(observed)}")
    for path in paths:
        validate_workflow_text(path.name, path.read_text(encoding="utf-8"), EXPECTED[path.name])


def validate_quality_contract(text: str) -> None:
    require("python3 scripts/validate-workflow-authority-contract.py" in text,
            "Profile Quality must execute the workflow authority firewall")
    require('- ".github/workflows/**"' in text,
            "Profile Quality push paths must cover every workflow authority change")


def validate_sync_contract(workflow: str, readme: str) -> None:
    for forbidden in ("pull_request_target", "workflow_run", "repository_dispatch", "issues: write", "id-token: write", "attestations: write"):
        require(forbidden not in workflow, f"Spotlight direct-link sync contains forbidden authority/trigger: {forbidden}")
    require('BOT_BRANCH: "automation/spotlight-links"' in workflow, "Spotlight bot branch identity changed")
    require('ref: generated' in workflow and 'persist-credentials: false' in workflow,
            "Spotlight plan must read the generated branch without persisted credentials")
    require("validate-portfolio-evidence-ledger.py published/portfolio-evidence --require-live" in workflow,
            "Spotlight plan must revalidate the published Ledger before selecting links")
    require("generate-engineering-spotlight.py projected-spotlight" in workflow,
            "Spotlight plan must reconstruct the deterministic projection from the published Ledger")
    require('cmp "projected-spotlight/spotlight-${slot}-${theme}.svg"' in workflow,
            "Spotlight plan must byte-compare all regenerated card variants with published evidence")
    require("spotlight_profile_links.py" in workflow and "spotlight-link-plan/plan.json" in workflow,
            "Spotlight plan must use the reviewed deterministic link renderer")

    propose = job_block(workflow, "propose", "approve")
    approve = job_block(workflow, "approve", "merge")
    merge = job_block(workflow, "merge", None)
    for block, label in ((propose, "propose"), (approve, "approve"), (merge, "merge")):
        require("actions/checkout@" not in block and "actions/setup-python@" not in block,
                f"Spotlight {label} authority job must not checkout or execute authored Python")
    require('test "$(jq -r .base_sha "$PLAN")" = "$SOURCE_SHA"' in propose,
            "Spotlight proposal must bind the plan to the exact main source SHA")
    require('test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$SOURCE_SHA"' in propose,
            "Spotlight proposal must fail if main moved")
    require('test "$(jq \'length\' <<<"$FILES")" = "1"' in merge and
            'test "$(jq -r \'.[0].filename\' <<<"$FILES")" = "README.md"' in merge,
            "Spotlight merge must enforce one-file README-only closure")
    require('app.id == 15368' in merge,
            "Spotlight merge must bind required checks to the GitHub Actions integration")
    for check in ("analyze-actions", "analyze-python", "dependency-review", "integration-pinned-upstream", "validate-contracts"):
        require(check in merge, f"Spotlight merge is missing required check: {check}")
    require('merge_method:"merge"' in merge and 'sha:$sha' in merge,
            "Spotlight merge must use exact-head merge-commit semantics")
    require('/approve' in approve and 'actions/runs?head_sha=${HEAD_SHA}&event=pull_request' in approve,
            "Spotlight approval job must be scoped to the exact automation PR head")

    require(readme.count(spotlight_links.START) == 1 and readme.count(spotlight_links.END) == 1,
            "README must contain exactly one guarded Spotlight direct-link block")
    start = readme.index(spotlight_links.START)
    end = readme.index(spotlight_links.END, start) + len(spotlight_links.END)
    block = readme[start:end]
    require("issues/122" not in block, "Spotlight direct-link block must not route through issue #122")
    card_targets = re.findall(r'<a href="(https://github\.com/portyu9/[A-Za-z0-9_.-]+)"><picture>', block)
    workflow_targets = re.findall(r'<a href="(https://github\.com/portyu9/[A-Za-z0-9_.-]+/actions/workflows/(?:ci|security)\.yml)">', block)
    require(len(card_targets) == 3 and len(set(card_targets)) == 3,
            "Spotlight direct-link block must contain three distinct repository card targets")
    require(len(workflow_targets) == 6 and len(set(workflow_targets)) == 6,
            "Spotlight direct-link block must contain six distinct direct workflow targets")
    image_shas = re.findall(r'raw\.githubusercontent\.com/portyu9/portyu9/([0-9a-f]{40})/engineering-spotlight/spotlight-[123]-(?:light|dark)\.svg', block)
    require(len(image_shas) == 6 and len(set(image_shas)) == 1,
            "All six Spotlight image variants must bind one immutable generated commit")
    require(block.count("img.shields.io/github/actions/workflow/status/portyu9/") == 6,
            "Spotlight external controls must use six live workflow-status badges")


def validate_governance(text: str) -> None:
    for phrase in (
        "## Workflow authority firewall",
        "closed allowlist",
        "security-events: write",
        "id-token: write",
        "attestations: write",
        "contents: write",
        "pull-requests: write",
        "actions: write",
        "checks: read",
        "Spotlight direct-link synchronization",
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
    spotlight_links.self_test()


def main() -> int:
    try:
        for path in (QUALITY, GOVERNANCE, README, SYNC):
            require(path.is_file(), f"Workflow authority input is missing: {path.relative_to(ROOT)}")
        self_test()
        validate_inventory()
        validate_quality_contract(QUALITY.read_text(encoding="utf-8"))
        validate_sync_contract(SYNC.read_text(encoding="utf-8"), README.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))
        print(
            "Workflow authority validation passed: five workflows form a closed authority inventory; "
            "read-only remains the default, direct Spotlight synchronization is PR-gated, and each "
            "write/Actions/check capability is isolated to one reviewed terminal purpose."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
