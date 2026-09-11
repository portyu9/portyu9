#!/usr/bin/env python3
"""Fail closed when governance/threat-model docs drift from the active trust graph."""
from __future__ import annotations

from pathlib import Path
import re
import sys

import automation_policy

ROOT = Path(__file__).resolve().parents[1]
GOV = ROOT / ".github" / "GOVERNANCE.md"
THREAT = ROOT / ".github" / "THREAT_MODEL.md"
SYNC = ROOT / ".github" / "workflows" / "spotlight-link-sync.yml"

SEMANTICS = "execution-result-subject-binding-freshness-v1"
CHECKPOINT = "**Checkpoint:** 2026-09-10"

GOV_REQUIRED = (
    CHECKPOINT,
    "Portfolio Evidence Ledger v2",
    "GitHub evidence → Portfolio Evidence Ledger → validated Engineering Spotlight projection",
    "exactly **11 subjects**",
    "spotlight-manifest.json",
    "frozen historical verification contract",
    "profile-evidence-v3.schema.json",
    "profile-evidence-v2.schema.json",
    "predicateSchema",
    "PL2-",
    SEMANTICS,
    "execution result",
    "subject binding",
    "freshness",
    "DIFFERENT_SUBJECT",
    "CURRENT_SUBJECT",
    "validate-profile-cache-contract.py",
    "generate-read-only",
    "prepare-attestation-read-only",
    "attest-write-only",
    "publish-write-only",
    "dispatch-spotlight-link-sync",
    "reconcile-stale-candidates-write",
    "stale-only monotone reconciliation",
    "30-minute stale floor",
    "source-epoch mutation budget",
    "diagnostic-only quarantine",
    "id-token: write",
    "attestations: write",
    "no repository-authored shell",
    "validate-ruleset-contract.py --live",
    "live GitHub control-plane",
    "admin-scope",
    "does **not certify every software behavior**",
)

THREAT_REQUIRED = (
    CHECKPOINT,
    "one Portfolio Evidence Ledger snapshot",
    "exactly 11 files",
    "Ledger-backed Spotlight projection",
    "frozen historical verification contract",
    "profile-evidence-v3.schema.json",
    "profile-evidence-v2.schema.json",
    "predicateSchema.digest",
    "PL2-",
    SEMANTICS,
    "execution result",
    "subject binding",
    "freshness",
    "DIFFERENT_SUBJECT",
    "CURRENT_SUBJECT",
    "Profile image cache boundary",
    "validate-ruleset-contract.py --live",
    "live GitHub control-plane",
    "admin-scope",
    "redact",
    "spotlight-manifest.json",
    "generated",
    "exactly five workflows",
    "spotlight-link-sync.yml",
    "dispatch-spotlight-link-sync",
    "reconcile-stale-candidates-write",
    "30-minute",
    "monotone-reductive",
    "source-epoch mutation budget",
    "diagnostic-only quarantine",
    "prepare-attestation-read-only",
    "attest-write-only",
    "stage-publication-read-only",
    "exactly four digest-checked downloads",
    "Local/composite `uses: ./...` execution is currently forbidden",
)

FORBIDDEN = (
    "merge-readme-only-after-required-checks",
    "Baseline: `main` after PR #65",
    "root is expected to contain only the generated Signal Field and Engineering Spotlight artifact trees",
    "revalidates both evidence sets",
    "New production attestations use `profile-evidence-v2.schema.json`",
    "current issuance uses v2",
    "PL1-XXXXXXXXXXXXXXXX",
    "signal state, and UTC whole-day freshness",
    "audited separately from source-controlled validators",
    "inspect repository rulesets separately from source-controlled validation",
    "redacted bypass actors are empty",
    "closed allowlist of exactly four workflows",
    "Reviewed write-capable exceptions are limited to CodeQL",
    "resets the fixed `automation/spotlight-links` branch",
    "update the fixed bot branch",
    "delete the fixed bot branch",
)

JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
NAME_KEY = re.compile(r"^    name:\s+([^#]+?)\s*$")
PERMISSION_KEY = re.compile(r"^      ([A-Za-z0-9-]+):\s*(read|write|none)\s*$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def spotlight_jobs(policy: dict[str, object]) -> dict[str, tuple[str, tuple[tuple[str, str], ...]]]:
    _workflow_id, workflow = automation_policy.workflow_by_path(policy, ".github/workflows/spotlight-link-sync.yml")
    jobs = workflow["jobs"]
    require(isinstance(jobs, dict), "Automation Policy IR Spotlight jobs are malformed")
    model: dict[str, tuple[str, tuple[tuple[str, str], ...]]] = {}
    for job_id, job in jobs.items():
        require(isinstance(job_id, str) and isinstance(job, dict), "Automation Policy IR Spotlight job entry is malformed")
        name = job.get("name")
        permissions = job.get("permissions")
        require(isinstance(name, str) and isinstance(permissions, dict),
                f"Automation Policy IR Spotlight job semantics are malformed: {job_id}")
        model[job_id] = (name, tuple(permissions.items()))
    require(model, "Automation Policy IR Spotlight job graph is empty")
    return model


def job_blocks(workflow: str) -> dict[str, str]:
    lines = workflow.splitlines()
    starts = [i for i, line in enumerate(lines) if line == "jobs:"]
    require(len(starts) == 1, "Spotlight workflow must contain exactly one jobs: block")
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines[starts[0] + 1 :]:
        if line and indentation(line) == 0:
            break
        match = JOB_KEY.fullmatch(line)
        if match:
            current = match.group(1)
            require(current not in blocks, f"duplicate Spotlight job identity: {current}")
            blocks[current] = [line]
            continue
        if current is not None:
            blocks[current].append(line)
    require(blocks, "Spotlight workflow job graph is empty")
    return {key: "\n".join(value) for key, value in blocks.items()}


def parse_job_semantics(block: str, job_id: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    lines = block.splitlines()
    names = [match.group(1).strip() for line in lines if (match := NAME_KEY.fullmatch(line))]
    require(len(names) == 1, f"Spotlight job {job_id} must expose exactly one canonical name")

    permission_starts = [i for i, line in enumerate(lines) if line == "    permissions:"]
    require(len(permission_starts) == 1, f"Spotlight job {job_id} must expose exactly one permissions block")
    permissions: list[tuple[str, str]] = []
    for line in lines[permission_starts[0] + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indentation(line) <= 4:
            break
        entry = PERMISSION_KEY.fullmatch(line)
        require(entry is not None, f"Spotlight job {job_id} contains unsupported permission syntax: {line.strip()}")
        pair = entry.groups()
        require(pair[0] not in {key for key, _ in permissions},
                f"Spotlight job {job_id} contains duplicate permission: {pair[0]}")
        permissions.append(pair)
    require(permissions, f"Spotlight job {job_id} permissions are empty")
    return names[0], tuple(permissions)


def validate_spotlight_workflow(
    workflow: str,
    expected_jobs: dict[str, tuple[str, tuple[tuple[str, str], ...]]],
) -> None:
    blocks = job_blocks(workflow)
    require(set(blocks) == set(expected_jobs),
            f"Spotlight assurance job inventory differs from Automation Policy IR: {sorted(blocks)}")
    observed = {job_id: parse_job_semantics(blocks[job_id], job_id) for job_id in blocks}
    require(observed == expected_jobs,
            f"Spotlight assurance authority graph differs from Automation Policy IR: observed={observed!r}")


def permission_markdown(permissions: tuple[tuple[str, str], ...]) -> str:
    return ", ".join(f"`{key}: {value}`" for key, value in permissions)


def validate_doc_job_graph(
    text: str,
    expected_jobs: dict[str, tuple[str, tuple[tuple[str, str], ...]]],
    *,
    label: str,
    table_scope: str,
) -> None:
    lines = text.splitlines()
    for _job_id, (name, permissions) in expected_jobs.items():
        rows = [line for line in lines if line.startswith(f"| {table_scope} / ") and f"`{name}`" in line]
        require(len(rows) == 1, f"{label} must contain exactly one authority-table row for {name}")
        expected = f"| {table_scope} / `{name}` | {permission_markdown(permissions)} |"
        require(rows[0].startswith(expected),
                f"{label} authority-table permissions drifted from Automation Policy IR for {name}: {rows[0]}")


def validate_required_phrases(governance: str, threat: str) -> None:
    for phrase in GOV_REQUIRED:
        require(phrase in governance, f"governance contract is missing current architecture phrase: {phrase}")
    for phrase in THREAT_REQUIRED:
        require(phrase in threat, f"threat model is missing current architecture phrase: {phrase}")
    joined = governance + "\n" + threat
    for phrase in FORBIDDEN:
        require(phrase not in joined, f"stale assurance statement remains: {phrase}")


def remove_authority_row(text: str, name: str) -> str:
    return "\n".join(line for line in text.splitlines() if not (line.startswith("| ") and f"`{name}`" in line)) + "\n"


def expect_failure(action, expected: str) -> None:
    try:
        action()
    except ValueError as exc:
        require(expected in str(exc), f"assurance self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"assurance self-test accepted forbidden drift: {expected}")


def self_test(
    workflow: str,
    governance: str,
    threat: str,
    expected_jobs: dict[str, tuple[str, tuple[tuple[str, str], ...]]],
) -> None:
    merge_name, merge_permissions = expected_jobs["merge"]
    stale_workflow = workflow.replace(
        f"name: {merge_name}",
        "name: merge-readme-only-after-required-checks",
        1,
    )
    expect_failure(
        lambda: validate_spotlight_workflow(stale_workflow, expected_jobs),
        "differs from Automation Policy IR",
    )

    overstated = governance.replace(
        permission_markdown(merge_permissions),
        "`contents: write`, `pull-requests: write`, `checks: read`",
        1,
    )
    expect_failure(
        lambda: validate_doc_job_graph(
            overstated,
            expected_jobs,
            label="governance",
            table_scope="Spotlight link sync",
        ),
        f"permissions drifted from Automation Policy IR for {merge_name}",
    )

    reconcile_name = expected_jobs["reconcile"][0]
    missing_reconcile = remove_authority_row(governance, reconcile_name)
    expect_failure(
        lambda: validate_doc_job_graph(
            missing_reconcile,
            expected_jobs,
            label="governance",
            table_scope="Spotlight link sync",
        ),
        reconcile_name,
    )

    budget_name = expected_jobs["budget"][0]
    missing_budget = remove_authority_row(governance, budget_name)
    expect_failure(
        lambda: validate_doc_job_graph(
            missing_budget,
            expected_jobs,
            label="governance",
            table_scope="Spotlight link sync",
        ),
        budget_name,
    )

    quarantine_name = expected_jobs["quarantine"][0]
    missing_quarantine = remove_authority_row(threat, quarantine_name)
    expect_failure(
        lambda: validate_doc_job_graph(
            missing_quarantine,
            expected_jobs,
            label="threat model",
            table_scope="Spotlight",
        ),
        quarantine_name,
    )

    stale_fixed_branch = governance.replace(
        "derives `automation/spotlight-links/<sha256(main SHA, generated SHA, proposed README digest)>`",
        "resets the fixed `automation/spotlight-links` branch",
        1,
    )
    expect_failure(
        lambda: validate_required_phrases(stale_fixed_branch, threat),
        "stale assurance statement remains",
    )


def main() -> int:
    try:
        for path in (GOV, THREAT, SYNC, automation_policy.POLICY_PATH):
            require(path.is_file() and not path.is_symlink(),
                    f"assurance input is missing or aliased: {path.relative_to(ROOT)}")
        governance = GOV.read_text(encoding="utf-8")
        threat = THREAT.read_text(encoding="utf-8")
        workflow = SYNC.read_text(encoding="utf-8")
        policy = automation_policy.load_policy()
        expected_jobs = spotlight_jobs(policy)

        validate_spotlight_workflow(workflow, expected_jobs)
        validate_doc_job_graph(governance, expected_jobs, label="governance", table_scope="Spotlight link sync")
        validate_doc_job_graph(threat, expected_jobs, label="threat model", table_scope="Spotlight")
        validate_required_phrases(governance, threat)
        self_test(workflow, governance, threat, expected_jobs)

        print(
            "Assurance documentation contract passed: governance and threat model are compiled against the Automation Policy IR "
            "seven-job Spotlight authority graph, including stale-only monotone reconciliation, Actions-read-only source-epoch "
            "constructive-mutation admission, diagnostic-only quarantine, PR-write proposal, Actions-only approval, and terminal "
            "contents-write/PR-read/check-read merge authority; Ledger v2, predicate v3, historical schema immutability, cache "
            "boundaries, live ruleset drift verification, and admin-scope audit semantics remain intact."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())