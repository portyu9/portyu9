#!/usr/bin/env python3
"""Compile short-lived autonomous mutation leases from Automation Policy IR to workflow source."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

LEASE_TTL_SECONDS = 1800
LEASE_IDENTITY_FIELDS = [
    "repository",
    "repositoryId",
    "workflowPath",
    "workflowRef",
    "workflowSha",
    "runId",
    "runAttempt",
    "baseSha",
    "candidateId",
    "issuedAt",
    "expiresAt",
]
LEASE_WORKFLOWS = {"profile-stats", "spotlight-link-sync"}
LEASE_STEP_NAME = "Verify exact short-lived mutation lease"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    observed = set(value)
    require(observed == expected,
            f"{label} keys changed: expected={sorted(expected)} observed={sorted(observed)}")
    return value


def validate_policy(workflow_id: str, workflow: dict[str, Any]) -> None:
    label = f"automation policy workflow {workflow_id} lease"
    require(workflow_id in LEASE_WORKFLOWS, f"{label} is not an authorized lease workflow")
    spec = exact_keys(
        workflow["lease"],
        {"job", "ttlSeconds", "identityFields", "boundJobs"},
        label,
    )
    jobs = workflow["jobs"]
    lease_job = spec["job"]
    require(isinstance(lease_job, str) and lease_job in jobs,
            f"{label} job must reference a declared workflow job")
    require(type(spec["ttlSeconds"]) is int and spec["ttlSeconds"] == LEASE_TTL_SECONDS,
            f"{label} ttlSeconds must remain exactly {LEASE_TTL_SECONDS}")
    require(spec["identityFields"] == LEASE_IDENTITY_FIELDS,
            f"{label} identityFields changed")
    bound_jobs = spec["boundJobs"]
    require(isinstance(bound_jobs, list) and bound_jobs and
            all(isinstance(job_id, str) and job_id for job_id in bound_jobs),
            f"{label} boundJobs must contain non-empty job ids")
    require(len(bound_jobs) == len(set(bound_jobs)), f"{label} boundJobs must be unique")
    for job_id in bound_jobs:
        require(job_id in jobs, f"{label} references unknown bound job: {job_id}")
    require(lease_job not in bound_jobs, f"{label} lease job cannot consume its own lease")

    lease_permissions = jobs[lease_job]["permissions"]
    require(lease_permissions == {"actions": "read"},
            f"{label} mint job must retain only Actions-read authority")
    write_jobs = {
        job_id for job_id, job in jobs.items()
        if any(permission == "write" for permission in job["permissions"].values())
    }
    require(set(bound_jobs) == write_jobs,
            f"{label} boundJobs must equal the complete write-capable job set: "
            f"expected={sorted(write_jobs)} observed={sorted(bound_jobs)}")

    terminal_jobs = set(workflow["concurrency"]["terminal"]["jobs"])
    require(lease_job in terminal_jobs, f"{label} mint job must remain in terminal concurrency")
    require(set(bound_jobs) <= terminal_jobs,
            f"{label} bound mutation jobs must remain in terminal concurrency")


def job_block(text: str, job_id: str, next_job_id: str | None) -> str:
    marker = f"  {job_id}:\n"
    require(text.count(marker) == 1, f"mutation lease compiler cannot isolate job: {job_id}")
    start = text.index(marker)
    if next_job_id is None:
        return text[start:]
    next_marker = f"  {next_job_id}:\n"
    require(text.count(next_marker) == 1,
            f"mutation lease compiler cannot isolate next job: {next_job_id}")
    end = text.index(next_marker, start + len(marker))
    return text[start:end]


def validate_workflow_source(workflow_id: str, workflow: dict[str, Any], text: str) -> None:
    spec = workflow["lease"]
    label = f"automation policy workflow {workflow_id} mutation lease source"
    job_ids = list(workflow["jobs"])
    lease_job_id = spec["job"]
    lease_index = job_ids.index(lease_job_id)
    lease_next = job_ids[lease_index + 1] if lease_index + 1 < len(job_ids) else None
    lease = job_block(text, lease_job_id, lease_next)

    workflow_path = workflow["path"]
    expected_ref = f'EXPECTED_WORKFLOW_REF="${{GITHUB_REPOSITORY}}/{workflow_path}@refs/heads/main"'
    for fragment in (
        "name: mint-mutation-lease-read-only",
        "permissions:\n      actions: read",
        "id: lease",
        f"LEASE_TTL_SECONDS={LEASE_TTL_SECONDS}",
        'RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}")"',
        'test "$(jq -r .id <<<"$RUN")" = "$GITHUB_RUN_ID"',
        'test "$(jq -r .run_attempt <<<"$RUN")" = "$GITHUB_RUN_ATTEMPT"',
        'test "$(jq -r .head_sha <<<"$RUN")" = "$BASE_SHA"',
        f'test "$(jq -r .path <<<"$RUN")" = "{workflow_path}"',
        'test "$(jq -r .repository.id <<<"$RUN")" = "$GITHUB_REPOSITORY_ID"',
        'test "$(jq -r .head_repository.id <<<"$RUN")" = "$GITHUB_REPOSITORY_ID"',
        expected_ref,
        'test "$GITHUB_WORKFLOW_REF" = "$EXPECTED_WORKFLOW_REF"',
        '[[ "$GITHUB_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]',
        'EXPIRES_AT=$((ISSUED_AT + LEASE_TTL_SECONDS))',
        'printf \'%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n\'',
        'echo "lease_id=$LEASE_ID" >> "$GITHUB_OUTPUT"',
        'echo "issued_at=$ISSUED_AT" >> "$GITHUB_OUTPUT"',
        'echo "expires_at=$EXPIRES_AT" >> "$GITHUB_OUTPUT"',
        'echo "base_sha=$BASE_SHA" >> "$GITHUB_OUTPUT"',
        'echo "candidate_id=$CANDIDATE_ID" >> "$GITHUB_OUTPUT"',
    ):
        require(fragment in lease, f"{label} mint job is missing: {fragment}")
    for forbidden in ("contents: write", "pull-requests: write", "actions: write", "checks: write"):
        require(forbidden not in lease, f"{label} mint job acquired write authority: {forbidden}")

    for job_id in spec["boundJobs"]:
        index = job_ids.index(job_id)
        next_job = job_ids[index + 1] if index + 1 < len(job_ids) else None
        block = job_block(text, job_id, next_job)
        require(block.count(f"- name: {LEASE_STEP_NAME}") == 1,
                f"{label} bound job {job_id} must verify exactly one mutation lease")
        for fragment in (
            f"LEASE_TTL_SECONDS={LEASE_TTL_SECONDS}",
            'test "$LEASE_BASE_SHA" = "$EXPECTED_BASE_SHA"',
            'test "$LEASE_CANDIDATE_ID" = "$EXPECTED_CANDIDATE_ID"',
            expected_ref,
            'test "$GITHUB_WORKFLOW_REF" = "$EXPECTED_WORKFLOW_REF"',
            '[[ "$GITHUB_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]',
            'test "$LEASE_EXPIRES_AT" -eq $((LEASE_ISSUED_AT + LEASE_TTL_SECONDS))',
            'test "$NOW_EPOCH" -ge "$LEASE_ISSUED_AT"',
            'test "$NOW_EPOCH" -lt "$LEASE_EXPIRES_AT"',
            'test "$EXPECTED_LEASE_ID" = "$LEASE_ID"',
        ):
            require(fragment in block,
                    f"{label} bound job {job_id} lost lease proof: {fragment}")


def validate_source(policy: dict[str, Any], root: Path) -> None:
    observed = set()
    for workflow_id in LEASE_WORKFLOWS:
        workflow = policy["workflows"][workflow_id]
        validate_policy(workflow_id, workflow)
        path = root / workflow["path"]
        require(path.is_file() and not path.is_symlink(),
                f"mutation lease workflow is missing or aliased: {workflow['path']}")
        validate_workflow_source(workflow_id, workflow, path.read_text(encoding="utf-8"))
        observed.add(workflow_id)
    require(observed == LEASE_WORKFLOWS, "mutation lease workflow inventory changed")


def expect_policy_failure(workflow_id: str, workflow: dict[str, Any], expected: str) -> None:
    try:
        validate_policy(workflow_id, workflow)
    except ValueError as exc:
        require(expected in str(exc), f"mutation lease policy self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"mutation lease policy self-test accepted forbidden drift: {expected}")


def expect_source_failure(workflow_id: str, workflow: dict[str, Any], text: str, expected: str) -> None:
    try:
        validate_workflow_source(workflow_id, workflow, text)
    except ValueError as exc:
        require(expected in str(exc), f"mutation lease source self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"mutation lease source self-test accepted forbidden drift: {expected}")


def self_test(policy: dict[str, Any], root: Path) -> None:
    validate_source(policy, root)

    profile = copy.deepcopy(policy["workflows"]["profile-stats"])
    profile["lease"]["ttlSeconds"] = LEASE_TTL_SECONDS + 1
    expect_policy_failure("profile-stats", profile, "ttlSeconds must remain exactly")

    spotlight = copy.deepcopy(policy["workflows"]["spotlight-link-sync"])
    spotlight["lease"]["boundJobs"].remove("merge")
    expect_policy_failure("spotlight-link-sync", spotlight, "complete write-capable job set")

    profile_source = (root / policy["workflows"]["profile-stats"]["path"]).read_text(encoding="utf-8")
    expect_source_failure(
        "profile-stats",
        policy["workflows"]["profile-stats"],
        profile_source.replace(f"LEASE_TTL_SECONDS={LEASE_TTL_SECONDS}", "LEASE_TTL_SECONDS=3600", 1),
        f"LEASE_TTL_SECONDS={LEASE_TTL_SECONDS}",
    )

    spotlight_source = (root / policy["workflows"]["spotlight-link-sync"]["path"]).read_text(encoding="utf-8")
    expect_source_failure(
        "spotlight-link-sync",
        policy["workflows"]["spotlight-link-sync"],
        spotlight_source.replace(f"- name: {LEASE_STEP_NAME}", "- name: Retired lease gate", 1),
        "must verify exactly one mutation lease",
    )
