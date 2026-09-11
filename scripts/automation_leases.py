#!/usr/bin/env python3
"""Compile short-lived autonomous mutation leases from Automation Policy IR to workflow source."""
from __future__ import annotations

import copy
from pathlib import Path
import re
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
LEASE_PROOF_MARKER = "# Verify exact short-lived mutation lease."
TIMEOUT_RE = re.compile(r"(?m)^    timeout-minutes: ([1-9][0-9]*)$")


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
        {"job", "ttlSeconds", "identityFields", "boundJobs", "minimumRemainingSeconds"},
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

    remaining = spec["minimumRemainingSeconds"]
    require(isinstance(remaining, dict), f"{label} minimumRemainingSeconds must be an object")
    require(set(remaining) == set(bound_jobs),
            f"{label} minimumRemainingSeconds must cover exactly boundJobs")
    for job_id, seconds in remaining.items():
        require(type(seconds) is int and 0 < seconds < LEASE_TTL_SECONDS,
                f"{label} minimumRemainingSeconds must be a positive integer below TTL: {job_id}")

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


def validate_profile_candidate_binding(text: str, label: str) -> None:
    """Keep the leased semantic candidate bound to the live generated base and exact predicate."""
    for fragment in (
        'GENERATED_SHA: ${{ needs.attest.outputs.generated_sha }}',
        'PREDICATE_SHA256: ${{ needs.attest.outputs.predicate_sha256 }}',
        'EXPECTED_CANDIDATE_ID="$(printf \'%s\\n%s\\n%s\\n\' "$BASE_SHA" "$GENERATED_SHA" "$PREDICATE_SHA256" | sha256sum | cut -d\' \' -f1)"',
        'test "$CANDIDATE_ID" = "$EXPECTED_CANDIDATE_ID"',
        'REMOTE_GENERATED="$(git ls-remote --exit-code "https://github.com/${GITHUB_REPOSITORY}.git" refs/heads/generated)"',
        '[[ "$REMOTE_GENERATED" =~ ^([0-9a-f]{40})[[:space:]]refs/heads/generated$ ]]',
        'test "${BASH_REMATCH[1]}" = "$GENERATED_SHA"',
        '- name: Verify leased attestation predicate identity',
        'EXPECTED_PREDICATE_SHA256: ${{ needs.attest.outputs.predicate_sha256 }}',
        'test "$(sha256sum attestation-input/attestation-predicate.json | cut -d\' \' -f1)" = "$EXPECTED_PREDICATE_SHA256"',
        'LEASED_GENERATED_SHA: ${{ needs.attest.outputs.generated_sha }}',
        '[[ "$LEASED_GENERATED_SHA" =~ ^[0-9a-f]{40}$ ]]',
        'test "$base_sha" = "$LEASED_GENERATED_SHA"',
    ):
        require(
            fragment in text,
            f"{label} lost Profile Stats generated base or predicate candidate binding: {fragment}",
        )


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

    if workflow_id == "profile-stats":
        validate_profile_candidate_binding(text, label)

    for job_id in spec["boundJobs"]:
        index = job_ids.index(job_id)
        next_job = job_ids[index + 1] if index + 1 < len(job_ids) else None
        block = job_block(text, job_id, next_job)
        proof_count = block.count(f"- name: {LEASE_STEP_NAME}") + block.count(LEASE_PROOF_MARKER)
        require(proof_count == 1,
                f"{label} bound job {job_id} must verify exactly one mutation lease")
        timeouts = TIMEOUT_RE.findall(block)
        require(len(timeouts) == 1, f"{label} bound job {job_id} must declare one literal timeout-minutes")
        timeout_seconds = int(timeouts[0]) * 60
        minimum_remaining = spec["minimumRemainingSeconds"][job_id]
        require(minimum_remaining >= timeout_seconds,
                f"{label} bound job {job_id} lease reserve is below its hard timeout")
        for fragment in (
            f"LEASE_TTL_SECONDS={LEASE_TTL_SECONDS}",
            f"LEASE_MIN_REMAINING_SECONDS={minimum_remaining}",
            'test "$LEASE_BASE_SHA" = "$EXPECTED_BASE_SHA"',
            'test "$LEASE_CANDIDATE_ID" = "$EXPECTED_CANDIDATE_ID"',
            expected_ref,
            'test "$GITHUB_WORKFLOW_REF" = "$EXPECTED_WORKFLOW_REF"',
            '[[ "$GITHUB_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]',
            'test "$LEASE_EXPIRES_AT" -eq $((LEASE_ISSUED_AT + LEASE_TTL_SECONDS))',
            'test "$NOW_EPOCH" -ge "$LEASE_ISSUED_AT"',
            'test "$NOW_EPOCH" -lt "$LEASE_EXPIRES_AT"',
            'test $((LEASE_EXPIRES_AT - NOW_EPOCH)) -ge "$LEASE_MIN_REMAINING_SECONDS"',
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
    expect_policy_failure("spotlight-link-sync", spotlight, "minimumRemainingSeconds must cover exactly boundJobs")

    missing_reserve = copy.deepcopy(policy["workflows"]["profile-stats"])
    del missing_reserve["lease"]["minimumRemainingSeconds"]["dispatch"]
    expect_policy_failure("profile-stats", missing_reserve, "minimumRemainingSeconds must cover exactly boundJobs")

    profile_source = (root / policy["workflows"]["profile-stats"]["path"]).read_text(encoding="utf-8")
    expect_source_failure(
        "profile-stats",
        policy["workflows"]["profile-stats"],
        profile_source.replace(f"LEASE_TTL_SECONDS={LEASE_TTL_SECONDS}", "LEASE_TTL_SECONDS=3600", 1),
        f"LEASE_TTL_SECONDS={LEASE_TTL_SECONDS}",
    )
    expect_source_failure(
        "profile-stats",
        policy["workflows"]["profile-stats"],
        profile_source.replace(
            'test "${BASH_REMATCH[1]}" = "$GENERATED_SHA"',
            'test "${BASH_REMATCH[1]}" = "$BASE_SHA"',
            1,
        ),
        "generated base",
    )
    expect_source_failure(
        "profile-stats",
        policy["workflows"]["profile-stats"],
        profile_source.replace(
            'test "$base_sha" = "$LEASED_GENERATED_SHA"',
            'test "$base_sha" = "$base_sha"',
            1,
        ),
        "generated base",
    )
    expect_source_failure(
        "profile-stats",
        policy["workflows"]["profile-stats"],
        profile_source.replace("LEASE_MIN_REMAINING_SECONDS=300", "LEASE_MIN_REMAINING_SECONDS=239", 1),
        "LEASE_MIN_REMAINING_SECONDS=300",
    )

    under_timeout = copy.deepcopy(policy["workflows"]["spotlight-link-sync"])
    under_timeout["lease"]["minimumRemainingSeconds"]["approve"] = 719
    spotlight_source = (root / policy["workflows"]["spotlight-link-sync"]["path"]).read_text(encoding="utf-8")
    expect_source_failure(
        "spotlight-link-sync",
        under_timeout,
        spotlight_source.replace("LEASE_MIN_REMAINING_SECONDS=780", "LEASE_MIN_REMAINING_SECONDS=719", 1),
        "lease reserve is below its hard timeout",
    )
    expect_source_failure(
        "spotlight-link-sync",
        policy["workflows"]["spotlight-link-sync"],
        spotlight_source.replace(LEASE_PROOF_MARKER, "# Retired lease gate.", 1),
        "must verify exactly one mutation lease",
    )
