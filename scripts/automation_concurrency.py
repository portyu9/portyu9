#!/usr/bin/env python3
"""Compile Automation Policy IR concurrency classes against canonical workflow source."""
from __future__ import annotations

import copy
from pathlib import Path
import re
from typing import Any

WORKFLOW_LEVEL_CONCURRENCY = re.compile(r"(?m)^concurrency:\s*$")
SPOTLIGHT_AUTHORIZATION = ".github/SPOTLIGHT_UI_MERGE_AUTHORIZATION.md"
REQUIRED_AUTHORIZATION_PHRASES = (
    "scheduling isolation is explicit",
    "not authorization",
    "spotlight-link-sync-planning",
    "non-cancellable serialized terminal",
    "spotlight-link-sync-terminal",
    "queue: max",
    "concurrency only controls scheduling",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def job_block(text: str, job_id: str, next_job_id: str | None) -> str:
    marker = f"  {job_id}:\n"
    require(text.count(marker) == 1, f"concurrency compiler cannot isolate job: {job_id}")
    start = text.index(marker)
    if next_job_id is None:
        end = len(text)
    else:
        next_marker = f"  {next_job_id}:\n"
        require(text.count(next_marker) == 1,
                f"concurrency compiler cannot isolate next job: {next_job_id}")
        end = text.index(next_marker, start + len(marker))
    return text[start:end]


def validate_workflow_source(workflow_id: str, workflow: dict[str, Any], text: str) -> None:
    label = f"automation policy workflow {workflow_id} concurrency source"
    require(WORKFLOW_LEVEL_CONCURRENCY.search(text) is None,
            f"{label} must not use workflow-level concurrency")

    classes = workflow["concurrency"]
    membership: dict[str, tuple[str, dict[str, Any]]] = {}
    for class_id in ("planning", "terminal"):
        spec = classes[class_id]
        for job_id in spec["jobs"]:
            require(job_id not in membership, f"{label} class overlap reached source compiler: {job_id}")
            membership[job_id] = (class_id, spec)

    job_ids = list(workflow["jobs"])
    require(set(membership) == set(job_ids), f"{label} job membership differs from workflow inventory")
    require(text.count("    concurrency:\n") == len(job_ids),
            f"{label} must define exactly one job-level concurrency block per job")

    for index, job_id in enumerate(job_ids):
        next_job = job_ids[index + 1] if index + 1 < len(job_ids) else None
        block = job_block(text, job_id, next_job)
        class_id, spec = membership[job_id]
        require(block.count("    concurrency:\n") == 1,
                f"{label} job {job_id} must define exactly one concurrency block")
        require(block.count("      cancel-in-progress:") == 1,
                f"{label} job {job_id} must define exactly one cancellation policy")

        cancel = "true" if spec["cancelInProgress"] else "false"
        expected = (
            "    concurrency:\n"
            f"      group: {spec['group']}\n"
            f"      cancel-in-progress: {cancel}\n"
        )
        require(expected in block,
                f"{label} job {job_id} differs from {class_id} IR group/cancellation policy")

        if spec["queue"] == "max":
            require(block.count("      queue: max\n") == 1,
                    f"{label} job {job_id} must retain queue: max")
            require("      queue: single\n" not in block,
                    f"{label} job {job_id} cannot replace pending terminal work")
        else:
            require("      queue:" not in block,
                    f"{label} job {job_id} planning queue must retain GitHub single-pending latest-wins default")


def validate_authorization_policy(text: str) -> None:
    lower = text.lower()
    for phrase in REQUIRED_AUTHORIZATION_PHRASES:
        require(phrase in lower,
                f"autonomous concurrency standing authorization is missing: {phrase}")


def validate(policy: dict[str, Any], root: Path) -> None:
    candidate_prefix = policy["branches"]["spotlightCandidatePrefix"]
    require("//" not in candidate_prefix,
            "automation policy Spotlight candidate prefix cannot contain an empty path segment")

    observed_groups: set[str] = set()
    validated = 0
    for workflow_id, workflow in policy["workflows"].items():
        concurrency = workflow.get("concurrency")
        if concurrency is None:
            continue
        path = root / workflow["path"]
        require(path.is_file() and not path.is_symlink(),
                f"concurrency-governed workflow is missing or aliased: {workflow['path']}")
        text = path.read_text(encoding="utf-8")
        validate_workflow_source(workflow_id, workflow, text)
        for spec in concurrency.values():
            folded = spec["group"].casefold()
            require(folded not in observed_groups,
                    f"concurrency compiler observed duplicate group across workflows: {spec['group']}")
            observed_groups.add(folded)
        validated += 1
    require(validated == 2, f"concurrency compiler workflow inventory changed: {validated}")
    require(len(observed_groups) == 4, f"concurrency compiler group inventory changed: {len(observed_groups)}")

    policy_path = root / SPOTLIGHT_AUTHORIZATION
    require(policy_path.is_file() and not policy_path.is_symlink(),
            f"concurrency standing authorization is missing or aliased: {SPOTLIGHT_AUTHORIZATION}")
    validate_authorization_policy(policy_path.read_text(encoding="utf-8"))


def expect_source_failure(
    workflow_id: str,
    workflow: dict[str, Any],
    text: str,
    expected: str,
) -> None:
    try:
        validate_workflow_source(workflow_id, workflow, text)
    except ValueError as exc:
        require(expected in str(exc), f"concurrency source self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"concurrency source self-test accepted forbidden drift: {expected}")


def expect_policy_failure(text: str, expected: str) -> None:
    try:
        validate_authorization_policy(text)
    except ValueError as exc:
        require(expected in str(exc), f"concurrency authorization self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"concurrency authorization self-test accepted forbidden drift: {expected}")


def self_test(policy: dict[str, Any], root: Path) -> None:
    validate(policy, root)

    malformed_prefix = copy.deepcopy(policy)
    malformed_prefix["branches"]["spotlightCandidatePrefix"] = "automation//spotlight-links/"
    try:
        validate(malformed_prefix, root)
    except ValueError as exc:
        require("empty path segment" in str(exc),
                f"candidate-prefix normalization self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("candidate-prefix normalization self-test accepted an empty path segment")

    profile = policy["workflows"]["profile-stats"]
    profile_text = (root / profile["path"]).read_text(encoding="utf-8")
    expect_source_failure(
        "profile-stats",
        profile,
        profile_text.replace(
            "permissions:\n  contents: read\n",
            "permissions:\n  contents: read\n\nconcurrency:\n  group: retired-whole-workflow\n  cancel-in-progress: true\n",
            1,
        ),
        "must not use workflow-level concurrency",
    )
    expect_source_failure(
        "profile-stats",
        profile,
        profile_text.replace("      queue: max\n", "", 1),
        "must retain queue: max",
    )

    spotlight = policy["workflows"]["spotlight-link-sync"]
    spotlight_text = (root / spotlight["path"]).read_text(encoding="utf-8")
    expect_source_failure(
        "spotlight-link-sync",
        spotlight,
        spotlight_text.replace(
            "      group: spotlight-link-sync-planning\n      cancel-in-progress: true\n",
            "      group: spotlight-link-sync-planning\n      cancel-in-progress: false\n",
            1,
        ),
        "differs from planning IR group/cancellation policy",
    )
    expect_source_failure(
        "spotlight-link-sync",
        spotlight,
        spotlight_text.replace(
            "      group: spotlight-link-sync-terminal\n",
            "      group: profile-stats-terminal\n",
            1,
        ),
        "differs from terminal IR group/cancellation policy",
    )

    authorization = (root / SPOTLIGHT_AUTHORIZATION).read_text(encoding="utf-8")
    expect_policy_failure(
        re.sub(r"non-cancellable serialized terminal", "terminal", authorization, flags=re.IGNORECASE),
        "non-cancellable serialized terminal",
    )
