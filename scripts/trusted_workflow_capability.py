#!/usr/bin/env python3
"""Compile Workflow Capabilities from an alternate repository tree using trusted code.

This module is intended for default-branch admission code. The repository tree supplied to
`compile_repository()` is untrusted data: no Python, Action, or shell content from that tree
is imported or executed. Parsing/validation logic comes exclusively from the trusted
checkout that imported this module.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import automation_policy
import workflow_authority_contract_core as authority
import workflow_capability_bom as compiler

TRUSTED_ROOT = Path(__file__).resolve().parents[1]
POLICY_RELATIVE = Path(".github/automation-policy-v1.json")
WORKFLOWS_RELATIVE = Path(".github/workflows")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_inventory(expected: list[str], observed: list[str], label: str) -> None:
    require(expected == sorted(set(expected)), f"{label}: expected workflow inventory is not canonical/unique")
    require(observed == sorted(set(observed)), f"{label}: observed workflow inventory is not canonical/unique")
    require(observed == expected,
            f"{label}: workflow inventory changed: expected={expected} observed={observed}")


def workflow_sources(root: Path, policy: dict[str, Any]) -> list[tuple[str, str, Path]]:
    workflows_dir = root / WORKFLOWS_RELATIVE
    require(workflows_dir.is_dir() and not workflows_dir.is_symlink(),
            f"candidate workflow directory is missing or aliased: {workflows_dir}")
    specs: list[tuple[str, str, Path]] = []
    for workflow_id, workflow in policy["workflows"].items():
        relative = workflow["path"]
        require(isinstance(relative, str), f"candidate workflow path is malformed: {workflow_id}")
        path = root / relative
        require(path.is_file() and not path.is_symlink(),
                f"candidate workflow source is missing or aliased: {relative}")
        specs.append((relative, workflow_id, path))
    specs.sort()
    expected = [relative for relative, _, _ in specs]
    observed = sorted(
        path.relative_to(root).as_posix()
        for path in {*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml")}
    )
    validate_inventory(expected, observed, "candidate repository")
    return specs


def compile_repository(root: Path) -> dict[str, Any]:
    """Compile a repository tree as data, executing only this trusted module set."""
    root = root.resolve(strict=True)
    require(root.is_dir() and not root.is_symlink(), f"candidate repository root is invalid: {root}")
    policy_path = root / POLICY_RELATIVE
    require(policy_path.is_file() and not policy_path.is_symlink(),
            f"candidate Automation Policy is missing or aliased: {policy_path}")

    # automation_policy.load_policy() validates arbitrary non-default policy paths with the
    # trusted parser. Source-coupled default-root checks intentionally remain owned by the
    # trusted checkout; candidate workflow bytes are independently compiled below.
    policy = automation_policy.load_policy(policy_path)
    policy_specs = authority.policy_specs(policy)
    workflows: list[dict[str, Any]] = []

    for relative, workflow_id, path in workflow_sources(root, policy):
        text = path.read_text(encoding="utf-8")
        filename = path.name
        require(filename in policy_specs, f"candidate workflow missing from policy specs: {filename}")
        authority.validate_workflow_text(filename, text, policy_specs[filename])
        names, needs = authority.parse_job_metadata(text, filename)
        permissions = authority.parse_permissions(text, filename)
        jobs = sorted(names)
        effective = compiler.effective_permissions(permissions, jobs, filename)
        compiled_steps = compiler.compile_steps(text, relative, jobs)
        blocks = compiler.job_blocks(text, jobs, filename)
        top_name = compiler.TOP_NAME.search(text)
        require(top_name is not None, f"{filename}: candidate workflow name is missing")

        job_entries: list[dict[str, Any]] = []
        for job in jobs:
            entry = {
                "id": job,
                "name": names[job],
                "needs": needs[job],
                "permissions": effective[job],
                "oidc": effective[job].get("id-token") == "write",
                "references": compiler.expression_references(blocks[job]),
                **compiled_steps[job],
            }
            compiler.validate_job_authority(filename, entry)
            job_entries.append(entry)

        workflows.append({
            "id": workflow_id,
            "name": compiler.unquote(top_name.group("name")),
            "path": relative,
            "triggers": compiler.parse_trigger_details(text, filename),
            "workflowPermissions": {
                key: permissions[authority.WORKFLOW_SCOPE][key]
                for key in sorted(permissions[authority.WORKFLOW_SCOPE])
            },
            "jobs": job_entries,
            "references": compiler.expression_references(text),
        })

    return {
        "schemaVersion": compiler.SCHEMA_VERSION,
        "bomId": compiler.BOM_ID,
        "repository": policy["repository"],
        "automationPolicyId": policy["policyId"],
        "workflows": workflows,
    }


def expect_failure(callback, fragment: str) -> None:
    try:
        callback()
    except ValueError as exc:
        require(fragment in str(exc), f"trusted candidate compiler self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"trusted candidate compiler self-test accepted forbidden input: {fragment}")


def self_test() -> None:
    # On the trusted repository itself, alternate-tree orchestration must be byte-identical
    # to the item-12 canonical compiler. This proves there is one capability semantics layer.
    trusted = compile_repository(TRUSTED_ROOT)
    canonical = compiler.compile_bom()
    require(compiler.canonical_json(trusted) == compiler.canonical_json(canonical),
            "trusted alternate-tree compiler diverged from canonical item-12 compilation")

    validate_inventory(
        [".github/workflows/a.yml", ".github/workflows/b.yml"],
        [".github/workflows/a.yml", ".github/workflows/b.yml"],
        "self-test",
    )
    expect_failure(
        lambda: validate_inventory(
            [".github/workflows/a.yml"],
            [".github/workflows/a.yml", ".github/workflows/unmodeled.yml"],
            "self-test",
        ),
        "workflow inventory changed",
    )
    expect_failure(
        lambda: validate_inventory(
            [".github/workflows/a.yml", ".github/workflows/a.yml"],
            [".github/workflows/a.yml"],
            "self-test",
        ),
        "expected workflow inventory is not canonical/unique",
    )


if __name__ == "__main__":
    self_test()
    print("Trusted alternate-tree Workflow Capability compiler self-test passed.")
