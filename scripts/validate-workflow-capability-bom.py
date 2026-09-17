#!/usr/bin/env python3
"""Recompile and validate the canonical Workflow Capability BOM snapshot."""
from __future__ import annotations

import sys
from typing import Any

import capability_admission_workflow_contract
import trusted_workflow_capability
import workflow_capability_admission
import workflow_capability_authorization
import workflow_capability_bom as compiler
import workflow_capability_diff as capability_diff
import workflow_capability_snapshot


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def first_difference(expected: Any, observed: Any, path: str = "$") -> str | None:
    if type(expected) is not type(observed):
        return f"{path}: type expected={type(expected).__name__} observed={type(observed).__name__}"
    if isinstance(expected, dict):
        expected_keys = set(expected)
        observed_keys = set(observed)
        if expected_keys != observed_keys:
            return f"{path}: keys expected={sorted(expected_keys)} observed={sorted(observed_keys)}"
        for key in sorted(expected):
            difference = first_difference(expected[key], observed[key], f"{path}.{key}")
            if difference is not None:
                return difference
        return None
    if isinstance(expected, list):
        if len(expected) != len(observed):
            return f"{path}: length expected={len(expected)} observed={len(observed)}"
        for index, (left, right) in enumerate(zip(expected, observed, strict=True)):
            difference = first_difference(left, right, f"{path}[{index}]")
            if difference is not None:
                return difference
        return None
    if expected != observed:
        return f"{path}: expected={expected!r} observed={observed!r}"
    return None


def codeql_extension(compiled: dict[str, Any]) -> dict[str, Any]:
    matches = [workflow for workflow in compiled["workflows"] if workflow.get("id") == "codeql-autofix"]
    require(len(matches) == 1, "diagnostic expected exactly one CodeQL Autofix workflow")
    return {
        "schemaVersion": compiled["schemaVersion"],
        "bomId": compiled["bomId"],
        "repository": compiled["repository"],
        "automationPolicyId": compiled["automationPolicyId"],
        "workflows": matches,
    }


def validate_snapshot() -> tuple[int, int]:
    snapshot = workflow_capability_snapshot.load_combined()

    compiler.self_test()
    capability_diff.self_test()
    trusted_workflow_capability.self_test()
    workflow_capability_authorization.self_test()
    workflow_capability_snapshot.self_test()
    capability_admission_workflow_contract.self_test()
    capability_admission_workflow_contract.validate()
    workflow_capability_admission.self_test()

    compiled = compiler.compile_bom()
    difference = first_difference(compiled, snapshot)
    if difference is not None:
        print("CANONICAL-CODEQL-AUTOFIX-EXTENSION-BEGIN", file=sys.stderr)
        print(compiler.canonical_json(codeql_extension(compiled)), file=sys.stderr, end="")
        print("CANONICAL-CODEQL-AUTOFIX-EXTENSION-END", file=sys.stderr)
        raise ValueError(f"Workflow Capability BOM snapshot differs from compiled source: {difference}")

    require(compiler.canonical_json(snapshot) == compiler.canonical_json(compiled),
            "composite Workflow Capability BOM canonical bytes differ from live compilation")
    identity_diff = capability_diff.semantic_diff(snapshot, compiled)
    require(not identity_diff["hasExpansion"] and not identity_diff["reductions"],
            "identical canonical BOMs produced a semantic capability diff")

    workflows = compiled["workflows"]
    jobs = sum(len(workflow["jobs"]) for workflow in workflows)
    require(len(workflows) == 7, f"Workflow Capability BOM workflow count changed: {len(workflows)}")
    require(jobs > 0, "Workflow Capability BOM contains no jobs")
    return len(workflows), jobs


def main() -> int:
    try:
        workflows, jobs = validate_snapshot()
        print(
            f"Workflow Capability BOM validation passed: {workflows} workflows, {jobs} jobs; "
            "semantic diff, trusted alternate-tree compiler, exact expansion authorization, "
            "composite snapshot, exact trusted-workflow bytes, and admission self-tests passed."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
