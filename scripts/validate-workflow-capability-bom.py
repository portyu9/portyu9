#!/usr/bin/env python3
"""Recompile and validate the canonical Workflow Capability BOM snapshot."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
from typing import Any

import automation_policy
import trusted_workflow_capability
import workflow_capability_bom as compiler
import workflow_capability_diff as capability_diff

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / ".github" / "workflow-capability-bom-v1.json"
EXPECTED_ROOT_KEYS = {"schemaVersion", "bomId", "repository", "automationPolicyId", "workflows"}


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


def validate_snapshot() -> tuple[int, int]:
    require(SNAPSHOT.is_file() and not SNAPSHOT.is_symlink(), "Workflow Capability BOM snapshot is missing or aliased")
    raw = SNAPSHOT.read_text(encoding="utf-8")
    try:
        snapshot = automation_policy.strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"Workflow Capability BOM JSON is invalid: {exc}") from exc
    require(isinstance(snapshot, dict), "Workflow Capability BOM root must be an object")
    require(set(snapshot) == EXPECTED_ROOT_KEYS,
            f"Workflow Capability BOM root keys changed: {sorted(snapshot)}")
    require(snapshot.get("schemaVersion") == compiler.SCHEMA_VERSION,
            "Workflow Capability BOM schema version changed")
    require(snapshot.get("bomId") == compiler.BOM_ID, "Workflow Capability BOM identity changed")
    require(snapshot.get("repository") == automation_policy.REPOSITORY,
            "Workflow Capability BOM repository changed")
    require(snapshot.get("automationPolicyId") == automation_policy.POLICY_ID,
            "Workflow Capability BOM Automation Policy binding changed")

    compiler.self_test()
    capability_diff.self_test()
    trusted_workflow_capability.self_test()
    compiled = compiler.compile_bom()
    canonical = compiler.canonical_json(compiled)
    difference = first_difference(compiled, snapshot)
    if difference is not None:
        raise ValueError(f"Workflow Capability BOM snapshot differs from compiled source: {difference}")

    require(raw == canonical,
            "Workflow Capability BOM bytes are not canonical: "
            f"expected_sha256={hashlib.sha256(canonical.encode()).hexdigest()} "
            f"observed_sha256={hashlib.sha256(raw.encode()).hexdigest()}")

    identity_diff = capability_diff.semantic_diff(snapshot, compiled)
    require(not identity_diff["hasExpansion"] and not identity_diff["reductions"],
            "identical canonical BOMs produced a semantic capability diff")

    workflows = compiled["workflows"]
    jobs = sum(len(workflow["jobs"]) for workflow in workflows)
    require(len(workflows) == 5, f"Workflow Capability BOM workflow count changed: {len(workflows)}")
    require(jobs > 0, "Workflow Capability BOM contains no jobs")
    return len(workflows), jobs


def main() -> int:
    try:
        workflows, jobs = validate_snapshot()
        print(
            f"Workflow Capability BOM validation passed: {workflows} workflows, {jobs} jobs; "
            "semantic diff and trusted alternate-tree compiler self-tests passed."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
