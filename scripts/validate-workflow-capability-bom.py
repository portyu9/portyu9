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


def validate_snapshot() -> tuple[int, int]:
    snapshot = workflow_capability_snapshot.load_combined()

    compiler.self_test()
    capability_diff.self_test()
    trusted_workflow_capability.self_test()
    workflow_capability_authorization.self_test()
    workflow_capability_snapshot.self_test()
    capability_admission_workflow_contract.self_test()
    capability_admission_workflow_contract.validate()

    compiled = compiler.compile_bom()
    difference = first_difference(compiled, snapshot)
    if difference is not None:
        raise ValueError(f"Workflow Capability BOM snapshot differs from compiled source: {difference}")

    # Run the admission self-test only after canonical snapshot parity is proven so
    # a stale snapshot reports its exact first mismatch instead of surfacing as a
    # generic trusted-repository capability drift.
    workflow_capability_admission.self_test()

    require(compiler.canonical_json(snapshot) == compiler.canonical_json(compiled),
            "composite Workflow Capability BOM canonical bytes differ from live compilation")
    identity_diff = capability_diff.semantic_diff(snapshot, compiled)
    require(not identity_diff["hasExpansion"] and not identity_diff["reductions"],
            "identical canonical BOMs produced a semantic capability diff")

    workflows = compiled["workflows"]
    jobs = sum(len(workflow["jobs"]) for workflow in workflows)
    require(len(workflows) == 13, f"Workflow Capability BOM workflow count changed: {len(workflows)}")
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
    # Read-only disposable measurement carrier. The production candidate is
    # checked out only as inert data; evaluator modules remain accepted main.
    exit_code = main()
    if exit_code == 0:
        import json
        import subprocess
        import tempfile
        from pathlib import Path

        FROZEN_SHA = "06c6c86eb2d9b2d9646c38a8b11b3ec29f6c78fd"
        FROZEN_TREE = "2e450505718b0b519a707750dbe677bd1dcc363a"
        with tempfile.TemporaryDirectory(prefix="measure-independent-activity-") as dirname:
            candidate = Path(dirname) / "candidate"
            candidate.mkdir()
            subprocess.run(["git", "init", "-q", str(candidate)], check=True)
            subprocess.run([
                "git", "-C", str(candidate), "fetch", "-q", "--depth=1",
                "https://github.com/portyu9/portyu9.git",
                "refs/heads/feat/independent-activity-metrics-5min-20261023",
            ], check=True)
            subprocess.run(["git", "-C", str(candidate), "checkout", "-q", "--detach", "FETCH_HEAD"], check=True)
            commit_sha = subprocess.check_output(
                ["git", "-C", str(candidate), "rev-parse", "HEAD"], text=True
            ).strip()
            tree_sha = subprocess.check_output(
                ["git", "-C", str(candidate), "rev-parse", "HEAD^{tree}"], text=True
            ).strip()
            require(commit_sha == FROZEN_SHA and tree_sha == FROZEN_TREE,
                    "frozen activity candidate SHA or tree changed")
            difference = workflow_capability_admission.measure(
                candidate, candidate_tree_sha=FROZEN_TREE,
            )
            measurement = workflow_capability_admission.public_measurement(
                difference, candidate_tree_sha=FROZEN_TREE,
            )
            print("EXACT_ACTIVITY_AUTHORIZATION_MEASUREMENT=" +
                  json.dumps(measurement, sort_keys=True, separators=(",", ":")), flush=True)
    raise SystemExit(exit_code)
