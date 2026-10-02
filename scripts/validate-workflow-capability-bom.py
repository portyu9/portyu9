#!/usr/bin/env python3
"""Recompile and validate the canonical Workflow Capability BOM snapshot."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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



def control_plane_recovery_measurement_diagnostic_v1() -> None:
    """Disposable carrier: measure frozen #1512 from exact accepted main."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return

    base_sha = "6e46f5d19f6b17ec8eb386049d37dd227cca19d5"
    source_sha = "9cbca1e7ae9b59bc6d0a7bd64a953da553306fec"
    expected_tree = "5631969afb8299ae8a2263672bc53ec805a91220"
    expected_blobs = {
        ".github/attestation/ruleset-reconciliation-receipt-v1.schema.json": "dcd01be439de50223e0c83451a04a6de371e4f82",
        ".github/automation-policy-v1.json": "0c96510820ad8c16e442909506e703744d4f9c26",
        ".github/rulesets/ruleset-transitions-v1.json": "84aaf2325816077c550522f9e59ca2dfedbd0fa3",
        ".github/workflow-capability-bom-v1-ruleset-reconciler.json": "401dab1a05f0edaf0125c7ef977cf46182d8dd29",
        ".github/workflows/ruleset-reconciler.yml": "3f0e45cf1ab4b2f35ccbe4fed17f98492a34d35b",
        "scripts/ruleset_transition_contract.py": "35a3040b11169708fc8a28658d89c480f13387d4",
        "scripts/validate-ruleset-contract.py": "5a098a606e8f376b6d10bc0fbebbc9c2b0034aac",
        "scripts/workflow_capability_snapshot.py": "a1bda50ae99abc5eed5585dea2ea97a882515e73",
    }

    subprocess.run(["git", "fetch", "--no-tags", "--depth=128", "origin", base_sha, source_sha], check=True)
    merge_base = subprocess.check_output(["git", "merge-base", base_sha, source_sha], text=True).strip()
    require(merge_base == base_sha, f"diagnostic candidate no longer descends from exact accepted main: {merge_base}")
    observed_paths = subprocess.check_output(["git", "diff", "--name-only", base_sha, source_sha], text=True).splitlines()
    require(observed_paths == sorted(expected_blobs), f"diagnostic candidate path set changed: {observed_paths!r}")
    for changed_path, expected_blob in expected_blobs.items():
        observed_blob = subprocess.check_output(
            ["git", "rev-parse", f"{source_sha}:{changed_path}"], text=True
        ).strip()
        require(observed_blob == expected_blob, f"diagnostic candidate blob changed for {changed_path}: {observed_blob}")
    tree = subprocess.check_output(["git", "rev-parse", f"{source_sha}^{{tree}}"], text=True).strip()
    require(tree == expected_tree, f"diagnostic candidate tree changed: {tree}")

    with tempfile.TemporaryDirectory(prefix="control-plane-recovery-measurement-v1-") as temporary:
        root = Path(temporary)
        trusted = root / "trusted"
        candidate = root / "candidate"
        subprocess.run(["git", "worktree", "add", "--detach", str(trusted), base_sha], check=True)
        subprocess.run(["git", "worktree", "add", "--detach", str(candidate), source_sha], check=True)
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(trusted / "scripts/workflow_capability_admission.py"),
                    str(candidate),
                    "--candidate-tree-sha",
                    tree,
                    "--measure",
                ],
                text=True,
                capture_output=True,
            )
            if result.stderr:
                print(result.stderr, file=sys.stderr, end="")
            require(result.returncode == 0, f"accepted-main production --measure failed: {result.returncode}")
            payload = json.loads(result.stdout)
            require(
                isinstance(payload, dict)
                and set(payload) == {"measurement"}
                and isinstance(payload["measurement"], dict),
                "production --measure output shape changed",
            )
            print(
                "CAPABILITY-MEASUREMENT-DIAGNOSTIC:"
                + json.dumps(payload, sort_keys=True, separators=(",", ":")),
                flush=True,
            )
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(candidate)], check=False)
            subprocess.run(["git", "worktree", "remove", "--force", str(trusted)], check=False)


def main() -> int:
    try:
        workflows, jobs = validate_snapshot()
        control_plane_recovery_measurement_diagnostic_v1()
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
