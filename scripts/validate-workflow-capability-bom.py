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




def python_runtime_31316_measurement_diagnostic() -> None:
    """Disposable carrier: measure frozen #1430 with accepted-main admission code."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return

    base_sha = "a708e91b7ec9c95d9734b52deee2855955da8e60"
    source_sha = "fa25b96ef86e7655d5e01e207613696a4e1e39f3"
    expected_tree = "0e5cdafeaa646431bf5246f21ba618bddb1a0120"
    expected_blobs = {
        ".github/workflows/action-provenance-witness.yml": "698282d814a2629d630f78f062f225baac1a2f5a",
        ".github/workflows/capability-admission.yml": "fc50c88a2e3050fe3bc9a16acc3ae4beea2c253d",
        ".github/workflows/codeql-autofix.yml": "eff5d5e11460aeeb3bea94fba475c4fde906294e",
        ".github/workflows/dependabot-controller.yml": "2d76bc7f0fcf9859a2f51c7c342b5539136f4599",
        ".github/workflows/profile-generator-compatibility-witness.yml": "c84766aa80cec21576be1312e887cedda21f02b6",
        ".github/workflows/profile-quality.yml": "de900445f3c019b156c8dcc639670cb1e2dc0c91",
        ".github/workflows/profile-stats.yml": "0a6a2ff4924a9c5e27c20f0feb69f5c8e7756001",
        ".github/workflows/spotlight-link-sync.yml": "df15c37d6890e8f3a6eb348535966d16642405d5",
        "scripts/capability_admission_workflow_contract.py": "eca911ec939f181d381c7275098776716576da71",
        "scripts/check-python-maintenance-freshness.py": "27df57ca8b14afe9158a74c3606560353edad2e4",
        "scripts/governance_contract_item10_core.py": "2a31a52f2985cb8a0829495cebadd1fde17a9a9e",
        "scripts/profile-stats-source-epoch-v1.json": "4f20b149071bb3e571007bf45ae85f042e744696",
        "scripts/python_runtime_contract_core.py": "edc9fa4fb6926b8e1598d53397a25c8cd440f1e9",
        "scripts/validate-privileged-workflow-identity.py": "a9e05860433bd03c81c0d1cb969bce77cfc2a089",
    }

    subprocess.run(
        ["git", "fetch", "--no-tags", "--depth=64", "origin", base_sha, source_sha],
        check=True,
    )
    merge_base = subprocess.check_output(
        ["git", "merge-base", base_sha, source_sha], text=True
    ).strip()
    require(
        merge_base == base_sha,
        f"diagnostic candidate no longer descends from exact accepted main: {merge_base}",
    )
    observed_paths = subprocess.check_output(
        ["git", "diff", "--name-only", base_sha, source_sha], text=True
    ).splitlines()
    require(
        observed_paths == sorted(expected_blobs),
        f"diagnostic candidate path set changed: {observed_paths!r}",
    )
    for changed_path, expected_blob in expected_blobs.items():
        observed_blob = subprocess.check_output(
            ["git", "rev-parse", f"{source_sha}:{changed_path}"], text=True
        ).strip()
        require(
            observed_blob == expected_blob,
            f"diagnostic candidate blob changed for {changed_path}: {observed_blob}",
        )
    tree = subprocess.check_output(
        ["git", "rev-parse", f"{source_sha}^{{tree}}"], text=True
    ).strip()
    require(tree == expected_tree, f"diagnostic candidate tree changed: {tree}")

    with tempfile.TemporaryDirectory(prefix="python-runtime-31316-measurement-") as temporary:
        root = Path(temporary)
        trusted = root / "trusted"
        candidate = root / "candidate"
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(trusted), base_sha],
            check=True,
        )
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(candidate), source_sha],
            check=True,
        )
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
        require(
            result.returncode == 0,
            f"accepted-main production --measure failed: {result.returncode}",
        )
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

        subprocess.run(
            ["git", "worktree", "remove", "--force", str(candidate)], check=True
        )
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(trusted)], check=True
        )

def main() -> int:
    try:
        workflows, jobs = validate_snapshot()
        python_runtime_31316_measurement_diagnostic()
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
