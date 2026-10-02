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


def item28_shared_control_plane_epoch_measurement_diagnostic() -> None:
    """Disposable carrier: measure frozen production #1500 using exact accepted main."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return

    base_sha = "df28f36990a417c9d6a178ca503dc4b7333088c5"
    source_sha = "7820d022d00e1d431a829e84891d48684c0ff735"
    expected_tree = "37f136ecab39103660b90ad278a4cc350fcdb95e"
    expected_blobs = {
        ".github/attestation/automation-decision-receipt-v1.schema.json": "f3d3497b4d512ef6ea5347637588f48bfdaf6a54",
        ".github/workflow-capability-bom-v1.json": "884d7a946025426234e01323721099aa279ea230",
        ".github/workflows/profile-stats.yml": "2f2c8a6f0741f7120c194cf624b59b387adec55d",
        ".github/workflows/spotlight-link-sync.yml": "a895db4a36a7f17e7287ab3c045796bd9e7fb07a",
        "scripts/automation_decision_receipt.py": "ac4e6a92dc7225528e100e9fe74582b813625887",
        "scripts/automation_decision_receipt_schema.py": "02d7cb46f9d89a78547cdb7b616fc256d88df453",
        "scripts/governance_contract_item10_core.py": "a4f2e4fe3835cd121179276d47803ab8c2cf4dec",
        "scripts/privileged_workflow_identity_v21_core.py": "c2830c8854a6a2fc223dd5ff620dd52f88094e8d",
        "scripts/profile-stats-source-epoch-v1.json": "c3a3eff0efb324650f863cf1d900f3f27f3fa212",
        "scripts/profile_stats_decision_receipt.py": "d6e62ac3d727e4c118c2c14e5e89773d67dc4dd7",
        "scripts/validate-privileged-workflow-identity.py": "3017f03f8f4df7470537cfb089541a9964eb9a0e",
        "scripts/workflow_capability_bom.py": "37ebf33530f16a361f16378e45461ca662d95b13",
    }

    subprocess.run(
        ["git", "fetch", "--no-tags", "--depth=128", "origin", base_sha, source_sha],
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

    with tempfile.TemporaryDirectory(prefix="item28-shared-control-plane-epoch-measurement-") as temporary:
        root = Path(temporary)
        trusted = root / "trusted"
        candidate = root / "candidate"
        subprocess.run(["git", "worktree", "add", "--detach", str(trusted), base_sha], check=True)
        subprocess.run(["git", "worktree", "add", "--detach", str(candidate), source_sha], check=True)
        try:
            probe = (
                "import pathlib,sys; "
                "sys.path.insert(0, str(pathlib.Path.cwd() / 'scripts')); "
                "import workflow_capability_admission as admission; "
                "import workflow_capability_bom as bom; "
                "candidate=pathlib.Path(sys.argv[1]); tree=sys.argv[2]; "
                "diff=admission.measure(candidate, candidate_tree_sha=tree); "
                "print(bom.canonical_json({'measurement': admission.public_measurement(diff, candidate_tree_sha=tree)}), end='')"
            )
            result = subprocess.run(
                [sys.executable, "-c", probe, str(candidate), tree],
                cwd=trusted,
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
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(candidate)], check=False)
            subprocess.run(["git", "worktree", "remove", "--force", str(trusted)], check=False)


def main() -> int:
    try:
        workflows, jobs = validate_snapshot()
        item28_shared_control_plane_epoch_measurement_diagnostic()
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
