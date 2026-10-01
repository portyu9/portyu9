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


def dependabot_maintainer_flag_volatility_measurement_diagnostic() -> None:
    """Disposable carrier: measure frozen production #1471 with exact accepted main."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return

    base_sha = "cb1dcc46b1ff430a935db714faf71190d0949382"
    source_sha = "87ea09ae696665856308982873c3ea4c8fd99358"
    expected_tree = "78d5a6b13db0e8bbf511c6dcd02425376ce42c38"
    expected_blobs = {
        ".github/workflows/capability-admission.yml": "bac9f39e9489c0b542d2fee3a03d72fb86c12bbb",
        ".github/workflows/profile-quality.yml": "f392c0d0351f55de82adf0331f4dd8d63b7753a9",
        "scripts/capability_admission_workflow_contract.py": "542064d6d586fcd09e0ca81b21e431d5e543d674",
        "scripts/dependabot_controller.py": "d6fbca25c4dfb049c8e410628f6ee3b53a5395ef",
        "scripts/dependabot_pr_identity.py": "c96222e960e00806e4adc2ec7f8cd858e7b5b20c",
        "scripts/validate-dependabot-contract.py": "7d5c82babd34f9e56a0677d43c5d4c7c586ccd6f",
        "scripts/validate-governance-contract.py": "9426816cb8dd157d7829cf61c5b4cd65b4565659",
        "scripts/validate-privileged-workflow-identity.py": "0a03aaacb6901de46bdb76f1016bb86ea9c39970",
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

    with tempfile.TemporaryDirectory(prefix="dependabot-maintainer-flag-measurement-") as temporary:
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
        dependabot_maintainer_flag_volatility_measurement_diagnostic()
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
