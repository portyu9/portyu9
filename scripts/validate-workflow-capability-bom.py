#!/usr/bin/env python3
"""Recompile and validate the canonical Workflow Capability BOM snapshot."""
from __future__ import annotations

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


def trusted_diagnostic() -> None:
    """Disposable carrier: derive the exact frozen #736 tuple with accepted-main admission code."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return

    trusted_base_sha = "3ab5faee17fd8a3b2744bfd08e958fda2943f891"
    frozen_source_sha = "9e566569504eefbc3f2048b207f154cd892e316c"
    frozen_source_tree = "6444531dd9e712a6d1808a4eafb95f89c8ce51ab"
    root = Path.cwd().resolve()

    observed_source = subprocess.check_output(
        ["git", "rev-parse", f"{frozen_source_sha}^{{commit}}"], cwd=root, text=True
    ).strip()
    observed_tree = subprocess.check_output(
        ["git", "rev-parse", f"{frozen_source_sha}^{{tree}}"], cwd=root, text=True
    ).strip()
    require(observed_source == frozen_source_sha,
            "trusted diagnostic source commit identity changed")
    require(observed_tree == frozen_source_tree,
            "trusted diagnostic source tree identity changed")

    subprocess.run(
        ["git", "fetch", "--no-tags", "--depth=1", "origin", trusted_base_sha],
        cwd=root,
        check=True,
    )
    with tempfile.TemporaryDirectory(prefix="trusted-base-") as temporary:
        trusted = Path(temporary) / "repo"
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(trusted), trusted_base_sha],
            cwd=root,
            check=True,
        )
        try:
            code = (
                "from pathlib import Path\n"
                "import sys\n"
                "trusted=Path(sys.argv[1]).resolve(); candidate=Path(sys.argv[2]).resolve(); tree=sys.argv[3]\n"
                "sys.path.insert(0, str(trusted / 'scripts'))\n"
                "import workflow_capability_admission as admission\n"
                "try:\n"
                "    admission.evaluate(candidate, candidate_tree_sha=tree)\n"
                "except ValueError as exc:\n"
                "    print('TRUSTED-ADMISSION-DIAGNOSTIC:', exc)\n"
                "    raise SystemExit(0)\n"
                "raise SystemExit('trusted diagnostic unexpectedly admitted frozen source')\n"
            )
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    code,
                    str(trusted),
                    str(root),
                    frozen_source_tree,
                ],
                cwd=root,
                check=True,
            )
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(trusted)],
                cwd=root,
                check=True,
            )


def main() -> int:
    try:
        workflows, jobs = validate_snapshot()
        trusted_diagnostic()
        print(
            f"Workflow Capability BOM validation passed: {workflows} workflows, {jobs} jobs; "
            "semantic diff, trusted alternate-tree compiler, exact expansion authorization, "
            "composite snapshot, exact trusted-workflow bytes, and admission self-tests passed."
        )
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
