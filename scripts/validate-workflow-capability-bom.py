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



def capability_measurement_diagnostic() -> None:
    """Disposable accepted-main carrier: measure corrected frozen #1304 with trusted-main code only."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return

    base_sha = "d4f3ec966f109ec646b8dfefbd35619d8cdd522c"
    source_sha = "3b80e7131e7c99a0cf8cf96e88e2fcec9f909022"
    expected_tree = "262652f64ce507454274d102ed77454428909335"
    expected_path = "scripts/workflow_capability_admission.py"
    expected_blob = "a832c73cc3be625a8af9b5997c815b73c3520dab"

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
    changed = subprocess.check_output(
        ["git", "diff", "--name-only", base_sha, source_sha], text=True
    ).splitlines()
    require(changed == [expected_path], f"diagnostic candidate path set changed: {changed!r}")
    observed_blob = subprocess.check_output(
        ["git", "rev-parse", f"{source_sha}:{expected_path}"], text=True
    ).strip()
    require(
        observed_blob == expected_blob,
        f"diagnostic candidate blob changed: {observed_blob}",
    )
    tree = subprocess.check_output(
        ["git", "rev-parse", f"{source_sha}^{{tree}}"], text=True
    ).strip()
    require(tree == expected_tree, f"diagnostic candidate tree changed: {tree}")

    with tempfile.TemporaryDirectory(prefix="capability-measurement-diagnostic-") as temporary:
        root = Path(temporary)
        trusted = root / "trusted"
        candidate = root / "candidate"
        subprocess.run(["git", "worktree", "add", "--detach", str(trusted), base_sha], check=True)
        subprocess.run(["git", "worktree", "add", "--detach", str(candidate), source_sha], check=True)

        code = r"""
from pathlib import Path
import json
import sys

trusted = Path(sys.argv[1]).resolve()
candidate = Path(sys.argv[2]).resolve()
tree = sys.argv[3]
source_sha = sys.argv[4]
sys.path.insert(0, str(trusted / "scripts"))

import trusted_workflow_capability as compiler
import workflow_capability_admission as admission
import workflow_capability_authorization as authorization
import workflow_capability_diff as diffmod
import workflow_capability_snapshot as snapshot

base = snapshot.load_combined()
candidate_bom = compiler.compile_repository(candidate)
diff = diffmod.semantic_diff(base, candidate_bom)
diff = admission.protect_trusted_control(base, candidate_bom, diff)
diff = admission.protect_trusted_sources(candidate, tree, diff)

ledger = admission.strict_json(
    admission.TRUSTED_LEDGER, "trusted capability authorization ledger"
)
authorization.validate_ledger(ledger)
matches = [
    entry for entry in ledger["authorizations"]
    if entry["baseBomSha256"] == diff["baseBomSha256"]
    and entry["candidateBomSha256"] == diff["candidateBomSha256"]
    and entry["expansionSha256"] == diff["expansionSha256"]
]
candidate_tcb_sha256 = sorted({
    item["after"]["candidateTcbSha256"]
    for item in diff["expansions"]
    if item.get("category") == "trusted-control-source"
    and isinstance(item.get("after"), dict)
    and isinstance(item["after"].get("candidateTcbSha256"), str)
})
measurement = {
    "candidateHead": source_sha,
    "candidateTree": tree,
    "baseBomSha256": diff["baseBomSha256"],
    "candidateBomSha256": diff["candidateBomSha256"],
    "expansionSha256": diff["expansionSha256"],
    "candidateTcbSha256": candidate_tcb_sha256,
    "expansionCount": len(diff["expansions"]),
    "reductionCount": len(diff["reductions"]),
    "priorMatches": len(matches),
    "matchingIds": [entry["id"] for entry in matches],
}
print(
    "CAPABILITY-MEASUREMENT-DIAGNOSTIC:"
    + json.dumps(measurement, sort_keys=True, separators=(",", ":")),
    flush=True,
)
"""
        result = subprocess.run(
            [sys.executable, "-c", code, str(trusted), str(candidate), tree, source_sha],
            text=True,
            capture_output=True,
        )
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        require(
            result.returncode == 0,
            f"#1304 capability measurement diagnostic subprocess failed: {result.returncode}",
        )

        subprocess.run(["git", "worktree", "remove", "--force", str(candidate)], check=True)
        subprocess.run(["git", "worktree", "remove", "--force", str(trusted)], check=True)


def main() -> int:
    try:
        workflows, jobs = validate_snapshot()
        capability_measurement_diagnostic()
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
