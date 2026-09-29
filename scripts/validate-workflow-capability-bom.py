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



def profile_quality_post_authorization_admission_diagnostic() -> None:
    """Disposable accepted-main carrier: expose exact #1300 post-authorization admission result."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return

    base_sha = "259636517039adaed278dcc116e82db7b305b4bb"
    source_sha = "fb8d5a4a6d2c332e46fcf52e21d18e5716d496bd"
    expected_tree = "ba96fafe62a5ad7c37c0f8804ebffb0c194f6cab"
    expected_blobs = {
        ".github/workflow-capability-bom-v1.json": "33c1e83de510b569d8d0fafefd3ae2700ccc839d",
        ".github/workflows/profile-quality.yml": "0a682e8956a5a1efee1308728aeeb7134a8b4e98",
        "scripts/automation_retry_policy.py": "3b5f018c2808f48106afa78f214b0fcc703f6b29",
        "scripts/validate-dependabot-contract.py": "be3b6f64e74af8c2c916d4e9a31298d558ba7af4",
        "scripts/validate-governance-contract.py": "13d09a9be7441273ebbd7c5e0d63ddcdd6093301",
        "scripts/validate-privileged-workflow-identity.py": "bcc1c41f8e1eb4b51ac7e0c7147587a43991f5ac",
    }
    expected_paths = sorted(expected_blobs)

    subprocess.run(
        ["git", "fetch", "--no-tags", "--depth=64", "origin", base_sha, source_sha],
        check=True,
    )
    merge_base = subprocess.check_output(
        ["git", "merge-base", base_sha, source_sha], text=True
    ).strip()
    require(
        merge_base == base_sha,
        f"diagnostic candidate no longer descends from exact current main: {merge_base}",
    )
    changed = subprocess.check_output(
        ["git", "diff", "--name-only", base_sha, source_sha], text=True
    ).splitlines()
    require(changed == expected_paths, f"diagnostic candidate path set changed: {changed!r}")
    for candidate_path, expected_blob in expected_blobs.items():
        observed_blob = subprocess.check_output(
            ["git", "rev-parse", f"{source_sha}:{candidate_path}"], text=True
        ).strip()
        require(
            observed_blob == expected_blob,
            f"diagnostic candidate blob changed for {candidate_path}: {observed_blob}",
        )
    tree = subprocess.check_output(
        ["git", "rev-parse", f"{source_sha}^{{tree}}"], text=True
    ).strip()
    require(tree == expected_tree, f"diagnostic candidate tree changed: {tree}")

    with tempfile.TemporaryDirectory(prefix="profile-quality-admission-diagnostic-") as temporary:
        root = Path(temporary)
        trusted = root / "trusted"
        candidate = root / "candidate"
        subprocess.run(["git", "worktree", "add", "--detach", str(trusted), base_sha], check=True)
        subprocess.run(["git", "worktree", "add", "--detach", str(candidate), source_sha], check=True)

        code = r"""
from pathlib import Path
import json
import sys
import traceback

trusted = Path(sys.argv[1]).resolve()
candidate = Path(sys.argv[2]).resolve()
tree = sys.argv[3]
source_sha = sys.argv[4]
sys.path.insert(0, str(trusted / "scripts"))

stage = "imports"
try:
    import trusted_workflow_capability as compiler
    import workflow_capability_admission as admission
    import workflow_capability_authorization as authorization
    import workflow_capability_diff as diffmod
    import workflow_capability_snapshot as snapshot

    stage = "load-base"
    base = snapshot.load_combined()
    stage = "load-ledger"
    ledger = admission.strict_json(
        admission.TRUSTED_LEDGER, "trusted capability authorization ledger"
    )
    stage = "validate-ledger"
    authorization.validate_ledger(ledger)
    stage = "compile-candidate"
    candidate_bom = compiler.compile_repository(candidate)
    stage = "semantic-diff"
    diff = diffmod.semantic_diff(base, candidate_bom)
    stage = "protect-control"
    diff = admission.protect_trusted_control(base, candidate_bom, diff)
    stage = "protect-sources"
    diff = admission.protect_trusted_sources(candidate, tree, diff)
    stage = "match-ledger"
    matches = [
        entry for entry in ledger["authorizations"]
        if entry["baseBomSha256"] == diff["baseBomSha256"]
        and entry["candidateBomSha256"] == diff["candidateBomSha256"]
        and entry["expansionSha256"] == diff["expansionSha256"]
    ]
    tcb = sorted({
        expansion.get("after", {}).get("candidateTcbSha256")
        for expansion in diff["expansions"]
        if expansion.get("category") == "trusted-control-source"
        and isinstance(expansion.get("after"), dict)
        and expansion.get("after", {}).get("candidateTcbSha256")
    })
    tuple_out = {
        "candidateHead": source_sha,
        "candidateTree": tree,
        "baseBomSha256": diff["baseBomSha256"],
        "candidateBomSha256": diff["candidateBomSha256"],
        "expansionSha256": diff["expansionSha256"],
        "candidateTcbSha256": tcb,
        "expansionCount": len(diff["expansions"]),
        "reductionCount": len(diff["reductions"]),
        "priorMatches": len(matches),
        "matchingIds": [entry["id"] for entry in matches],
    }
    print(
        "PROFILE-QUALITY-POST-AUTH-TUPLE:"
        + json.dumps(tuple_out, sort_keys=True, separators=(",", ":")),
        flush=True,
    )

    stage = "authorize"
    decision = authorization.authorize(diff, ledger)
    print(
        "PROFILE-QUALITY-POST-AUTH-AUTHORIZE:"
        + json.dumps(decision, sort_keys=True, separators=(",", ":")),
        flush=True,
    )

    stage = "evaluate"
    evaluated_decision, evaluated_diff = admission.evaluate(
        candidate, candidate_tree_sha=tree
    )
    print(
        "PROFILE-QUALITY-POST-AUTH-EVALUATE:"
        + json.dumps(
            {
                "decision": evaluated_decision,
                "expansionCount": len(evaluated_diff["expansions"]),
                "reductionCount": len(evaluated_diff["reductions"]),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )
except Exception as exc:
    print(
        "PROFILE-QUALITY-POST-AUTH-ERROR:"
        + json.dumps(
            {
                "stage": stage,
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": traceback.format_exc(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )
    raise
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
            f"#1300 post-authorization diagnostic subprocess failed: {result.returncode}",
        )

        subprocess.run(["git", "worktree", "remove", "--force", str(candidate)], check=True)
        subprocess.run(["git", "worktree", "remove", "--force", str(trusted)], check=True)


def main() -> int:
    try:
        workflows, jobs = validate_snapshot()
        profile_quality_post_authorization_admission_diagnostic()
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
