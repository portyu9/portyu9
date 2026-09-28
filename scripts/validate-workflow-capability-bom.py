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



def codeql_readiness_snapshot_diagnostic() -> None:
    """Disposable accepted-main carrier: measure frozen #1286 capability diff."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return

    base_sha = "bd88ba4bc754f5eb6f5ef69fd3a3406416eac84b"
    source_sha = "8f4c23d7c4253379203387a76a9fab0c7e19e57a"
    expected_paths = [
        ".github/workflow-capability-bom-v1-codeql-autofix.json",
        ".github/workflows/codeql-autofix.yml",
        "scripts/codeql_autofix_controller.py",
        "scripts/validate-codeql-contract.py",
    ]

    subprocess.run(
        ["git", "fetch", "--no-tags", "--depth=32", "origin", base_sha, source_sha],
        check=True,
    )
    merge_base = subprocess.check_output(
        ["git", "merge-base", base_sha, source_sha], text=True
    ).strip()
    require(
        merge_base == base_sha,
        f"diagnostic candidate no longer descends from base: {merge_base}",
    )
    changed = subprocess.check_output(
        ["git", "diff", "--name-only", base_sha, source_sha], text=True
    ).splitlines()
    require(changed == expected_paths, f"diagnostic candidate path set changed: {changed!r}")
    tree = subprocess.check_output(
        ["git", "rev-parse", f"{source_sha}^{{tree}}"], text=True
    ).strip()
    require(
        tree == "0d26b0a60e0f726a8cf4e33ce932d4ba7e2560a3",
        f"diagnostic candidate tree changed: {tree}",
    )

    with tempfile.TemporaryDirectory(prefix="codeql-readiness-diagnostic-") as temporary:
        root = Path(temporary)
        trusted = root / "trusted"
        candidate = root / "candidate"
        subprocess.run(["git", "worktree", "add", "--detach", str(trusted), base_sha], check=True)
        subprocess.run(["git", "worktree", "add", "--detach", str(candidate), source_sha], check=True)

        code = (
            "from pathlib import Path\n"
            "import json\n"
            "import sys\n"
            "trusted=Path(sys.argv[1]).resolve()\n"
            "candidate=Path(sys.argv[2]).resolve()\n"
            "tree=sys.argv[3]\n"
            "source_sha=sys.argv[4]\n"
            "sys.path.insert(0, str(trusted / 'scripts'))\n"
            "import trusted_workflow_capability as compiler\n"
            "import workflow_capability_admission as admission\n"
            "import workflow_capability_authorization as authorization\n"
            "import workflow_capability_diff as diffmod\n"
            "import workflow_capability_snapshot as snapshot\n"
            "base=snapshot.load_combined()\n"
            "candidate_bom=compiler.compile_repository(candidate)\n"
            "diff=diffmod.semantic_diff(base, candidate_bom)\n"
            "diff=admission.protect_trusted_control(base, candidate_bom, diff)\n"
            "diff=admission.protect_trusted_sources(candidate, tree, diff)\n"
            "ledger=admission.strict_json(admission.TRUSTED_LEDGER, 'trusted capability authorization ledger')\n"
            "authorization.validate_ledger(ledger)\n"
            "matches=[entry for entry in ledger['authorizations'] if entry['baseBomSha256']==diff['baseBomSha256'] and entry['candidateBomSha256']==diff['candidateBomSha256'] and entry['expansionSha256']==diff['expansionSha256']]\n"
            "tcb=sorted({e.get('after',{}).get('candidateTcbSha256') for e in diff['expansions'] if e.get('category')=='trusted-control-source' and isinstance(e.get('after'),dict) and e.get('after',{}).get('candidateTcbSha256')})\n"
            "out={'candidateHead':source_sha,'candidateTree':tree,'baseBomSha256':diff['baseBomSha256'],'candidateBomSha256':diff['candidateBomSha256'],'expansionSha256':diff['expansionSha256'],'candidateTcbSha256':tcb,'expansions':diff['expansions'],'reductions':diff['reductions'],'priorMatches':len(matches)}\n"
            "print('CODEQL-READINESS-SNAPSHOT-DIAGNOSTIC:' + json.dumps(out, sort_keys=True, separators=(',', ':')))\n"
        )
        subprocess.run(
            [sys.executable, "-c", code, str(trusted), str(candidate), tree, source_sha],
            check=True,
        )
        subprocess.run(["git", "worktree", "remove", "--force", str(candidate)], check=True)
        subprocess.run(["git", "worktree", "remove", "--force", str(trusted)], check=True)

def main() -> int:
    try:
        workflows, jobs = validate_snapshot()
        codeql_readiness_snapshot_diagnostic()
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
