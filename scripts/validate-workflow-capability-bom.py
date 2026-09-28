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
    """Disposable carrier: measure exact post-recovery #1230 selector authorization tuple."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return

    base_sha = "5a4df4b5b8516740aed30c94d42655f6a1f11d44"
    source_sha = "ccb2c8e1f18c880441f811e84ae546a945995e7d"
    expected_selector_blob = "58f4d55e7e65bc7f417c1ce3c006f0b7b9c412c7"
    expected_candidate_tree = "f9edacabd37b0c01b4e3bde4affe721d3e427fd4"
    selector_path = "scripts/workflow_capability_tcb.py"

    subprocess.run(
        ["git", "fetch", "--no-tags", "--depth=1", "origin", base_sha, source_sha],
        check=True,
    )
    observed_selector_blob = subprocess.check_output(
        ["git", "rev-parse", f"{source_sha}:{selector_path}"],
        text=True,
    ).strip()
    require(
        observed_selector_blob == expected_selector_blob,
        f"diagnostic selector blob changed: {observed_selector_blob}",
    )

    with tempfile.TemporaryDirectory(prefix="trusted-aiqa-tcb-diagnostic-") as temporary:
        root = Path(temporary)
        trusted = root / "trusted"
        candidate = root / "candidate"
        subprocess.run(["git", "worktree", "add", "--detach", str(trusted), base_sha], check=True)
        subprocess.run(["git", "worktree", "add", "--detach", str(candidate), base_sha], check=True)

        selector_bytes = subprocess.check_output(
            ["git", "show", f"{source_sha}:{selector_path}"],
        )
        target = candidate / selector_path
        target.write_bytes(selector_bytes)
        subprocess.run(["git", "-C", str(candidate), "add", selector_path], check=True)
        changed = subprocess.check_output(
            ["git", "-C", str(candidate), "diff", "--cached", "--name-only"],
            text=True,
        ).splitlines()
        require(
            changed == [selector_path],
            f"diagnostic candidate changed unexpected paths: {changed!r}",
        )
        tree = subprocess.check_output(
            ["git", "-C", str(candidate), "write-tree"],
            text=True,
        ).strip()
        require(
            tree == expected_candidate_tree,
            f"diagnostic candidate tree changed: expected={expected_candidate_tree} observed={tree}",
        )

        code = (
            "from pathlib import Path\n"
            "import json\n"
            "import sys\n"
            "trusted=Path(sys.argv[1]).resolve()\n"
            "candidate=Path(sys.argv[2]).resolve()\n"
            "tree=sys.argv[3]\n"
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
            "if diff['baseBomSha256'] != diff['candidateBomSha256']: raise SystemExit('diagnostic semantic BOM unexpectedly changed')\n"
            "if diff['reductions'] != []: raise SystemExit('diagnostic unexpectedly produced reductions')\n"
            "if len(diff['expansions']) != 1: raise SystemExit('diagnostic expected exactly one trusted-source expansion')\n"
            "exp=diff['expansions'][0]\n"
            "if exp.get('category') != 'trusted-control-source' or exp.get('key') != 'scripts/workflow_capability_tcb.py': raise SystemExit('diagnostic expansion identity changed')\n"
            "out={'candidateTree':tree,'baseBomSha256':diff['baseBomSha256'],'candidateBomSha256':diff['candidateBomSha256'],'expansionSha256':diff['expansionSha256'],'expansionKey':exp['key'],'candidateTcbSha256':exp['after']['candidateTcbSha256'],'priorMatches':len(matches)}\n"
            "print('TRUSTED-AIQA-TCB-DIAGNOSTIC:' + json.dumps(out, sort_keys=True, separators=(',', ':')))\n"
        )
        subprocess.run(
            [sys.executable, "-c", code, str(trusted), str(candidate), tree],
            check=True,
        )
        subprocess.run(["git", "worktree", "remove", "--force", str(candidate)], check=True)
        subprocess.run(["git", "worktree", "remove", "--force", str(trusted)], check=True)


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
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
