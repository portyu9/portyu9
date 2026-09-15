#!/usr/bin/env python3
"""Evaluate an untrusted candidate repository against trusted capability policy.

This module must execute from the trusted default-branch checkout. Candidate workflow/policy
bytes are data only: trusted_workflow_capability parses them without importing or executing
candidate code. Candidate protected Python bytes are represented only by a digest manifest;
they are never materialized into executable-looking source paths. The base BOM and
authorization ledger are always read from this module's trusted repository root.
"""
from __future__ import annotations

import argparse
import copy
from pathlib import Path
import sys
from typing import Any, Mapping

import automation_policy
import trusted_workflow_capability
import workflow_capability_authorization
import workflow_capability_bom
import workflow_capability_diff
import workflow_capability_snapshot
import workflow_capability_tcb

ROOT = Path(__file__).resolve().parents[1]
TRUSTED_LEDGER = ROOT / ".github/workflow-capability-expansion-authorizations-v1.json"
CANDIDATE_DATA_ROOT = ROOT / "candidate-capability-source"
CANDIDATE_TCB_MANIFEST = CANDIDATE_DATA_ROOT / ".candidate-tcb-sha256"
CONTROL_WORKFLOW_ID = "capability-admission"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def strict_json(path: Path, label: str) -> Any:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing or aliased: {path}")
    try:
        return automation_policy.strict_json_loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"{label} JSON is invalid: {exc}") from exc


def canonical_candidate_root(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    require(resolved.is_dir() and not resolved.is_symlink(), f"candidate repository root is invalid: {resolved}")
    if resolved == ROOT:
        return resolved
    require(resolved == CANDIDATE_DATA_ROOT.resolve(strict=True),
            "candidate repository root must be the fixed admission data directory")
    return resolved


def candidate_manifest(path: Path | None, candidate_root: Path) -> Mapping[str, str] | None:
    if candidate_root == ROOT:
        require(path is None, "trusted self-comparison must not accept an external candidate TCB manifest")
        return None
    require(path is not None, "candidate TCB digest manifest is required for PR admission")
    resolved = path.resolve(strict=True)
    require(resolved == CANDIDATE_TCB_MANIFEST.resolve(strict=True),
            "candidate TCB manifest must be the fixed admission manifest path")
    return workflow_capability_tcb.load_manifest(resolved)


def workflow_by_id(bom: dict[str, Any], workflow_id: str) -> dict[str, Any] | None:
    matches = [workflow for workflow in bom["workflows"] if workflow.get("id") == workflow_id]
    require(len(matches) <= 1, f"Workflow Capability BOM duplicates workflow identity: {workflow_id}")
    return matches[0] if matches else None


def with_expansions(diff: dict[str, Any], additions: list[dict[str, object]]) -> dict[str, Any]:
    if not additions:
        return diff
    result = copy.deepcopy(diff)
    result["expansions"].extend(copy.deepcopy(additions))
    result["expansions"].sort(key=workflow_capability_diff.stable_key)
    result["hasExpansion"] = True
    result["expansionSha256"] = workflow_capability_diff.digest(result["expansions"])
    return result


def protect_trusted_control(
    base: dict[str, Any], candidate: dict[str, Any], diff: dict[str, Any]
) -> dict[str, Any]:
    """Treat every semantic change to the admission gate itself as authority expansion."""
    before = workflow_by_id(base, CONTROL_WORKFLOW_ID)
    require(before is not None, "trusted base BOM is missing the capability admission control workflow")
    after = workflow_by_id(candidate, CONTROL_WORKFLOW_ID)
    if after is not None and workflow_capability_diff.stable_key(before) == workflow_capability_diff.stable_key(after):
        return diff
    return with_expansions(diff, [{
        "direction": "expansion",
        "category": "trusted-control-boundary",
        "workflow": CONTROL_WORKFLOW_ID,
        "before": before,
        "after": after,
    }])


def protect_trusted_sources(
    candidate_root: Path,
    candidate_tree_sha: str | None,
    diff: dict[str, Any],
    manifest: Mapping[str, str] | None,
) -> dict[str, Any]:
    additions = workflow_capability_tcb.source_expansions(
        ROOT,
        candidate_root,
        candidate_tree_sha,
        candidate_manifest=manifest,
    )
    return with_expansions(diff, additions)


def evaluate(
    candidate_root: Path,
    *,
    candidate_tree_sha: str | None = None,
    candidate_tcb_manifest: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate_root = canonical_candidate_root(candidate_root)
    manifest = candidate_manifest(candidate_tcb_manifest, candidate_root)

    base = workflow_capability_snapshot.load_combined()
    ledger = strict_json(TRUSTED_LEDGER, "trusted capability authorization ledger")
    workflow_capability_authorization.validate_ledger(ledger)

    candidate = trusted_workflow_capability.compile_repository(candidate_root)
    diff = workflow_capability_diff.semantic_diff(base, candidate)
    diff = protect_trusted_control(base, candidate, diff)
    diff = protect_trusted_sources(candidate_root, candidate_tree_sha, diff, manifest)
    decision = workflow_capability_authorization.authorize(diff, ledger)
    require(decision["allowed"] is True, "capability admission returned a non-allow decision")
    return decision, diff


def self_test() -> None:
    workflow_capability_snapshot.self_test()
    workflow_capability_tcb.self_test()
    base = workflow_capability_snapshot.load_combined()
    decision, diff = evaluate(ROOT)
    require(not diff["hasExpansion"] and not diff["expansions"] and not diff["reductions"],
            "trusted repository self-comparison produced capability drift")
    require(decision == {
        "allowed": True,
        "authorizationRequired": False,
        "authorizationId": None,
        "baseBomSha256": diff["baseBomSha256"],
        "candidateBomSha256": diff["candidateBomSha256"],
        "expansionSha256": diff["expansionSha256"],
    }, "trusted repository self-comparison produced unexpected admission decision")

    narrowed = copy.deepcopy(base)
    narrowed_control = workflow_by_id(narrowed, CONTROL_WORKFLOW_ID)
    require(narrowed_control is not None, "trusted admission self-test fixture lost control workflow")
    narrowed_control["jobs"][0]["permissions"]["contents"] = "none"
    narrowed_diff = workflow_capability_diff.semantic_diff(base, narrowed)
    require(not narrowed_diff["hasExpansion"],
            "trusted admission self-test expected isolated permission narrowing to be a semantic reduction")
    protected_narrowing = protect_trusted_control(base, narrowed, narrowed_diff)
    require(protected_narrowing["hasExpansion"] and any(
        item["category"] == "trusted-control-boundary" for item in protected_narrowing["expansions"]
    ), "trusted admission control narrowing did not require prior authorization")

    removed = copy.deepcopy(base)
    removed["workflows"] = [workflow for workflow in removed["workflows"] if workflow["id"] != CONTROL_WORKFLOW_ID]
    removed_diff = protect_trusted_control(base, removed, workflow_capability_diff.semantic_diff(base, removed))
    require(removed_diff["hasExpansion"] and any(
        item["category"] == "trusted-control-boundary" and item["after"] is None
        for item in removed_diff["expansions"]
    ), "trusted admission control removal did not require prior authorization")

    source_probe = with_expansions(copy.deepcopy(diff), [{
        "direction": "expansion",
        "category": "trusted-control-source",
        "workflow": CONTROL_WORKFLOW_ID,
        "key": "scripts/json.py",
        "before": None,
        "after": {"sha256": "a" * 64, "candidateTcbSha256": "b" * 64},
    }])
    require(source_probe["hasExpansion"] and source_probe["expansionSha256"] != diff["expansionSha256"],
            "trusted source expansion did not alter the exact authorization digest")

    trusted_github = ROOT / ".github"
    require(workflow_capability_snapshot.BASE_SNAPSHOT.parent == trusted_github,
            "trusted base BOM escaped the trusted checkout")
    require(workflow_capability_snapshot.ADMISSION_EXTENSION.parent == trusted_github,
            "trusted admission BOM extension escaped the trusted checkout")
    require(TRUSTED_LEDGER.parent == trusted_github,
            "trusted authorization ledger escaped the trusted checkout")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument(
        "candidate_root",
        nargs="?",
        type=Path,
        default=ROOT,
        help="Fixed repository data tree containing untrusted candidate Automation Policy/workflow bytes",
    )
    value.add_argument(
        "--candidate-tree-sha",
        default=None,
        help="Exact fetched candidate Git tree SHA transport proof; required when trusted control-source bytes differ",
    )
    value.add_argument(
        "--candidate-tcb-manifest",
        type=Path,
        default=None,
        help="Fixed digest-only manifest for candidate trusted-control-source Git blobs",
    )
    value.add_argument("--self-test", action="store_true", help="Run trusted admission self-tests first")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.self_test:
            self_test()
        decision, diff = evaluate(
            args.candidate_root,
            candidate_tree_sha=args.candidate_tree_sha,
            candidate_tcb_manifest=args.candidate_tcb_manifest,
        )
        print(workflow_capability_bom.canonical_json({
            "decision": decision,
            "diff": diff,
        }), end="")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
