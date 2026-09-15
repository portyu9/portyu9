#!/usr/bin/env python3
"""Evaluate an untrusted candidate repository against trusted capability policy.

This module must execute from the trusted default-branch checkout. `candidate_root` is data
only: trusted_workflow_capability parses candidate Automation Policy/workflows without
importing or executing candidate code. The base BOM and authorization ledger are always read
from this module's trusted repository root, never from the candidate tree.
"""
from __future__ import annotations

import argparse
import copy
from pathlib import Path
import sys
from typing import Any

import automation_policy
import trusted_workflow_capability
import workflow_capability_authorization
import workflow_capability_bom
import workflow_capability_diff
import workflow_capability_snapshot

ROOT = Path(__file__).resolve().parents[1]
TRUSTED_LEDGER = ROOT / ".github/workflow-capability-expansion-authorizations-v1.json"
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


def workflow_by_id(bom: dict[str, Any], workflow_id: str) -> dict[str, Any] | None:
    matches = [workflow for workflow in bom["workflows"] if workflow.get("id") == workflow_id]
    require(len(matches) <= 1, f"Workflow Capability BOM duplicates workflow identity: {workflow_id}")
    return matches[0] if matches else None


def protect_trusted_control(
    base: dict[str, Any], candidate: dict[str, Any], diff: dict[str, Any]
) -> dict[str, Any]:
    """Treat every change to the admission gate itself as authority expansion.

    A syntactic restriction such as deleting the read-only gate is a capability reduction in
    isolation but weakens the repository control plane. Binding the complete before/after
    workflow object makes any self-change require an exact prior trusted authorization.
    """
    before = workflow_by_id(base, CONTROL_WORKFLOW_ID)
    require(before is not None, "trusted base BOM is missing the capability admission control workflow")
    after = workflow_by_id(candidate, CONTROL_WORKFLOW_ID)
    if after is not None and workflow_capability_diff.stable_key(before) == workflow_capability_diff.stable_key(after):
        return diff

    result = copy.deepcopy(diff)
    boundary = {
        "direction": "expansion",
        "category": "trusted-control-boundary",
        "workflow": CONTROL_WORKFLOW_ID,
        "before": before,
        "after": after,
    }
    result["expansions"].append(boundary)
    result["expansions"].sort(key=workflow_capability_diff.stable_key)
    result["hasExpansion"] = True
    result["expansionSha256"] = workflow_capability_diff.digest(result["expansions"])
    return result


def evaluate(candidate_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    base = workflow_capability_snapshot.load_combined()
    ledger = strict_json(TRUSTED_LEDGER, "trusted capability authorization ledger")
    workflow_capability_authorization.validate_ledger(ledger)

    candidate = trusted_workflow_capability.compile_repository(candidate_root)
    diff = workflow_capability_diff.semantic_diff(base, candidate)
    diff = protect_trusted_control(base, candidate, diff)
    decision = workflow_capability_authorization.authorize(diff, ledger)
    require(decision["allowed"] is True, "capability admission returned a non-allow decision")
    return decision, diff


def self_test() -> None:
    workflow_capability_snapshot.self_test()
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
        help="Repository tree containing untrusted candidate Automation Policy/workflow bytes",
    )
    value.add_argument("--self-test", action="store_true", help="Run trusted admission self-tests first")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.self_test:
            self_test()
        decision, diff = evaluate(args.candidate_root)
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
