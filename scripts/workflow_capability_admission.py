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
import workflow_capability_tcb

ROOT = Path(__file__).resolve().parents[1]
TRUSTED_LEDGER = ROOT / ".github/workflow-capability-expansion-authorizations-v1.json"
CONTROL_WORKFLOW_ID = "capability-admission"
MEASUREMENT_ID = "workflow-capability-admission-measurement-v1"


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
) -> dict[str, Any]:
    additions = workflow_capability_tcb.source_expansions(ROOT, candidate_root, candidate_tree_sha)
    return with_expansions(diff, additions)


def measure(
    candidate_root: Path,
    *,
    candidate_tree_sha: str | None = None,
) -> dict[str, Any]:
    """Compile the exact production admission diff without consulting authorization state."""
    base = workflow_capability_snapshot.load_combined()
    candidate = trusted_workflow_capability.compile_repository(candidate_root)
    diff = workflow_capability_diff.semantic_diff(base, candidate)
    diff = protect_trusted_control(base, candidate, diff)
    return protect_trusted_sources(candidate_root, candidate_tree_sha, diff)


def public_measurement(
    diff_value: dict[str, Any],
    *,
    candidate_tree_sha: str | None,
) -> dict[str, Any]:
    """Return the safe immutable tuple needed to create an exact prior authorization."""
    diff = workflow_capability_authorization.validate_diff(diff_value)
    if candidate_tree_sha is not None:
        require(
            workflow_capability_tcb.SHA40.fullmatch(candidate_tree_sha) is not None,
            "candidate tree SHA measurement binding is invalid",
        )

    candidate_tcb_sha256 = sorted({
        item["after"]["candidateTcbSha256"]
        for item in diff["expansions"]
        if item.get("category") == "trusted-control-source"
        and isinstance(item.get("after"), dict)
        and isinstance(item["after"].get("candidateTcbSha256"), str)
    })
    require(
        all(workflow_capability_authorization.SHA256.fullmatch(value) is not None
            for value in candidate_tcb_sha256),
        "trusted control-source measurement contains an invalid TCB SHA-256",
    )
    return {
        "schemaVersion": 1,
        "measurementId": MEASUREMENT_ID,
        "candidateTreeSha": candidate_tree_sha,
        "baseBomSha256": diff["baseBomSha256"],
        "candidateBomSha256": diff["candidateBomSha256"],
        "expansionSha256": diff["expansionSha256"],
        "candidateTcbSha256": candidate_tcb_sha256,
        "expansionCount": len(diff["expansions"]),
        "reductionCount": len(diff["reductions"]),
    }


def authorize_measurement(diff: dict[str, Any]) -> dict[str, Any]:
    ledger = strict_json(TRUSTED_LEDGER, "trusted capability authorization ledger")
    workflow_capability_authorization.validate_ledger(ledger)
    decision = workflow_capability_authorization.authorize(diff, ledger)
    require(decision["allowed"] is True, "capability admission returned a non-allow decision")
    return decision


def evaluate(
    candidate_root: Path,
    *,
    candidate_tree_sha: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    diff = measure(candidate_root, candidate_tree_sha=candidate_tree_sha)
    return authorize_measurement(diff), diff


def self_test() -> None:
    workflow_capability_snapshot.self_test()
    workflow_capability_tcb.self_test()
    base = workflow_capability_snapshot.load_combined()
    measured = measure(ROOT)
    decision, diff = evaluate(ROOT)
    require(
        workflow_capability_bom.canonical_json(measured) == workflow_capability_bom.canonical_json(diff),
        "trusted admission measure/evaluate paths diverged",
    )
    trusted_measurement = public_measurement(measured, candidate_tree_sha=None)
    require(trusted_measurement == {
        "schemaVersion": 1,
        "measurementId": MEASUREMENT_ID,
        "candidateTreeSha": None,
        "baseBomSha256": diff["baseBomSha256"],
        "candidateBomSha256": diff["candidateBomSha256"],
        "expansionSha256": diff["expansionSha256"],
        "candidateTcbSha256": [],
        "expansionCount": 0,
        "reductionCount": 0,
    }, "trusted repository measurement output shape changed")
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
    source_measurement = public_measurement(source_probe, candidate_tree_sha="1" * 40)
    require(
        source_measurement["candidateTcbSha256"] == ["b" * 64]
        and source_measurement["candidateTreeSha"] == "1" * 40
        and source_measurement["expansionCount"] == 1,
        "trusted source measurement lost exact tree/TCB/count binding",
    )

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
        help="Repository tree containing untrusted candidate Automation Policy/workflow/control-source bytes",
    )
    value.add_argument(
        "--candidate-tree-sha",
        default=None,
        help="Exact fetched candidate Git tree SHA transport proof; required when trusted control-source bytes differ",
    )
    value.add_argument("--self-test", action="store_true", help="Run trusted admission self-tests first")
    value.add_argument(
        "--measure",
        action="store_true",
        help="Emit only the safe exact production authorization measurement; do not authorize",
    )
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.self_test:
            self_test()
        diff = measure(args.candidate_root, candidate_tree_sha=args.candidate_tree_sha)
        measurement = public_measurement(diff, candidate_tree_sha=args.candidate_tree_sha)
        if args.measure:
            print(workflow_capability_bom.canonical_json({"measurement": measurement}), end="")
            return 0

        decision = authorize_measurement(diff)
        public_result = {
            "decision": {"allowed": decision["allowed"]},
            "diff": {
                "expansions": [None] * len(diff["expansions"]),
                "reductions": [None] * len(diff["reductions"]),
            },
        }
        print(workflow_capability_bom.canonical_json(public_result), end="")
        return 0
    except (OSError, ValueError):
        print(
            "ERROR: trusted capability admission rejected candidate input; "
            "use --measure for the sanitized exact authorization tuple",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
