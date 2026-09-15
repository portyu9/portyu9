#!/usr/bin/env python3
"""Evaluate an untrusted candidate repository against trusted capability policy.

The script itself must execute from the trusted default-branch checkout. `candidate_root`
is data only: trusted_workflow_capability parses candidate Automation Policy/workflows without
importing or executing candidate code. The base BOM and authorization ledger are always read
from this script's trusted repository root, never from the candidate tree.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

import automation_policy
import trusted_workflow_capability
import workflow_capability_authorization
import workflow_capability_bom
import workflow_capability_diff

ROOT = Path(__file__).resolve().parents[1]
BASE_BOM = ROOT / ".github/workflow-capability-bom-v1.json"
TRUSTED_LEDGER = ROOT / ".github/workflow-capability-expansion-authorizations-v1.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def strict_json(path: Path, label: str) -> Any:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing or aliased: {path}")
    try:
        return automation_policy.strict_json_loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"{label} JSON is invalid: {exc}") from exc


def evaluate(candidate_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    base = strict_json(BASE_BOM, "trusted base Workflow Capability BOM")
    ledger = strict_json(TRUSTED_LEDGER, "trusted capability authorization ledger")
    workflow_capability_authorization.validate_ledger(ledger)

    candidate = trusted_workflow_capability.compile_repository(candidate_root)
    diff = workflow_capability_diff.semantic_diff(base, candidate)
    decision = workflow_capability_authorization.authorize(diff, ledger)
    require(decision["allowed"] is True, "capability admission returned a non-allow decision")
    return decision, diff


def self_test() -> None:
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

    # Candidate-authored BOM/authorization files are deliberately outside the compile input.
    # The trusted compiler consumes only candidate policy/workflow source while BASE_BOM and
    # TRUSTED_LEDGER are module constants rooted at the trusted checkout.
    require(BASE_BOM.parent == ROOT / ".github" and TRUSTED_LEDGER.parent == ROOT / ".github",
            "trusted admission evidence escaped the trusted checkout")


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
