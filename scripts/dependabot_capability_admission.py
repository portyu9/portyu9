#!/usr/bin/env python3
"""Trusted delegated capability admission for reconciled native Dependabot CodeQL updates.

This is deliberately narrower than the general ledger authorization path. It may authorize
only an exact native Dependabot GitHub-Actions PR whose workflow delta is one atomic forward
CodeQL Action release, whose public tag resolves to the candidate SHA, and whose additional
files are exactly the deterministic governance outputs derived by trusted code. All other
capability expansions continue to require the existing exact prior ledger authorization.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping

import dependabot_controller
import trusted_workflow_capability
import workflow_capability_admission
import workflow_capability_bom
import workflow_capability_diff
import workflow_capability_snapshot

ROOT = Path(__file__).resolve().parents[1]
DELEGATION_ID = "delegated-dependabot-codeql-v1"
BASE_BOM_PATH = ".github/workflow-capability-bom-v1.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def strict_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    require(isinstance(value, Mapping), f"{label} must be an object")
    return value


def _action_identity(value: Mapping[str, Any]) -> str:
    repository = value.get("repository")
    path = value.get("path")
    require(repository == dependabot_controller.CODEQL_REPOSITORY,
            "delegated Dependabot action repository changed")
    require(isinstance(path, str), "delegated Dependabot action subpath is malformed")
    return repository + (f"/{path}" if path else "")


def _validate_semantic_bounds(diff: Mapping[str, Any], proof: Mapping[str, Any]) -> None:
    before = _mapping(proof.get("before"), "Dependabot before identity")
    after = _mapping(proof.get("after"), "Dependabot after identity")
    old_sha = before.get("sha")
    new_sha = after.get("sha")
    actions = set(proof.get("actions", []))
    require(actions, "Dependabot delegated admission has no action inventory")

    expansions = diff.get("expansions")
    reductions = diff.get("reductions")
    require(isinstance(expansions, list) and isinstance(reductions, list),
            "Dependabot delegated capability diff is malformed")
    require(expansions, "Dependabot delegated admission requires an actual capability expansion")

    action_expansions = []
    source_expansions = []
    for item in expansions:
        entry = _mapping(item, "Dependabot capability expansion")
        category = entry.get("category")
        if category == "action":
            candidate = _mapping(entry.get("after"), "Dependabot candidate action capability")
            require(candidate.get("ref") == new_sha,
                    "delegated Dependabot expansion introduced an unproved Action SHA")
            require(_action_identity(candidate) in actions,
                    "delegated Dependabot expansion introduced an unproved Action subpath")
            action_expansions.append(entry)
        elif category == "trusted-control-source":
            require(entry.get("key") == BASE_BOM_PATH,
                    "delegated Dependabot admission changed an unapproved trusted-control source")
            source_expansions.append(entry)
        else:
            raise ValueError(f"delegated Dependabot admission forbids capability expansion category: {category}")

    require(len(action_expansions) == len(actions),
            "delegated Dependabot capability expansion does not exactly cover the admitted Action set")
    require(len(source_expansions) == 1,
            "delegated Dependabot reconciliation must change exactly the protected base BOM snapshot")

    action_reductions = []
    for item in reductions:
        entry = _mapping(item, "Dependabot capability reduction")
        require(entry.get("category") == "action",
                f"delegated Dependabot admission forbids capability reduction category: {entry.get('category')}")
        previous = _mapping(entry.get("before"), "Dependabot previous action capability")
        require(previous.get("ref") == old_sha,
                "delegated Dependabot reduction removed an unproved Action SHA")
        require(_action_identity(previous) in actions,
                "delegated Dependabot reduction removed an unproved Action subpath")
        action_reductions.append(entry)
    require(len(action_reductions) == len(actions),
            "delegated Dependabot capability reductions do not exactly retire the prior Action set")


def evaluate(
    *,
    candidate_root: Path,
    candidate_tree_sha: str,
    pr: Mapping[str, Any],
    expected_head_sha: str,
    resolved_release: Mapping[str, Any],
    changed_paths: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    proof = dependabot_controller.admit(
        pr=pr,
        expected_head_sha=expected_head_sha,
        base_root=ROOT,
        candidate_root=candidate_root,
        resolved_release=resolved_release,
    )
    dependabot_controller.validate_reconciled_candidate(
        base_root=ROOT,
        candidate_root=candidate_root,
        proof=proof,
        changed_paths=changed_paths,
    )

    base = workflow_capability_snapshot.load_combined()
    candidate = trusted_workflow_capability.compile_repository(candidate_root)
    diff = workflow_capability_diff.semantic_diff(base, candidate)
    diff = workflow_capability_admission.protect_trusted_control(base, candidate, diff)
    diff = workflow_capability_admission.protect_trusted_sources(candidate_root, candidate_tree_sha, diff)
    _validate_semantic_bounds(diff, proof)

    decision = {
        "allowed": True,
        "authorizationRequired": True,
        "authorizationId": DELEGATION_ID,
        "baseBomSha256": diff["baseBomSha256"],
        "candidateBomSha256": diff["candidateBomSha256"],
        "expansionSha256": diff["expansionSha256"],
    }
    return decision, diff


def self_test() -> None:
    require(DELEGATION_ID.startswith("delegated-dependabot-"), "Dependabot delegation identity drifted")
    good = {
        "expansions": [
            {
                "category": "action",
                "after": {"repository": "github/codeql-action", "path": "init", "ref": "b" * 40},
            },
            {
                "category": "action",
                "after": {"repository": "github/codeql-action", "path": "analyze", "ref": "b" * 40},
            },
            {"category": "trusted-control-source", "key": BASE_BOM_PATH},
        ],
        "reductions": [
            {
                "category": "action",
                "before": {"repository": "github/codeql-action", "path": "init", "ref": "a" * 40},
            },
            {
                "category": "action",
                "before": {"repository": "github/codeql-action", "path": "analyze", "ref": "a" * 40},
            },
        ],
    }
    proof = {
        "before": {"sha": "a" * 40},
        "after": {"sha": "b" * 40},
        "actions": ["github/codeql-action/analyze", "github/codeql-action/init"],
    }
    _validate_semantic_bounds(good, proof)
    bad = json.loads(json.dumps(good))
    bad["expansions"][0]["after"]["ref"] = "c" * 40
    try:
        _validate_semantic_bounds(bad, proof)
    except ValueError:
        pass
    else:
        raise ValueError("Dependabot delegated admission self-test accepted an unproved Action SHA")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("candidate_root", type=Path)
    value.add_argument("--candidate-tree-sha", required=True)
    value.add_argument("--pr", type=Path, required=True)
    value.add_argument("--expected-head-sha", required=True)
    value.add_argument("--resolved-release", type=Path, required=True)
    value.add_argument("--changed-paths", type=Path, required=True)
    value.add_argument("--self-test", action="store_true")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.self_test:
            self_test()
        pr = strict_json(args.pr)
        changed_paths = [line.strip() for line in args.changed_paths.read_text(encoding="utf-8").splitlines() if line.strip()]
        decision, diff = evaluate(
            candidate_root=args.candidate_root,
            candidate_tree_sha=args.candidate_tree_sha,
            pr=pr,
            expected_head_sha=args.expected_head_sha,
            resolved_release=strict_json(args.resolved_release),
            changed_paths=changed_paths,
        )
        public = {
            "decision": {"allowed": decision["allowed"], "authorizationId": decision["authorizationId"]},
            "diff": {
                "expansions": [None] * len(diff["expansions"]),
                "reductions": [None] * len(diff["reductions"]),
            },
        }
        print(workflow_capability_bom.canonical_json(public), end="")
        return 0
    except (OSError, ValueError, json.JSONDecodeError):
        print("ERROR: trusted delegated Dependabot admission rejected candidate input", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
