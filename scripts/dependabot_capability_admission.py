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
import dependabot_artifact_reconciliation as artifact_reconciliation
import trusted_workflow_capability
import workflow_capability_admission
import workflow_capability_bom
import workflow_capability_diff
import workflow_capability_snapshot

ROOT = Path(__file__).resolve().parents[1]
DELEGATION_ID = "delegated-dependabot-codeql-v1"
ARTIFACT_DELEGATION_ID = "delegated-dependabot-artifact-v1"
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


def _action_identity(value: Mapping[str, Any], expected_repository: str) -> str:
    repository = value.get("repository")
    path = value.get("path")
    require(repository == expected_repository,
            "delegated Dependabot action repository changed")
    require(isinstance(path, str), "delegated Dependabot action subpath is malformed")
    return repository + (f"/{path}" if path else "")


def _validate_semantic_bounds(
    diff: Mapping[str, Any], proof: Mapping[str, Any],
    derived_paths: set[str] | None = None,
) -> None:
    before = _mapping(proof.get("before"), "Dependabot before identity")
    after = _mapping(proof.get("after"), "Dependabot after identity")
    old_sha = before.get("sha")
    new_sha = after.get("sha")
    actions = set(proof.get("actions", []))
    require(actions, "Dependabot delegated admission has no action inventory")
    repository = proof.get("dependencyRepository", dependabot_controller.CODEQL_REPOSITORY)
    require(repository == dependabot_controller.CODEQL_REPOSITORY or
            repository in artifact_reconciliation.REPOSITORIES,
            "delegated Dependabot repository is outside the approved governance scope")

    expansions = diff.get("expansions")
    reductions = diff.get("reductions")
    require(isinstance(expansions, list) and isinstance(reductions, list),
            "Dependabot delegated capability diff is malformed")
    require(expansions, "Dependabot delegated admission requires an actual capability expansion")

    # The native workflow files have already been proven to be ONLY atomic
    # release-pin edits by dependabot_controller.admit(), and the exact
    # changed-file closure is re-proved by validate_reconciled_candidate().
    # They must remain eligible trusted-control-source identities alongside
    # the deterministic derivative outputs, but no other candidate path can
    # become authorized merely because it appeared in the pull request.
    if repository in artifact_reconciliation.REPOSITORIES:
        native_paths = proof.get("files")
        require(
            isinstance(native_paths, list)
            and bool(native_paths)
            and native_paths == sorted(set(native_paths))
            and all(
                isinstance(path, str)
                and path.startswith(".github/workflows/")
                and path.endswith((".yml", ".yaml"))
                for path in native_paths
            ),
            "delegated artifact admission requires canonical proven native workflow paths",
        )
        require(
            isinstance(derived_paths, set) and BASE_BOM_PATH in derived_paths,
            "delegated artifact admission requires exact trusted derivative provenance",
        )
        expected_source_paths = derived_paths | set(native_paths)
    else:
        expected_source_paths = {BASE_BOM_PATH}

    action_expansions = []
    source_expansions = []
    expanded_actions: set[str] = set()
    for item in expansions:
        entry = _mapping(item, "Dependabot capability expansion")
        category = entry.get("category")
        if category == "action":
            candidate = _mapping(entry.get("after"), "Dependabot candidate action capability")
            require(candidate.get("ref") == new_sha,
                    "delegated Dependabot expansion introduced an unproved Action SHA")
            name = _action_identity(candidate, repository)
            require(name in actions,
                    "delegated Dependabot expansion introduced an unproved Action subpath")
            expanded_actions.add(name)
            action_expansions.append(entry)
        elif category == "trusted-control-source":
            require(entry.get("key") in expected_source_paths,
                    "delegated Dependabot admission changed an unapproved trusted-control source")
            source_expansions.append(entry)
        else:
            raise ValueError(f"delegated Dependabot admission forbids capability expansion category: {category}")

    require(expanded_actions == actions,
            "delegated Dependabot capability expansion does not cover exactly the admitted Action set")
    require(source_expansions and BASE_BOM_PATH in {e.get("key") for e in source_expansions},
            "delegated Dependabot reconciliation lost the protected base BOM snapshot")

    action_reductions = []
    reduced_actions: set[str] = set()
    for item in reductions:
        entry = _mapping(item, "Dependabot capability reduction")
        require(entry.get("category") == "action",
                f"delegated Dependabot admission forbids capability reduction category: {entry.get('category')}")
        previous = _mapping(entry.get("before"), "Dependabot previous action capability")
        require(previous.get("ref") == old_sha,
                "delegated Dependabot reduction removed an unproved Action SHA")
        name = _action_identity(previous, repository)
        require(name in actions,
                "delegated Dependabot reduction removed an unproved Action subpath")
        reduced_actions.add(name)
        action_reductions.append(entry)
    require(reduced_actions == actions and len(action_expansions) == len(action_reductions),
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
    derived_paths = None
    if proof["dependencyRepository"] in artifact_reconciliation.REPOSITORIES:
        derived_paths = set(artifact_reconciliation.derive(
            trusted_root=ROOT, candidate_root=candidate_root, proof=proof,
        ))
    _validate_semantic_bounds(diff, proof, derived_paths)

    decision = {
        "allowed": True,
        "authorizationRequired": True,
        "authorizationId": (ARTIFACT_DELEGATION_ID
                            if proof["dependencyRepository"] in artifact_reconciliation.REPOSITORIES
                            else DELEGATION_ID),
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

    native_workflow = ".github/workflows/dependabot-controller.yml"
    native_peer = ".github/workflows/ruleset-reconciler.yml"
    derived_validator = "scripts/workflow_capability_bom.py"
    artifact_proof = {
        **proof,
        "dependencyRepository": "actions/upload-artifact",
        "actions": ["actions/upload-artifact"],
        "files": [native_workflow, native_peer],
    }
    artifact_diff = {
        "expansions": [
            {"category": "action", "after": {
                "repository": "actions/upload-artifact", "path": "", "ref": "b" * 40}},
            {"category": "trusted-control-source", "key": BASE_BOM_PATH},
            {"category": "trusted-control-source", "key": native_workflow},
            {"category": "trusted-control-source", "key": native_peer},
            {"category": "trusted-control-source", "key": derived_validator},
        ],
        "reductions": [
            {"category": "action", "before": {
                "repository": "actions/upload-artifact", "path": "", "ref": "a" * 40}},
        ],
    }
    approved_derivatives = {BASE_BOM_PATH, derived_validator}
    _validate_semantic_bounds(artifact_diff, artifact_proof, approved_derivatives)

    # Changes must be restricted to the exact native proof + reproducible
    # derivative sets. Explicitly reject every attempt to expand this scope.
    for source in (
        ".github/workflows/capability-admission.yml",
        "scripts/dependabot_capability_admission.py",
        "scripts/workflow_capability_tcb.py",
    ):
        unauthorized = json.loads(json.dumps(artifact_diff))
        unauthorized["expansions"].append(
            {"category": "trusted-control-source", "key": source})
        try:
            _validate_semantic_bounds(unauthorized, artifact_proof, approved_derivatives)
        except ValueError as exc:
            require("unapproved trusted-control source" in str(exc),
                    "artifact source-bound regression failed at wrong trust boundary")
        else:
            raise ValueError("artifact source-bound regression admitted a non-proven source")

    for malformed_files in (
        [], [native_workflow, native_workflow],
        [native_peer, native_workflow],
        [native_workflow, "scripts/dependabot_capability_admission.py"],
    ):
        malformed = {**artifact_proof, "files": malformed_files}
        try:
            _validate_semantic_bounds(artifact_diff, malformed, approved_derivatives)
        except ValueError as exc:
            require("canonical proven native workflow paths" in str(exc),
                    "artifact forged native path regression failed at wrong trust boundary")
        else:
            raise ValueError("artifact source-bound regression admitted forged native paths")

    bad_release = json.loads(json.dumps(artifact_diff))
    bad_release["expansions"][0]["after"]["ref"] = "c" * 40
    try:
        _validate_semantic_bounds(bad_release, artifact_proof, approved_derivatives)
    except ValueError as exc:
        require("unproved Action SHA" in str(exc),
                "artifact unproved pin regression failed at wrong trust boundary")
    else:
        raise ValueError("artifact source-bound regression admitted an unproved Action SHA")


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
