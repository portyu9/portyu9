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
import copy
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


def _validate_setup_python_control_boundary(
    entry: Mapping[str, Any], old_sha: str, new_sha: str,
) -> None:
    """Admit precisely one proven setup-python pin within the admission workflow.

    The native signed-release gate has already proved atomic pin-only edits
    across all workflow files. Reprove the *entire* control workflow capability
    object here: no job/permission/trigger/mutation/source authority is excused.
    """
    require(entry.get("workflow") == "capability-admission",
            "delegated setup-python control boundary names another workflow")
    before = _mapping(entry.get("before"), "setup-python control boundary before")
    after = _mapping(entry.get("after"), "setup-python control boundary after")
    require(before.get("id") == after.get("id") == "capability-admission"
            and before.get("path") == after.get("path") ==
                ".github/workflows/capability-admission.yml",
            "delegated setup-python control workflow identity changed")
    expected = copy.deepcopy(before)
    jobs = expected.get("jobs")
    require(isinstance(jobs, list) and bool(jobs),
            "delegated setup-python control jobs are missing")
    substitutions = 0
    for job in jobs:
        require(isinstance(job, dict) and isinstance(job.get("actions"), list),
                "delegated setup-python control job/action shape changed")
        for action in job["actions"]:
            require(isinstance(action, dict),
                    "delegated setup-python control action shape changed")
            if action.get("repository") == "actions/setup-python":
                require(action.get("kind") == "remote"
                        and action.get("path") == ""
                        and action.get("ref") == old_sha,
                        "delegated setup-python control source is not the proven old Action")
                action["ref"] = new_sha
                substitutions += 1
    require(substitutions == 1 and expected == after,
            "delegated setup-python control boundary changed beyond one signed Action pin")


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
    control_expansions = []
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
        elif category == "trusted-control-boundary":
            require(repository == "actions/setup-python",
                    "delegated control-boundary admission is exclusive to signed setup-python")
            _validate_setup_python_control_boundary(entry, old_sha, new_sha)
            control_expansions.append(entry)
        else:
            raise ValueError(f"delegated Dependabot admission forbids capability expansion category: {category}")

    require(expanded_actions == actions,
            "delegated Dependabot capability expansion does not cover exactly the admitted Action set")
    require(len(control_expansions) == (1 if repository == "actions/setup-python" else 0),
            "delegated setup-python requires exactly one independently proven control boundary")
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

    # A signed setup-python update necessarily changes the pinned Action ref in
    # the Capability Admission workflow. The trusted-control-boundary guard
    # must accept only that single exact ref replacement, never permissions,
    # triggers, a second action, source-path changes or other repositories.
    setup_before = {
        "id": "capability-admission",
        "path": ".github/workflows/capability-admission.yml",
        "jobs": [{"id": "admission", "permissions": {"contents": "read"},
                  "actions": [{"kind": "remote", "repository": "actions/setup-python",
                               "path": "", "ref": "a" * 40, "step": "Set up Python"}]}],
        "triggers": ["pull_request_target"],
    }
    setup_after = copy.deepcopy(setup_before)
    setup_after["jobs"][0]["actions"][0]["ref"] = "b" * 40
    setup_diff = copy.deepcopy(artifact_diff)
    for source_expansion in setup_diff["expansions"]:
        if source_expansion["category"] == "action":
            source_expansion["after"]["repository"] = "actions/setup-python"
    for source_reduction in setup_diff["reductions"]:
        source_reduction["before"]["repository"] = "actions/setup-python"
    control_entry = {
        "category": "trusted-control-boundary",
        "workflow": "capability-admission",
        "before": setup_before,
        "after": setup_after,
    }
    setup_diff["expansions"].append(copy.deepcopy(control_entry))
    setup_proof = {**artifact_proof, "dependencyRepository": "actions/setup-python",
                   "actions": ["actions/setup-python"]}
    _validate_semantic_bounds(setup_diff, setup_proof, approved_derivatives)

    def reject_setup_control(mutated: dict[str, Any], expected: str) -> None:
        try:
            _validate_semantic_bounds(mutated, setup_proof, approved_derivatives)
        except ValueError as exc:
            require(expected in str(exc),
                    f"setup-python control negative test failed at wrong boundary: {exc}")
        else:
            raise ValueError(f"setup-python control negative test accepted: {expected}")

    no_control = copy.deepcopy(setup_diff)
    no_control["expansions"].pop()
    reject_setup_control(no_control, "requires exactly one independently proven control boundary")
    duplicate_control = copy.deepcopy(setup_diff)
    duplicate_control["expansions"].append(copy.deepcopy(control_entry))
    reject_setup_control(duplicate_control, "requires exactly one independently proven control boundary")
    wrong_control = copy.deepcopy(setup_diff)
    wrong_control["expansions"][-1]["workflow"] = "dependabot-controller"
    reject_setup_control(wrong_control, "names another workflow")
    widened_permissions = copy.deepcopy(setup_diff)
    widened_permissions["expansions"][-1]["after"]["jobs"][0]["permissions"]["contents"] = "write"
    reject_setup_control(widened_permissions, "changed beyond one signed Action pin")
    forged_old_sha = copy.deepcopy(setup_diff)
    forged_old_sha["expansions"][-1]["before"]["jobs"][0]["actions"][0]["ref"] = "c" * 40
    reject_setup_control(forged_old_sha, "not the proven old Action")
    changed_trigger = copy.deepcopy(setup_diff)
    changed_trigger["expansions"][-1]["after"]["triggers"].append("workflow_dispatch")
    reject_setup_control(changed_trigger, "changed beyond one signed Action pin")
    extra_remote_action = copy.deepcopy(setup_diff)
    extra_remote_action["expansions"][-1]["after"]["jobs"][0]["actions"].append({
        "kind": "remote", "repository": "thirdparty/unreviewed",
        "path": "", "ref": "b" * 40, "step": "Unapproved",
    })
    reject_setup_control(extra_remote_action, "changed beyond one signed Action pin")
    wrong_artifact_control = copy.deepcopy(artifact_diff)
    wrong_artifact_control["expansions"].append(copy.deepcopy(control_entry))
    try:
        _validate_semantic_bounds(wrong_artifact_control, artifact_proof, approved_derivatives)
    except ValueError as exc:
        require("exclusive to signed setup-python" in str(exc),
                f"artifact negative control test failed at wrong boundary: {exc}")
    else:
        raise ValueError("artifact control-boundary bypass was accepted")

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
