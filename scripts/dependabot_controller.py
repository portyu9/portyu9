#!/usr/bin/env python3
"""Trusted, network-free planning for zero-touch Dependabot CodeQL Action updates.

The module never executes candidate-authored source. Callers provide trusted GitHub PR
metadata plus repository trees assembled as data. It proves the native Dependabot identity
and atomic immutable pin diff, binds public release provenance supplied by the caller, and
derives the exact repository-governance files that must accompany one CodeQL Action release.
Repository/API mutations remain visible in the trusted workflow rather than hidden here.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Mapping

from action_identity_lock import (
    ENTRY_KEYS,
    load_action_lock,
    parse_action_lock_json,
    repository_for_action,
    validate_payload as validate_action_lock_payload,
)
from dependabot_admission import evaluate_dependabot_admission
from dependabot_pin_diff import classify_pin_only_update
from dependabot_pr_identity import classify_pr_identity, fixture as pr_fixture
import trusted_workflow_capability
import workflow_capability_bom

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "portyu9/portyu9"
CODEQL_REPOSITORY = "github/codeql-action"
ACTION_LOCK = Path(".github/action-lock.json")
CODEQL_VALIDATOR = Path("scripts/validate-codeql-contract.py")
BASE_BOM = Path(".github/workflow-capability-bom-v1.json")
DERIVED_PATHS = (ACTION_LOCK.as_posix(), BASE_BOM.as_posix(), CODEQL_VALIDATOR.as_posix())
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def strict_json(path: Path, label: str) -> Any:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing or aliased: {path}")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def workflow_corpus(root: Path) -> dict[str, str]:
    directory = root / ".github/workflows"
    require(directory.is_dir() and not directory.is_symlink(), "workflow corpus directory is missing or aliased")
    paths = sorted({*directory.glob("*.yml"), *directory.glob("*.yaml")})
    require(paths, "workflow corpus is empty")
    return {path.relative_to(root).as_posix(): path.read_text(encoding="utf-8") for path in paths}


def probe(
    *,
    pr: Mapping[str, Any],
    expected_head_sha: str,
    base_root: Path,
    candidate_root: Path,
) -> dict[str, object]:
    require(SHA40.fullmatch(expected_head_sha) is not None, "Dependabot controller expected head SHA is invalid")
    identity = classify_pr_identity(pr, repository=REPOSITORY, expected_head_sha=expected_head_sha)
    require(identity.get("classification") == "dependabot-github-actions",
            "Dependabot controller applies only to exact native GitHub-Actions Dependabot PRs")
    pin = classify_pin_only_update(
        workflow_corpus(base_root),
        workflow_corpus(candidate_root),
        load_action_lock(base_root / ACTION_LOCK),
    )
    require(pin.get("repository") == CODEQL_REPOSITORY,
            "zero-touch delegated admission is initially restricted to github/codeql-action")
    return {
        "classification": "dependabot-codeql-probe",
        "repository": REPOSITORY,
        "pullRequest": identity["pullRequest"],
        "headRef": identity["headRef"],
        "headSha": identity["headSha"],
        "dependencyRepository": pin["repository"],
        "before": copy.deepcopy(pin["before"]),
        "after": copy.deepcopy(pin["after"]),
        "actions": copy.deepcopy(pin["actions"]),
        "files": copy.deepcopy(pin["files"]),
        "occurrences": pin["occurrences"],
    }


def admit(
    *,
    pr: Mapping[str, Any],
    expected_head_sha: str,
    base_root: Path,
    candidate_root: Path,
    resolved_release: Mapping[str, Any],
) -> dict[str, object]:
    result = evaluate_dependabot_admission(
        pr=pr,
        repository=REPOSITORY,
        expected_head_sha=expected_head_sha,
        base_files=workflow_corpus(base_root),
        candidate_files=workflow_corpus(candidate_root),
        trusted_lock=load_action_lock(base_root / ACTION_LOCK),
        resolve_release=lambda repository, tag, expected_sha: resolved_release,
    )
    require(result.get("classification") == "allowed", "Dependabot release was not admitted")
    require(result.get("dependencyRepository") == CODEQL_REPOSITORY,
            "zero-touch delegated admission is initially restricted to github/codeql-action")
    return result


def _replace_exact_assignment(text: str, name: str, old: str, new: str) -> str:
    before = f'{name} = "{old}"'
    after = f'{name} = "{new}"'
    require(text.count(before) == 1, f"trusted CodeQL validator lost exact {name} assignment")
    require(after not in text or old == new, f"trusted CodeQL validator already contains unexpected {name} target")
    return text.replace(before, after, 1)


def derive_codeql_files(
    *,
    base_root: Path,
    candidate_root: Path,
    proof: Mapping[str, Any],
) -> dict[str, str]:
    require(proof.get("classification") == "allowed", "Dependabot reconciliation requires an allowed provenance proof")
    require(proof.get("dependencyRepository") == CODEQL_REPOSITORY,
            "Dependabot reconciliation only derives CodeQL Action governance")
    after = proof.get("after")
    before = proof.get("before")
    require(isinstance(after, Mapping) and isinstance(before, Mapping), "Dependabot proof lost release identities")
    target_identity = {key: after.get(key) for key in ENTRY_KEYS}
    old_identity = {key: before.get(key) for key in ENTRY_KEYS}
    target_sha = target_identity["sha"]
    target_tag = target_identity["tag"]
    old_sha = old_identity["sha"]
    old_tag = old_identity["tag"]
    require(all(value is not None for value in target_identity.values())
            and all(value is not None for value in old_identity.values()),
            "Dependabot proof release identities are incomplete")
    require(isinstance(target_sha, str) and isinstance(target_tag, str)
            and isinstance(old_sha, str) and isinstance(old_tag, str),
            "Dependabot proof release identities are malformed")
    require(SHA40.fullmatch(target_sha) is not None and SHA40.fullmatch(old_sha) is not None,
            "Dependabot proof release SHA is malformed")

    lock_path = base_root / ACTION_LOCK
    payload = parse_action_lock_json(lock_path.read_text(encoding="utf-8"))
    lock = validate_action_lock_payload(payload)
    updated_actions = copy.deepcopy(payload["actions"])
    matched = []
    for action in sorted(updated_actions):
        if repository_for_action(action) != CODEQL_REPOSITORY:
            continue
        require(lock[action] == old_identity,
                f"trusted CodeQL Action lock base identity drifted for {action}")
        updated_actions[action] = dict(target_identity)
        matched.append(action)
    require(matched and set(matched) == set(proof.get("actions", [])),
            "Dependabot proof does not cover every locked CodeQL sub-action")
    lock_output = json.dumps(
        {"version": payload["version"], "actions": updated_actions},
        indent=2,
        ensure_ascii=True,
    ) + "\n"
    validate_action_lock_payload(parse_action_lock_json(lock_output))

    validator_text = (base_root / CODEQL_VALIDATOR).read_text(encoding="utf-8")
    validator_text = _replace_exact_assignment(validator_text, "CODEQL_SHA", str(old_sha), str(target_sha))
    validator_text = _replace_exact_assignment(validator_text, "CODEQL_RELEASE", str(old_tag), str(target_tag))

    compiled = trusted_workflow_capability.compile_repository(candidate_root)
    extension_ids = {"action-provenance-witness", "bot-pr-user-approval", "capability-admission", "codeql-autofix", "dependabot-controller", "profile-generator-compatibility-witness", "ruleset-drift-sentinel", "ruleset-reconciler"}
    base_workflows = [
        copy.deepcopy(workflow)
        for workflow in compiled["workflows"]
        if workflow.get("id") not in extension_ids
    ]
    require(len(base_workflows) == 5, "Dependabot reconciliation expected the historical five-workflow base snapshot")
    base_snapshot = {key: copy.deepcopy(compiled[key]) for key in compiled if key != "workflows"}
    base_snapshot["workflows"] = base_workflows
    bom_output = workflow_capability_bom.canonical_json(base_snapshot)

    return {
        ACTION_LOCK.as_posix(): lock_output,
        BASE_BOM.as_posix(): bom_output,
        CODEQL_VALIDATOR.as_posix(): validator_text,
    }


def validate_reconciled_candidate(
    *,
    base_root: Path,
    candidate_root: Path,
    proof: Mapping[str, Any],
    changed_paths: list[str],
) -> dict[str, object]:
    expected = derive_codeql_files(base_root=base_root, candidate_root=candidate_root, proof=proof)
    pin_files = proof.get("files")
    require(isinstance(pin_files, list) and all(isinstance(path, str) for path in pin_files),
            "Dependabot proof changed-file inventory is malformed")
    expected_paths = sorted(set(pin_files) | set(DERIVED_PATHS))
    require(sorted(set(changed_paths)) == expected_paths,
            f"reconciled Dependabot PR changed unexpected files: expected={expected_paths} observed={sorted(set(changed_paths))}")
    for relative, text in expected.items():
        path = candidate_root / relative
        require(path.is_file() and not path.is_symlink(), f"reconciled Dependabot derived file is missing: {relative}")
        require(path.read_text(encoding="utf-8") == text,
                f"reconciled Dependabot derived file differs from trusted derivation: {relative}")
    return {
        "classification": "dependabot-codeql-reconciled",
        "pullRequest": proof["pullRequest"],
        "headSha": proof["headSha"],
        "dependencyRepository": CODEQL_REPOSITORY,
        "changedPaths": expected_paths,
    }


def write_outputs(files: Mapping[str, str], output_root: Path) -> None:
    for relative, text in files.items():
        path = output_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def load_json(path: Path) -> Any:
    return strict_json(path, str(path))


def _response_sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
            f"{label} must be an exact lowercase SHA-40")
    return value


def _response_positive_int(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


PROTECTED_PR_RUN_STATUSES = {"queued", "in_progress", "requested", "waiting", "pending", "completed"}
PROTECTED_PR_RUN_CONCLUSIONS = {
    "success",
    "failure",
    "neutral",
    "cancelled",
    "skipped",
    "timed_out",
    "action_required",
    "stale",
    "startup_failure",
    "waiting",
}
PROTECTED_WORKFLOW_IDENTITIES = {
    ".github/workflows/codeql.yml": "CodeQL",
    ".github/workflows/dependency-review.yml": "Dependency review",
    ".github/workflows/profile-quality.yml": "Profile quality",
}


def validate_workflow_definition_response(value: Any, *, expected_path: str) -> dict[str, Any]:
    expected_name = PROTECTED_WORKFLOW_IDENTITIES.get(expected_path)
    require(expected_name is not None, "Dependabot protected workflow path is not reviewed")
    require(isinstance(value, Mapping), "Dependabot workflow-definition response must be an object")
    workflow_id = _response_positive_int(value.get("id"), "Dependabot workflow-definition id")
    require(value.get("path") == expected_path, "Dependabot workflow-definition path mismatch")
    require(value.get("name") == expected_name, "Dependabot workflow-definition name mismatch")
    require(value.get("state") == "active", "Dependabot workflow-definition state changed")
    for key in ("url", "html_url"):
        observed = value.get(key)
        require(
            isinstance(observed, str) and bool(observed.strip()),
            f"Dependabot workflow-definition {key} must be a nonempty string",
        )
    return {"id": workflow_id, "path": expected_path, "name": expected_name, "state": "active"}


def validate_protected_pr_workflow_runs_response(
    value: Any,
    *,
    expected_sha: str,
    branch: str,
    codeql_workflow_id: int,
    dependency_workflow_id: int,
    profile_workflow_id: int,
) -> dict[str, Any]:
    expected_sha = _response_sha(expected_sha, "Dependabot protected workflow-run head sha")
    require(isinstance(branch, str) and bool(branch.strip()),
            "Dependabot protected workflow-run branch must be nonempty")
    expected_workflows = {
        _response_positive_int(codeql_workflow_id, "Dependabot CodeQL workflow id"):
            (".github/workflows/codeql.yml", "CodeQL"),
        _response_positive_int(dependency_workflow_id, "Dependabot Dependency Review workflow id"):
            (".github/workflows/dependency-review.yml", "Dependency review"),
        _response_positive_int(profile_workflow_id, "Dependabot Profile Quality workflow id"):
            (".github/workflows/profile-quality.yml", "Profile quality"),
    }
    require(len(expected_workflows) == 3,
            "Dependabot protected workflow ids must be three distinct identities")

    require(isinstance(value, Mapping), "Dependabot protected workflow-run response must be an object")
    total_count = value.get("total_count")
    require(type(total_count) is int and 0 <= total_count <= 100,
            "Dependabot protected workflow-run total_count must be an integer in [0,100]")
    raw_runs = value.get("workflow_runs")
    require(isinstance(raw_runs, list) and len(raw_runs) <= 100,
            "Dependabot protected workflow_runs must be an array with at most 100 entries")
    require(total_count == len(raw_runs),
            "Dependabot protected workflow-run total_count does not match returned array length")
    require(total_count <= 3,
            "Dependabot protected workflow-run set is ambiguous")

    seen_run_ids: set[int] = set()
    seen_workflow_ids: set[int] = set()
    seen_check_suite_ids: set[int] = set()
    normalized: list[dict[str, Any]] = []
    for raw in raw_runs:
        require(isinstance(raw, Mapping),
                "Dependabot protected workflow-run collection contains a non-object")
        run_id = _response_positive_int(raw.get("id"), "Dependabot protected workflow run id")
        require(run_id not in seen_run_ids,
                f"duplicate Dependabot protected workflow run id: {run_id}")
        seen_run_ids.add(run_id)

        workflow_id = _response_positive_int(
            raw.get("workflow_id"), "Dependabot protected workflow id"
        )
        require(workflow_id in expected_workflows,
                "Dependabot protected workflow run references an unexpected workflow id")
        require(workflow_id not in seen_workflow_ids,
                f"duplicate Dependabot protected workflow id: {workflow_id}")
        seen_workflow_ids.add(workflow_id)

        check_suite_id = _response_positive_int(
            raw.get("check_suite_id"), "Dependabot protected workflow check-suite id"
        )
        require(check_suite_id not in seen_check_suite_ids,
                f"duplicate Dependabot protected workflow check-suite id: {check_suite_id}")
        seen_check_suite_ids.add(check_suite_id)
        run_attempt = _response_positive_int(
            raw.get("run_attempt"), "Dependabot protected workflow run attempt"
        )

        expected_path, expected_name = expected_workflows[workflow_id]
        require(raw.get("path") == expected_path,
                "Dependabot protected workflow run path mismatch")
        require(raw.get("name") == expected_name,
                "Dependabot protected workflow run name mismatch")
        require(raw.get("event") == "pull_request",
                "Dependabot protected workflow run event changed")
        require(
            _response_sha(raw.get("head_sha"), "Dependabot protected workflow run head sha")
            == expected_sha,
            "Dependabot protected workflow run head sha mismatch",
        )
        require(raw.get("head_branch") == branch,
                "Dependabot protected workflow run head branch mismatch")
        for key in ("repository", "head_repository"):
            repository = raw.get(key)
            require(isinstance(repository, Mapping),
                    f"Dependabot protected workflow run {key} must be an object")
            require(repository.get("full_name") == REPOSITORY,
                    f"Dependabot protected workflow run {key} identity mismatch")

        status = raw.get("status")
        require(
            isinstance(status, str) and status in PROTECTED_PR_RUN_STATUSES,
            "Dependabot protected workflow run status is outside the reviewed status set",
        )
        conclusion = raw.get("conclusion")
        if status == "completed":
            require(
                isinstance(conclusion, str)
                and bool(conclusion)
                and conclusion in PROTECTED_PR_RUN_CONCLUSIONS,
                "Dependabot completed protected workflow run conclusion is outside the reviewed conclusion set",
            )
        else:
            require(conclusion is None,
                    "Dependabot non-completed protected workflow run conclusion must be null")

        normalized.append({
            "id": run_id,
            "name": expected_name,
            "workflowId": workflow_id,
            "checkSuiteId": check_suite_id,
            "runAttempt": run_attempt,
            "status": status,
            "conclusion": conclusion,
        })
    normalized.sort(key=lambda item: item["name"])
    return {"totalCount": total_count, "runs": normalized}


def validate_git_blob_response(value: Any) -> dict[str, str]:
    require(isinstance(value, Mapping), "Dependabot Git blob response must be an object")
    observed = _response_sha(value.get("sha"), "Dependabot Git blob response sha")
    return {"kind": "blob", "sha": observed}


def validate_git_tree_response(value: Any) -> dict[str, str]:
    require(isinstance(value, Mapping), "Dependabot Git tree response must be an object")
    observed = _response_sha(value.get("sha"), "Dependabot Git tree response sha")
    return {"kind": "tree", "sha": observed}


def validate_git_commit_response(
    value: Any,
    *,
    expected_tree_sha: str,
    expected_parent_sha: str,
) -> dict[str, str]:
    expected_tree_sha = _response_sha(expected_tree_sha, "expected Dependabot Git tree sha")
    expected_parent_sha = _response_sha(expected_parent_sha, "expected Dependabot Git parent sha")
    require(isinstance(value, Mapping), "Dependabot Git commit response must be an object")
    commit_sha = _response_sha(value.get("sha"), "Dependabot Git commit response sha")
    tree = value.get("tree")
    require(isinstance(tree, Mapping), "Dependabot Git commit response tree must be an object")
    require(_response_sha(tree.get("sha"), "Dependabot Git commit response tree sha") == expected_tree_sha,
            "Dependabot Git commit response tree sha changed")
    parents = value.get("parents")
    require(isinstance(parents, list) and len(parents) == 1,
            "Dependabot Git commit response must contain exactly one parent")
    require(isinstance(parents[0], Mapping),
            "Dependabot Git commit response parent must be an object")
    require(_response_sha(parents[0].get("sha"), "Dependabot Git commit response parent sha") == expected_parent_sha,
            "Dependabot Git commit response parent sha changed")
    return {
        "kind": "commit",
        "sha": commit_sha,
        "treeSha": expected_tree_sha,
        "parentSha": expected_parent_sha,
    }


def validate_git_ref_response(
    value: Any,
    *,
    expected_ref: str,
    expected_sha: str,
) -> dict[str, str]:
    require(isinstance(expected_ref, str) and expected_ref.startswith("refs/heads/")
            and expected_ref != "refs/heads/",
            "expected Dependabot Git ref must be a concrete heads ref")
    expected_sha = _response_sha(expected_sha, "expected Dependabot Git ref sha")
    require(isinstance(value, Mapping), "Dependabot Git ref response must be an object")
    require(value.get("ref") == expected_ref, "Dependabot Git ref response identity changed")
    obj = value.get("object")
    require(isinstance(obj, Mapping), "Dependabot Git ref response object must be an object")
    require(obj.get("type") == "commit", "Dependabot Git ref response object type must be commit")
    observed = _response_sha(obj.get("sha"), "Dependabot Git ref response object sha")
    require(observed == expected_sha, "Dependabot Git ref response object sha changed")
    return {"kind": "ref", "ref": expected_ref, "sha": expected_sha}


def validate_git_ref_read_response(
    value: Any,
    *,
    expected_ref: str,
    expected_sha: str | None = None,
) -> dict[str, str]:
    require(isinstance(expected_ref, str) and expected_ref.startswith("refs/heads/")
            and expected_ref != "refs/heads/",
            "expected Dependabot read Git ref must be a concrete heads ref")
    require(isinstance(value, Mapping), "Dependabot read Git ref response must be an object")
    require(value.get("ref") == expected_ref, "Dependabot read Git ref response identity changed")
    obj = value.get("object")
    require(isinstance(obj, Mapping), "Dependabot read Git ref response object must be an object")
    require(obj.get("type") == "commit",
            "Dependabot read Git ref response object type must be commit")
    observed = _response_sha(obj.get("sha"), "Dependabot read Git ref response object sha")
    object_url = obj.get("url")
    require(isinstance(object_url, str) and bool(object_url.strip()),
            "Dependabot read Git ref response object url must be a nonempty string")
    if expected_sha is not None:
        expected_sha = _response_sha(expected_sha, "expected Dependabot read Git ref sha")
        require(observed == expected_sha, "Dependabot read Git ref response object sha changed")
    return {"kind": "read-ref", "ref": expected_ref, "sha": observed, "objectUrl": object_url}


def validate_wake_run_response(
    value: Any,
    *,
    expected_run_id: int,
    expected_repository: str,
) -> dict[str, Any]:
    require(type(expected_run_id) is int and expected_run_id > 0,
            "expected Dependabot wake run id must be a positive integer")
    require(isinstance(expected_repository, str) and bool(expected_repository.strip()),
            "expected Dependabot wake repository must be a nonempty string")
    require(isinstance(value, Mapping), "Dependabot wake run response must be an object")
    run_id = value.get("id")
    require(type(run_id) is int and run_id > 0 and run_id == expected_run_id,
            "Dependabot wake run response id changed")
    name = value.get("name")
    require(isinstance(name, str) and name in {"Profile quality", "CodeQL"},
            "Dependabot wake run response workflow identity changed")
    event = value.get("event")
    require(isinstance(event, str) and event in {"push", "pull_request", "workflow_dispatch"},
            "Dependabot wake run response event changed")
    head_branch = value.get("head_branch")
    require(isinstance(head_branch, str) and bool(head_branch),
            "Dependabot wake run response head_branch must be a nonempty string")
    head_sha = _response_sha(value.get("head_sha"), "Dependabot wake run response head_sha")
    for key in ("repository", "head_repository"):
        repository = value.get(key)
        require(isinstance(repository, Mapping),
                f"Dependabot wake run response {key} must be an object")
        full_name = repository.get("full_name")
        require(isinstance(full_name, str) and full_name == expected_repository,
                f"Dependabot wake run response {key} identity changed")
    return {
        "kind": "wake-run",
        "id": run_id,
        "name": name,
        "event": event,
        "headBranch": head_branch,
        "headSha": head_sha,
        "repository": expected_repository,
    }


def validate_merge_success_response(value: Any) -> dict[str, Any]:
    require(isinstance(value, Mapping), "Dependabot merge success response must be an object")
    require(type(value.get("merged")) is bool, "Dependabot merge success response merged must be boolean")
    require(value.get("merged") is True, "Dependabot merge success response must report merged=true")
    merge_sha = _response_sha(value.get("sha"), "Dependabot merge success response sha")
    message = value.get("message")
    require(isinstance(message, str) and bool(message.strip()),
            "Dependabot merge success response message must be a nonempty string")
    return {"kind": "merge", "merged": True, "sha": merge_sha, "message": message}


def self_test() -> None:
    base = ROOT
    lock = load_action_lock(base / ACTION_LOCK)
    codeql_actions = sorted(action for action in lock if repository_for_action(action) == CODEQL_REPOSITORY)
    require(codeql_actions, "Dependabot controller self-test found no CodeQL actions")
    old_identity = dict(lock[codeql_actions[0]])
    old_sha = str(old_identity["sha"])
    old_tag = str(old_identity["tag"])
    require(all(lock[action] == old_identity for action in codeql_actions),
            "Dependabot controller self-test requires one CodeQL base release")
    new_sha = "b" * 40 if old_sha != "b" * 40 else "c" * 40
    new_tag = "v999.0.0"
    new_identity = dict(old_identity)
    new_identity["releaseId"] = int(old_identity["releaseId"]) + 1
    new_identity["sha"] = new_sha
    new_identity["tag"] = new_tag
    new_identity["tagRefSha"] = "e" * 40 if new_sha != "e" * 40 else "f" * 40
    new_identity["tagRefType"] = "tag"
    with tempfile.TemporaryDirectory(prefix="dependabot-controller-") as directory:
        candidate = Path(directory) / "candidate"
        shutil.copytree(base, candidate, symlinks=True)
        for path in (candidate / ".github/workflows").glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            for action in codeql_actions:
                text = text.replace(f"{action}@{old_sha} # {old_tag}", f"{action}@{new_sha} # {new_tag}")
            path.write_text(text, encoding="utf-8")
        pr = pr_fixture()
        pr["head"]["sha"] = "d" * 40
        proof = admit(
            pr=pr,
            expected_head_sha="d" * 40,
            base_root=base,
            candidate_root=candidate,
            resolved_release=new_identity,
        )
        derived = derive_codeql_files(base_root=base, candidate_root=candidate, proof=proof)
        write_outputs(derived, candidate)
        changed = sorted(set(proof["files"]) | set(DERIVED_PATHS))
        reconciled = validate_reconciled_candidate(
            base_root=base,
            candidate_root=candidate,
            proof=proof,
            changed_paths=changed,
        )
        require(reconciled["classification"] == "dependabot-codeql-reconciled",
                "Dependabot controller self-test failed reconciliation")

    blob_sha = "1" * 40
    tree_sha = "2" * 40
    parent_sha = "3" * 40
    commit_sha = "4" * 40
    ref_name = "refs/heads/dependabot/github_actions/github/codeql-action"
    require(validate_git_blob_response({"sha": blob_sha}) == {"kind": "blob", "sha": blob_sha},
            "Dependabot Git blob response positive fixture changed")
    require(validate_git_tree_response({"sha": tree_sha}) == {"kind": "tree", "sha": tree_sha},
            "Dependabot Git tree response positive fixture changed")
    commit = validate_git_commit_response(
        {"sha": commit_sha, "tree": {"sha": tree_sha}, "parents": [{"sha": parent_sha}]},
        expected_tree_sha=tree_sha,
        expected_parent_sha=parent_sha,
    )
    require(commit["sha"] == commit_sha and commit["treeSha"] == tree_sha and commit["parentSha"] == parent_sha,
            "Dependabot Git commit response positive fixture changed")
    ref = validate_git_ref_response(
        {"ref": ref_name, "object": {"type": "commit", "sha": commit_sha}},
        expected_ref=ref_name,
        expected_sha=commit_sha,
    )
    require(ref == {"kind": "ref", "ref": ref_name, "sha": commit_sha},
            "Dependabot Git ref response positive fixture changed")
    ref_url = f"https://api.github.com/repos/{REPOSITORY}/git/commits/{commit_sha}"
    read_ref = validate_git_ref_read_response(
        {"ref": ref_name, "object": {"type": "commit", "sha": commit_sha, "url": ref_url}},
        expected_ref=ref_name,
        expected_sha=commit_sha,
    )
    require(
        read_ref == {
            "kind": "read-ref",
            "ref": ref_name,
            "sha": commit_sha,
            "objectUrl": ref_url,
        },
        "Dependabot read Git ref response positive fixture changed",
    )
    wake_run = validate_wake_run_response(
        {
            "id": 123456,
            "name": "CodeQL",
            "event": "push",
            "head_branch": "main",
            "head_sha": commit_sha,
            "repository": {"full_name": REPOSITORY},
            "head_repository": {"full_name": REPOSITORY},
        },
        expected_run_id=123456,
        expected_repository=REPOSITORY,
    )
    require(
        wake_run == {
            "kind": "wake-run",
            "id": 123456,
            "name": "CodeQL",
            "event": "push",
            "headBranch": "main",
            "headSha": commit_sha,
            "repository": REPOSITORY,
        },
        "Dependabot wake run response positive fixture changed",
    )
    workflow_fixture = {
        "id": 1001,
        "path": ".github/workflows/codeql.yml",
        "name": "CodeQL",
        "state": "active",
        "url": "https://api.github.com/repos/portyu9/portyu9/actions/workflows/1001",
        "html_url": "https://github.com/portyu9/portyu9/actions/workflows/codeql.yml",
    }
    require(
        validate_workflow_definition_response(
            workflow_fixture, expected_path=".github/workflows/codeql.yml"
        )["id"] == 1001,
        "Dependabot workflow-definition positive fixture changed",
    )
    for mutated, expected in (
        ([], "must be an object"),
        ({**workflow_fixture, "id": True}, "positive integer"),
        ({**workflow_fixture, "path": ".github/workflows/other.yml"}, "path mismatch"),
        ({**workflow_fixture, "name": "Other"}, "name mismatch"),
        ({**workflow_fixture, "state": "disabled_manually"}, "state changed"),
        ({**workflow_fixture, "url": ""}, "url must be a nonempty string"),
        ({**workflow_fixture, "html_url": None}, "html_url must be a nonempty string"),
    ):
        try:
            validate_workflow_definition_response(
                mutated, expected_path=".github/workflows/codeql.yml"
            )
        except ValueError as exc:
            require(expected in str(exc),
                    f"workflow-definition fixture failed for wrong reason: {exc}")
        else:
            raise ValueError(
                f"Dependabot workflow-definition response accepted forbidden fixture: {expected}"
            )

    protected_branch = "dependabot/github_actions/github/codeql-action"
    protected_ids = (1001, 1002, 1003)

    def protected_run(
        run_id: Any,
        workflow_id: Any,
        check_suite_id: Any,
        *,
        run_attempt: Any = 1,
        path: Any | None = None,
        name: Any | None = None,
        event_name: Any = "pull_request",
        observed_head: Any = commit_sha,
        observed_branch: Any = protected_branch,
        repository: Any = REPOSITORY,
        head_repository: Any = REPOSITORY,
        status: Any = "waiting",
        conclusion: Any = None,
    ) -> dict[str, Any]:
        identities = {
            1001: (".github/workflows/codeql.yml", "CodeQL"),
            1002: (".github/workflows/dependency-review.yml", "Dependency review"),
            1003: (".github/workflows/profile-quality.yml", "Profile quality"),
        }
        expected_path, expected_name = identities.get(
            workflow_id, (".github/workflows/codeql.yml", "CodeQL")
        )
        return {
            "id": run_id,
            "workflow_id": workflow_id,
            "check_suite_id": check_suite_id,
            "run_attempt": run_attempt,
            "path": expected_path if path is None else path,
            "name": expected_name if name is None else name,
            "event": event_name,
            "head_sha": observed_head,
            "head_branch": observed_branch,
            "repository": {"full_name": repository} if isinstance(repository, str) else repository,
            "head_repository": (
                {"full_name": head_repository}
                if isinstance(head_repository, str)
                else head_repository
            ),
            "status": status,
            "conclusion": conclusion,
        }

    protected_response = {
        "total_count": 3,
        "workflow_runs": [
            protected_run(201, 1001, 301, status="completed", conclusion="success"),
            protected_run(202, 1002, 302, status="waiting"),
            protected_run(203, 1003, 303, status="completed", conclusion="action_required"),
        ],
    }
    protected = validate_protected_pr_workflow_runs_response(
        protected_response,
        expected_sha=commit_sha,
        branch=protected_branch,
        codeql_workflow_id=protected_ids[0],
        dependency_workflow_id=protected_ids[1],
        profile_workflow_id=protected_ids[2],
    )
    require(
        protected["totalCount"] == 3
        and [item["name"] for item in protected["runs"]]
        == ["CodeQL", "Dependency review", "Profile quality"],
        "Dependabot protected workflow-run positive fixture changed",
    )
    protected_mutations = (
        ([], "must be an object"),
        ({"total_count": True, "workflow_runs": []}, "integer in [0,100]"),
        ({"total_count": 1, "workflow_runs": []}, "does not match returned array length"),
        ({"total_count": 4, "workflow_runs": [
            protected_run(201, 1001, 301),
            protected_run(202, 1002, 302),
            protected_run(203, 1003, 303),
            protected_run(204, 1001, 304),
        ]}, "set is ambiguous"),
        ({"total_count": 1, "workflow_runs": [None]}, "contains a non-object"),
        ({"total_count": 1, "workflow_runs": [protected_run(True, 1001, 301)]}, "positive integer"),
        ({"total_count": 2, "workflow_runs": [
            protected_run(201, 1001, 301), protected_run(201, 1002, 302)
        ]}, "duplicate Dependabot protected workflow run id"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 9999, 301)]}, "unexpected workflow id"),
        ({"total_count": 2, "workflow_runs": [
            protected_run(201, 1001, 301), protected_run(202, 1001, 302)
        ]}, "duplicate Dependabot protected workflow id"),
        ({"total_count": 2, "workflow_runs": [
            protected_run(201, 1001, 301), protected_run(202, 1002, 301)
        ]}, "duplicate Dependabot protected workflow check-suite id"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, run_attempt=0)]}, "positive integer"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, path=".github/workflows/other.yml")]}, "path mismatch"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, name="Other")]}, "name mismatch"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, event_name="push")]}, "event changed"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, observed_head="BAD")]}, "lowercase SHA-40"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, observed_branch="other")]}, "head branch mismatch"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, repository="other/repo")]}, "repository identity mismatch"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, status="mystery")]}, "reviewed status set"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, status="waiting", conclusion="success")]}, "must be null"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, status="completed", conclusion=None)]}, "reviewed conclusion set"),
    )
    for mutated, expected in protected_mutations:
        try:
            validate_protected_pr_workflow_runs_response(
                mutated,
                expected_sha=commit_sha,
                branch=protected_branch,
                codeql_workflow_id=protected_ids[0],
                dependency_workflow_id=protected_ids[1],
                profile_workflow_id=protected_ids[2],
            )
        except ValueError as exc:
            require(expected in str(exc),
                    f"protected workflow-run fixture failed for wrong reason: {exc}")
        else:
            raise ValueError(
                f"Dependabot protected workflow-run response accepted forbidden fixture: {expected}"
            )

    merge = validate_merge_success_response({
        "sha": commit_sha,
        "merged": True,
        "message": "Pull Request successfully merged",
    })
    require(
        merge == {
            "kind": "merge",
            "merged": True,
            "sha": commit_sha,
            "message": "Pull Request successfully merged",
        },
        "Dependabot merge success response positive fixture changed",
    )

    negative_response_fixtures = (
        (
            "read ref non-object",
            lambda: validate_git_ref_read_response([], expected_ref=ref_name),
            "must be an object",
        ),
        (
            "read ref identity",
            lambda: validate_git_ref_read_response(
                {"ref": "refs/heads/main", "object": {"type": "commit", "sha": commit_sha, "url": ref_url}},
                expected_ref=ref_name,
            ),
            "identity changed",
        ),
        (
            "read ref object type",
            lambda: validate_git_ref_read_response(
                {"ref": ref_name, "object": {"type": "tag", "sha": commit_sha, "url": ref_url}},
                expected_ref=ref_name,
            ),
            "type must be commit",
        ),
        (
            "read ref bad sha",
            lambda: validate_git_ref_read_response(
                {"ref": ref_name, "object": {"type": "commit", "sha": "ABC", "url": ref_url}},
                expected_ref=ref_name,
            ),
            "lowercase SHA-40",
        ),
        (
            "read ref missing url",
            lambda: validate_git_ref_read_response(
                {"ref": ref_name, "object": {"type": "commit", "sha": commit_sha}},
                expected_ref=ref_name,
            ),
            "url must be a nonempty string",
        ),
        (
            "read ref expected sha mismatch",
            lambda: validate_git_ref_read_response(
                {"ref": ref_name, "object": {"type": "commit", "sha": commit_sha, "url": ref_url}},
                expected_ref=ref_name,
                expected_sha="5" * 40,
            ),
            "object sha changed",
        ),
        (
            "wake non-object",
            lambda: validate_wake_run_response(
                [], expected_run_id=123456, expected_repository=REPOSITORY
            ),
            "must be an object",
        ),
        (
            "wake string id",
            lambda: validate_wake_run_response(
                {
                    "id": "123456",
                    "name": "CodeQL",
                    "event": "push",
                    "head_branch": "main",
                    "head_sha": commit_sha,
                    "repository": {"full_name": REPOSITORY},
                    "head_repository": {"full_name": REPOSITORY},
                },
                expected_run_id=123456,
                expected_repository=REPOSITORY,
            ),
            "id changed",
        ),
        (
            "wake workflow",
            lambda: validate_wake_run_response(
                {
                    "id": 123456,
                    "name": "Dependency review",
                    "event": "push",
                    "head_branch": "main",
                    "head_sha": commit_sha,
                    "repository": {"full_name": REPOSITORY},
                    "head_repository": {"full_name": REPOSITORY},
                },
                expected_run_id=123456,
                expected_repository=REPOSITORY,
            ),
            "workflow identity changed",
        ),
        (
            "wake event",
            lambda: validate_wake_run_response(
                {
                    "id": 123456,
                    "name": "CodeQL",
                    "event": "schedule",
                    "head_branch": "main",
                    "head_sha": commit_sha,
                    "repository": {"full_name": REPOSITORY},
                    "head_repository": {"full_name": REPOSITORY},
                },
                expected_run_id=123456,
                expected_repository=REPOSITORY,
            ),
            "event changed",
        ),
        (
            "wake head sha",
            lambda: validate_wake_run_response(
                {
                    "id": 123456,
                    "name": "CodeQL",
                    "event": "push",
                    "head_branch": "main",
                    "head_sha": "BAD",
                    "repository": {"full_name": REPOSITORY},
                    "head_repository": {"full_name": REPOSITORY},
                },
                expected_run_id=123456,
                expected_repository=REPOSITORY,
            ),
            "lowercase SHA-40",
        ),
        (
            "wake repository",
            lambda: validate_wake_run_response(
                {
                    "id": 123456,
                    "name": "CodeQL",
                    "event": "push",
                    "head_branch": "main",
                    "head_sha": commit_sha,
                    "repository": {"full_name": "portyu9/other"},
                    "head_repository": {"full_name": REPOSITORY},
                },
                expected_run_id=123456,
                expected_repository=REPOSITORY,
            ),
            "repository identity changed",
        ),
        ("blob non-object", lambda: validate_git_blob_response([]), "must be an object"),
        ("blob bad sha", lambda: validate_git_blob_response({"sha": "abc"}), "lowercase SHA-40"),
        ("tree bad sha", lambda: validate_git_tree_response({"sha": "A" * 40}), "lowercase SHA-40"),
        (
            "commit wrong tree",
            lambda: validate_git_commit_response(
                {"sha": commit_sha, "tree": {"sha": "5" * 40}, "parents": [{"sha": parent_sha}]},
                expected_tree_sha=tree_sha,
                expected_parent_sha=parent_sha,
            ),
            "tree sha changed",
        ),
        (
            "commit parent cardinality",
            lambda: validate_git_commit_response(
                {"sha": commit_sha, "tree": {"sha": tree_sha}, "parents": []},
                expected_tree_sha=tree_sha,
                expected_parent_sha=parent_sha,
            ),
            "exactly one parent",
        ),
        (
            "commit wrong parent",
            lambda: validate_git_commit_response(
                {"sha": commit_sha, "tree": {"sha": tree_sha}, "parents": [{"sha": "6" * 40}]},
                expected_tree_sha=tree_sha,
                expected_parent_sha=parent_sha,
            ),
            "parent sha changed",
        ),
        (
            "ref wrong identity",
            lambda: validate_git_ref_response(
                {"ref": "refs/heads/other", "object": {"type": "commit", "sha": commit_sha}},
                expected_ref=ref_name,
                expected_sha=commit_sha,
            ),
            "identity changed",
        ),
        (
            "ref wrong type",
            lambda: validate_git_ref_response(
                {"ref": ref_name, "object": {"type": "tag", "sha": commit_sha}},
                expected_ref=ref_name,
                expected_sha=commit_sha,
            ),
            "type must be commit",
        ),
        (
            "ref wrong sha",
            lambda: validate_git_ref_response(
                {"ref": ref_name, "object": {"type": "commit", "sha": "7" * 40}},
                expected_ref=ref_name,
                expected_sha=commit_sha,
            ),
            "object sha changed",
        ),
        ("merge non-object", lambda: validate_merge_success_response([]), "must be an object"),
        (
            "merge string status",
            lambda: validate_merge_success_response(
                {"sha": commit_sha, "merged": "true", "message": "Pull Request successfully merged"}
            ),
            "merged must be boolean",
        ),
        (
            "merge numeric status",
            lambda: validate_merge_success_response(
                {"sha": commit_sha, "merged": 1, "message": "Pull Request successfully merged"}
            ),
            "merged must be boolean",
        ),
        (
            "merge false",
            lambda: validate_merge_success_response(
                {"sha": commit_sha, "merged": False, "message": "Merge rejected"}
            ),
            "merged=true",
        ),
        (
            "merge bad sha",
            lambda: validate_merge_success_response(
                {"sha": "abc", "merged": True, "message": "Pull Request successfully merged"}
            ),
            "lowercase SHA-40",
        ),
        (
            "merge missing message",
            lambda: validate_merge_success_response({"sha": commit_sha, "merged": True}),
            "message must be a nonempty string",
        ),
        (
            "merge non-string message",
            lambda: validate_merge_success_response({"sha": commit_sha, "merged": True, "message": 7}),
            "message must be a nonempty string",
        ),
        (
            "merge empty message",
            lambda: validate_merge_success_response({"sha": commit_sha, "merged": True, "message": "   "}),
            "message must be a nonempty string",
        ),
    )
    for label, operation, expected in negative_response_fixtures:
        try:
            operation()
        except ValueError as exc:
            require(expected in str(exc), f"{label} fixture failed for the wrong reason: {exc}")
        else:
            raise ValueError(f"Dependabot Git response self-test accepted forbidden fixture: {label}")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    sub = value.add_subparsers(dest="command", required=True)
    for name in ("probe", "admit"):
        command = sub.add_parser(name)
        command.add_argument("--pr", type=Path, required=True)
        command.add_argument("--expected-head", required=True)
        command.add_argument("--base-root", type=Path, required=True)
        command.add_argument("--candidate-root", type=Path, required=True)
        command.add_argument("--out", type=Path, required=True)
        if name == "admit":
            command.add_argument("--resolved-release", type=Path, required=True)
    derive = sub.add_parser("derive")
    derive.add_argument("--proof", type=Path, required=True)
    derive.add_argument("--base-root", type=Path, required=True)
    derive.add_argument("--candidate-root", type=Path, required=True)
    derive.add_argument("--output-root", type=Path, required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--proof", type=Path, required=True)
    validate.add_argument("--base-root", type=Path, required=True)
    validate.add_argument("--candidate-root", type=Path, required=True)
    validate.add_argument("--changed-paths", type=Path, required=True)
    validate.add_argument("--out", type=Path, required=True)
    for name in ("git-blob-response", "git-tree-response", "merge-success-response"):
        command = sub.add_parser(name)
        command.add_argument("--response", type=Path, required=True)
        command.add_argument("--out", type=Path, required=True)
    commit_response = sub.add_parser("git-commit-response")
    commit_response.add_argument("--response", type=Path, required=True)
    commit_response.add_argument("--expected-tree", required=True)
    commit_response.add_argument("--expected-parent", required=True)
    commit_response.add_argument("--out", type=Path, required=True)
    ref_response = sub.add_parser("git-ref-response")
    ref_response.add_argument("--response", type=Path, required=True)
    ref_response.add_argument("--expected-ref", required=True)
    ref_response.add_argument("--expected-sha", required=True)
    ref_response.add_argument("--out", type=Path, required=True)
    read_ref_response = sub.add_parser("git-ref-read-response")
    read_ref_response.add_argument("--response", type=Path, required=True)
    read_ref_response.add_argument("--expected-ref", required=True)
    read_ref_response.add_argument("--expected-sha")
    read_ref_response.add_argument("--out", type=Path, required=True)
    wake_run_response = sub.add_parser("wake-run-response")
    wake_run_response.add_argument("--response", type=Path, required=True)
    wake_run_response.add_argument("--expected-run-id", type=int, required=True)
    wake_run_response.add_argument("--expected-repository", required=True)
    wake_run_response.add_argument("--out", type=Path, required=True)
    workflow_definition_response = sub.add_parser("workflow-definition-response")
    workflow_definition_response.add_argument("--response", type=Path, required=True)
    workflow_definition_response.add_argument("--expected-path", required=True)
    workflow_definition_response.add_argument("--out", type=Path, required=True)
    protected_runs_response = sub.add_parser("protected-workflow-runs-response")
    protected_runs_response.add_argument("--response", type=Path, required=True)
    protected_runs_response.add_argument("--head-sha", required=True)
    protected_runs_response.add_argument("--branch", required=True)
    protected_runs_response.add_argument("--codeql-workflow-id", type=int, required=True)
    protected_runs_response.add_argument("--dependency-workflow-id", type=int, required=True)
    protected_runs_response.add_argument("--profile-workflow-id", type=int, required=True)
    protected_runs_response.add_argument("--out", type=Path, required=True)
    sub.add_parser("self-test")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "self-test":
            self_test()
            print("Dependabot zero-touch controller self-test passed.")
            return 0
        if args.command in {
            "git-blob-response",
            "git-tree-response",
            "git-commit-response",
            "git-ref-response",
            "git-ref-read-response",
            "wake-run-response",
            "workflow-definition-response",
            "protected-workflow-runs-response",
            "merge-success-response",
        }:
            response = load_json(args.response)
            if args.command == "git-blob-response":
                result = validate_git_blob_response(response)
            elif args.command == "git-tree-response":
                result = validate_git_tree_response(response)
            elif args.command == "git-commit-response":
                result = validate_git_commit_response(
                    response,
                    expected_tree_sha=args.expected_tree,
                    expected_parent_sha=args.expected_parent,
                )
            elif args.command == "git-ref-response":
                result = validate_git_ref_response(
                    response,
                    expected_ref=args.expected_ref,
                    expected_sha=args.expected_sha,
                )
            elif args.command == "git-ref-read-response":
                result = validate_git_ref_read_response(
                    response,
                    expected_ref=args.expected_ref,
                    expected_sha=args.expected_sha,
                )
            elif args.command == "wake-run-response":
                result = validate_wake_run_response(
                    response,
                    expected_run_id=args.expected_run_id,
                    expected_repository=args.expected_repository,
                )
            elif args.command == "workflow-definition-response":
                result = validate_workflow_definition_response(
                    response,
                    expected_path=args.expected_path,
                )
            elif args.command == "protected-workflow-runs-response":
                result = validate_protected_pr_workflow_runs_response(
                    response,
                    expected_sha=args.head_sha,
                    branch=args.branch,
                    codeql_workflow_id=args.codeql_workflow_id,
                    dependency_workflow_id=args.dependency_workflow_id,
                    profile_workflow_id=args.profile_workflow_id,
                )
            else:
                result = validate_merge_success_response(response)
            args.out.write_text(canonical_json(result), encoding="utf-8")
            return 0
        if args.command in {"probe", "admit"}:
            pr = load_json(args.pr)
            if args.command == "probe":
                result = probe(
                    pr=pr,
                    expected_head_sha=args.expected_head,
                    base_root=args.base_root,
                    candidate_root=args.candidate_root,
                )
            else:
                result = admit(
                    pr=pr,
                    expected_head_sha=args.expected_head,
                    base_root=args.base_root,
                    candidate_root=args.candidate_root,
                    resolved_release=strict_json(args.resolved_release, "resolved Dependabot release identity"),
                )
            args.out.write_text(canonical_json(result), encoding="utf-8")
            return 0
        proof = load_json(args.proof)
        if args.command == "derive":
            files = derive_codeql_files(base_root=args.base_root, candidate_root=args.candidate_root, proof=proof)
            write_outputs(files, args.output_root)
            return 0
        if args.command == "validate":
            changed = [line.strip() for line in args.changed_paths.read_text(encoding="utf-8").splitlines() if line.strip()]
            result = validate_reconciled_candidate(
                base_root=args.base_root,
                candidate_root=args.candidate_root,
                proof=proof,
                changed_paths=changed,
            )
            args.out.write_text(canonical_json(result), encoding="utf-8")
            return 0
        raise ValueError("unknown Dependabot controller command")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
