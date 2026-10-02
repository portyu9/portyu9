#!/usr/bin/env python3
"""Validate source-controlled repository and GitHub Actions settings desired state."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SETTINGS = ROOT / ".github" / "repository-settings-v1.json"
ACTION_LOCK = ROOT / ".github" / "action-lock.json"
RULESETS = ROOT / ".github" / "rulesets" / "repository-rulesets-v1.json"

EXPECTED_REPOSITORY_ID = 1355082509
EXPECTED_REPOSITORY = "portyu9/portyu9"
EXPECTED_PATTERNS = (
    "actions/attest@*",
    "actions/checkout@*",
    "actions/dependency-review-action@*",
    "actions/download-artifact@*",
    "actions/setup-python@*",
    "actions/upload-artifact@*",
    "github/codeql-action@*",
    "shinpr/github-profile-stats@*",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == keys, f"{label} field inventory changed")
    return value


def exact_bool(value: Any, expected: bool, label: str) -> None:
    require(type(value) is bool and value is expected, f"{label} changed")


def exact_int(value: Any, expected: int, label: str) -> None:
    require(type(value) is int and value == expected, f"{label} changed")


def action_repository(action_key: str) -> str:
    parts = action_key.split("/")
    require(len(parts) >= 2 and all(parts[:2]), f"action-lock key is not repository-qualified: {action_key}")
    return "/".join(parts[:2])


def locked_action_patterns(action_lock: dict[str, Any]) -> tuple[str, ...]:
    exact_object(action_lock, {"version", "actions"}, "action lock")
    require(action_lock["version"] == "github-actions-identity-lock-v2", "action-lock version changed")
    actions = action_lock["actions"]
    require(isinstance(actions, dict) and actions, "action-lock actions inventory missing")
    repositories: set[str] = set()
    for key, identity in actions.items():
        require(isinstance(key, str) and key, "action-lock action key malformed")
        require(isinstance(identity, dict), f"action-lock identity malformed: {key}")
        repositories.add(action_repository(key))
    return tuple(f"{repository}@*" for repository in sorted(repositories))


def validate_document(
    document: dict[str, Any],
    action_lock: dict[str, Any],
    rulesets: dict[str, Any],
) -> None:
    exact_object(
        document,
        {"schemaVersion", "repository", "repositorySettings", "actionsSettings"},
        "repository settings contract",
    )
    exact_int(document["schemaVersion"], 1, "repository settings schemaVersion")

    repository = exact_object(document["repository"], {"id", "fullName"}, "repository identity")
    exact_int(repository["id"], EXPECTED_REPOSITORY_ID, "repository id")
    require(repository["fullName"] == EXPECTED_REPOSITORY, "repository full name changed")

    settings = exact_object(
        document["repositorySettings"],
        {
            "visibility",
            "defaultBranch",
            "archived",
            "isTemplate",
            "allowForking",
            "webCommitSignoffRequired",
            "features",
            "pullRequests",
        },
        "repository settings",
    )
    require(settings["visibility"] == "public", "repository visibility changed")
    require(settings["defaultBranch"] == "main", "repository default branch changed")
    exact_bool(settings["archived"], False, "repository archived state")
    exact_bool(settings["isTemplate"], False, "repository template state")
    exact_bool(settings["allowForking"], True, "repository forking policy")
    exact_bool(settings["webCommitSignoffRequired"], False, "web commit signoff policy")

    features = exact_object(
        settings["features"],
        {"issues", "projects", "wiki", "discussions"},
        "repository feature settings",
    )
    exact_bool(features["issues"], True, "issues feature")
    exact_bool(features["projects"], True, "projects feature")
    exact_bool(features["wiki"], True, "wiki feature")
    exact_bool(features["discussions"], False, "discussions feature")

    pull_requests = exact_object(
        settings["pullRequests"],
        {
            "creationPolicy",
            "allowMergeCommit",
            "allowSquashMerge",
            "allowRebaseMerge",
            "allowAutoMerge",
            "deleteBranchOnMerge",
            "allowUpdateBranch",
        },
        "repository pull-request settings",
    )
    require(
        pull_requests["creationPolicy"] == "collaborators_only",
        "pull-request creation policy changed",
    )
    exact_bool(pull_requests["allowMergeCommit"], True, "merge-commit repository policy")
    exact_bool(pull_requests["allowSquashMerge"], True, "squash-merge repository policy")
    exact_bool(pull_requests["allowRebaseMerge"], True, "rebase-merge repository policy")
    exact_bool(pull_requests["allowAutoMerge"], False, "repository auto-merge policy")
    exact_bool(pull_requests["deleteBranchOnMerge"], True, "delete-branch-on-merge policy")
    exact_bool(pull_requests["allowUpdateBranch"], False, "update-branch repository policy")

    actions = exact_object(
        document["actionsSettings"],
        {"enabled", "allowedActions", "selectedActions", "workflowPermissions"},
        "Actions settings",
    )
    exact_bool(actions["enabled"], True, "Actions enabled state")
    require(actions["allowedActions"] == "selected", "Actions allow policy broadened")

    selected = exact_object(
        actions["selectedActions"],
        {"githubOwnedAllowed", "verifiedAllowed", "patternsAllowed"},
        "selected Actions settings",
    )
    exact_bool(selected["githubOwnedAllowed"], False, "blanket GitHub-owned Actions policy")
    exact_bool(selected["verifiedAllowed"], False, "blanket verified Actions policy")
    patterns = selected["patternsAllowed"]
    require(isinstance(patterns, list) and all(isinstance(value, str) for value in patterns),
            "selected Actions pattern inventory malformed")
    require(len(patterns) == len(set(patterns)), "selected Actions patterns duplicated")
    require(tuple(patterns) == tuple(sorted(patterns)), "selected Actions patterns must be sorted")
    require(tuple(patterns) == EXPECTED_PATTERNS, "selected Actions desired allowlist changed")
    require(
        tuple(patterns) == locked_action_patterns(action_lock),
        "selected Actions desired allowlist diverges from action-lock repository inventory",
    )

    workflow = exact_object(
        actions["workflowPermissions"],
        {"defaultWorkflowPermissions", "canApprovePullRequestReviews"},
        "Actions workflow permissions",
    )
    require(
        workflow["defaultWorkflowPermissions"] == "read",
        "default GITHUB_TOKEN permission broadened",
    )
    exact_bool(
        workflow["canApprovePullRequestReviews"],
        False,
        "GITHUB_TOKEN pull-request approval policy",
    )

    exact_object(rulesets, {"schemaVersion", "repository", "rulesets"}, "ruleset desired state")
    exact_int(rulesets["schemaVersion"], 1, "ruleset schemaVersion")
    require(rulesets["repository"] == EXPECTED_REPOSITORY, "ruleset repository identity changed")
    ruleset_inventory = rulesets["rulesets"]
    require(isinstance(ruleset_inventory, dict), "ruleset inventory malformed")
    protect_main = ruleset_inventory.get("Protect Main")
    require(isinstance(protect_main, dict), "Protect Main desired state missing")
    rules = protect_main.get("rules")
    require(isinstance(rules, dict), "Protect Main rule inventory malformed")
    pr_rule = rules.get("pull_request")
    require(isinstance(pr_rule, dict), "Protect Main pull-request rule missing")
    allowed_methods = pr_rule.get("allowed_merge_methods")
    require(allowed_methods == ["merge"], "Protect Main merge-method contract changed")
    require(
        pull_requests["allowMergeCommit"] is True,
        "repository settings must permit the merge method required by Protect Main",
    )


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.relative_to(ROOT)} root must be an object")
    return value


def expect_failure(
    document: dict[str, Any],
    action_lock: dict[str, Any],
    rulesets: dict[str, Any],
    expected: str,
) -> None:
    try:
        validate_document(document, action_lock, rulesets)
    except ValueError as exc:
        require(expected in str(exc), f"negative self-test failed for wrong reason: {exc}")
        return
    raise ValueError(f"negative self-test accepted forbidden mutation: {expected}")


def self_test(document: dict[str, Any], action_lock: dict[str, Any], rulesets: dict[str, Any]) -> None:
    validate_document(document, action_lock, rulesets)

    mutated = copy.deepcopy(document)
    mutated["unexpected"] = True
    expect_failure(mutated, action_lock, rulesets, "field inventory changed")

    mutated = copy.deepcopy(document)
    mutated["repository"]["id"] = True
    expect_failure(mutated, action_lock, rulesets, "repository id changed")

    mutated = copy.deepcopy(document)
    mutated["repositorySettings"]["defaultBranch"] = "develop"
    expect_failure(mutated, action_lock, rulesets, "default branch changed")

    mutated = copy.deepcopy(document)
    mutated["repositorySettings"]["pullRequests"]["allowAutoMerge"] = True
    expect_failure(mutated, action_lock, rulesets, "auto-merge policy")

    mutated = copy.deepcopy(document)
    mutated["actionsSettings"]["allowedActions"] = "all"
    expect_failure(mutated, action_lock, rulesets, "allow policy broadened")

    mutated = copy.deepcopy(document)
    mutated["actionsSettings"]["selectedActions"]["githubOwnedAllowed"] = True
    expect_failure(mutated, action_lock, rulesets, "blanket GitHub-owned")

    mutated = copy.deepcopy(document)
    mutated["actionsSettings"]["selectedActions"]["patternsAllowed"].append("docker/*@*")
    expect_failure(mutated, action_lock, rulesets, "selected Actions patterns must be sorted")

    mutated = copy.deepcopy(document)
    mutated["actionsSettings"]["selectedActions"]["patternsAllowed"] = (
        mutated["actionsSettings"]["selectedActions"]["patternsAllowed"][:-1]
    )
    expect_failure(mutated, action_lock, rulesets, "desired allowlist changed")

    mutated = copy.deepcopy(document)
    mutated["actionsSettings"]["workflowPermissions"]["defaultWorkflowPermissions"] = "write"
    expect_failure(mutated, action_lock, rulesets, "default GITHUB_TOKEN permission broadened")

    mutated = copy.deepcopy(document)
    mutated["actionsSettings"]["workflowPermissions"]["canApprovePullRequestReviews"] = True
    expect_failure(mutated, action_lock, rulesets, "pull-request approval policy")

    expanded_lock = copy.deepcopy(action_lock)
    expanded_lock["actions"]["octo/example"] = {
        "repositoryId": 1,
        "releaseId": 1,
        "sha": "0" * 40,
        "tag": "v1.0.0",
        "tagRefSha": "0" * 40,
        "tagRefType": "commit",
    }
    expect_failure(
        copy.deepcopy(document),
        expanded_lock,
        rulesets,
        "diverges from action-lock repository inventory",
    )

    mutated_rulesets = copy.deepcopy(rulesets)
    mutated_rulesets["rulesets"]["Protect Main"]["rules"]["pull_request"]["allowed_merge_methods"] = [
        "merge",
        "squash",
    ]
    expect_failure(
        copy.deepcopy(document),
        action_lock,
        mutated_rulesets,
        "Protect Main merge-method contract changed",
    )


def validate_and_self_test() -> None:
    document = load_json(SETTINGS)
    action_lock = load_json(ACTION_LOCK)
    rulesets = load_json(RULESETS)
    self_test(document, action_lock, rulesets)


def main() -> int:
    try:
        validate_and_self_test()
        print(
            "Repository/Actions settings desired state passed: "
            "closed repository policy · selected locked Actions only · "
            "read-only default GITHUB_TOKEN · no token PR approvals"
        )
        return 0
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
