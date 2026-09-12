#!/usr/bin/env python3
"""Independently re-prove durable Spotlight side-effect state for decision receipts."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

import automation_decision_receipt

REPOSITORY = "portyu9/portyu9"
WORKFLOW_PATH = ".github/workflows/spotlight-link-sync.yml"
WORKFLOW_REF = f"{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"
BOT_BRANCH_PREFIX = "automation/spotlight-links/"
PR_TITLE = "chore: sync rotating Spotlight links"
PR_BODY = (
    "Automation-managed README-only update. Direct Spotlight repository/workflow links "
    "and immutable card snapshot are derived from the validated published evidence. Main "
    "protection and all required checks remain in force."
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
BRANCH = re.compile(r"^automation/spotlight-links/[0-9a-f]{64}$")
WORKFLOW_NAMES = {"CodeQL", "Dependency review", "Profile quality"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def env_value(env: dict[str, str], name: str, pattern: re.Pattern[str] | None = None) -> str:
    value = env.get(name, "").strip()
    require(bool(value), f"required environment variable is missing: {name}")
    if pattern is not None:
        require(pattern.fullmatch(value) is not None, f"{name} has invalid canonical form")
    return value


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"Spotlight decision journal contains duplicate key: {key}")
        result[key] = value
    return result


def strict_journal(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"Spotlight decision journal is missing or aliased: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Spotlight decision journal is invalid JSON: {exc}") from exc
    require(isinstance(value, dict) and set(value) == {"effects"},
            "Spotlight decision journal root shape changed")
    effects = value["effects"]
    require(isinstance(effects, list) and 1 <= len(effects) <= 32,
            "Spotlight decision journal must contain between one and 32 effects")
    return value


def gh_json(endpoint: str) -> Any:
    require(not endpoint.startswith("-"), "GitHub API endpoint must be one read-only path")
    completed = subprocess.run(
        ["gh", "api", endpoint],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"GitHub API returned invalid JSON for {endpoint}: {exc}") from exc


def exact_candidate_absent(branch: str) -> None:
    refs = gh_json(f"repos/{REPOSITORY}/git/matching-refs/heads/{branch}")
    require(isinstance(refs, list), "Spotlight decision candidate-ref response is malformed")
    exact = [item for item in refs if item.get("ref") == f"refs/heads/{branch}"]
    require(len(exact) == 0, f"Spotlight decision candidate ref is not absent: {branch}")


def pr_identity(number: int, branch: str, head: str) -> dict[str, Any]:
    pr = gh_json(f"repos/{REPOSITORY}/pulls/{number}")
    observed = {
        "number": pr.get("number"),
        "title": pr.get("title"),
        "body": pr.get("body"),
        "baseRef": pr.get("base", {}).get("ref"),
        "headRef": pr.get("head", {}).get("ref"),
        "headSha": pr.get("head", {}).get("sha"),
        "headRepository": pr.get("head", {}).get("repo", {}).get("full_name"),
        "maintainerCanModify": pr.get("maintainer_can_modify"),
    }
    require(observed == {
        "number": number,
        "title": PR_TITLE,
        "body": PR_BODY,
        "baseRef": "main",
        "headRef": branch,
        "headSha": head,
        "headRepository": REPOSITORY,
        "maintainerCanModify": False,
    }, f"Spotlight decision PR identity changed: {number}")
    return pr


def reprove_stale_cleanup(effect: dict[str, Any]) -> None:
    target = effect["target"]
    branch = target["candidateBranch"]
    head = target["headSha"]
    pr_number = target["prNumber"]
    exact_candidate_absent(branch)
    if pr_number is not None:
        pr = pr_identity(pr_number, branch, head)
        require(pr.get("state") == "closed" and pr.get("merged_at") is None,
                "Spotlight stale cleanup PR is not closed-unmerged")
        require(effect["observation"]["prClosed"] is True,
                "Spotlight stale cleanup journal lost PR closure outcome")
    else:
        require(effect["observation"]["prClosed"] is False,
                "Spotlight stale cleanup journal claims PR closure without a PR")


def reprove_candidate_publication(effect: dict[str, Any]) -> None:
    target = effect["target"]
    pr = pr_identity(target["prNumber"], target["candidateBranch"], target["headSha"])
    require(pr.get("state") in {"open", "closed"}, "Spotlight candidate PR state is invalid")
    require(type(effect["observation"]["refCreated"]) is bool
            and type(effect["observation"]["prCreated"]) is bool,
            "Spotlight candidate publication observations must be booleans")


def reprove_approval(effect: dict[str, Any], expected_head: str) -> None:
    target = effect["target"]
    require(target["workflowName"] in WORKFLOW_NAMES,
            "Spotlight approval journal workflow identity changed")
    run = gh_json(f"repos/{REPOSITORY}/actions/runs/{target['runId']}")
    require(run.get("id") == target["runId"]
            and run.get("workflow_id") == target["workflowId"]
            and run.get("run_attempt") == target["runAttempt"]
            and run.get("check_suite_id") == target["checkSuiteId"],
            "Spotlight approval run identity differs from journal")
    require(run.get("name") == target["workflowName"]
            and run.get("event") == "pull_request"
            and run.get("head_sha") == expected_head
            and run.get("repository", {}).get("full_name") == REPOSITORY
            and run.get("head_repository", {}).get("full_name") == REPOSITORY,
            "Spotlight approval run provenance changed")
    require(run.get("status") == "completed" and run.get("conclusion") == "success",
            "Spotlight approval receipt requires the selected run to finish successfully")
    require(effect["observation"]["approvalRequested"] is True,
            "Spotlight approval receipt must represent an actual approval POST")


def reprove_merge(effect: dict[str, Any]) -> None:
    target = effect["target"]
    observation = effect["observation"]
    pr = pr_identity(target["prNumber"], target["candidateBranch"], target["headSha"])
    require(pr.get("state") == "closed" and pr.get("merged") is True,
            "Spotlight terminal receipt PR is not merged")
    require(pr.get("merge_commit_sha") == observation["mergeSha"],
            "Spotlight terminal receipt merge SHA differs from durable PR state")
    exact_candidate_absent(target["candidateBranch"])


def prepare_state(journal: dict[str, Any], env: dict[str, str], *, reprove: bool = True) -> dict[str, Any]:
    require(env_value(env, "GITHUB_REPOSITORY") == REPOSITORY,
            "Spotlight decision receipt repository identity changed")
    require(env_value(env, "GITHUB_WORKFLOW_REF") == WORKFLOW_REF,
            "Spotlight decision receipt workflow identity changed")
    base = env_value(env, "LEASE_BASE_SHA", SHA40)
    require(env_value(env, "GITHUB_WORKFLOW_SHA", SHA40) == base,
            "Spotlight decision receipt workflow SHA differs from leased base")
    env_value(env, "GITHUB_RUN_ID", POSITIVE)
    env_value(env, "GITHUB_RUN_ATTEMPT", POSITIVE)
    expected_head = env_value(env, "EXPECTED_HEAD_SHA", SHA40)
    lease = {
        "leaseId": env_value(env, "LEASE_ID", automation_decision_receipt.SHA64),
        "candidateId": env_value(env, "LEASE_CANDIDATE_ID", automation_decision_receipt.SHA64),
        "baseSha": base,
        "issuedAt": env_value(env, "LEASE_ISSUED_AT", POSITIVE),
        "expiresAt": env_value(env, "LEASE_EXPIRES_AT", POSITIVE),
    }
    require(int(lease["expiresAt"]) == int(lease["issuedAt"]) + 1800,
            "Spotlight decision receipt lease lifetime changed")

    validated: list[dict[str, Any]] = []
    seen_merge = 0
    for ordinal, raw in enumerate(journal["effects"], start=1):
        effect = automation_decision_receipt.validate_effect(raw, WORKFLOW_PATH, lease, ordinal)
        kind = effect["kind"]
        require(kind != "spotlight-workflow-dispatch",
                "Profile Stats dispatch effect cannot appear in a Spotlight decision journal")
        if kind == "workflow-run-approval-request":
            require(effect["target"]["headSha"] if "headSha" in effect["target"] else expected_head,
                    "Spotlight approval expected head is missing")
        if reprove:
            if kind == "stale-candidate-reconciliation":
                reprove_stale_cleanup(effect)
            elif kind == "spotlight-candidate-publication":
                reprove_candidate_publication(effect)
            elif kind == "workflow-run-approval-request":
                reprove_approval(effect, expected_head)
            elif kind == "spotlight-terminal-merge":
                reprove_merge(effect)
        if kind == "spotlight-terminal-merge":
            seen_merge += 1
            require(effect["target"]["headSha"] == expected_head,
                    "Spotlight terminal merge head differs from expected candidate head")
        validated.append(effect)
    require(seen_merge <= 1, "Spotlight decision journal contains multiple terminal merge effects")
    return {"effects": validated}


def fixture() -> tuple[dict[str, Any], dict[str, str]]:
    base = "a" * 40
    candidate_id = "b" * 64
    branch = f"{BOT_BRANCH_PREFIX}{candidate_id}"
    head = "c" * 40
    env = {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_WORKFLOW_SHA": base,
        "GITHUB_RUN_ID": "100",
        "GITHUB_RUN_ATTEMPT": "2",
        "LEASE_ID": "d" * 64,
        "LEASE_CANDIDATE_ID": candidate_id,
        "LEASE_BASE_SHA": base,
        "LEASE_ISSUED_AT": "1000000",
        "LEASE_EXPIRES_AT": "1001800",
        "EXPECTED_HEAD_SHA": head,
    }
    journal = {
        "effects": [
            {
                "ordinal": 1,
                "job": "propose",
                "kind": "spotlight-candidate-publication",
                "outcome": "applied",
                "target": {"candidateBranch": branch, "headSha": head, "prNumber": 123},
                "observation": {"refCreated": True, "prCreated": True},
            },
            {
                "ordinal": 2,
                "job": "approve",
                "kind": "workflow-run-approval-request",
                "outcome": "applied",
                "target": {"workflowName": "CodeQL", "workflowId": 10, "runId": 20,
                           "runAttempt": 1, "checkSuiteId": 30},
                "observation": {"approvalRequested": True},
            },
            {
                "ordinal": 3,
                "job": "merge",
                "kind": "spotlight-terminal-merge",
                "outcome": "applied",
                "target": {"prNumber": 123, "candidateBranch": branch, "headSha": head, "baseSha": base},
                "observation": {"mergeSha": "e" * 40, "mainSha": "e" * 40, "candidateRefAbsent": True},
            },
        ]
    }
    return journal, env


def self_test() -> None:
    journal, env = fixture()
    state = prepare_state(journal, env, reprove=False)
    require(len(state["effects"]) == 3, "Spotlight decision receipt self-test lost effects")

    wrong_head = json.loads(json.dumps(journal))
    wrong_head["effects"][2]["target"]["headSha"] = "f" * 40
    try:
        prepare_state(wrong_head, dict(env), reprove=False)
    except ValueError as exc:
        require("expected candidate head" in str(exc), f"Spotlight decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Spotlight decision receipt accepted terminal merge on wrong head")

    duplicate_merge = json.loads(json.dumps(journal))
    duplicate = json.loads(json.dumps(duplicate_merge["effects"][2]))
    duplicate["ordinal"] = 4
    duplicate_merge["effects"].append(duplicate)
    try:
        prepare_state(duplicate_merge, dict(env), reprove=False)
    except ValueError as exc:
        require("multiple terminal merge" in str(exc), f"Spotlight decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Spotlight decision receipt accepted multiple terminal merges")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("journal", nargs="?", type=Path)
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("Spotlight Automation Decision Receipt preparer self-test passed")
            return 0
        require(args.journal is not None and args.output is not None,
                "journal and output paths are required outside --self-test")
        journal = strict_journal(args.journal)
        state = prepare_state(journal, dict(os.environ))
        args.output.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print(f"Spotlight Automation Decision Receipt state independently re-proved: {args.output}")
        return 0
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
