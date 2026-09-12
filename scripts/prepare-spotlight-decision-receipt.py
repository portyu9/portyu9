#!/usr/bin/env python3
"""Independently re-prove durable Spotlight side-effect state for decision receipts."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import spotlight_decision_receipt as core

REPOSITORY = core.REPOSITORY
PR_TITLE = "chore: sync rotating Spotlight links"
PR_BODY = (
    "Automation-managed README-only update. Direct Spotlight repository/workflow links "
    "and immutable card snapshot are derived from the validated published evidence. Main "
    "protection and all required checks remain in force."
)
WORKFLOW_NAMES = {"CodeQL", "Dependency review", "Profile quality"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


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
    exact_candidate_absent(target["candidateBranch"])
    pr_number = target["prNumber"]
    if pr_number is not None:
        pr = pr_identity(pr_number, target["candidateBranch"], target["headSha"])
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


def reprove_state(state: dict[str, Any], expected_head: str) -> None:
    for effect in state["effects"]:
        kind = effect["kind"]
        if kind == "stale-candidate-reconciliation":
            reprove_stale_cleanup(effect)
        elif kind == "spotlight-candidate-publication":
            reprove_candidate_publication(effect)
        elif kind == "workflow-run-approval-request":
            reprove_approval(effect, expected_head)
        elif kind == "spotlight-terminal-merge":
            reprove_merge(effect)
        else:
            raise ValueError(f"unreviewed Spotlight decision effect reached reproof: {kind}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("journal", nargs="?", type=Path)
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            core.self_test()
            print("Spotlight Automation Decision Receipt preparer self-test passed")
            return 0
        require(args.journal is not None and args.output is not None,
                "journal and output paths are required outside --self-test")
        journal = strict_journal(args.journal)
        env = dict(os.environ)
        state = core.validate_journal(journal, env)
        reprove_state(state, core.env_value(env, "EXPECTED_HEAD_SHA", core.SHA40))
        args.output.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print(f"Spotlight Automation Decision Receipt state independently re-proved: {args.output}")
        return 0
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
