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
APPROVAL_REQUIRED_STATES = {"waiting", "action_required"}


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


def approval_left_gate(run: dict[str, Any]) -> None:
    status = run.get("status")
    conclusion = run.get("conclusion")
    require(isinstance(status, str) and status,
            "Spotlight approval run status is missing")
    require(status not in APPROVAL_REQUIRED_STATES and conclusion != "action_required",
            "Spotlight approval run is still blocked on approval")


def validate_approval_provenance(run: dict[str, Any], target: dict[str, Any], expected_head: str) -> None:
    require(run.get("id") == target["runId"]
            and run.get("workflow_id") == target["workflowId"]
            and run.get("check_suite_id") == target["checkSuiteId"],
            "Spotlight approval run identity differs from journal")
    require(run.get("name") == target["workflowName"]
            and run.get("event") == "pull_request"
            and run.get("head_sha") == expected_head
            and run.get("repository", {}).get("full_name") == REPOSITORY
            and run.get("head_repository", {}).get("full_name") == REPOSITORY,
            "Spotlight approval run provenance changed")


def validate_approved_attempt(run: dict[str, Any], target: dict[str, Any], expected_head: str) -> None:
    validate_approval_provenance(run, target, expected_head)
    require(run.get("run_attempt") == target["runAttempt"],
            "Spotlight approval historical attempt differs from journal")
    require(run.get("status") == "completed" and run.get("conclusion") == "action_required",
            "Spotlight approval historical attempt was not approval-required")


def validate_latest_after_approval(run: dict[str, Any], target: dict[str, Any], expected_head: str) -> None:
    validate_approval_provenance(run, target, expected_head)
    current_attempt = run.get("run_attempt")
    require(isinstance(current_attempt, int) and not isinstance(current_attempt, bool),
            "Spotlight approval current run attempt is malformed")
    require(current_attempt > target["runAttempt"],
            "Spotlight approval current run did not advance beyond the approved attempt")
    approval_left_gate(run)


def reprove_approval(effect: dict[str, Any], expected_head: str) -> None:
    target = effect["target"]
    require(target["workflowName"] in WORKFLOW_NAMES,
            "Spotlight approval journal workflow identity changed")
    approved_attempt = gh_json(
        f"repos/{REPOSITORY}/actions/runs/{target['runId']}/attempts/{target['runAttempt']}"
    )
    validate_approved_attempt(approved_attempt, target, expected_head)
    current_run = gh_json(f"repos/{REPOSITORY}/actions/runs/{target['runId']}")
    validate_latest_after_approval(current_run, target, expected_head)
    require(effect["observation"]["approvalRequested"] is True,
            "Spotlight approval receipt must represent an actual approval POST")


def validate_main_ref(main_ref: Any, expected_merge_sha: str) -> None:
    require(isinstance(main_ref, dict) and main_ref.get("ref") == "refs/heads/main",
            "Spotlight terminal receipt main-ref response is malformed")
    require(main_ref.get("object", {}).get("type") == "commit"
            and main_ref.get("object", {}).get("sha") == expected_merge_sha,
            "Spotlight terminal receipt merge SHA is not the durable current main")


def reprove_merge(effect: dict[str, Any]) -> None:
    target = effect["target"]
    observation = effect["observation"]
    pr = pr_identity(target["prNumber"], target["candidateBranch"], target["headSha"])
    require(pr.get("state") == "closed" and pr.get("merged") is True,
            "Spotlight terminal receipt PR is not merged")
    require(pr.get("merge_commit_sha") == observation["mergeSha"],
            "Spotlight terminal receipt merge SHA differs from durable PR state")
    validate_main_ref(gh_json(f"repos/{REPOSITORY}/git/ref/heads/main"), observation["mergeSha"])
    require(observation["mainSha"] == observation["mergeSha"],
            "Spotlight terminal receipt journal lost merge/current-main equality")
    exact_candidate_absent(target["candidateBranch"])


def reprove_state(state: dict[str, Any]) -> None:
    expected_head: str | None = None
    for effect in state["effects"]:
        kind = effect["kind"]
        if kind == "stale-candidate-reconciliation":
            reprove_stale_cleanup(effect)
        elif kind == "spotlight-candidate-publication":
            expected_head = effect["target"]["headSha"]
            reprove_candidate_publication(effect)
        elif kind == "workflow-run-approval-request":
            require(expected_head is not None,
                    "Spotlight approval reproof reached without candidate publication head")
            reprove_approval(effect, expected_head)
        elif kind == "spotlight-terminal-merge":
            reprove_merge(effect)
        else:
            raise ValueError(f"unreviewed Spotlight decision effect reached reproof: {kind}")


def self_test() -> None:
    core.self_test()
    merge_sha = "a" * 40
    validate_main_ref({"ref": "refs/heads/main", "object": {"type": "commit", "sha": merge_sha}}, merge_sha)
    try:
        validate_main_ref({"ref": "refs/heads/main", "object": {"type": "commit", "sha": "b" * 40}}, merge_sha)
    except ValueError as exc:
        require("durable current main" in str(exc), f"Spotlight main-ref self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("Spotlight main-ref self-test accepted a divergent main SHA")

    for allowed in (
        {"status": "queued", "conclusion": None},
        {"status": "in_progress", "conclusion": None},
        {"status": "completed", "conclusion": "failure"},
        {"status": "completed", "conclusion": "success"},
    ):
        approval_left_gate(allowed)
    for blocked in (
        {"status": "waiting", "conclusion": None},
        {"status": "action_required", "conclusion": None},
        {"status": "completed", "conclusion": "action_required"},
    ):
        try:
            approval_left_gate(blocked)
        except ValueError as exc:
            require("still blocked on approval" in str(exc),
                    f"Spotlight approval gate self-test failed for wrong reason: {exc}")
        else:
            raise ValueError("Spotlight approval gate accepted an approval-required run")

    head = "c" * 40
    target = {
        "workflowName": "CodeQL",
        "workflowId": 101,
        "runId": 202,
        "runAttempt": 1,
        "checkSuiteId": 303,
    }
    provenance = {
        "id": 202,
        "name": "CodeQL",
        "workflow_id": 101,
        "check_suite_id": 303,
        "event": "pull_request",
        "head_sha": head,
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
    }
    validate_approved_attempt(
        {**provenance, "run_attempt": 1, "status": "completed", "conclusion": "action_required"},
        target,
        head,
    )
    validate_latest_after_approval(
        {**provenance, "run_attempt": 2, "status": "completed", "conclusion": "success"},
        target,
        head,
    )
    try:
        validate_approved_attempt(
            {**provenance, "run_attempt": 2, "status": "completed", "conclusion": "action_required"},
            target,
            head,
        )
    except ValueError as exc:
        require("historical attempt differs" in str(exc),
                f"Spotlight approved-attempt self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("Spotlight approved-attempt self-test accepted the wrong run attempt")
    try:
        validate_latest_after_approval(
            {**provenance, "run_attempt": 1, "status": "completed", "conclusion": "success"},
            target,
            head,
        )
    except ValueError as exc:
        require("did not advance" in str(exc),
                f"Spotlight approval-advance self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("Spotlight approval-advance self-test accepted an unadvanced run attempt")


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
        env = dict(os.environ)
        state = core.validate_journal(journal, env)
        reprove_state(state)
        args.output.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print(f"Spotlight Automation Decision Receipt state independently re-proved: {args.output}")
        return 0
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
