#!/usr/bin/env python3
"""Compile observed Spotlight side-effect outputs into one strict ADR journal."""
from __future__ import annotations

import copy
import json
import re
from typing import Any

import automation_decision_receipt
import spotlight_decision_receipt

SHA40 = re.compile(r"^[0-9a-f]{40}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
CANDIDATE_BRANCH = re.compile(r"^automation/spotlight-links/[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == keys, f"{label} keys changed: {sorted(value)}")
    return value


def env_value(env: dict[str, str], name: str, pattern: re.Pattern[str] | None = None) -> str:
    value = env.get(name, "").strip()
    require(bool(value), f"required environment variable is missing: {name}")
    if pattern is not None:
        require(pattern.fullmatch(value) is not None, f"{name} has invalid canonical form")
    return value


def json_env(env: dict[str, str], name: str, expected_type: type) -> Any:
    raw = env_value(env, name)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} is not valid JSON: {exc}") from exc
    require(type(value) is expected_type, f"{name} has invalid JSON type")
    return value


def json_bool(env: dict[str, str], name: str) -> bool:
    value = json_env(env, name, bool)
    require(type(value) is bool, f"{name} must be one JSON boolean")
    return value


def positive_int_env(env: dict[str, str], name: str) -> int:
    return int(env_value(env, name, POSITIVE))


def normalized_approval(value: Any, expected_head: str) -> dict[str, Any]:
    item = exact_object(
        value,
        {"workflowName", "workflowId", "runId", "runAttempt", "checkSuiteId", "headSha"},
        "Spotlight approval observation",
    )
    require(item["workflowName"] in automation_decision_receipt.WORKFLOW_NAMES,
            "Spotlight approval observation workflow name changed")
    for key in ("workflowId", "runId", "runAttempt", "checkSuiteId"):
        require(type(item[key]) is int and item[key] > 0,
                f"Spotlight approval observation {key} must be one positive integer")
    require(isinstance(item["headSha"], str) and SHA40.fullmatch(item["headSha"]) is not None,
            "Spotlight approval observation headSha is invalid")
    require(item["headSha"] == expected_head,
            "Spotlight approval observation differs from expected candidate head")
    return item


def build(env: dict[str, str], approval_runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Build one ordered raw journal from already observed writer outputs.

    The later read-only preparer must independently re-prove every emitted effect against
    durable GitHub state before this journal is converted into an attested ADR predicate.
    """
    lease_candidate = env_value(env, "LEASE_CANDIDATE_ID", automation_decision_receipt.SHA64)
    current_branch = f"{spotlight_decision_receipt.BOT_BRANCH_PREFIX}{lease_candidate}"
    expected_head = env_value(env, "EXPECTED_HEAD_SHA", SHA40)
    base_sha = env_value(env, "LEASE_BASE_SHA", SHA40)

    effects: list[dict[str, Any]] = []
    stale = json_env(env, "STALE_CLEANUPS_JSON", list)
    require(len(stale) <= 20, "Spotlight stale-cleanup observation exceeds reviewed namespace bound")
    stale_branches: set[str] = set()
    for raw in stale:
        item = exact_object(raw, {"candidateBranch", "headSha", "prNumber", "prClosed"},
                            "Spotlight stale-cleanup observation")
        branch = item["candidateBranch"]
        head = item["headSha"]
        pr_number = item["prNumber"]
        pr_closed = item["prClosed"]
        require(isinstance(branch, str) and CANDIDATE_BRANCH.fullmatch(branch) is not None,
                "Spotlight stale-cleanup candidate branch is invalid")
        require(branch != current_branch,
                "Spotlight stale-cleanup observation targets the leased current candidate")
        require(branch not in stale_branches, "Spotlight stale-cleanup observation duplicates a candidate branch")
        stale_branches.add(branch)
        require(isinstance(head, str) and SHA40.fullmatch(head) is not None,
                "Spotlight stale-cleanup candidate head is invalid")
        require(pr_number is None or (type(pr_number) is int and pr_number > 0),
                "Spotlight stale-cleanup PR number must be null or one positive integer")
        require(type(pr_closed) is bool, "Spotlight stale-cleanup prClosed must be one JSON boolean")
        require((pr_number is None and not pr_closed) or (pr_number is not None and pr_closed),
                "Spotlight stale-cleanup PR closure differs from PR identity")
        effects.append({
            "job": "reconcile",
            "kind": "stale-candidate-reconciliation",
            "outcome": "applied",
            "target": {"candidateBranch": branch, "headSha": head, "prNumber": pr_number},
            "observation": {"prClosed": pr_closed, "candidateRefAbsent": True},
        })

    ref_created = json_bool(env, "PROPOSE_REF_CREATED")
    pr_created = json_bool(env, "PROPOSE_PR_CREATED")
    pr_number = positive_int_env(env, "PR_NUMBER")
    effects.append({
        "job": "propose",
        "kind": "spotlight-candidate-publication",
        "outcome": "applied" if ref_created or pr_created else "reused",
        "target": {"candidateBranch": current_branch, "headSha": expected_head, "prNumber": pr_number},
        "observation": {"refCreated": ref_created, "prCreated": pr_created},
    })

    require(isinstance(approval_runs, list) and len(approval_runs) <= 3,
            "Spotlight approval observation exceeds canonical workflow bound")
    approval_ids: set[int] = set()
    for raw in approval_runs:
        item = normalized_approval(raw, expected_head)
        require(item["runId"] not in approval_ids, "Spotlight approval observation duplicates one run")
        approval_ids.add(item["runId"])
        effects.append({
            "job": "approve",
            "kind": "workflow-run-approval-request",
            "outcome": "applied",
            "target": {key: item[key] for key in (
                "workflowName", "workflowId", "runId", "runAttempt", "checkSuiteId"
            )},
            "observation": {"approvalRequested": True},
        })

    merge_sha = env_value(env, "MERGE_SHA", SHA40)
    current_main = env_value(env, "CURRENT_MAIN_SHA", SHA40)
    require(current_main == merge_sha, "Spotlight merge observation does not match current main")
    effects.append({
        "job": "merge",
        "kind": "spotlight-terminal-merge",
        "outcome": "applied",
        "target": {
            "prNumber": pr_number,
            "candidateBranch": current_branch,
            "headSha": expected_head,
            "baseSha": base_sha,
        },
        "observation": {"mergeSha": merge_sha, "mainSha": current_main, "candidateRefAbsent": True},
    })

    for ordinal, effect in enumerate(effects, start=1):
        effect["ordinal"] = ordinal
    return spotlight_decision_receipt.validate_journal({"effects": effects}, env)


def expect_failure(env: dict[str, str], approvals: list[dict[str, Any]], expected: str) -> None:
    try:
        build(env, approvals)
    except ValueError as exc:
        require(expected in str(exc), f"Spotlight decision journal self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"Spotlight decision journal self-test accepted forbidden drift: {expected}")


def self_test() -> None:
    _journal, env = spotlight_decision_receipt.fixture()
    env.update({
        "STALE_CLEANUPS_JSON": json.dumps([{
            "candidateBranch": spotlight_decision_receipt.BOT_BRANCH_PREFIX + "e" * 64,
            "headSha": "1" * 40,
            "prNumber": 122,
            "prClosed": True,
        }], separators=(",", ":")),
        "PROPOSE_REF_CREATED": "true",
        "PROPOSE_PR_CREATED": "true",
        "PR_NUMBER": "123",
        "MERGE_SHA": "f" * 40,
        "CURRENT_MAIN_SHA": "f" * 40,
    })
    approvals = [{
        "workflowName": "CodeQL",
        "workflowId": 10,
        "runId": 20,
        "runAttempt": 2,
        "checkSuiteId": 30,
        "headSha": env["EXPECTED_HEAD_SHA"],
    }]
    state = build(dict(env), copy.deepcopy(approvals))
    require([effect["kind"] for effect in state["effects"]] == [
        "stale-candidate-reconciliation",
        "spotlight-candidate-publication",
        "workflow-run-approval-request",
        "spotlight-terminal-merge",
    ], "Spotlight decision journal self-test lost canonical effect order")

    reused = dict(env)
    reused["STALE_CLEANUPS_JSON"] = "[]"
    reused["PROPOSE_REF_CREATED"] = "false"
    reused["PROPOSE_PR_CREATED"] = "false"
    reused_state = build(reused, [])
    require(reused_state["effects"][0]["outcome"] == "reused",
            "Spotlight decision journal self-test lost candidate reuse semantics")

    stale_current = dict(env)
    stale_current["STALE_CLEANUPS_JSON"] = json.dumps([{
        "candidateBranch": spotlight_decision_receipt.BOT_BRANCH_PREFIX + env["LEASE_CANDIDATE_ID"],
        "headSha": "1" * 40,
        "prNumber": None,
        "prClosed": False,
    }], separators=(",", ":"))
    expect_failure(stale_current, [], "leased current candidate")

    duplicate_approval = copy.deepcopy(approvals) * 2
    expect_failure(dict(env), duplicate_approval, "duplicates one run")

    wrong_main = dict(env)
    wrong_main["CURRENT_MAIN_SHA"] = "0" * 40
    expect_failure(wrong_main, approvals, "does not match current main")


if __name__ == "__main__":
    try:
        self_test()
        print("Spotlight decision journal compiler self-test passed")
    except ValueError as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)
