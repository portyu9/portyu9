#!/usr/bin/env python3
"""Pure Spotlight Automation Decision Receipt journal validation."""
from __future__ import annotations

import copy
import re
from typing import Any

import automation_decision_receipt

REPOSITORY = "portyu9/portyu9"
WORKFLOW_PATH = ".github/workflows/spotlight-link-sync.yml"
WORKFLOW_REF = f"{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"
BOT_BRANCH_PREFIX = "automation/spotlight-links/"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
EFFECT_PHASE = {
    "stale-candidate-reconciliation": 0,
    "spotlight-candidate-publication": 1,
    "workflow-run-approval-request": 2,
    "spotlight-terminal-merge": 3,
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def env_value(env: dict[str, str], name: str, pattern: re.Pattern[str] | None = None) -> str:
    value = env.get(name, "").strip()
    require(bool(value), f"required environment variable is missing: {name}")
    if pattern is not None:
        require(pattern.fullmatch(value) is not None, f"{name} has invalid canonical form")
    return value


def transaction(env: dict[str, str]) -> dict[str, str]:
    issued = env_value(env, "LEASE_ISSUED_AT", POSITIVE)
    expires = env_value(env, "LEASE_EXPIRES_AT", POSITIVE)
    require(int(expires) == int(issued) + 1800,
            "Spotlight decision receipt lease lifetime changed")
    base = env_value(env, "LEASE_BASE_SHA", SHA40)
    return {
        "leaseId": env_value(env, "LEASE_ID", automation_decision_receipt.SHA64),
        "candidateId": env_value(env, "LEASE_CANDIDATE_ID", automation_decision_receipt.SHA64),
        "baseSha": base,
        "issuedAt": issued,
        "expiresAt": expires,
    }


def validate_journal(journal: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    require(isinstance(journal, dict) and set(journal) == {"effects"},
            "Spotlight decision journal root shape changed")
    raw_effects = journal["effects"]
    require(isinstance(raw_effects, list) and 2 <= len(raw_effects) <= 32,
            "Spotlight decision journal must contain between two and 32 effects")
    require(env_value(env, "GITHUB_REPOSITORY") == REPOSITORY,
            "Spotlight decision receipt repository identity changed")
    require(env_value(env, "GITHUB_WORKFLOW_REF") == WORKFLOW_REF,
            "Spotlight decision receipt workflow identity changed")
    lease = transaction(env)
    require(env_value(env, "GITHUB_SHA", SHA40) == lease["baseSha"],
            "Spotlight decision receipt event source SHA differs from leased base")
    require(env_value(env, "GITHUB_WORKFLOW_SHA", SHA40) == lease["baseSha"],
            "Spotlight decision receipt workflow SHA differs from leased base")
    env_value(env, "GITHUB_RUN_ID", POSITIVE)
    env_value(env, "GITHUB_RUN_ATTEMPT", POSITIVE)
    expected_head = env_value(env, "EXPECTED_HEAD_SHA", SHA40)
    current_candidate_branch = BOT_BRANCH_PREFIX + lease["candidateId"]

    validated: list[dict[str, Any]] = []
    candidate_publications = 0
    terminal_merges = 0
    candidate_pr_number: int | None = None
    last_phase = 0
    stale_branches: set[str] = set()
    approval_runs: set[int] = set()
    approval_workflows: set[str] = set()

    for ordinal, raw in enumerate(raw_effects, start=1):
        effect = automation_decision_receipt.validate_effect(raw, WORKFLOW_PATH, lease, ordinal)
        kind = effect["kind"]
        require(kind != "spotlight-workflow-dispatch",
                "Profile Stats dispatch effect cannot appear in a Spotlight decision journal")
        phase = EFFECT_PHASE[kind]
        require(phase >= last_phase,
                "Spotlight decision journal effects are not in canonical transaction phase order")
        last_phase = phase

        if kind == "stale-candidate-reconciliation":
            branch = effect["target"]["candidateBranch"]
            require(branch != current_candidate_branch,
                    "Spotlight stale reconciliation must never consume the leased current candidate")
            require(branch not in stale_branches,
                    "Spotlight decision journal contains duplicate stale-candidate effects")
            stale_branches.add(branch)
        elif kind == "spotlight-candidate-publication":
            candidate_publications += 1
            require(effect["target"]["candidateBranch"] == current_candidate_branch,
                    "Spotlight candidate publication differs from leased candidate identity")
            require(effect["target"]["headSha"] == expected_head,
                    "Spotlight candidate publication head differs from expected candidate head")
            candidate_pr_number = effect["target"]["prNumber"]
        elif kind == "workflow-run-approval-request":
            run_id = effect["target"]["runId"]
            workflow_name = effect["target"]["workflowName"]
            require(run_id not in approval_runs,
                    "Spotlight decision journal contains duplicate approval run effects")
            require(workflow_name not in approval_workflows,
                    "Spotlight decision journal contains duplicate workflow approval effects")
            approval_runs.add(run_id)
            approval_workflows.add(workflow_name)
            require(len(approval_runs) <= 3,
                    "Spotlight decision journal exceeds the canonical three protected workflow approvals")
        elif kind == "spotlight-terminal-merge":
            terminal_merges += 1
            require(effect["target"]["candidateBranch"] == current_candidate_branch,
                    "Spotlight terminal merge differs from leased candidate identity")
            require(effect["target"]["headSha"] == expected_head,
                    "Spotlight terminal merge head differs from expected candidate head")
        validated.append(effect)

    require(candidate_publications == 1,
            "Spotlight decision journal must contain exactly one candidate-publication effect")
    require(terminal_merges == 1,
            "Spotlight decision journal must contain exactly one terminal merge effect")
    require(validated[-1]["kind"] == "spotlight-terminal-merge",
            "Spotlight decision journal terminal merge effect must be final")
    merge_pr_number = validated[-1]["target"]["prNumber"]
    require(candidate_pr_number == merge_pr_number,
            "Spotlight decision journal candidate publication and merge PR identities differ")
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
        "GITHUB_SHA": base,
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


def expect_failure(journal: dict[str, Any], env: dict[str, str], expected: str) -> None:
    try:
        validate_journal(journal, env)
    except ValueError as exc:
        require(expected in str(exc), f"Spotlight decision receipt self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"Spotlight decision receipt self-test accepted forbidden drift: {expected}")


def renumber(journal: dict[str, Any]) -> None:
    for ordinal, effect in enumerate(journal["effects"], start=1):
        effect["ordinal"] = ordinal


def self_test() -> None:
    journal, env = fixture()
    state = validate_journal(copy.deepcopy(journal), dict(env))
    require(len(state["effects"]) == 3, "Spotlight decision receipt self-test lost effects")

    wrong_head = copy.deepcopy(journal)
    wrong_head["effects"][2]["target"]["headSha"] = "f" * 40
    expect_failure(wrong_head, dict(env), "expected candidate head")

    wrong_candidate = copy.deepcopy(journal)
    wrong_candidate["effects"][0]["target"]["candidateBranch"] = BOT_BRANCH_PREFIX + "f" * 64
    expect_failure(wrong_candidate, dict(env), "leased candidate identity")

    stale_current = copy.deepcopy(journal)
    stale_current["effects"].insert(0, {
        "ordinal": 1,
        "job": "reconcile",
        "kind": "stale-candidate-reconciliation",
        "outcome": "applied",
        "target": {"candidateBranch": BOT_BRANCH_PREFIX + env["LEASE_CANDIDATE_ID"], "headSha": "1" * 40,
                   "prNumber": None},
        "observation": {"prClosed": False, "candidateRefAbsent": True},
    })
    renumber(stale_current)
    expect_failure(stale_current, dict(env), "must never consume")

    duplicate_merge = copy.deepcopy(journal)
    duplicate_merge["effects"].append(copy.deepcopy(duplicate_merge["effects"][2]))
    renumber(duplicate_merge)
    expect_failure(duplicate_merge, dict(env), "exactly one terminal merge")

    duplicate_publication = copy.deepcopy(journal)
    duplicate_publication["effects"].insert(1, copy.deepcopy(duplicate_publication["effects"][0]))
    renumber(duplicate_publication)
    expect_failure(duplicate_publication, dict(env), "exactly one candidate-publication")

    missing_merge = copy.deepcopy(journal)
    missing_merge["effects"].pop()
    renumber(missing_merge)
    expect_failure(missing_merge, dict(env), "exactly one terminal merge")

    missing_publication = copy.deepcopy(journal)
    missing_publication["effects"].pop(0)
    renumber(missing_publication)
    expect_failure(missing_publication, dict(env), "exactly one candidate-publication")

    reordered = copy.deepcopy(journal)
    reordered["effects"][0], reordered["effects"][1] = reordered["effects"][1], reordered["effects"][0]
    renumber(reordered)
    expect_failure(reordered, dict(env), "canonical transaction phase order")

    wrong_pr = copy.deepcopy(journal)
    wrong_pr["effects"][2]["target"]["prNumber"] = 124
    expect_failure(wrong_pr, dict(env), "PR identities differ")

    duplicate_approval = copy.deepcopy(journal)
    extra_approval = copy.deepcopy(duplicate_approval["effects"][1])
    extra_approval["target"]["runId"] = 21
    extra_approval["target"]["checkSuiteId"] = 31
    duplicate_approval["effects"].insert(2, extra_approval)
    renumber(duplicate_approval)
    expect_failure(duplicate_approval, dict(env), "duplicate workflow approval")

    wrong_source = dict(env)
    wrong_source["GITHUB_SHA"] = "f" * 40
    expect_failure(copy.deepcopy(journal), wrong_source, "event source SHA differs")

    bad_ordinal = copy.deepcopy(journal)
    bad_ordinal["effects"][1]["ordinal"] = 3
    expect_failure(bad_ordinal, dict(env), "ordinals")
