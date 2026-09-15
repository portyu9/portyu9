#!/usr/bin/env python3
"""Pure Spotlight Automation Decision Receipt journal validation."""
from __future__ import annotations

import copy
import re
from typing import Any

import automation_decision_lease as lease_contract
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
    return lease_contract.validate(env, WORKFLOW_PATH)


def validate_journal(journal: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    require(isinstance(journal, dict) and set(journal) == {"effects"},
            "Spotlight decision journal root shape changed")
    raw_effects = journal["effects"]
    require(isinstance(raw_effects, list) and 1 <= len(raw_effects) <= 32,
            "Spotlight decision journal must contain between one and 32 effects")
    lease = transaction(env)
    current_candidate_branch = BOT_BRANCH_PREFIX + lease["candidateId"]

    validated: list[dict[str, Any]] = []
    candidate_publications = 0
    terminal_merges = 0
    candidate_pr_number: int | None = None
    expected_head: str | None = None
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
            require(candidate_publications == 1,
                    "Spotlight decision journal contains multiple candidate-publication effects")
            expected_head = env_value(env, "EXPECTED_HEAD_SHA", SHA40)
            require(effect["target"]["candidateBranch"] == current_candidate_branch,
                    "Spotlight candidate publication differs from leased candidate identity")
            require(effect["target"]["headSha"] == expected_head,
                    "Spotlight candidate publication head differs from expected candidate head")
            candidate_pr_number = effect["target"]["prNumber"]
        elif kind == "workflow-run-approval-request":
            require(candidate_publications == 1 and expected_head is not None,
                    "Spotlight approval effects require a preceding candidate-publication disposition")
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
            require(terminal_merges == 1,
                    "Spotlight decision journal contains multiple terminal merge effects")
            require(candidate_publications == 1 and expected_head is not None,
                    "Spotlight terminal merge effect requires a preceding candidate-publication disposition")
            require(effect["target"]["candidateBranch"] == current_candidate_branch,
                    "Spotlight terminal merge differs from leased candidate identity")
            require(effect["target"]["headSha"] == expected_head,
                    "Spotlight terminal merge head differs from expected candidate head")
            require(candidate_pr_number == effect["target"]["prNumber"],
                    "Spotlight decision journal candidate publication and merge PR identities differ")
        validated.append(effect)

    if terminal_merges:
        require(validated[-1]["kind"] == "spotlight-terminal-merge",
                "Spotlight decision journal terminal merge effect must be final")
    return {"effects": validated}


def fixture() -> tuple[dict[str, Any], dict[str, str]]:
    env = lease_contract.fixture(WORKFLOW_PATH)
    base = env["LEASE_BASE_SHA"]
    candidate_id = env["LEASE_CANDIDATE_ID"]
    branch = f"{BOT_BRANCH_PREFIX}{candidate_id}"
    head = "c" * 40
    env["EXPECTED_HEAD_SHA"] = head
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
    lease_contract.self_test()
    journal, env = fixture()
    state = validate_journal(copy.deepcopy(journal), dict(env))
    require(len(state["effects"]) == 3, "Spotlight decision receipt self-test lost effects")

    stale_only = {
        "effects": [{
            "ordinal": 1,
            "job": "reconcile",
            "kind": "stale-candidate-reconciliation",
            "outcome": "applied",
            "target": {"candidateBranch": BOT_BRANCH_PREFIX + "d" * 64, "headSha": "1" * 40,
                       "prNumber": 122},
            "observation": {"prClosed": True, "candidateRefAbsent": True},
        }]
    }
    maintenance_env = dict(env)
    maintenance_env.pop("EXPECTED_HEAD_SHA", None)
    require(len(validate_journal(stale_only, maintenance_env)["effects"]) == 1,
            "Spotlight decision receipt rejected headless maintenance-only reconciliation")

    publication_only = {"effects": [copy.deepcopy(journal["effects"][0])]}
    require(len(validate_journal(publication_only, dict(env))["effects"]) == 1,
            "Spotlight decision receipt rejected publication-only recovery")

    publication_approval = {"effects": copy.deepcopy(journal["effects"][:2])}
    require(len(validate_journal(publication_approval, dict(env))["effects"]) == 2,
            "Spotlight decision receipt rejected approval recovery subset")

    empty = {"effects": []}
    expect_failure(empty, dict(env), "between one and 32")

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
    expect_failure(duplicate_merge, dict(env), "multiple terminal merge")

    duplicate_publication = copy.deepcopy(journal)
    duplicate_publication["effects"].insert(1, copy.deepcopy(duplicate_publication["effects"][0]))
    renumber(duplicate_publication)
    expect_failure(duplicate_publication, dict(env), "multiple candidate-publication")

    merge_without_publication = {"effects": [copy.deepcopy(journal["effects"][2])]}
    merge_without_publication["effects"][0]["ordinal"] = 1
    expect_failure(merge_without_publication, dict(env), "requires a preceding candidate-publication")

    approval_without_publication = {"effects": [copy.deepcopy(journal["effects"][1])]}
    approval_without_publication["effects"][0]["ordinal"] = 1
    expect_failure(approval_without_publication, dict(env), "require a preceding candidate-publication")

    reordered = copy.deepcopy(journal)
    reordered["effects"][0], reordered["effects"][1] = reordered["effects"][1], reordered["effects"][0]
    renumber(reordered)
    expect_failure(reordered, dict(env), "require a preceding candidate-publication")

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

    wrong_lease = dict(env)
    wrong_lease["LEASE_ID"] = "f" * 64
    expect_failure(copy.deepcopy(journal), wrong_lease, "lease ID differs")

    bad_ordinal = copy.deepcopy(journal)
    bad_ordinal["effects"][1]["ordinal"] = 3
    expect_failure(bad_ordinal, dict(env), "ordinals")
