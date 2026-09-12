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
    require(isinstance(raw_effects, list) and 1 <= len(raw_effects) <= 32,
            "Spotlight decision journal must contain between one and 32 effects")
    require(env_value(env, "GITHUB_REPOSITORY") == REPOSITORY,
            "Spotlight decision receipt repository identity changed")
    require(env_value(env, "GITHUB_WORKFLOW_REF") == WORKFLOW_REF,
            "Spotlight decision receipt workflow identity changed")
    lease = transaction(env)
    require(env_value(env, "GITHUB_WORKFLOW_SHA", SHA40) == lease["baseSha"],
            "Spotlight decision receipt workflow SHA differs from leased base")
    env_value(env, "GITHUB_RUN_ID", POSITIVE)
    env_value(env, "GITHUB_RUN_ATTEMPT", POSITIVE)
    expected_head = env_value(env, "EXPECTED_HEAD_SHA", SHA40)

    validated: list[dict[str, Any]] = []
    terminal_merges = 0
    for ordinal, raw in enumerate(raw_effects, start=1):
        effect = automation_decision_receipt.validate_effect(raw, WORKFLOW_PATH, lease, ordinal)
        kind = effect["kind"]
        require(kind != "spotlight-workflow-dispatch",
                "Profile Stats dispatch effect cannot appear in a Spotlight decision journal")
        if kind == "spotlight-terminal-merge":
            terminal_merges += 1
            require(effect["target"]["headSha"] == expected_head,
                    "Spotlight terminal merge head differs from expected candidate head")
        validated.append(effect)
    require(terminal_merges <= 1, "Spotlight decision journal contains multiple terminal merge effects")
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


def expect_failure(journal: dict[str, Any], env: dict[str, str], expected: str) -> None:
    try:
        validate_journal(journal, env)
    except ValueError as exc:
        require(expected in str(exc), f"Spotlight decision receipt self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"Spotlight decision receipt self-test accepted forbidden drift: {expected}")


def self_test() -> None:
    journal, env = fixture()
    state = validate_journal(copy.deepcopy(journal), dict(env))
    require(len(state["effects"]) == 3, "Spotlight decision receipt self-test lost effects")

    wrong_head = copy.deepcopy(journal)
    wrong_head["effects"][2]["target"]["headSha"] = "f" * 40
    expect_failure(wrong_head, dict(env), "expected candidate head")

    duplicate_merge = copy.deepcopy(journal)
    duplicate = copy.deepcopy(duplicate_merge["effects"][2])
    duplicate["ordinal"] = 4
    duplicate_merge["effects"].append(duplicate)
    expect_failure(duplicate_merge, dict(env), "multiple terminal merge")

    bad_ordinal = copy.deepcopy(journal)
    bad_ordinal["effects"][1]["ordinal"] = 3
    expect_failure(bad_ordinal, dict(env), "ordinals")
