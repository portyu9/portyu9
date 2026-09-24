#!/usr/bin/env python3
"""Pure Profile Stats Automation Decision Receipt state construction."""
from __future__ import annotations

from typing import Any
import re

import automation_decision_lease as lease_contract

REPOSITORY = "portyu9/portyu9"
WORKFLOW_PATH = ".github/workflows/profile-stats.yml"
SPOTLIGHT_PATH = ".github/workflows/spotlight-link-sync.yml"
WORKFLOW_REF = f"{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"
BOT_LOGIN = "github-actions[bot]"
BOT_ID = 41898282
SHA40 = re.compile(r"^[0-9a-f]{40}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
NONNEGATIVE = re.compile(r"^(?:0|[1-9][0-9]*)$")
DOWNSTREAM_KEYS = {
    "workflowId",
    "runId",
    "runAttempt",
    "checkSuiteId",
    "path",
    "event",
    "headBranch",
    "headSha",
    "actorLogin",
    "actorId",
    "triggeringActorLogin",
    "triggeringActorId",
    "repository",
    "repositoryId",
    "headRepository",
    "headRepositoryId",
}
SOURCE_ANCESTRY_KEYS = {
    "baseSha",
    "headSha",
    "status",
    "mergeBaseSha",
    "aheadBy",
    "behindBy",
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


def positive_int(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be one positive integer")
    return value


def nonnegative_int(value: Any, label: str) -> int:
    require(type(value) is int and value >= 0, f"{label} must be one non-negative integer")
    return value


def exact_downstream_run(value: Any, env: dict[str, str], high_water: int) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == DOWNSTREAM_KEYS,
            "Profile Stats downstream Spotlight run shape changed")
    for key in ("workflowId", "runId", "runAttempt", "checkSuiteId", "actorId", "triggeringActorId",
                "repositoryId", "headRepositoryId"):
        positive_int(value[key], f"Profile Stats downstream Spotlight {key}")
    require(value["runId"] > high_water,
            "Profile Stats downstream Spotlight run does not cross the pre-dispatch high-water mark")
    require(value["runAttempt"] == 1,
            "Profile Stats downstream Spotlight dispatch must bind the newly created first run attempt")
    require(value["path"] == SPOTLIGHT_PATH and value["event"] == "workflow_dispatch"
            and value["headBranch"] == "main",
            "Profile Stats downstream Spotlight workflow/event/branch identity changed")
    require(isinstance(value["headSha"], str) and SHA40.fullmatch(value["headSha"]) is not None,
            "Profile Stats downstream Spotlight head SHA is invalid")
    require(value["actorLogin"] == BOT_LOGIN and value["actorId"] == BOT_ID
            and value["triggeringActorLogin"] == BOT_LOGIN and value["triggeringActorId"] == BOT_ID,
            "Profile Stats downstream Spotlight actor identity changed")
    repository_id = int(env_value(env, "GITHUB_REPOSITORY_ID", POSITIVE))
    require(value["repository"] == REPOSITORY and value["headRepository"] == REPOSITORY
            and value["repositoryId"] == repository_id and value["headRepositoryId"] == repository_id,
            "Profile Stats downstream Spotlight repository identity changed")
    return value


def exact_source_ancestry(value: Any, env: dict[str, str], downstream_head: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == SOURCE_ANCESTRY_KEYS,
            "Profile Stats downstream Spotlight source ancestry shape changed")
    base = env_value(env, "LEASE_BASE_SHA", SHA40)
    require(value["baseSha"] == base and value["headSha"] == downstream_head,
            "Profile Stats downstream Spotlight source ancestry SHA binding changed")
    require(value["mergeBaseSha"] == base,
            "Profile Stats downstream Spotlight source ancestry merge base escaped leased main")
    status = value["status"]
    require(status in {"identical", "ahead"},
            "Profile Stats downstream Spotlight source ancestry is not a forward main transition")
    ahead = nonnegative_int(value["aheadBy"], "Profile Stats downstream Spotlight source ancestry aheadBy")
    behind = nonnegative_int(value["behindBy"], "Profile Stats downstream Spotlight source ancestry behindBy")
    require(behind == 0,
            "Profile Stats downstream Spotlight source ancestry moved behind leased main")
    if status == "identical":
        require(downstream_head == base and ahead == 0,
                "Profile Stats identical downstream source ancestry is inconsistent")
    else:
        require(downstream_head != base and ahead > 0,
                "Profile Stats ahead downstream source ancestry is inconsistent")
    return value


def build_state(
    env: dict[str, str],
    downstream_run: dict[str, Any],
    source_ancestry: dict[str, Any],
) -> dict[str, Any]:
    lease = lease_contract.validate(env, WORKFLOW_PATH)
    status = env_value(env, "DISPATCH_ACCEPTED_STATUS", POSITIVE)
    require(status == "204", "Profile Stats Spotlight dispatch must record exact HTTP 204 acceptance")
    target = env_value(env, "DISPATCH_WORKFLOW_PATH")
    target_ref = env_value(env, "DISPATCH_REF")
    require(target == SPOTLIGHT_PATH and target_ref == "main",
            "Profile Stats Spotlight dispatch target changed")
    high_water = int(env_value(env, "DISPATCH_PREVIOUS_RUN_HIGH_WATER", NONNEGATIVE))
    observed = exact_downstream_run(downstream_run, env, high_water)
    ancestry = exact_source_ancestry(source_ancestry, env, observed["headSha"])
    require(ancestry["baseSha"] == lease["baseSha"],
            "Profile Stats downstream Spotlight ancestry escaped exact lease identity")
    return {
        "effects": [{
            "ordinal": 1,
            "job": "dispatch",
            "kind": "spotlight-workflow-dispatch",
            "outcome": "applied",
            "target": {"workflowPath": target, "ref": target_ref},
            "observation": {
                "acceptedStatus": 204,
                "previousRunHighWater": high_water,
                "downstreamRun": observed,
                "sourceAncestry": ancestry,
            },
        }]
    }


def fixture() -> tuple[dict[str, str], dict[str, Any]]:
    env = lease_contract.fixture(WORKFLOW_PATH)
    base = env["LEASE_BASE_SHA"]
    repository_id = int(env["GITHUB_REPOSITORY_ID"])
    env.update({
        "DISPATCH_ACCEPTED_STATUS": "204",
        "DISPATCH_WORKFLOW_PATH": SPOTLIGHT_PATH,
        "DISPATCH_REF": "main",
        "DISPATCH_PREVIOUS_RUN_HIGH_WATER": "900",
    })
    downstream = {
        "workflowId": 351927175,
        "runId": 901,
        "runAttempt": 1,
        "checkSuiteId": 94229114333,
        "path": SPOTLIGHT_PATH,
        "event": "workflow_dispatch",
        "headBranch": "main",
        "headSha": base,
        "actorLogin": BOT_LOGIN,
        "actorId": BOT_ID,
        "triggeringActorLogin": BOT_LOGIN,
        "triggeringActorId": BOT_ID,
        "repository": REPOSITORY,
        "repositoryId": repository_id,
        "headRepository": REPOSITORY,
        "headRepositoryId": repository_id,
    }
    return env, downstream


def source_ancestry_fixture(env: dict[str, str], head_sha: str | None = None) -> dict[str, Any]:
    base = env["LEASE_BASE_SHA"]
    head = base if head_sha is None else head_sha
    identical = head == base
    return {
        "baseSha": base,
        "headSha": head,
        "status": "identical" if identical else "ahead",
        "mergeBaseSha": base,
        "aheadBy": 0 if identical else 1,
        "behindBy": 0,
    }


def self_test() -> None:
    lease_contract.self_test()
    env, downstream = fixture()
    ancestry = source_ancestry_fixture(env)
    state = build_state(dict(env), dict(downstream), dict(ancestry))
    observation = state["effects"][0]["observation"]
    require(observation["acceptedStatus"] == 204 and observation["previousRunHighWater"] == 900,
            "Profile Stats decision receipt self-test lost dispatch acceptance/high-water identity")
    require(observation["downstreamRun"]["runId"] == 901,
            "Profile Stats decision receipt self-test lost exact downstream run")
    require(observation["sourceAncestry"]["status"] == "identical",
            "Profile Stats decision receipt self-test lost exact source ancestry")

    advanced = dict(downstream)
    advanced["headSha"] = "b" * 40
    advanced_ancestry = source_ancestry_fixture(env, advanced["headSha"])
    advanced_state = build_state(dict(env), advanced, advanced_ancestry)
    require(advanced_state["effects"][0]["observation"]["sourceAncestry"]["status"] == "ahead",
            "Profile Stats decision receipt rejected proven forward main advance")

    wrong_status = dict(env)
    wrong_status["DISPATCH_ACCEPTED_STATUS"] = "200"
    try:
        build_state(wrong_status, dict(downstream), dict(ancestry))
    except ValueError as exc:
        require("HTTP 204" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted wrong dispatch status")

    wrong_target = dict(env)
    wrong_target["DISPATCH_WORKFLOW_PATH"] = ".github/workflows/profile-quality.yml"
    try:
        build_state(wrong_target, dict(downstream), dict(ancestry))
    except ValueError as exc:
        require("target changed" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted wrong workflow target")

    stale = dict(downstream)
    stale["runId"] = 900
    try:
        build_state(dict(env), stale, dict(ancestry))
    except ValueError as exc:
        require("high-water" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted a pre-dispatch downstream run")

    wrong_attempt = dict(downstream)
    wrong_attempt["runAttempt"] = 2
    try:
        build_state(dict(env), wrong_attempt, dict(ancestry))
    except ValueError as exc:
        require("first run attempt" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted a rerun as the dispatched downstream run")

    wrong_actor = dict(downstream)
    wrong_actor["actorLogin"] = "portyu9"
    try:
        build_state(dict(env), wrong_actor, dict(ancestry))
    except ValueError as exc:
        require("actor identity" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted wrong downstream actor")

    wrong_head = dict(downstream)
    wrong_head["headSha"] = "c" * 40
    try:
        build_state(dict(env), wrong_head, dict(ancestry))
    except ValueError as exc:
        require("SHA binding" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted downstream/ancestry head mismatch")

    diverged = dict(advanced_ancestry)
    diverged["status"] = "diverged"
    try:
        build_state(dict(env), advanced, diverged)
    except ValueError as exc:
        require("forward main transition" in str(exc),
                f"Profile Stats decision receipt failed for wrong ancestry reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted diverged downstream ancestry")

    behind = dict(advanced_ancestry)
    behind["behindBy"] = 1
    try:
        build_state(dict(env), advanced, behind)
    except ValueError as exc:
        require("moved behind" in str(exc),
                f"Profile Stats decision receipt failed for wrong behind reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted downstream ancestry behind leased main")

    wrong_merge_base = dict(advanced_ancestry)
    wrong_merge_base["mergeBaseSha"] = "c" * 40
    try:
        build_state(dict(env), advanced, wrong_merge_base)
    except ValueError as exc:
        require("merge base" in str(exc),
                f"Profile Stats decision receipt failed for wrong merge-base reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted wrong downstream merge base")

    wrong_source = dict(env)
    wrong_source["GITHUB_SHA"] = "b" * 40
    try:
        build_state(wrong_source, dict(downstream), dict(ancestry))
    except ValueError as exc:
        require("event source SHA differs" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted an event/lease source split")

    wrong_lease = dict(env)
    wrong_lease["LEASE_ID"] = "f" * 64
    try:
        build_state(wrong_lease, dict(downstream), dict(ancestry))
    except ValueError as exc:
        require("lease ID differs" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted an arbitrary lease id")
