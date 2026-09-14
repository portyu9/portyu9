#!/usr/bin/env python3
"""Pure Profile Stats Automation Decision Receipt state construction."""
from __future__ import annotations

from typing import Any
import re

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
    base = env_value(env, "LEASE_BASE_SHA", SHA40)
    require(value["headSha"] == base,
            "Profile Stats downstream Spotlight head differs from leased source main")
    require(value["actorLogin"] == BOT_LOGIN and value["actorId"] == BOT_ID
            and value["triggeringActorLogin"] == BOT_LOGIN and value["triggeringActorId"] == BOT_ID,
            "Profile Stats downstream Spotlight actor identity changed")
    repository_id = int(env_value(env, "GITHUB_REPOSITORY_ID", POSITIVE))
    require(value["repository"] == REPOSITORY and value["headRepository"] == REPOSITORY
            and value["repositoryId"] == repository_id and value["headRepositoryId"] == repository_id,
            "Profile Stats downstream Spotlight repository identity changed")
    return value


def build_state(env: dict[str, str], downstream_run: dict[str, Any]) -> dict[str, Any]:
    require(env_value(env, "GITHUB_REPOSITORY") == REPOSITORY,
            "Profile Stats decision receipt repository identity changed")
    require(env_value(env, "GITHUB_WORKFLOW_REF") == WORKFLOW_REF,
            "Profile Stats decision receipt workflow identity changed")
    base = env_value(env, "LEASE_BASE_SHA", SHA40)
    require(env_value(env, "GITHUB_SHA", SHA40) == base,
            "Profile Stats decision receipt event source SHA differs from leased base")
    require(env_value(env, "GITHUB_WORKFLOW_SHA", SHA40) == base,
            "Profile Stats decision receipt workflow SHA differs from leased base")
    env_value(env, "GITHUB_RUN_ID", POSITIVE)
    env_value(env, "GITHUB_RUN_ATTEMPT", POSITIVE)
    status = env_value(env, "DISPATCH_ACCEPTED_STATUS", POSITIVE)
    require(status == "204", "Profile Stats Spotlight dispatch must record exact HTTP 204 acceptance")
    target = env_value(env, "DISPATCH_WORKFLOW_PATH")
    target_ref = env_value(env, "DISPATCH_REF")
    require(target == SPOTLIGHT_PATH and target_ref == "main",
            "Profile Stats Spotlight dispatch target changed")
    high_water = int(env_value(env, "DISPATCH_PREVIOUS_RUN_HIGH_WATER", NONNEGATIVE))
    observed = exact_downstream_run(downstream_run, env, high_water)
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
            },
        }]
    }


def fixture() -> tuple[dict[str, str], dict[str, Any]]:
    base = "a" * 40
    repository_id = 1355082509
    env = {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(repository_id),
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_WORKFLOW_SHA": base,
        "GITHUB_SHA": base,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "2",
        "LEASE_BASE_SHA": base,
        "DISPATCH_ACCEPTED_STATUS": "204",
        "DISPATCH_WORKFLOW_PATH": SPOTLIGHT_PATH,
        "DISPATCH_REF": "main",
        "DISPATCH_PREVIOUS_RUN_HIGH_WATER": "900",
    }
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


def self_test() -> None:
    env, downstream = fixture()
    state = build_state(dict(env), dict(downstream))
    observation = state["effects"][0]["observation"]
    require(observation["acceptedStatus"] == 204 and observation["previousRunHighWater"] == 900,
            "Profile Stats decision receipt self-test lost dispatch acceptance/high-water identity")
    require(observation["downstreamRun"]["runId"] == 901,
            "Profile Stats decision receipt self-test lost exact downstream run")

    wrong_status = dict(env)
    wrong_status["DISPATCH_ACCEPTED_STATUS"] = "200"
    try:
        build_state(wrong_status, dict(downstream))
    except ValueError as exc:
        require("HTTP 204" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted wrong dispatch status")

    wrong_target = dict(env)
    wrong_target["DISPATCH_WORKFLOW_PATH"] = ".github/workflows/profile-quality.yml"
    try:
        build_state(wrong_target, dict(downstream))
    except ValueError as exc:
        require("target changed" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted wrong workflow target")

    stale = dict(downstream)
    stale["runId"] = 900
    try:
        build_state(dict(env), stale)
    except ValueError as exc:
        require("high-water" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted a pre-dispatch downstream run")

    wrong_actor = dict(downstream)
    wrong_actor["actorLogin"] = "portyu9"
    try:
        build_state(dict(env), wrong_actor)
    except ValueError as exc:
        require("actor identity" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted wrong downstream actor")

    wrong_head = dict(downstream)
    wrong_head["headSha"] = "b" * 40
    try:
        build_state(dict(env), wrong_head)
    except ValueError as exc:
        require("leased source main" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted wrong downstream head")

    wrong_source = dict(env)
    wrong_source["GITHUB_SHA"] = "b" * 40
    try:
        build_state(wrong_source, dict(downstream))
    except ValueError as exc:
        require("event source SHA differs" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted an event/lease source split")
