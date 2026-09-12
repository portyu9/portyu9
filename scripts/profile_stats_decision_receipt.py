#!/usr/bin/env python3
"""Pure Profile Stats Automation Decision Receipt state construction."""
from __future__ import annotations

from typing import Any
import re

REPOSITORY = "portyu9/portyu9"
WORKFLOW_PATH = ".github/workflows/profile-stats.yml"
SPOTLIGHT_PATH = ".github/workflows/spotlight-link-sync.yml"
WORKFLOW_REF = f"{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"
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


def build_state(env: dict[str, str]) -> dict[str, Any]:
    require(env_value(env, "GITHUB_REPOSITORY") == REPOSITORY,
            "Profile Stats decision receipt repository identity changed")
    require(env_value(env, "GITHUB_WORKFLOW_REF") == WORKFLOW_REF,
            "Profile Stats decision receipt workflow identity changed")
    require(env_value(env, "GITHUB_WORKFLOW_SHA", SHA40) == env_value(env, "LEASE_BASE_SHA", SHA40),
            "Profile Stats decision receipt workflow SHA differs from leased base")
    env_value(env, "GITHUB_RUN_ID", POSITIVE)
    env_value(env, "GITHUB_RUN_ATTEMPT", POSITIVE)
    status = env_value(env, "DISPATCH_ACCEPTED_STATUS", POSITIVE)
    require(status == "204", "Profile Stats Spotlight dispatch must record exact HTTP 204 acceptance")
    target = env_value(env, "DISPATCH_WORKFLOW_PATH")
    target_ref = env_value(env, "DISPATCH_REF")
    require(target == SPOTLIGHT_PATH and target_ref == "main",
            "Profile Stats Spotlight dispatch target changed")
    return {
        "effects": [{
            "ordinal": 1,
            "job": "dispatch",
            "kind": "spotlight-workflow-dispatch",
            "outcome": "applied",
            "target": {"workflowPath": target, "ref": target_ref},
            "observation": {"acceptedStatus": 204},
        }]
    }


def self_test() -> None:
    base = "a" * 40
    env = {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_WORKFLOW_SHA": base,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "2",
        "LEASE_BASE_SHA": base,
        "DISPATCH_ACCEPTED_STATUS": "204",
        "DISPATCH_WORKFLOW_PATH": SPOTLIGHT_PATH,
        "DISPATCH_REF": "main",
    }
    state = build_state(dict(env))
    require(state["effects"][0]["observation"]["acceptedStatus"] == 204,
            "Profile Stats decision receipt self-test lost exact dispatch status")

    wrong_status = dict(env)
    wrong_status["DISPATCH_ACCEPTED_STATUS"] = "200"
    try:
        build_state(wrong_status)
    except ValueError as exc:
        require("HTTP 204" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted wrong dispatch status")

    wrong_target = dict(env)
    wrong_target["DISPATCH_WORKFLOW_PATH"] = ".github/workflows/profile-quality.yml"
    try:
        build_state(wrong_target)
    except ValueError as exc:
        require("target changed" in str(exc), f"Profile Stats decision receipt failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats decision receipt accepted wrong workflow target")
