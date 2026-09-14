#!/usr/bin/env python3
"""Independently re-prove the exact downstream Spotlight run caused by Profile Stats dispatch."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

import profile_stats_decision_receipt as core

REPOSITORY = core.REPOSITORY
SPOTLIGHT_WORKFLOW_NAME = "spotlight-link-sync.yml"
POLL_ATTEMPTS = 30
POLL_SECONDS = 2


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


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


def downstream_identity(run: dict[str, Any]) -> dict[str, Any]:
    return {
        "workflowId": run.get("workflow_id"),
        "runId": run.get("id"),
        "runAttempt": run.get("run_attempt"),
        "checkSuiteId": run.get("check_suite_id"),
        "path": run.get("path"),
        "event": run.get("event"),
        "headBranch": run.get("head_branch"),
        "headSha": run.get("head_sha"),
        "actorLogin": run.get("actor", {}).get("login"),
        "actorId": run.get("actor", {}).get("id"),
        "triggeringActorLogin": run.get("triggering_actor", {}).get("login"),
        "triggeringActorId": run.get("triggering_actor", {}).get("id"),
        "repository": run.get("repository", {}).get("full_name"),
        "repositoryId": run.get("repository", {}).get("id"),
        "headRepository": run.get("head_repository", {}).get("full_name"),
        "headRepositoryId": run.get("head_repository", {}).get("id"),
    }


def complete_newer_window(payload: Any, high_water: int) -> list[dict[str, Any]]:
    require(isinstance(payload, dict), "Profile Stats downstream workflow-run response is malformed")
    runs = payload.get("workflow_runs")
    total = payload.get("total_count")
    require(isinstance(runs, list) and type(total) is int and total >= 0,
            "Profile Stats downstream workflow-run response shape changed")
    require(all(isinstance(run, dict) for run in runs),
            "Profile Stats downstream workflow-run response contains a malformed run")
    require(total >= len(runs),
            "Profile Stats downstream workflow-run response total is below returned run count")
    if high_water == 0:
        require(total == len(runs),
                "Profile Stats dispatch attribution cannot prove a complete first-run history")
    else:
        boundary = [run for run in runs if run.get("id") == high_water]
        require(len(boundary) == 1,
                "Profile Stats dispatch attribution high-water boundary is absent or ambiguous in the newest run page")
    return runs


def matching_runs(payload: Any, env: dict[str, str], workflow_id: int, high_water: int) -> list[dict[str, Any]]:
    runs = complete_newer_window(payload, high_water)
    repository_id = int(core.env_value(env, "GITHUB_REPOSITORY_ID", core.POSITIVE))
    base = core.env_value(env, "LEASE_BASE_SHA", core.SHA40)
    matches: list[dict[str, Any]] = []
    for run in runs:
        if run.get("id") is None or type(run.get("id")) is not int or run["id"] <= high_water:
            continue
        if not (
            run.get("workflow_id") == workflow_id
            and run.get("path") == core.SPOTLIGHT_PATH
            and run.get("event") == "workflow_dispatch"
            and run.get("head_branch") == "main"
            and run.get("head_sha") == base
            and run.get("actor", {}).get("login") == core.BOT_LOGIN
            and run.get("actor", {}).get("id") == core.BOT_ID
            and run.get("triggering_actor", {}).get("login") == core.BOT_LOGIN
            and run.get("triggering_actor", {}).get("id") == core.BOT_ID
            and run.get("repository", {}).get("full_name") == REPOSITORY
            and run.get("repository", {}).get("id") == repository_id
            and run.get("head_repository", {}).get("full_name") == REPOSITORY
            and run.get("head_repository", {}).get("id") == repository_id
        ):
            continue
        matches.append(run)
    return matches


def select_downstream_run(payload: Any, env: dict[str, str], workflow_id: int, high_water: int) -> dict[str, Any] | None:
    matches = matching_runs(payload, env, workflow_id, high_water)
    require(len(matches) <= 1,
            "Profile Stats dispatch attribution is ambiguous: multiple exact downstream Spotlight runs cross the high-water mark")
    if not matches:
        return None
    run = matches[0]
    identity = downstream_identity(run)
    core.exact_downstream_run(identity, env, high_water)
    return identity


def observe_downstream_run(env: dict[str, str]) -> dict[str, Any]:
    high_water = int(core.env_value(env, "DISPATCH_PREVIOUS_RUN_HIGH_WATER", core.NONNEGATIVE))
    workflow = gh_json(f"repos/{REPOSITORY}/actions/workflows/{SPOTLIGHT_WORKFLOW_NAME}")
    workflow_id = workflow.get("id") if isinstance(workflow, dict) else None
    require(type(workflow_id) is int and workflow_id > 0,
            "Profile Stats downstream Spotlight workflow identity response changed")
    require(workflow.get("path") == core.SPOTLIGHT_PATH,
            "Profile Stats downstream Spotlight workflow path changed")
    endpoint = (
        f"repos/{REPOSITORY}/actions/workflows/{SPOTLIGHT_WORKFLOW_NAME}/runs"
        "?event=workflow_dispatch&branch=main&per_page=100"
    )
    for attempt in range(1, POLL_ATTEMPTS + 1):
        identity = select_downstream_run(gh_json(endpoint), env, workflow_id, high_water)
        if identity is not None:
            return identity
        if attempt < POLL_ATTEMPTS:
            time.sleep(POLL_SECONDS)
    raise ValueError("Profile Stats dispatch produced no exact downstream Spotlight run inside the bounded observation window")


def self_test() -> None:
    core.self_test()
    env, downstream = core.fixture()
    workflow_id = downstream["workflowId"]
    high_water = int(env["DISPATCH_PREVIOUS_RUN_HIGH_WATER"])
    run = {
        "workflow_id": workflow_id,
        "id": downstream["runId"],
        "run_attempt": downstream["runAttempt"],
        "check_suite_id": downstream["checkSuiteId"],
        "path": downstream["path"],
        "event": downstream["event"],
        "head_branch": downstream["headBranch"],
        "head_sha": downstream["headSha"],
        "actor": {"login": downstream["actorLogin"], "id": downstream["actorId"]},
        "triggering_actor": {
            "login": downstream["triggeringActorLogin"], "id": downstream["triggeringActorId"]
        },
        "repository": {"full_name": downstream["repository"], "id": downstream["repositoryId"]},
        "head_repository": {
            "full_name": downstream["headRepository"], "id": downstream["headRepositoryId"]
        },
    }
    boundary = {**run, "id": high_water, "check_suite_id": downstream["checkSuiteId"] - 1}
    payload = {"total_count": 2, "workflow_runs": [run, boundary]}
    require(select_downstream_run(payload, dict(env), workflow_id, high_water) == downstream,
            "Profile Stats downstream-run selector rejected the exact causal fixture")

    ambiguous_run = {**run, "id": run["id"] + 1, "check_suite_id": run["check_suite_id"] + 1}
    ambiguous = {"total_count": 3, "workflow_runs": [ambiguous_run, run, boundary]}
    try:
        select_downstream_run(ambiguous, dict(env), workflow_id, high_water)
    except ValueError as exc:
        require("ambiguous" in str(exc), f"Profile Stats selector failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats downstream-run selector accepted ambiguous causal attribution")

    stale = {"total_count": 1, "workflow_runs": [boundary]}
    require(select_downstream_run(stale, dict(env), workflow_id, high_water) is None,
            "Profile Stats downstream-run selector accepted a pre-dispatch run")

    missing_boundary = {"total_count": 150, "workflow_runs": [run]}
    try:
        select_downstream_run(missing_boundary, dict(env), workflow_id, high_water)
    except ValueError as exc:
        require("high-water boundary" in str(exc), f"Profile Stats incomplete-history test failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats downstream-run selector accepted an incomplete newest-run page")

    first_history = dict(env)
    first_history["DISPATCH_PREVIOUS_RUN_HIGH_WATER"] = "0"
    first_payload = {"total_count": 1, "workflow_runs": [run]}
    first_identity = dict(downstream)
    require(select_downstream_run(first_payload, first_history, workflow_id, 0) == first_identity,
            "Profile Stats first downstream-run history was not accepted when complete")
    incomplete_first = {"total_count": 2, "workflow_runs": [run]}
    try:
        select_downstream_run(incomplete_first, first_history, workflow_id, 0)
    except ValueError as exc:
        require("complete first-run history" in str(exc), f"Profile Stats first-history test failed for wrong reason: {exc}")
    else:
        raise ValueError("Profile Stats downstream-run selector accepted incomplete history with zero high-water")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("Profile Stats Automation Decision Receipt preparer self-test passed")
            return 0
        core.require(args.output is not None, "output path is required outside --self-test")
        env = dict(os.environ)
        downstream = observe_downstream_run(env)
        state = core.build_state(env, downstream)
        args.output.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print(f"Profile Stats Automation Decision Receipt state independently re-proved: {args.output}")
        return 0
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
