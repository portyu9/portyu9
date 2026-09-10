#!/usr/bin/env python3
"""Strict read-only loader for the repository Automation Policy IR."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / ".github" / "automation-policy-v1.json"
POLICY_ID = "automation-policy-v1"
REPOSITORY = "portyu9/portyu9"
PERMISSION_VALUES = {"read", "write", "none"}
JOB_ID = re.compile(r"^[A-Za-z0-9_-]+$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_int(value: Any, *, minimum: int | None = None) -> bool:
    return type(value) is int and (minimum is None or value >= minimum)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"automation policy contains duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=unique_object)


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    observed = set(value)
    require(observed == expected,
            f"{label} keys changed: expected={sorted(expected)} observed={sorted(observed)}")
    return value


def string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{label} must be an array")
    require(allow_empty or value, f"{label} must not be empty")
    require(all(isinstance(item, str) and item for item in value), f"{label} must contain non-empty strings")
    require(len(value) == len(set(value)), f"{label} must not contain duplicates")
    return value


def validate_permissions(value: Any, label: str) -> dict[str, str]:
    require(isinstance(value, dict) and value, f"{label} permissions must be a non-empty object")
    for key, permission in value.items():
        require(isinstance(key, str) and JOB_ID.fullmatch(key.replace("-", "_")) is not None,
                f"{label} contains an invalid permission key: {key!r}")
        require(permission in PERMISSION_VALUES,
                f"{label} contains an unsupported permission value for {key}: {permission!r}")
    return value


def validate_job_graph(workflow_id: str, jobs: dict[str, Any]) -> None:
    colors: dict[str, int] = {job_id: 0 for job_id in jobs}

    def visit(job_id: str) -> None:
        color = colors[job_id]
        require(color != 1, f"automation policy workflow {workflow_id} contains a needs cycle at {job_id}")
        if color == 2:
            return
        colors[job_id] = 1
        for dependency in jobs[job_id]["needs"]:
            require(dependency in jobs,
                    f"automation policy workflow {workflow_id} job {job_id} needs unknown job {dependency}")
            require(dependency != job_id,
                    f"automation policy workflow {workflow_id} job {job_id} cannot need itself")
            visit(dependency)
        colors[job_id] = 2

    for job_id in jobs:
        visit(job_id)


def validate_policy(payload: Any) -> dict[str, Any]:
    root = exact_keys(
        payload,
        {"schemaVersion", "policyId", "repository", "branches", "githubActionsAppId", "rulesetContract", "workflows", "requiredChecks"},
        "automation policy root",
    )
    require(exact_int(root["schemaVersion"]) and root["schemaVersion"] == 1,
            "automation policy schemaVersion must be exact integer 1")
    require(root["policyId"] == POLICY_ID, f"automation policy id changed: {root['policyId']!r}")
    require(root["repository"] == REPOSITORY, f"automation policy repository changed: {root['repository']!r}")
    require(exact_int(root["githubActionsAppId"], minimum=1),
            "automation policy githubActionsAppId must be a positive integer")
    require(
        isinstance(root["rulesetContract"], str)
        and root["rulesetContract"].startswith(".github/rulesets/")
        and root["rulesetContract"].endswith(".json")
        and ".." not in root["rulesetContract"].split("/"),
        "automation policy rulesetContract path is invalid",
    )

    branches = exact_keys(root["branches"], {"main", "generated", "spotlightBot"}, "automation policy branches")
    require(all(isinstance(value, str) and value for value in branches.values()),
            "automation policy branch identities must be non-empty strings")
    require(len(set(branches.values())) == len(branches), "automation policy branch identities must be distinct")

    workflows = root["workflows"]
    require(isinstance(workflows, dict) and workflows, "automation policy workflows must be a non-empty object")
    paths: set[str] = set()
    for workflow_id, workflow_value in workflows.items():
        require(isinstance(workflow_id, str) and JOB_ID.fullmatch(workflow_id) is not None,
                f"automation policy workflow id is invalid: {workflow_id!r}")
        workflow = exact_keys(workflow_value, {"path", "triggers", "permissions", "jobs"},
                              f"automation policy workflow {workflow_id}")
        path = workflow["path"]
        require(
            isinstance(path, str)
            and path.startswith(".github/workflows/")
            and (path.endswith(".yml") or path.endswith(".yaml"))
            and ".." not in path.split("/"),
            f"automation policy workflow {workflow_id} path is invalid",
        )
        require(path not in paths, f"automation policy workflow path is duplicated: {path}")
        paths.add(path)

        triggers = string_list(workflow["triggers"], f"automation policy workflow {workflow_id} triggers")
        require(triggers == sorted(triggers),
                f"automation policy workflow {workflow_id} triggers must be canonically sorted")
        validate_permissions(workflow["permissions"], f"automation policy workflow {workflow_id}")

        jobs = workflow["jobs"]
        require(isinstance(jobs, dict) and jobs, f"automation policy workflow {workflow_id} jobs must be a non-empty object")
        for job_id, job_value in jobs.items():
            require(isinstance(job_id, str) and JOB_ID.fullmatch(job_id) is not None,
                    f"automation policy workflow {workflow_id} job id is invalid: {job_id!r}")
            job = exact_keys(job_value, {"name", "needs", "permissions"},
                             f"automation policy workflow {workflow_id} job {job_id}")
            require(isinstance(job["name"], str) and job["name"].strip() == job["name"] and job["name"],
                    f"automation policy workflow {workflow_id} job {job_id} name is invalid")
            string_list(job["needs"], f"automation policy workflow {workflow_id} job {job_id} needs", allow_empty=True)
            validate_permissions(job["permissions"], f"automation policy workflow {workflow_id} job {job_id}")
        validate_job_graph(workflow_id, jobs)

    checks = root["requiredChecks"]
    require(isinstance(checks, list) and checks, "automation policy requiredChecks must be a non-empty array")
    contexts: set[str] = set()
    bindings: set[tuple[str, str, str]] = set()
    for index, check_value in enumerate(checks):
        check = exact_keys(check_value, {"context", "workflow", "job"},
                           f"automation policy requiredChecks[{index}]")
        context = check["context"]
        workflow_id = check["workflow"]
        job_id = check["job"]
        require(isinstance(context, str) and context,
                f"automation policy requiredChecks[{index}] context is invalid")
        require(context not in contexts, f"automation policy required check context is duplicated: {context}")
        contexts.add(context)
        require(isinstance(workflow_id, str) and workflow_id in workflows,
                f"automation policy required check {context} references unknown workflow: {workflow_id!r}")
        jobs = workflows[workflow_id]["jobs"]
        require(isinstance(job_id, str) and job_id in jobs,
                f"automation policy required check {context} references unknown job: {job_id!r}")
        binding = (context, workflow_id, job_id)
        require(binding not in bindings, f"automation policy required check binding is duplicated: {binding!r}")
        bindings.add(binding)

    return root


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"automation policy is missing or aliased: {path}")
    try:
        payload = strict_json_loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"automation policy JSON is invalid: {exc}") from exc
    return validate_policy(payload)


def workflow_by_path(policy: dict[str, Any], path: str) -> tuple[str, dict[str, Any]]:
    matches = [(workflow_id, workflow) for workflow_id, workflow in policy["workflows"].items() if workflow["path"] == path]
    require(len(matches) == 1, f"automation policy must contain exactly one workflow for path: {path}")
    return matches[0]


def self_test(policy: dict[str, Any]) -> None:
    validate_policy(copy.deepcopy(policy))
    try:
        strict_json_loads('{"schemaVersion":1,"schemaVersion":1}')
    except ValueError as exc:
        require("duplicate JSON key" in str(exc), f"automation policy duplicate-key self-test failed: {exc}")
    else:
        raise ValueError("automation policy duplicate-key self-test accepted ambiguous JSON")

    unknown = copy.deepcopy(policy)
    unknown["unreviewed"] = True
    try:
        validate_policy(unknown)
    except ValueError as exc:
        require("root keys changed" in str(exc), f"automation policy unknown-key self-test failed: {exc}")
    else:
        raise ValueError("automation policy unknown-key self-test accepted authority drift")

    wrong_type = copy.deepcopy(policy)
    wrong_type["githubActionsAppId"] = True
    try:
        validate_policy(wrong_type)
    except ValueError as exc:
        require("positive integer" in str(exc), f"automation policy integer-identity self-test failed: {exc}")
    else:
        raise ValueError("automation policy integer-identity self-test accepted boolean coercion")

    first_workflow_id = next(iter(policy["workflows"]))
    first_job_id = next(iter(policy["workflows"][first_workflow_id]["jobs"]))
    dangling = copy.deepcopy(policy)
    dangling["workflows"][first_workflow_id]["jobs"][first_job_id]["needs"] = ["missing-job"]
    try:
        validate_policy(dangling)
    except ValueError as exc:
        require("needs unknown job" in str(exc), f"automation policy dangling-edge self-test failed: {exc}")
    else:
        raise ValueError("automation policy dangling-edge self-test accepted unknown dependency")

    cycle_workflow_id = "profile-stats"
    cycle = copy.deepcopy(policy)
    cycle["workflows"][cycle_workflow_id]["jobs"]["generate"]["needs"] = ["dispatch"]
    try:
        validate_policy(cycle)
    except ValueError as exc:
        require("needs cycle" in str(exc), f"automation policy cycle self-test failed: {exc}")
    else:
        raise ValueError("automation policy cycle self-test accepted cyclic authority graph")
