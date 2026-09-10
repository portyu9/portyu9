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
STATE_ID = re.compile(r"^[a-z][a-z0-9-]*$")
TRANSACTION_PHASES = ("propose", "approve", "mutate", "verify", "terminalize")
TRANSACTION_WORKFLOWS = {"profile-stats", "spotlight-link-sync"}


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


def validate_transaction_machine(workflow_id: str, value: Any, workflows: dict[str, Any]) -> None:
    label = f"automation policy transaction machine {workflow_id}"
    require(workflow_id in workflows, f"{label} references unknown workflow")
    machine = exact_keys(value, {"initialState", "states", "terminalStates", "transitions"}, label)

    states = string_list(machine["states"], f"{label} states")
    require(all(STATE_ID.fullmatch(state) is not None for state in states),
            f"{label} contains an invalid state identity")
    initial = machine["initialState"]
    require(isinstance(initial, str) and initial in states, f"{label} initialState must reference a declared state")
    terminals = string_list(machine["terminalStates"], f"{label} terminalStates")
    require(set(terminals) <= set(states), f"{label} terminalStates must reference declared states")
    require(initial not in terminals, f"{label} initialState cannot be terminal")

    transitions = machine["transitions"]
    require(isinstance(transitions, list) and transitions, f"{label} transitions must be a non-empty array")
    outgoing: dict[str, list[tuple[str, int]]] = {state: [] for state in states}
    incoming: dict[str, list[tuple[str, int]]] = {state: [] for state in states}
    covered_jobs: set[str] = set()
    observed_phases: set[str] = set()
    identities: set[tuple[str, str, str, tuple[str, ...]]] = set()
    phase_rank = {phase: rank for rank, phase in enumerate(TRANSACTION_PHASES)}
    workflow_jobs = workflows[workflow_id]["jobs"]
    job_phase_ranks: dict[str, set[int]] = {job_id: set() for job_id in workflow_jobs}

    for index, transition_value in enumerate(transitions):
        transition_label = f"{label} transitions[{index}]"
        transition = exact_keys(transition_value, {"from", "to", "phase", "jobs"}, transition_label)
        source = transition["from"]
        target = transition["to"]
        phase = transition["phase"]
        require(isinstance(source, str) and source in states,
                f"{transition_label} from references unknown state")
        require(isinstance(target, str) and target in states,
                f"{transition_label} to references unknown state")
        require(source != target, f"{transition_label} cannot self-loop")
        require(phase in TRANSACTION_PHASES, f"{transition_label} has unsupported lifecycle phase: {phase!r}")
        jobs = string_list(transition["jobs"], f"{transition_label} jobs")
        for job_id in jobs:
            require(job_id in workflow_jobs, f"{transition_label} references unknown workflow job: {job_id}")
        identity = (source, target, phase, tuple(jobs))
        require(identity not in identities, f"{label} contains a duplicate transition: {identity!r}")
        identities.add(identity)
        rank = phase_rank[phase]
        outgoing[source].append((target, rank))
        incoming[target].append((source, rank))
        covered_jobs.update(jobs)
        observed_phases.add(phase)
        for job_id in jobs:
            job_phase_ranks[job_id].add(rank)

        if phase == "mutate":
            require(any("write" in workflow_jobs[job_id]["permissions"].values() for job_id in jobs),
                    f"{transition_label} mutate phase must contain a write-capable job")
        if phase == "terminalize":
            require(target in terminals, f"{transition_label} terminalize must enter a terminal state")
        else:
            require(target not in terminals,
                    f"{transition_label} nonterminal phase cannot enter a terminal state")

    require(observed_phases == set(TRANSACTION_PHASES),
            f"{label} lifecycle phases changed: expected={list(TRANSACTION_PHASES)} observed={sorted(observed_phases)}")
    require(covered_jobs == set(workflow_jobs),
            f"{label} job closure changed: expected={sorted(workflow_jobs)} observed={sorted(covered_jobs)}")
    require(outgoing[initial] and all(rank == phase_rank["propose"] for _, rank in outgoing[initial]),
            f"{label} initial transitions must be propose phase")

    # The earliest phase assigned to a dependent job may never precede the
    # earliest phase assigned to one of its declared workflow dependencies.
    for job_id, job in workflow_jobs.items():
        for dependency in job["needs"]:
            require(min(job_phase_ranks[job_id]) >= min(job_phase_ranks[dependency]),
                    f"{label} job dependency phase regresses: {dependency} -> {job_id}")

    for terminal in terminals:
        require(not outgoing[terminal], f"{label} terminal state has outgoing transitions: {terminal}")
    for state in states:
        if state not in terminals:
            require(outgoing[state], f"{label} reachable nonterminal state cannot be a dead end: {state}")

    # Phase progression is monotonic on every path. Terminal side paths may jump
    # directly to terminalize, but no later edge may regress lifecycle authority.
    for state in states:
        if state == initial or state in terminals:
            continue
        for _, inbound_rank in incoming[state]:
            for _, outbound_rank in outgoing[state]:
                require(outbound_rank >= inbound_rank,
                        f"{label} lifecycle phase regresses through state: {state}")

    # Every state must be reachable from the initial state.
    reachable: set[str] = set()
    stack = [initial]
    while stack:
        state = stack.pop()
        if state in reachable:
            continue
        reachable.add(state)
        stack.extend(target for target, _ in outgoing[state])
    require(reachable == set(states),
            f"{label} contains unreachable states: {sorted(set(states) - reachable)}")

    # The transaction graph must be acyclic. Combined with nonterminal
    # out-degree and terminal absorption, this proves every path terminates.
    colors: dict[str, int] = {state: 0 for state in states}

    def visit(state: str) -> None:
        require(colors[state] != 1, f"{label} contains a nonterminal transaction cycle at {state}")
        if colors[state] == 2:
            return
        colors[state] = 1
        for target, _ in outgoing[state]:
            visit(target)
        colors[state] = 2

    visit(initial)

    # Independently prove every reachable nonterminal has a path to a terminal.
    convergent = set(terminals)
    changed = True
    while changed:
        changed = False
        for state in states:
            if state not in convergent and any(target in convergent for target, _ in outgoing[state]):
                convergent.add(state)
                changed = True
    require(convergent == set(states),
            f"{label} contains states without terminal convergence: {sorted(set(states) - convergent)}")


def validate_policy(payload: Any) -> dict[str, Any]:
    root = exact_keys(
        payload,
        {"schemaVersion", "policyId", "repository", "branches", "githubActionsAppId", "rulesetContract",
         "workflows", "transactionMachines", "requiredChecks"},
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

    branches = exact_keys(
        root["branches"],
        {"main", "generated", "spotlightCandidatePrefix"},
        "automation policy branches",
    )
    require(all(isinstance(value, str) and value for value in branches.values()),
            "automation policy branch identities must be non-empty strings")
    main_branch = branches["main"]
    generated_branch = branches["generated"]
    candidate_prefix = branches["spotlightCandidatePrefix"]
    require(main_branch != generated_branch, "automation policy mutable branch identities must be distinct")
    require(
        candidate_prefix.startswith("automation/")
        and candidate_prefix.endswith("/")
        and not candidate_prefix.startswith("refs/")
        and ".." not in candidate_prefix.split("/")
        and "//" not in candidate_prefix,
        "automation policy Spotlight candidate prefix is invalid",
    )
    require(not main_branch.startswith(candidate_prefix) and not generated_branch.startswith(candidate_prefix),
            "automation policy Spotlight candidate prefix overlaps a mutable branch identity")

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
        require(isinstance(jobs, dict) and jobs,
                f"automation policy workflow {workflow_id} jobs must be a non-empty object")
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

    machines = root["transactionMachines"]
    require(isinstance(machines, dict) and machines,
            "automation policy transactionMachines must be a non-empty object")
    require(set(machines) == TRANSACTION_WORKFLOWS,
            f"automation policy transaction workflow set changed: expected={sorted(TRANSACTION_WORKFLOWS)} "
            f"observed={sorted(machines)}")
    for workflow_id, machine in machines.items():
        validate_transaction_machine(workflow_id, machine, workflows)

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
    matches = [(workflow_id, workflow) for workflow_id, workflow in policy["workflows"].items()
               if workflow["path"] == path]
    require(len(matches) == 1, f"automation policy must contain exactly one workflow for path: {path}")
    return matches[0]


def expect_policy_failure(payload: dict[str, Any], expected: str) -> None:
    try:
        validate_policy(payload)
    except ValueError as exc:
        require(expected in str(exc), f"automation policy self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"automation policy self-test accepted forbidden drift: {expected}")


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
    expect_policy_failure(unknown, "root keys changed")

    wrong_type = copy.deepcopy(policy)
    wrong_type["githubActionsAppId"] = True
    expect_policy_failure(wrong_type, "positive integer")

    invalid_candidate_prefix = copy.deepcopy(policy)
    invalid_candidate_prefix["branches"]["spotlightCandidatePrefix"] = "automation/spotlight-links"
    expect_policy_failure(invalid_candidate_prefix, "candidate prefix is invalid")

    mutable_candidate_branch = copy.deepcopy(policy)
    mutable_candidate_branch["branches"]["spotlightBot"] = mutable_candidate_branch["branches"].pop("spotlightCandidatePrefix")
    expect_policy_failure(mutable_candidate_branch, "branches keys changed")

    workflow_ids = list(policy["workflows"])
    require(len(workflow_ids) >= 2, "automation policy self-test requires at least two workflows")
    first_workflow_id, second_workflow_id = workflow_ids[:2]
    first_job_id = next(iter(policy["workflows"][first_workflow_id]["jobs"]))

    duplicate_path = copy.deepcopy(policy)
    duplicate_path["workflows"][second_workflow_id]["path"] = duplicate_path["workflows"][first_workflow_id]["path"]
    expect_policy_failure(duplicate_path, "workflow path is duplicated")

    duplicate_trigger = copy.deepcopy(policy)
    trigger = duplicate_trigger["workflows"][first_workflow_id]["triggers"][0]
    duplicate_trigger["workflows"][first_workflow_id]["triggers"].append(trigger)
    expect_policy_failure(duplicate_trigger, "triggers must not contain duplicates")

    dangling = copy.deepcopy(policy)
    dangling["workflows"][first_workflow_id]["jobs"][first_job_id]["needs"] = ["missing-job"]
    expect_policy_failure(dangling, "needs unknown job")

    duplicate_needs = copy.deepcopy(policy)
    duplicate_needs["workflows"]["profile-stats"]["jobs"]["stage"]["needs"].append("generate")
    expect_policy_failure(duplicate_needs, "needs must not contain duplicates")

    cycle = copy.deepcopy(policy)
    cycle["workflows"]["profile-stats"]["jobs"]["generate"]["needs"] = ["dispatch"]
    expect_policy_failure(cycle, "needs cycle")

    missing_machine = copy.deepcopy(policy)
    del missing_machine["transactionMachines"]["profile-stats"]
    expect_policy_failure(missing_machine, "transaction workflow set changed")

    missing_phase = copy.deepcopy(policy)
    missing_phase["transactionMachines"]["profile-stats"]["transitions"] = [
        transition for transition in missing_phase["transactionMachines"]["profile-stats"]["transitions"]
        if transition["phase"] != "verify"
    ]
    expect_policy_failure(missing_phase, "lifecycle phases changed")

    unknown_transaction_job = copy.deepcopy(policy)
    unknown_transaction_job["transactionMachines"]["spotlight-link-sync"]["transitions"][0]["jobs"] = ["missing-job"]
    expect_policy_failure(unknown_transaction_job, "references unknown workflow job")

    unmodeled_job = copy.deepcopy(policy)
    unmodeled_job["transactionMachines"]["spotlight-link-sync"]["transitions"] = [
        transition for transition in unmodeled_job["transactionMachines"]["spotlight-link-sync"]["transitions"]
        if "quarantine" not in transition["jobs"]
    ]
    expect_policy_failure(unmodeled_job, "job closure changed")

    read_only_mutation = copy.deepcopy(policy)
    for transition in read_only_mutation["transactionMachines"]["profile-stats"]["transitions"]:
        if transition["phase"] == "mutate":
            transition["jobs"] = ["stage"]
            break
    expect_policy_failure(read_only_mutation, "mutate phase must contain a write-capable job")

    dead_end = copy.deepcopy(policy)
    dead_end["transactionMachines"]["profile-stats"]["states"].append("stalled")
    dead_end["transactionMachines"]["profile-stats"]["transitions"].append(
        {"from": "proposed", "to": "stalled", "phase": "approve", "jobs": ["attest"]}
    )
    expect_policy_failure(dead_end, "reachable nonterminal state cannot be a dead end")

    unreachable = copy.deepcopy(policy)
    unreachable["transactionMachines"]["profile-stats"]["states"].append("orphaned")
    unreachable["transactionMachines"]["profile-stats"]["transitions"].append(
        {"from": "orphaned", "to": "completed", "phase": "terminalize", "jobs": ["dispatch"]}
    )
    expect_policy_failure(unreachable, "contains unreachable states")

    terminal_escape = copy.deepcopy(policy)
    terminal_escape["transactionMachines"]["profile-stats"]["transitions"].append(
        {"from": "completed", "to": "proposed", "phase": "approve", "jobs": ["attest"]}
    )
    expect_policy_failure(terminal_escape, "terminal state has outgoing transitions")

    phase_regression = copy.deepcopy(policy)
    phase_regression["transactionMachines"]["profile-stats"]["transitions"].append(
        {"from": "mutated", "to": "approved", "phase": "approve", "jobs": ["attest"]}
    )
    expect_policy_failure(phase_regression, "lifecycle phase regresses")

    transaction_cycle = copy.deepcopy(policy)
    transaction_cycle["transactionMachines"]["profile-stats"]["transitions"].append(
        {"from": "mutated", "to": "approved", "phase": "mutate", "jobs": ["publish"]}
    )
    expect_policy_failure(transaction_cycle, "nonterminal transaction cycle")

    duplicate_check = copy.deepcopy(policy)
    duplicate_check["requiredChecks"][1]["context"] = duplicate_check["requiredChecks"][0]["context"]
    expect_policy_failure(duplicate_check, "required check context is duplicated")

    invalid_workflow_check = copy.deepcopy(policy)
    invalid_workflow_check["requiredChecks"][0]["workflow"] = "missing-workflow"
    expect_policy_failure(invalid_workflow_check, "references unknown workflow")

    invalid_job_check = copy.deepcopy(policy)
    invalid_job_check["requiredChecks"][0]["job"] = "missing-job"
    expect_policy_failure(invalid_job_check, "references unknown job")


def main() -> int:
    policy = load_policy()
    self_test(policy)
    print(
        f"Automation Policy IR passed: {policy['policyId']} · {len(policy['workflows'])} workflows · "
        f"{sum(len(workflow['jobs']) for workflow in policy['workflows'].values())} jobs · "
        f"{len(policy['transactionMachines'])} finite-state transactions · "
        f"{len(policy['requiredChecks'])} protected required-check bindings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
