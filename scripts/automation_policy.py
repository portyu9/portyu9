#!/usr/bin/env python3
"""Lease/receipt/MAC/decision-receipt-aware loader for the Automation Policy IR.

The pre-lease loader is retained byte-for-byte in automation_policy_core.py. This
wrapper projects only the item-8 lease, item-9 publication-receipt, item-10 Spotlight
merge-authorization, and item-11 decision-receipt pointer extensions out for the frozen
legacy checks, then validates the complete current graph and compiles it against workflow
source. Existing consumers continue importing this module as the canonical policy.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any

import automation_concurrency
import automation_decision_receipts
import automation_leases
import automation_policy_core as core
from automation_policy_core import *  # noqa: F401,F403 - preserve the established public helper surface.

ROOT = core.ROOT
POLICY_PATH = core.POLICY_PATH
LEASE_WORKFLOWS = automation_leases.LEASE_WORKFLOWS
RECEIPT_JOBS = ("receipt", "receipt_attest")
MAC_JOBS = ("authorize", "authorize_attest")
DECISION_RECEIPT_CONTRACT = ".github/automation-decision-receipts-v1.json"

# Dependencies introduced only by items 8-11 are projected away for the byte-frozen
# legacy validator.
LEGACY_NEEDS = {
    "profile-stats": {
        "generate": [],
        "attest": ["generate"],
        "attest_publish": ["attest"],
        "stage": ["generate", "attest", "attest_publish"],
        "publish": ["stage"],
        "dispatch": ["publish"],
    },
    "spotlight-link-sync": {
        "plan": [],
        "reconcile": ["plan"],
        "budget": ["plan"],
        "quarantine": ["plan", "budget"],
        "propose": ["plan", "reconcile", "budget"],
        "approve": ["plan", "reconcile", "budget", "propose"],
        "merge": ["plan", "reconcile", "budget", "propose", "approve"],
    },
}

PROFILE_LEGACY_TRANSITIONS = [
    {"from": "idle", "to": "proposed", "phase": "propose", "jobs": ["generate"]},
    {"from": "proposed", "to": "no-change", "phase": "terminalize", "jobs": ["attest"]},
    {"from": "proposed", "to": "approved", "phase": "approve", "jobs": ["attest", "attest_publish", "stage"]},
    {"from": "approved", "to": "no-change", "phase": "terminalize", "jobs": ["stage"]},
    {"from": "approved", "to": "mutated", "phase": "mutate", "jobs": ["publish"]},
    {"from": "mutated", "to": "verified", "phase": "verify", "jobs": ["publish"]},
    {"from": "verified", "to": "completed", "phase": "terminalize", "jobs": ["dispatch"]},
]


def project_legacy_policy(payload: dict[str, Any]) -> dict[str, Any]:
    """Remove exactly the lease/receipt/MAC/decision-receipt extensions."""
    projected = copy.deepcopy(payload)
    require(projected.get("decisionReceiptContract") == DECISION_RECEIPT_CONTRACT,
            "automation policy decision receipt contract pointer changed")
    del projected["decisionReceiptContract"]
    for workflow_id in sorted(LEASE_WORKFLOWS):
        workflow = projected["workflows"][workflow_id]
        lease_job = workflow["lease"]["job"]
        del workflow["lease"]
        require(lease_job in workflow["jobs"],
                f"automation policy lease projection cannot find mint job: {workflow_id}/{lease_job}")
        del workflow["jobs"][lease_job]
        for class_spec in workflow["concurrency"].values():
            class_spec["jobs"] = [job_id for job_id in class_spec["jobs"] if job_id != lease_job]

        extension_jobs: tuple[str, ...] = ()
        if workflow_id == "profile-stats":
            extension_jobs = RECEIPT_JOBS
        elif workflow_id == "spotlight-link-sync":
            extension_jobs = MAC_JOBS
        for job_id in extension_jobs:
            require(job_id in workflow["jobs"],
                    f"automation policy extension projection cannot find job: {workflow_id}/{job_id}")
            del workflow["jobs"][job_id]
            for class_spec in workflow["concurrency"].values():
                class_spec["jobs"] = [member for member in class_spec["jobs"] if member != job_id]

        require(set(workflow["jobs"]) == set(LEGACY_NEEDS[workflow_id]),
                f"automation policy extension projection legacy job inventory changed: {workflow_id}")
        for job_id, needs in LEGACY_NEEDS[workflow_id].items():
            workflow["jobs"][job_id]["needs"] = list(needs)

        if workflow_id == "profile-stats":
            projected["transactionMachines"][workflow_id]["transitions"] = copy.deepcopy(PROFILE_LEGACY_TRANSITIONS)
        else:
            for transition in projected["transactionMachines"][workflow_id]["transitions"]:
                transition["jobs"] = [
                    job_id for job_id in transition["jobs"]
                    if job_id != lease_job and job_id not in MAC_JOBS
                ]
                require(transition["jobs"],
                        f"automation policy extension projection emptied transaction transition: {workflow_id}")
    return projected


def _validate_full_workflow_extensions(policy: dict[str, Any]) -> None:
    require(policy.get("decisionReceiptContract") == DECISION_RECEIPT_CONTRACT,
            "automation policy decision receipt contract pointer changed")
    global_groups: set[str] = set()
    for workflow_id, workflow in policy["workflows"].items():
        if workflow_id not in LEASE_WORKFLOWS:
            continue
        exact_keys(
            workflow,
            {"path", "triggers", "permissions", "concurrency", "lease", "jobs"},
            f"automation policy workflow {workflow_id}",
        )
        jobs = workflow["jobs"]
        lease_job_id = workflow["lease"]["job"]
        require(lease_job_id in jobs, f"automation policy workflow {workflow_id} lease job is missing")
        lease_job = exact_keys(
            jobs[lease_job_id],
            {"name", "needs", "permissions"},
            f"automation policy workflow {workflow_id} job {lease_job_id}",
        )
        require(lease_job["name"] == "mint-mutation-lease-read-only",
                f"automation policy workflow {workflow_id} lease job name changed")
        string_list(lease_job["needs"],
                    f"automation policy workflow {workflow_id} job {lease_job_id} needs")
        validate_permissions(lease_job["permissions"],
                             f"automation policy workflow {workflow_id} job {lease_job_id}")
        validate_job_graph(workflow_id, jobs)
        validate_concurrency_policy(workflow_id, workflow["concurrency"], jobs, global_groups)

        if workflow_id == "profile-stats":
            require(jobs["receipt"] == {
                "name": "prepare-publication-receipt-read-only",
                "needs": ["publish", "stage", "lease", "attest"],
                "permissions": {"contents": "read"},
            }, "automation policy Profile Stats receipt preparer authority changed")
            require(jobs["receipt_attest"] == {
                "name": "attest-publication-receipt-write-only",
                "needs": ["receipt", "lease", "attest"],
                "permissions": {"contents": "read", "id-token": "write", "attestations": "write"},
            }, "automation policy Profile Stats receipt signer authority changed")
            require(jobs["dispatch"]["needs"] == ["receipt_attest", "lease", "attest"],
                    "automation policy dispatch must remain downstream of publication receipt attestation")
        else:
            require(jobs["authorize"] == {
                "name": "prepare-merge-authorization-read-only",
                "needs": ["plan", "lease", "reconcile", "budget", "propose", "approve"],
                "permissions": {
                    "contents": "read", "pull-requests": "read", "checks": "read", "actions": "read"
                },
            }, "automation policy Spotlight merge authorization preparer authority changed")
            require(jobs["authorize_attest"] == {
                "name": "attest-merge-authorization-write-only",
                "needs": ["authorize", "lease", "plan", "propose", "approve"],
                "permissions": {"contents": "read", "id-token": "write", "attestations": "write"},
            }, "automation policy Spotlight merge authorization signer authority changed")
            require(jobs["merge"]["needs"] == [
                "plan", "lease", "reconcile", "budget", "propose", "approve", "authorize", "authorize_attest"
            ], "automation policy Spotlight merge must remain downstream of attested merge authorization")

        automation_leases.validate_policy(workflow_id, workflow)

    machines = policy["transactionMachines"]
    require(set(machines) == LEASE_WORKFLOWS,
            f"automation policy lease transaction workflow set changed: {sorted(machines)}")
    for workflow_id in sorted(LEASE_WORKFLOWS):
        validate_transaction_machine(workflow_id, machines[workflow_id], policy["workflows"])


def validate_policy(payload: Any) -> dict[str, Any]:
    require(isinstance(payload, dict), "automation policy root must be an object")
    require(payload.get("decisionReceiptContract") == DECISION_RECEIPT_CONTRACT,
            "automation policy decision receipt contract pointer changed")
    require(set(payload.get("workflows", {})) >= LEASE_WORKFLOWS,
            "automation policy lease workflows are missing")
    for workflow_id in sorted(LEASE_WORKFLOWS):
        workflow = payload["workflows"][workflow_id]
        exact_keys(
            workflow,
            {"path", "triggers", "permissions", "concurrency", "lease", "jobs"},
            f"automation policy workflow {workflow_id}",
        )

    core.validate_policy(project_legacy_policy(payload))
    _validate_full_workflow_extensions(payload)
    return payload


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"automation policy is missing or aliased: {path}")
    try:
        payload = strict_json_loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"automation policy JSON is invalid: {exc}") from exc
    policy = validate_policy(payload)
    if path == POLICY_PATH:
        automation_concurrency.validate(policy, ROOT)
        automation_leases.validate_source(policy, ROOT)
        decision_contract = automation_decision_receipts.strict_json(
            ROOT / policy["decisionReceiptContract"]
        )
        automation_decision_receipts.validate(policy, decision_contract)
        automation_decision_receipts.self_test(policy, decision_contract)
    return policy


def workflow_by_path(policy: dict[str, Any], path: str) -> tuple[str, dict[str, Any]]:
    matches = [(workflow_id, workflow) for workflow_id, workflow in policy["workflows"].items()
               if workflow["path"] == path]
    require(len(matches) == 1, f"automation policy must contain exactly one workflow for path: {path}")
    return matches[0]


def expect_policy_failure(payload: dict[str, Any], expected: str) -> None:
    try:
        validate_policy(payload)
    except (KeyError, ValueError) as exc:
        require(expected in str(exc), f"automation policy extension self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"automation policy extension self-test accepted forbidden drift: {expected}")


def _run_frozen_core_self_tests(projected: dict[str, Any]) -> None:
    original = core.automation_concurrency.self_test
    core.automation_concurrency.self_test = lambda *_args, **_kwargs: None
    try:
        core.self_test(projected)
    finally:
        core.automation_concurrency.self_test = original


def self_test(policy: dict[str, Any]) -> None:
    validate_policy(copy.deepcopy(policy))
    projected = project_legacy_policy(policy)
    _run_frozen_core_self_tests(projected)
    automation_concurrency.self_test(policy, ROOT)
    automation_leases.self_test(policy, ROOT)

    missing_receipt_contract = copy.deepcopy(policy)
    del missing_receipt_contract["decisionReceiptContract"]
    expect_policy_failure(missing_receipt_contract, "decision receipt contract pointer changed")

    wrong_receipt_contract = copy.deepcopy(policy)
    wrong_receipt_contract["decisionReceiptContract"] = ".github/unreviewed.json"
    expect_policy_failure(wrong_receipt_contract, "decision receipt contract pointer changed")

    missing_lease = copy.deepcopy(policy)
    del missing_lease["workflows"]["profile-stats"]["lease"]
    expect_policy_failure(missing_lease, "workflow profile-stats keys changed")

    unbound_writer = copy.deepcopy(policy)
    unbound_writer["workflows"]["spotlight-link-sync"]["lease"]["boundJobs"].remove("merge")
    del unbound_writer["workflows"]["spotlight-link-sync"]["lease"]["minimumRemainingSeconds"]["merge"]
    expect_policy_failure(unbound_writer, "complete write-capable job set")

    lease_write = copy.deepcopy(policy)
    lease_write["workflows"]["profile-stats"]["jobs"]["lease"]["permissions"] = {"actions": "write"}
    expect_policy_failure(lease_write, "only Actions-read authority")

    receipt_write = copy.deepcopy(policy)
    receipt_write["workflows"]["profile-stats"]["jobs"]["receipt"]["permissions"] = {"contents": "write"}
    expect_policy_failure(receipt_write, "receipt preparer authority changed")

    dispatch_bypass = copy.deepcopy(policy)
    dispatch_bypass["workflows"]["profile-stats"]["jobs"]["dispatch"]["needs"] = ["publish", "lease", "attest"]
    expect_policy_failure(dispatch_bypass, "downstream of publication receipt attestation")

    mac_preparer_write = copy.deepcopy(policy)
    mac_preparer_write["workflows"]["spotlight-link-sync"]["jobs"]["authorize"]["permissions"] = {
        "contents": "write"
    }
    expect_policy_failure(mac_preparer_write, "merge authorization preparer authority changed")

    mac_signer_mutation = copy.deepcopy(policy)
    mac_signer_mutation["workflows"]["spotlight-link-sync"]["jobs"]["authorize_attest"]["permissions"][
        "actions"
    ] = "write"
    expect_policy_failure(mac_signer_mutation, "merge authorization signer authority changed")

    mac_bypass = copy.deepcopy(policy)
    mac_bypass["workflows"]["spotlight-link-sync"]["jobs"]["merge"]["needs"].remove("authorize_attest")
    expect_policy_failure(mac_bypass, "downstream of attested merge authorization")


def main() -> int:
    try:
        policy = load_policy()
        self_test(policy)
        lease_jobs = sum(1 for workflow_id in LEASE_WORKFLOWS if policy["workflows"][workflow_id]["lease"]["job"])
        bound_jobs = sum(len(policy["workflows"][workflow_id]["lease"]["boundJobs"])
                         for workflow_id in LEASE_WORKFLOWS)
        print(
            f"Automation Policy IR passed: {policy['policyId']} · {len(policy['workflows'])} workflows · "
            f"{sum(len(workflow['jobs']) for workflow in policy['workflows'].values())} jobs · "
            f"{len(policy['transactionMachines'])} finite-state transactions · "
            f"{lease_jobs} short-lived mutation leases · {bound_jobs} lease-bound mutation jobs · "
            "one post-publication generated-commit receipt boundary · "
            "one attested Spotlight merge-authorization boundary · "
            "one source-bound append-only decision-receipt coverage contract · "
            f"{len(policy['requiredChecks'])} protected required-check bindings"
        )
        return 0
    except (OSError, KeyError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
