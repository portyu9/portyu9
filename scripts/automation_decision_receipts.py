#!/usr/bin/env python3
"""Compile append-only decision-receipt coverage against the Automation Policy IR."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
from typing import Any

import automation_decision_receipt
import automation_decision_receipt_schema
import profile_stats_decision_receipt
import spotlight_decision_receipt

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / ".github/automation-decision-receipts-v1.json"
CONTRACT_RELATIVE_PATH = ".github/automation-decision-receipts-v1.json"
CONTRACT_ID = "automation-decision-receipts-v1"
REPOSITORY = "portyu9/portyu9"
LEASE_WORKFLOWS = {"profile-stats", "spotlight-link-sync"}
GENERIC_PREDICATE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "automation-decision-receipt-v1.schema.json"
)
MODES = {"self-attested", "specialized-attested-receipt", "generic-decision-receipt"}
WRITE_PERMISSIONS = {"actions", "attestations", "contents", "pull-requests", "security-events"}
EXPECTED_GENERIC_EFFECTS = {
    ("profile-stats", "dispatch"): ("spotlight-workflow-dispatch",),
    ("spotlight-link-sync", "reconcile"): ("stale-candidate-reconciliation",),
    ("spotlight-link-sync", "propose"): ("spotlight-candidate-publication",),
    ("spotlight-link-sync", "approve"): ("workflow-run-approval-request",),
    ("spotlight-link-sync", "merge"): ("spotlight-terminal-merge",),
}
EXPECTED_SELF_ATTESTED = {
    ("profile-stats", "attest_publish"): (
        "profile-evidence-attestation",
        "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v3.schema.json",
    ),
    ("profile-stats", "receipt_attest"): (
        "generated-publication-receipt-attestation",
        "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/generated-publication-receipt-v1.schema.json",
    ),
    ("spotlight-link-sync", "authorize_attest"): (
        "spotlight-merge-authorization-attestation",
        "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/spotlight-merge-authorization-v1.schema.json",
    ),
}
EXPECTED_SPECIALIZED = {
    ("profile-stats", "publish"): (
        "generated-publication",
        "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/generated-publication-receipt-v1.schema.json",
    ),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"decision-receipt coverage JSON contains duplicate key: {key}")
        result[key] = value
    return result


def strict_json(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"decision-receipt coverage contract is missing or aliased: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"decision-receipt coverage contract is invalid JSON: {exc}") from exc
    require(isinstance(value, dict), "decision-receipt coverage root must be an object")
    return value


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == expected, f"{label} keys changed: {sorted(value)}")
    return value


def string_list(value: Any, label: str) -> tuple[str, ...]:
    require(isinstance(value, list) and value, f"{label} must be a non-empty list")
    require(all(isinstance(item, str) and item for item in value), f"{label} entries must be non-empty strings")
    require(len(value) == len(set(value)), f"{label} entries must be unique")
    return tuple(value)


def write_capabilities(permissions: dict[str, str]) -> set[str]:
    return {name for name, level in permissions.items() if level == "write" and name in WRITE_PERMISSIONS}


def validate(policy: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    require(policy.get("decisionReceiptContract") == CONTRACT_RELATIVE_PATH,
            "Automation Policy IR decision receipt contract pointer differs from coverage contract")
    root = exact_keys(
        contract,
        {"schemaVersion", "contractId", "repository", "genericPredicateType", "workflows"},
        "decision-receipt coverage root",
    )
    require(root["schemaVersion"] == 1, "decision-receipt coverage schema version changed")
    require(root["contractId"] == CONTRACT_ID, "decision-receipt coverage contract identity changed")
    require(root["repository"] == REPOSITORY, "decision-receipt coverage repository identity changed")
    require(root["genericPredicateType"] == GENERIC_PREDICATE,
            "decision-receipt generic predicate identity changed")

    workflows = exact_keys(root["workflows"], LEASE_WORKFLOWS,
                           "decision-receipt workflow coverage")
    observed_effect_kinds: set[str] = set()
    generic_jobs: set[tuple[str, str]] = set()
    self_attested_jobs: set[tuple[str, str]] = set()
    specialized_jobs: set[tuple[str, str]] = set()

    for workflow_id in sorted(LEASE_WORKFLOWS):
        policy_workflow = policy["workflows"][workflow_id]
        workflow_contract = exact_keys(workflows[workflow_id], {"jobs"},
                                       f"decision-receipt workflow {workflow_id}")
        jobs = workflow_contract["jobs"]
        require(isinstance(jobs, dict), f"decision-receipt workflow {workflow_id} jobs must be an object")
        bound_jobs = set(policy_workflow["lease"]["boundJobs"])
        require(set(jobs) == bound_jobs,
                f"decision-receipt workflow {workflow_id} must cover the complete lease-bound job set")

        for job_id in sorted(jobs):
            spec = exact_keys(
                jobs[job_id],
                {"mode", "effectKinds", "predicateType"},
                f"decision-receipt coverage {workflow_id}/{job_id}",
            )
            mode = spec["mode"]
            require(mode in MODES, f"decision-receipt coverage mode is unreviewed: {workflow_id}/{job_id}/{mode}")
            effects = string_list(spec["effectKinds"], f"decision-receipt effects {workflow_id}/{job_id}")
            require(not (set(effects) & observed_effect_kinds),
                    f"decision-receipt effect kind is assigned to multiple privileged jobs: {effects}")
            observed_effect_kinds.update(effects)
            predicate = spec["predicateType"]
            require(isinstance(predicate, str) and predicate.startswith("https://raw.githubusercontent.com/portyu9/portyu9/main/"),
                    f"decision-receipt predicate type is not repository-bound: {workflow_id}/{job_id}")

            job = policy_workflow["jobs"][job_id]
            writes = write_capabilities(job["permissions"])
            require(writes, f"decision-receipt coverage includes non-write job: {workflow_id}/{job_id}")
            key = (workflow_id, job_id)

            if mode == "generic-decision-receipt":
                generic_jobs.add(key)
                require(predicate == GENERIC_PREDICATE,
                        f"generic decision receipt predicate changed: {workflow_id}/{job_id}")
                require(key in EXPECTED_GENERIC_EFFECTS and effects == EXPECTED_GENERIC_EFFECTS[key],
                        f"generic decision receipt effect class changed: {workflow_id}/{job_id}")
                require("id-token" not in job["permissions"] and "attestations" not in writes,
                        f"observed generic-effect job must not gain receipt-signing authority: {workflow_id}/{job_id}")
            elif mode == "self-attested":
                self_attested_jobs.add(key)
                require(key in EXPECTED_SELF_ATTESTED,
                        f"unreviewed self-attested privileged job: {workflow_id}/{job_id}")
                expected_effect, expected_predicate = EXPECTED_SELF_ATTESTED[key]
                require(effects == (expected_effect,) and predicate == expected_predicate,
                        f"self-attested decision receipt identity changed: {workflow_id}/{job_id}")
                require(job["permissions"].get("id-token") == "write"
                        and job["permissions"].get("attestations") == "write",
                        f"self-attested job lacks exact OIDC/attestations authority: {workflow_id}/{job_id}")
            else:
                specialized_jobs.add(key)
                require(key in EXPECTED_SPECIALIZED,
                        f"unreviewed specialized decision receipt job: {workflow_id}/{job_id}")
                expected_effect, expected_predicate = EXPECTED_SPECIALIZED[key]
                require(effects == (expected_effect,) and predicate == expected_predicate,
                        f"specialized decision receipt identity changed: {workflow_id}/{job_id}")

    require(generic_jobs == set(EXPECTED_GENERIC_EFFECTS),
            "decision-receipt generic privileged-job inventory changed")
    require(self_attested_jobs == set(EXPECTED_SELF_ATTESTED),
            "decision-receipt self-attested privileged-job inventory changed")
    require(specialized_jobs == set(EXPECTED_SPECIALIZED),
            "decision-receipt specialized privileged-job inventory changed")
    return contract


def expect_failure(policy: dict[str, Any], contract: dict[str, Any], expected: str) -> None:
    try:
        validate(policy, contract)
    except (KeyError, ValueError) as exc:
        require(expected in str(exc), f"decision-receipt coverage self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"decision-receipt coverage self-test accepted forbidden drift: {expected}")


def self_test(policy: dict[str, Any], contract: dict[str, Any]) -> None:
    validate(policy, copy.deepcopy(contract))

    missing = copy.deepcopy(contract)
    del missing["workflows"]["spotlight-link-sync"]["jobs"]["merge"]
    expect_failure(policy, missing, "complete lease-bound job set")

    wrong_mode = copy.deepcopy(contract)
    wrong_mode["workflows"]["profile-stats"]["jobs"]["dispatch"]["mode"] = "self-attested"
    expect_policy_failure = expect_failure
    expect_policy_failure(policy, wrong_mode, "unreviewed self-attested")

    duplicate_effect = copy.deepcopy(contract)
    duplicate_effect["workflows"]["spotlight-link-sync"]["jobs"]["merge"]["effectKinds"] = [
        "spotlight-workflow-dispatch"
    ]
    expect_failure(policy, duplicate_effect, "multiple privileged jobs")

    wrong_predicate = copy.deepcopy(contract)
    wrong_predicate["workflows"]["spotlight-link-sync"]["jobs"]["approve"]["predicateType"] = (
        "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v3.schema.json"
    )
    expect_failure(policy, wrong_predicate, "generic decision receipt predicate changed")

    writer_signs = copy.deepcopy(policy)
    writer_signs["workflows"]["spotlight-link-sync"]["jobs"]["propose"]["permissions"]["id-token"] = "write"
    writer_signs["workflows"]["spotlight-link-sync"]["jobs"]["propose"]["permissions"]["attestations"] = "write"
    expect_failure(writer_signs, contract, "must not gain receipt-signing authority")

    wrong_pointer = copy.deepcopy(policy)
    wrong_pointer["decisionReceiptContract"] = ".github/wrong.json"
    expect_failure(wrong_pointer, contract, "pointer differs")

    automation_decision_receipt_schema.self_test()
    automation_decision_receipt.self_test()
    profile_stats_decision_receipt.self_test()
    spotlight_decision_receipt.self_test()


def main() -> int:
    try:
        import automation_policy

        policy = automation_policy.load_policy()
        contract = strict_json(CONTRACT_PATH)
        validate(policy, contract)
        self_test(policy, contract)
        total = sum(len(workflow["jobs"]) for workflow in contract["workflows"].values())
        generic = sum(
            1
            for workflow in contract["workflows"].values()
            for job in workflow["jobs"].values()
            if job["mode"] == "generic-decision-receipt"
        )
        print(
            f"Automation Decision Receipt coverage passed: {CONTRACT_ID} · {total} lease-bound privileged jobs · "
            f"{generic} generic receipt effect classes · remaining jobs self-attested or covered by a stronger "
            "specialized attested receipt"
        )
        return 0
    except (OSError, KeyError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
