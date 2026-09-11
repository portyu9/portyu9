#!/usr/bin/env python3
"""Compile the post-publication receipt authority overlay from Policy IR to workflow source."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

PROFILE_WORKFLOW = "profile-stats"
RECEIPT_JOB = "receipt"
SIGNER_JOB = "receipt_attest"
RECEIPT_NAME = "prepare-publication-receipt-read-only"
SIGNER_NAME = "attest-publication-receipt-write-only"
RECEIPT_ARTIFACT = "profile-publication-receipt"
RECEIPT_SCHEMA = ".github/attestation/profile-publication-receipt-v1.schema.json"
RECEIPT_BUILDER = "scripts/build-profile-publication-receipt.py"
ATTEST_SHA = "1e69f48acb82d1966a394da916b4c1698aa569d6"
DOWNLOAD_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def job_block(text: str, job_id: str, next_job_id: str | None) -> str:
    marker = f"  {job_id}:\n"
    require(text.count(marker) == 1, f"publication receipt compiler cannot isolate job: {job_id}")
    start = text.index(marker)
    if next_job_id is None:
        return text[start:]
    next_marker = f"  {next_job_id}:\n"
    require(text.count(next_marker) == 1,
            f"publication receipt compiler cannot isolate next job: {next_job_id}")
    return text[start:text.index(next_marker, start + len(marker))]


def validate_policy(policy: dict[str, Any]) -> None:
    workflow = policy["workflows"][PROFILE_WORKFLOW]
    jobs = workflow["jobs"]
    require(RECEIPT_JOB in jobs and SIGNER_JOB in jobs,
            "publication receipt jobs are missing from Profile Stats policy")
    receipt = jobs[RECEIPT_JOB]
    signer = jobs[SIGNER_JOB]
    require(receipt == {
        "name": RECEIPT_NAME,
        "needs": ["publish", "stage", "lease", "attest"],
        "permissions": {"contents": "read"},
    }, "publication receipt preparation policy changed")
    require(signer == {
        "name": SIGNER_NAME,
        "needs": ["receipt", "lease", "attest"],
        "permissions": {"contents": "read", "id-token": "write", "attestations": "write"},
    }, "publication receipt signer policy changed")
    require(workflow["jobs"]["dispatch"]["needs"] == ["receipt_attest", "publish", "lease", "attest"],
            "Spotlight dispatch must remain downstream of the signed publication receipt")
    terminal_jobs = workflow["concurrency"]["terminal"]["jobs"]
    require(RECEIPT_JOB in terminal_jobs and SIGNER_JOB in terminal_jobs,
            "publication receipt jobs must remain in terminal concurrency")
    lease = workflow["lease"]
    require(SIGNER_JOB in lease["boundJobs"],
            "publication receipt signer must remain lease-bound")
    require(lease["minimumRemainingSeconds"].get(SIGNER_JOB) == 240,
            "publication receipt signer lease reserve changed")

    machine = policy["transactionMachines"][PROFILE_WORKFLOW]
    verify = [transition for transition in machine["transitions"]
              if transition["from"] == "mutated" and transition["to"] == "verified"]
    require(len(verify) == 1 and verify[0] == {
        "from": "mutated",
        "to": "verified",
        "phase": "verify",
        "jobs": ["publish", "receipt", "receipt_attest"],
    }, "publication receipt transaction verify phase changed")


def project_pre_receipt_policy(payload: dict[str, Any]) -> dict[str, Any]:
    """Remove exactly the item-9 receipt overlay before frozen item-8/legacy validation."""
    projected = copy.deepcopy(payload)
    validate_policy(projected)
    workflow = projected["workflows"][PROFILE_WORKFLOW]
    for job_id in (RECEIPT_JOB, SIGNER_JOB):
        del workflow["jobs"][job_id]
        for class_spec in workflow["concurrency"].values():
            class_spec["jobs"] = [member for member in class_spec["jobs"] if member != job_id]
    workflow["lease"]["boundJobs"] = [job for job in workflow["lease"]["boundJobs"] if job != SIGNER_JOB]
    del workflow["lease"]["minimumRemainingSeconds"][SIGNER_JOB]
    workflow["jobs"]["dispatch"]["needs"] = ["publish", "lease", "attest"]
    for transition in projected["transactionMachines"][PROFILE_WORKFLOW]["transitions"]:
        transition["jobs"] = [job for job in transition["jobs"] if job not in {RECEIPT_JOB, SIGNER_JOB}]
        require(transition["jobs"], "publication receipt projection emptied a transaction transition")
    return projected


def validate_source(policy: dict[str, Any], root: Path) -> None:
    validate_policy(policy)
    workflow_path = root / policy["workflows"][PROFILE_WORKFLOW]["path"]
    require(workflow_path.is_file() and not workflow_path.is_symlink(),
            "publication receipt workflow is missing or aliased")
    schema_path = root / RECEIPT_SCHEMA
    builder_path = root / RECEIPT_BUILDER
    require(schema_path.is_file() and not schema_path.is_symlink(),
            "publication receipt schema is missing or aliased")
    require(builder_path.is_file() and not builder_path.is_symlink(),
            "publication receipt builder is missing or aliased")
    text = workflow_path.read_text(encoding="utf-8")
    receipt = job_block(text, RECEIPT_JOB, SIGNER_JOB)
    signer = job_block(text, SIGNER_JOB, "dispatch")
    dispatch = job_block(text, "dispatch", None)

    for fragment in (
        f"name: {RECEIPT_NAME}",
        "needs: [publish, stage, lease, attest]",
        "timeout-minutes: 4",
        "permissions:\n      contents: read",
        f"actions/checkout@{CHECKOUT_SHA}",
        "ref: generated",
        "path: published",
        "fetch-depth: 2",
        f"actions/setup-python@{SETUP_PYTHON_SHA}",
        "python3 source/scripts/build-profile-publication-receipt.py \\",
        "EXPECTED_GENERATED_SHA: ${{ needs.stage.outputs.candidate_sha }}",
        "EXPECTED_GENERATED_PARENT_SHA: ${{ needs.stage.outputs.base_sha }}",
        "TRANSACTION_CANDIDATE_ID: ${{ needs.attest.outputs.candidate_id }}",
        "MUTATION_LEASE_ID: ${{ needs.lease.outputs.lease_id }}",
        "generated-publication-subject.json profile-publication-receipt.json",
        "subject_sha256=$SUBJECT_SHA256",
        "predicate_sha256=$PREDICATE_SHA256",
        f"actions/upload-artifact@{UPLOAD_SHA}",
        f"name: {RECEIPT_ARTIFACT}",
        "generated-publication-subject.json",
        "profile-publication-receipt.json",
        "retention-days: 1",
    ):
        require(fragment in receipt, f"publication receipt preparation source is missing: {fragment}")
    for forbidden in ("contents: write", "id-token: write", "attestations: write", "actions: write"):
        require(forbidden not in receipt,
                f"publication receipt preparation acquired write authority: {forbidden}")

    for fragment in (
        f"name: {SIGNER_NAME}",
        "needs: [receipt, lease, attest]",
        "timeout-minutes: 3",
        "contents: read\n      id-token: write\n      attestations: write",
        f"actions/download-artifact@{DOWNLOAD_SHA}",
        f"name: {RECEIPT_ARTIFACT}",
        "path: receipt-input",
        "digest-mismatch: error",
        "LEASE_MIN_REMAINING_SECONDS=240",
        "EXPECTED_SUBJECT_SHA256: ${{ needs.receipt.outputs.subject_sha256 }}",
        "EXPECTED_RECEIPT_SHA256: ${{ needs.receipt.outputs.predicate_sha256 }}",
        "sha256sum receipt-input/generated-publication-subject.json",
        "sha256sum receipt-input/profile-publication-receipt.json",
        f"actions/attest@{ATTEST_SHA}",
        "subject-path: receipt-input/generated-publication-subject.json",
        "predicate-type: https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-publication-receipt-v1.schema.json",
        "predicate-path: receipt-input/profile-publication-receipt.json",
    ):
        require(fragment in signer, f"publication receipt signer source is missing: {fragment}")
    require(signer.count("        run: |") == 1,
            "publication receipt signer must execute exactly one reviewed proof shell")
    require(signer.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 1,
            "publication receipt signer must download exactly one receipt artifact")
    require(signer.count(f"actions/attest@{ATTEST_SHA}") == 1,
            "publication receipt signer must execute pinned actions/attest exactly once")
    for forbidden in (
        "contents: write", "actions: write", "actions/checkout@", "actions/setup-python@",
        "python3 ", "git ", "gh ", "curl ", "wget ", "GITHUB_TOKEN:", "GH_TOKEN:",
    ):
        require(forbidden not in signer,
                f"publication receipt signer acquired unauthorized executable/mutation surface: {forbidden}")
    require("needs: [receipt_attest, publish, lease, attest]" in dispatch,
            "Spotlight dispatch no longer waits for signed publication receipt")


def expect_policy_failure(policy: dict[str, Any], expected: str) -> None:
    try:
        validate_policy(policy)
    except ValueError as exc:
        require(expected in str(exc), f"publication receipt policy self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"publication receipt policy self-test accepted forbidden drift: {expected}")


def expect_source_failure(policy: dict[str, Any], root: Path, transform: tuple[str, str], expected: str) -> None:
    workflow_path = root / policy["workflows"][PROFILE_WORKFLOW]["path"]
    original = workflow_path.read_text(encoding="utf-8")
    require(transform[0] in original, f"publication receipt source self-test fixture missing: {transform[0]}")
    mutated = original.replace(transform[0], transform[1], 1)
    # Validate the relevant source blocks directly without mutating the repository.
    receipt = job_block(mutated, RECEIPT_JOB, SIGNER_JOB)
    signer = job_block(mutated, SIGNER_JOB, "dispatch")
    dispatch = job_block(mutated, "dispatch", None)
    try:
        if expected == "generated checkout depth":
            require("fetch-depth: 2" in receipt, "generated checkout depth")
        elif expected == "builder invocation":
            require("python3 source/scripts/build-profile-publication-receipt.py \\" in receipt,
                    "builder invocation")
        elif expected == "signer executable surface":
            require("python3 " not in signer, "signer executable surface")
        elif expected == "dispatch receipt dependency":
            require("needs: [receipt_attest, publish, lease, attest]" in dispatch,
                    "dispatch receipt dependency")
        else:
            raise ValueError(f"unknown publication receipt source self-test: {expected}")
    except ValueError as exc:
        require(expected in str(exc), f"publication receipt source self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"publication receipt source self-test accepted forbidden drift: {expected}")


def self_test(policy: dict[str, Any], root: Path) -> None:
    validate_source(policy, root)
    missing_signer = copy.deepcopy(policy)
    del missing_signer["workflows"][PROFILE_WORKFLOW]["jobs"][SIGNER_JOB]
    expect_policy_failure(missing_signer, "publication receipt jobs are missing")

    dispatch_bypass = copy.deepcopy(policy)
    dispatch_bypass["workflows"][PROFILE_WORKFLOW]["jobs"]["dispatch"]["needs"] = ["publish", "lease", "attest"]
    expect_policy_failure(dispatch_bypass, "downstream of the signed publication receipt")

    signer_write = copy.deepcopy(policy)
    signer_write["workflows"][PROFILE_WORKFLOW]["jobs"][SIGNER_JOB]["permissions"]["contents"] = "write"
    expect_policy_failure(signer_write, "signer policy changed")

    reserve_drift = copy.deepcopy(policy)
    reserve_drift["workflows"][PROFILE_WORKFLOW]["lease"]["minimumRemainingSeconds"][SIGNER_JOB] = 180
    expect_policy_failure(reserve_drift, "lease reserve changed")

    expect_source_failure(policy, root, ("fetch-depth: 2", "fetch-depth: 1"), "generated checkout depth")
    expect_source_failure(
        policy, root,
        ("python3 source/scripts/build-profile-publication-receipt.py \\", "echo retired-builder \\"),
        "builder invocation",
    )
    expect_source_failure(
        policy, root,
        ("          set -euo pipefail\n          LEASE_TTL_SECONDS=1800",
         "          set -euo pipefail\n          python3 unsafe.py\n          LEASE_TTL_SECONDS=1800"),
        "signer executable surface",
    )
    expect_source_failure(
        policy, root,
        ("needs: [receipt_attest, publish, lease, attest]", "needs: [publish, lease, attest]"),
        "dispatch receipt dependency",
    )
