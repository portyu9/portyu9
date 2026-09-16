#!/usr/bin/env python3
"""Validation-only trust contract for the future privileged CodeQL Autofix controller.

No production workflow imports this module yet. It defines the exact default-branch execution,
least-authority, mutation-surface, branch identity, and artifact-receipt requirements that must
be satisfied before a write-capable controller is introduced.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Mapping

REPOSITORY = "portyu9/portyu9"
DEFAULT_BRANCH = "main"
CONTROLLER_ID = "portyu9-codeql-autofix-v1"
FLOW_ID = "github-codeql-autofix-v1"
WORKFLOW_NAME = "CodeQL Autofix controller"
WORKFLOW_PATH = ".github/workflows/codeql-autofix.yml"
CODEQL_WORKFLOW_NAME = "CodeQL"
DISPATCH_TYPE = "codeql-autofix"
FALLBACK_CRON = "37 * * * *"
ALLOWED_EVENTS = {"workflow_run", "schedule", "repository_dispatch"}
EXPECTED_PERMISSIONS = {
    "actions": "write",
    "checks": "read",
    "contents": "write",
    "pull-requests": "write",
    "security-events": "write",
}
ALLOWED_MUTATIONS = {
    "POST /repos/{repository}/git/refs",
    "POST /repos/{repository}/code-scanning/alerts/{alert}/autofix",
    "POST /repos/{repository}/code-scanning/alerts/{alert}/autofix/commits",
    "POST /repos/{repository}/pulls",
    "POST /repos/{repository}/dispatches",
    "GRAPHQL enablePullRequestAutoMerge",
}
FORBIDDEN_MUTATION_FRAGMENTS = {
    "/merges",
    "/branches/main",
    "/git/refs/heads/main",
    "/actions/workflows/",
    "/rulesets",
    "/secrets",
    "dismiss",
    "DELETE ",
}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$")


class ControllerContractError(ValueError):
    """Stable fail-closed controller contract rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ControllerContractError(message)


def require_sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
            f"{label} must be an exact lowercase SHA-40")
    return value


def expected_blueprint() -> dict[str, Any]:
    return {
        "repository": REPOSITORY,
        "workflowName": WORKFLOW_NAME,
        "workflowPath": WORKFLOW_PATH,
        "triggers": {
            "workflow_run": {
                "workflows": [CODEQL_WORKFLOW_NAME],
                "types": ["completed"],
                "branches": [DEFAULT_BRANCH],
            },
            "schedule": [FALLBACK_CRON],
            "repository_dispatch": {"types": [DISPATCH_TYPE]},
        },
        "permissions": dict(EXPECTED_PERMISSIONS),
        "mutations": sorted(ALLOWED_MUTATIONS),
        "checkout": {"ref": "${{ github.sha }}", "persistCredentials": False, "fetchDepth": 1},
        "candidateExecution": False,
        "directMainMutation": False,
        "receiptArtifactRequired": True,
    }


def validate_blueprint(value: Any) -> dict[str, Any]:
    require(isinstance(value, Mapping), "controller blueprint must be an object")
    expected = expected_blueprint()
    require(dict(value) == expected, "controller blueprint differs from the reviewed least-authority design")
    triggers = value["triggers"]
    require("workflow_dispatch" not in triggers,
            "privileged Autofix controller must not allow arbitrary-ref workflow_dispatch")
    require("push" not in triggers and "pull_request" not in triggers and "pull_request_target" not in triggers,
            "privileged Autofix controller acquired an unreviewed source-ref trigger")
    require(set(triggers) == ALLOWED_EVENTS,
            "privileged Autofix controller trigger inventory changed")
    require(value["permissions"] == EXPECTED_PERMISSIONS,
            "privileged Autofix controller token permissions changed")
    mutations = set(value["mutations"])
    require(mutations == ALLOWED_MUTATIONS, "privileged Autofix controller mutation surface changed")
    for mutation in mutations:
        require(not any(fragment in mutation for fragment in FORBIDDEN_MUTATION_FRAGMENTS),
                f"privileged Autofix controller mutation is forbidden: {mutation}")
    require(value["directMainMutation"] is False and value["candidateExecution"] is False,
            "privileged Autofix controller may not execute candidate code or mutate main directly")
    return copy.deepcopy(expected)


def receipt_name(run_id: int, alert_number: int) -> str:
    require(type(run_id) is int and run_id > 0, "controller run id must be a positive integer")
    require(type(alert_number) is int and alert_number > 0, "controller alert number must be a positive integer")
    return f"codeql-autofix-receipt-run-{run_id}-alert-{alert_number}"


def branch_name(run_id: int, alert_number: int) -> str:
    require(type(run_id) is int and run_id > 0, "controller run id must be a positive integer")
    require(type(alert_number) is int and alert_number > 0, "controller alert number must be a positive integer")
    return f"codeql-autofix/alert-{alert_number}/run-{run_id}"


def validate_receipt(receipt: Any, *, workflow_run: Any, artifact: Any) -> dict[str, Any]:
    """Verify provenance using trusted Actions run/artifact API data, never PR metadata."""
    require(isinstance(receipt, Mapping), "Autofix provenance receipt must be an object")
    expected_keys = {
        "controllerId", "flowId", "repository", "workflowPath", "runId", "runAttempt", "event",
        "baseSha", "alertNumber", "ruleId", "targetBranch", "autofixCommitSha", "prNumber",
    }
    require(set(receipt) == expected_keys, "Autofix provenance receipt keys changed")
    require(receipt.get("controllerId") == CONTROLLER_ID, "Autofix receipt controller identity mismatch")
    require(receipt.get("flowId") == FLOW_ID, "Autofix receipt flow identity mismatch")
    require(receipt.get("repository") == REPOSITORY, "Autofix receipt repository identity mismatch")
    require(receipt.get("workflowPath") == WORKFLOW_PATH, "Autofix receipt workflow path mismatch")

    run_id = receipt.get("runId")
    attempt = receipt.get("runAttempt")
    alert = receipt.get("alertNumber")
    pr_number = receipt.get("prNumber")
    require(type(run_id) is int and run_id > 0, "Autofix receipt runId is invalid")
    require(type(attempt) is int and attempt > 0, "Autofix receipt runAttempt is invalid")
    require(type(alert) is int and alert > 0, "Autofix receipt alertNumber is invalid")
    require(type(pr_number) is int and pr_number > 0, "Autofix receipt prNumber is invalid")
    event = receipt.get("event")
    require(event in ALLOWED_EVENTS, "Autofix receipt event is not default-branch trusted")
    base_sha = require_sha(receipt.get("baseSha"), "Autofix receipt baseSha")
    head_sha = require_sha(receipt.get("autofixCommitSha"), "Autofix receipt commit SHA")
    rule_id = receipt.get("ruleId")
    require(isinstance(rule_id, str) and RULE_ID.fullmatch(rule_id) is not None,
            "Autofix receipt rule id is invalid")
    expected_branch = branch_name(run_id, alert)
    require(receipt.get("targetBranch") == expected_branch,
            "Autofix receipt target branch does not bind run and alert identity")

    run = workflow_run
    require(isinstance(run, Mapping), "trusted workflow-run evidence must be an object")
    require(run.get("id") == run_id, "Autofix provenance workflow run id mismatch")
    require(run.get("run_attempt") == attempt, "Autofix provenance workflow attempt mismatch")
    require(run.get("name") == WORKFLOW_NAME, "Autofix provenance workflow name mismatch")
    require(run.get("path") == WORKFLOW_PATH, "Autofix provenance workflow path mismatch")
    require(run.get("event") == event, "Autofix provenance workflow event mismatch")
    require(run.get("head_branch") == DEFAULT_BRANCH, "Autofix provenance workflow did not run on main")
    require(run.get("head_sha") == base_sha, "Autofix provenance workflow base SHA mismatch")
    require(run.get("status") == "completed" and run.get("conclusion") == "success",
            "Autofix provenance workflow run is not a completed success")

    artifact_value = artifact
    require(isinstance(artifact_value, Mapping), "trusted receipt artifact evidence must be an object")
    require(artifact_value.get("name") == receipt_name(run_id, alert),
            "Autofix provenance artifact name mismatch")
    require(artifact_value.get("expired") is False, "Autofix provenance artifact is expired")
    artifact_digest = artifact_value.get("digest")
    require(isinstance(artifact_digest, str) and DIGEST.fullmatch(artifact_digest) is not None,
            "Autofix provenance artifact digest is missing or invalid")
    artifact_run = artifact_value.get("workflow_run")
    require(isinstance(artifact_run, Mapping), "Autofix provenance artifact lacks workflow_run identity")
    require(artifact_run.get("id") == run_id,
            "Autofix provenance artifact belongs to another workflow run")
    require(artifact_run.get("head_branch") == DEFAULT_BRANCH,
            "Autofix provenance artifact was not produced from main")
    require(artifact_run.get("head_sha") == base_sha,
            "Autofix provenance artifact is bound to another base SHA")

    return {
        "controllerId": CONTROLLER_ID,
        "flowId": FLOW_ID,
        "autofixGenerated": True,
        "artifactVerified": True,
        "artifactDigest": artifact_digest,
        "runId": run_id,
        "runAttempt": attempt,
        "alertNumber": alert,
        "ruleId": rule_id,
        "baseSha": base_sha,
        "headSha": head_sha,
        "targetBranch": expected_branch,
        "prNumber": pr_number,
    }


def fixture() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    run_id = 12345
    alert = 4
    base = "a" * 40
    head = "b" * 40
    receipt = {
        "controllerId": CONTROLLER_ID,
        "flowId": FLOW_ID,
        "repository": REPOSITORY,
        "workflowPath": WORKFLOW_PATH,
        "runId": run_id,
        "runAttempt": 1,
        "event": "workflow_run",
        "baseSha": base,
        "alertNumber": alert,
        "ruleId": "py/clear-text-logging-sensitive-data",
        "targetBranch": branch_name(run_id, alert),
        "autofixCommitSha": head,
        "prNumber": 418,
    }
    workflow_run = {
        "id": run_id,
        "run_attempt": 1,
        "name": WORKFLOW_NAME,
        "path": WORKFLOW_PATH,
        "event": "workflow_run",
        "head_branch": DEFAULT_BRANCH,
        "head_sha": base,
        "status": "completed",
        "conclusion": "success",
    }
    artifact = {
        "name": receipt_name(run_id, alert),
        "expired": False,
        "digest": "sha256:" + "c" * 64,
        "workflow_run": {
            "id": run_id,
            "repository_id": 1355082509,
            "head_repository_id": 1355082509,
            "head_branch": DEFAULT_BRANCH,
            "head_sha": base,
        },
    }
    return receipt, workflow_run, artifact


def expect_failure(fn: Any, expected: str) -> None:
    try:
        fn()
    except ControllerContractError as exc:
        require(expected in str(exc), f"controller contract self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"controller contract self-test accepted forbidden case: {expected}")


def self_test() -> None:
    validate_blueprint(expected_blueprint())
    bad_trigger = expected_blueprint()
    bad_trigger["triggers"]["workflow_dispatch"] = {}
    expect_failure(lambda: validate_blueprint(bad_trigger), "blueprint differs")

    bad_permission = expected_blueprint()
    bad_permission["permissions"]["actions"] = "read"
    expect_failure(lambda: validate_blueprint(bad_permission), "blueprint differs")

    receipt, workflow_run, artifact = fixture()
    provenance = validate_receipt(receipt, workflow_run=workflow_run, artifact=artifact)
    require(provenance["artifactVerified"] is True and provenance["headSha"] == "b" * 40,
            "controller receipt positive fixture changed")

    spoofed = dict(receipt)
    spoofed["controllerId"] = "spoof"
    expect_failure(lambda: validate_receipt(spoofed, workflow_run=workflow_run, artifact=artifact), "controller identity")

    branch_spoof = dict(receipt)
    branch_spoof["targetBranch"] = "codeql-autofix/alert-4/run-99999"
    expect_failure(lambda: validate_receipt(branch_spoof, workflow_run=workflow_run, artifact=artifact), "target branch")

    stale_run = dict(workflow_run)
    stale_run["head_sha"] = "c" * 40
    expect_failure(lambda: validate_receipt(receipt, workflow_run=stale_run, artifact=artifact), "base SHA")

    wrong_attempt = dict(workflow_run)
    wrong_attempt["run_attempt"] = 2
    expect_failure(lambda: validate_receipt(receipt, workflow_run=wrong_attempt, artifact=artifact), "attempt mismatch")

    branch_run = dict(workflow_run)
    branch_run["head_branch"] = "feature"
    expect_failure(lambda: validate_receipt(receipt, workflow_run=branch_run, artifact=artifact), "did not run on main")

    failed_run = dict(workflow_run)
    failed_run["conclusion"] = "failure"
    expect_failure(lambda: validate_receipt(receipt, workflow_run=failed_run, artifact=artifact), "completed success")

    expired = copy.deepcopy(artifact)
    expired["expired"] = True
    expect_failure(lambda: validate_receipt(receipt, workflow_run=workflow_run, artifact=expired), "expired")

    wrong_artifact_run = copy.deepcopy(artifact)
    wrong_artifact_run["workflow_run"]["id"] = 99999
    expect_failure(lambda: validate_receipt(receipt, workflow_run=workflow_run, artifact=wrong_artifact_run), "another workflow run")

    wrong_artifact_sha = copy.deepcopy(artifact)
    wrong_artifact_sha["workflow_run"]["head_sha"] = "c" * 40
    expect_failure(lambda: validate_receipt(receipt, workflow_run=workflow_run, artifact=wrong_artifact_sha), "another base SHA")

    no_digest = copy.deepcopy(artifact)
    no_digest["digest"] = None
    expect_failure(lambda: validate_receipt(receipt, workflow_run=workflow_run, artifact=no_digest), "digest")


def main() -> int:
    self_test()
    print(
        "CodeQL Autofix controller trust contract passed: only default-branch workflow_run/schedule/repository_dispatch "
        "execution, least reviewed token permissions/mutations, deterministic remediation branches, and successful "
        "workflow-run artifacts with exact run/base identity may establish controller provenance."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())