#!/usr/bin/env python3
"""Pure fail-closed policy for CodeQL Autofix PR auto-merge eligibility.

The future production controller must construct this module's input only from trusted GitHub
API responses and its verified controller receipt, never from PR title/body/labels. This module
performs no network or repository mutation. It decides only whether an already-created,
exact-head CodeQL Autofix PR is eligible to have GitHub auto-merge enabled.

Sensitive governance/TCB fixes may still be created automatically, but this policy refuses
to auto-merge them. Protect Main and the repository's six required checks remain the final
merge authority even for eligible ordinary source fixes.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

REPOSITORY = "portyu9/portyu9"
BASE_REF = "main"
CONTROLLER_ID = "portyu9-codeql-autofix-v1"
FLOW_ID = "github-codeql-autofix-v1"
GITHUB_ACTIONS_APP_ID = 15368
REQUIRED_CHECKS = (
    "validate-contracts",
    "trusted-capability-admission",
    "integration-pinned-upstream",
    "dependency-review",
    "analyze-actions",
    "analyze-python",
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SAFE_SOURCE = re.compile(r"^scripts/[A-Za-z0-9_.-]+\.py$")

# These files/prefixes are trusted-control source, controller source, governance validators,
# or can alter the repository's security/automation contract. Autofix PRs may propose changes
# here, but they must go through ordinary prior-authorization/review rather than auto-merge.
FORBIDDEN_SOURCE_EXACT = {
    "scripts/capability_admission_workflow_contract.py",
    "scripts/profile_stats_decision_receipt.py",
    "scripts/spotlight_decision_receipt.py",
    "scripts/spotlight_profile_links.py",
    "scripts/trusted_workflow_capability.py",
    "scripts/verify-python-runtime.py",
    "scripts/workflow_authority_contract_core.py",
}
FORBIDDEN_SOURCE_PREFIXES = (
    "scripts/automation_",
    "scripts/codeql_autofix_",
    "scripts/workflow_capability_",
    "scripts/validate-",
)
BLOCKING_SEVERITIES = {"critical", "high"}


class AdmissionError(ValueError):
    """A stable, public reason that an Autofix PR is not auto-merge eligible."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionError(message)


def require_sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
            f"{label} must be an exact lowercase SHA-40")
    return value


def is_forbidden_source(path: str) -> bool:
    return path in FORBIDDEN_SOURCE_EXACT or any(path.startswith(prefix) for prefix in FORBIDDEN_SOURCE_PREFIXES)


def validate_changed_files(value: Any) -> tuple[str, ...]:
    require(isinstance(value, list) and value, "Autofix PR must change at least one file")
    require(len(value) <= 5, "Autofix PR exceeds the five-file auto-merge limit")
    require(all(isinstance(path, str) for path in value), "Autofix changed-file inventory must contain strings")
    require(len(value) == len(set(value)), "Autofix changed-file inventory contains duplicates")
    ordered = tuple(sorted(value))
    for path in ordered:
        require(SAFE_SOURCE.fullmatch(path) is not None,
                f"Autofix auto-merge is limited to flat Python source under scripts/: {path}")
        require(not is_forbidden_source(path),
                f"Autofix touches trusted/governance source and requires ordinary review: {path}")
    return ordered


def validate_checks(value: Any, head_sha: str) -> None:
    require(isinstance(value, list), "required-check evidence must be a list")
    by_name: dict[str, Mapping[str, Any]] = {}
    for raw in value:
        require(isinstance(raw, Mapping), "required-check evidence contains a non-object")
        name = raw.get("name")
        require(isinstance(name, str), "required-check evidence is missing a string name")
        require(name not in by_name, f"required-check evidence duplicates context: {name}")
        by_name[name] = raw
    require(set(by_name) == set(REQUIRED_CHECKS),
            "required-check evidence must contain exactly the six protected contexts")
    for name in REQUIRED_CHECKS:
        check = by_name[name]
        require(check.get("status") == "completed" and check.get("conclusion") == "success",
                f"required check is not successful: {name}")
        require(check.get("appId") == GITHUB_ACTIONS_APP_ID,
                f"required check came from an unexpected app: {name}")
        require(check.get("headSha") == head_sha,
                f"required check is stale or belongs to another head: {name}")


def validate_security(value: Any, alert_number: int, head_sha: str) -> None:
    require(isinstance(value, Mapping), "security proof must be an object")
    require(value.get("headSha") == head_sha, "security proof is stale or belongs to another head")
    require(value.get("advancedSecurityConclusion") == "success",
            "GitHub Advanced Security aggregate is not successful")
    require(value.get("targetAlertNumber") == alert_number,
            "security proof is bound to the wrong target alert")
    require(value.get("targetAlertPresent") is False,
            "target CodeQL alert is still present on the candidate")
    findings = value.get("newFindings")
    require(isinstance(findings, list), "security proof newFindings must be a list")
    for finding in findings:
        require(isinstance(finding, Mapping), "security proof contains a malformed finding")
        severity = finding.get("severity")
        require(isinstance(severity, str), "security finding is missing severity")
        require(severity.lower() not in BLOCKING_SEVERITIES,
                f"candidate introduces blocking CodeQL severity: {severity}")


def evaluate(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return a canonical allow decision or raise AdmissionError with a stable reason."""
    require(record.get("repository") == REPOSITORY, "Autofix repository identity mismatch")
    require(record.get("baseRef") == BASE_REF, "Autofix target branch must be main")
    base_sha = require_sha(record.get("baseSha"), "baseSha")
    current_main_sha = require_sha(record.get("currentMainSha"), "currentMainSha")
    require(current_main_sha == base_sha,
            "Autofix PR base is stale relative to current main")
    head_sha = require_sha(record.get("headSha"), "headSha")
    current_head_sha = require_sha(record.get("currentHeadSha"), "currentHeadSha")
    require(head_sha == current_head_sha, "Autofix PR head moved after evidence collection")
    require(base_sha != head_sha, "Autofix candidate head must differ from its base")

    alert_number = record.get("alertNumber")
    require(isinstance(alert_number, int) and alert_number > 0, "target CodeQL alert number is invalid")
    open_alerts = record.get("alertsAddressed")
    require(open_alerts == [alert_number], "Autofix PR must address exactly one target alert")

    provenance = record.get("provenance")
    require(isinstance(provenance, Mapping), "trusted Autofix provenance receipt is missing")
    require(provenance.get("controllerId") == CONTROLLER_ID, "Autofix controller identity mismatch")
    require(provenance.get("flowId") == FLOW_ID, "Autofix generation flow identity mismatch")
    require(provenance.get("autofixGenerated") is True, "candidate was not generated by the trusted Autofix flow")
    require(provenance.get("artifactVerified") is True,
            "Autofix provenance was not verified against a trusted workflow-run artifact")
    run_id = provenance.get("runId")
    require(isinstance(run_id, int) and not isinstance(run_id, bool) and run_id > 0,
            "Autofix provenance controller run id is invalid")
    require(provenance.get("alertNumber") == alert_number, "Autofix provenance is bound to another alert")
    require(provenance.get("baseSha") == base_sha, "Autofix provenance is bound to another base")
    require(provenance.get("headSha") == head_sha, "Autofix provenance is bound to another head")

    changed_files = validate_changed_files(record.get("changedFiles"))
    require(record.get("unresolvedReviewThreads") == 0,
            "Autofix PR has unresolved review threads")
    require(record.get("draft") is False, "Autofix PR must be ready for review")
    require(record.get("mergeable") is True, "GitHub does not report the exact Autofix head mergeable")

    validate_checks(record.get("requiredChecks"), head_sha)
    validate_security(record.get("security"), alert_number, head_sha)

    return {
        "eligible": True,
        "repository": REPOSITORY,
        "alertNumber": alert_number,
        "baseSha": base_sha,
        "currentMainSha": current_main_sha,
        "headSha": head_sha,
        "changedFiles": list(changed_files),
        "requiredChecks": list(REQUIRED_CHECKS),
        "controllerId": CONTROLLER_ID,
        "controllerRunId": run_id,
        "flowId": FLOW_ID,
    }


def check(name: str, *, head: str) -> dict[str, Any]:
    return {
        "name": name,
        "status": "completed",
        "conclusion": "success",
        "appId": GITHUB_ACTIONS_APP_ID,
        "headSha": head,
    }


def fixture() -> dict[str, Any]:
    base = "a" * 40
    head = "b" * 40
    return {
        "repository": REPOSITORY,
        "baseRef": BASE_REF,
        "baseSha": base,
        "currentMainSha": base,
        "headSha": head,
        "currentHeadSha": head,
        "alertNumber": 42,
        "alertsAddressed": [42],
        "provenance": {
            "controllerId": CONTROLLER_ID,
            "flowId": FLOW_ID,
            "autofixGenerated": True,
            "artifactVerified": True,
            "runId": 12345,
            "alertNumber": 42,
            "baseSha": base,
            "headSha": head,
        },
        "changedFiles": ["scripts/example_source.py"],
        "unresolvedReviewThreads": 0,
        "draft": False,
        "mergeable": True,
        "requiredChecks": [check(name, head=head) for name in REQUIRED_CHECKS],
        "security": {
            "headSha": head,
            "advancedSecurityConclusion": "success",
            "targetAlertNumber": 42,
            "targetAlertPresent": False,
            "newFindings": [],
        },
    }


def expect_failure(record: Mapping[str, Any], expected: str) -> None:
    try:
        evaluate(record)
    except AdmissionError as exc:
        require(expected in str(exc), f"Autofix admission self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"Autofix admission self-test accepted forbidden case: {expected}")


def mutated(base: Mapping[str, Any], **changes: Any) -> dict[str, Any]:
    value = dict(base)
    value.update(changes)
    return value


def self_test() -> None:
    good = fixture()
    decision = evaluate(good)
    require(decision["eligible"] is True and decision["alertNumber"] == 42,
            "Autofix admission positive fixture changed")

    expect_failure(mutated(good, repository="attacker/repo"), "repository identity")
    expect_failure(mutated(good, currentMainSha="c" * 40), "base is stale")
    expect_failure(mutated(good, currentHeadSha="c" * 40), "head moved")
    expect_failure(mutated(good, alertsAddressed=[42, 43]), "exactly one")
    expect_failure(mutated(good, changedFiles=[".github/workflows/codeql.yml"]), "limited to flat Python source")
    expect_failure(mutated(good, changedFiles=["scripts/workflow_capability_admission.py"]), "trusted/governance")
    expect_failure(mutated(good, changedFiles=["scripts/codeql_autofix_admission.py"]), "trusted/governance")
    expect_failure(mutated(good, changedFiles=["scripts/validate-codeql-contract.py"]), "trusted/governance")
    expect_failure(mutated(good, unresolvedReviewThreads=1), "unresolved review")
    expect_failure(mutated(good, mergeable=False), "does not report")

    wrong_provenance = dict(good["provenance"])
    wrong_provenance["controllerId"] = "spoof"
    expect_failure(mutated(good, provenance=wrong_provenance), "controller identity")

    unverified = dict(good["provenance"])
    unverified["artifactVerified"] = False
    expect_failure(mutated(good, provenance=unverified), "workflow-run artifact")

    wrong_base = dict(good["provenance"])
    wrong_base["baseSha"] = "c" * 40
    expect_failure(mutated(good, provenance=wrong_base), "another base")

    stale_checks = [dict(item) for item in good["requiredChecks"]]
    stale_checks[0]["headSha"] = "c" * 40
    expect_failure(mutated(good, requiredChecks=stale_checks), "stale")

    wrong_app = [dict(item) for item in good["requiredChecks"]]
    wrong_app[1]["appId"] = 57789
    expect_failure(mutated(good, requiredChecks=wrong_app), "unexpected app")

    missing = [dict(item) for item in good["requiredChecks"]][:-1]
    expect_failure(mutated(good, requiredChecks=missing), "exactly the six")

    failed = [dict(item) for item in good["requiredChecks"]]
    failed[2]["conclusion"] = "failure"
    expect_failure(mutated(good, requiredChecks=failed), "not successful")

    still_present = dict(good["security"])
    still_present["targetAlertPresent"] = True
    expect_failure(mutated(good, security=still_present), "still present")

    high = dict(good["security"])
    high["newFindings"] = [{"severity": "high", "ruleId": "py/example"}]
    expect_failure(mutated(good, security=high), "blocking CodeQL severity")

    stale_security = dict(good["security"])
    stale_security["headSha"] = "c" * 40
    expect_failure(mutated(good, security=stale_security), "security proof is stale")


def main() -> int:
    self_test()
    print(
        "CodeQL Autofix admission self-test passed: only current-main, exact-head, single-alert ordinary Python fixes "
        "with artifact-verified controller provenance, six expected green checks, no unresolved reviews, and a clean "
        "Advanced Security proof are eligible for protected auto-merge."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
