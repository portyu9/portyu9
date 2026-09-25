#!/usr/bin/env python3
"""Load the canonical Workflow Capability BOM as a strict composite snapshot.

The item-12 five-workflow snapshot remains a canonical historical partition. Later trusted
workflow extensions are stored as one-workflow canonical snapshots. This module is the only
assembly boundary: callers receive one ordinary thirteen-workflow BOM object whose semantic and
canonical representation is compared with live trusted compilation.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import automation_policy
import workflow_capability_bom as compiler

ROOT = Path(__file__).resolve().parents[1]
BASE_SNAPSHOT = ROOT / ".github/workflow-capability-bom-v1.json"
ACTION_PROVENANCE_WITNESS_EXTENSION = ROOT / ".github/workflow-capability-bom-v1-action-provenance-witness.json"
ADMISSION_EXTENSION = ROOT / ".github/workflow-capability-bom-v1-capability-admission.json"
AUTOFIX_EXTENSION = ROOT / ".github/workflow-capability-bom-v1-codeql-autofix.json"
DEPENDABOT_EXTENSION = ROOT / ".github/workflow-capability-bom-v1-dependabot-controller.json"
PROFILE_GENERATOR_COMPATIBILITY_WITNESS_EXTENSION = ROOT / ".github/workflow-capability-bom-v1-profile-generator-compatibility-witness.json"
BOT_PR_USER_APPROVAL_EXTENSION = ROOT / ".github/workflow-capability-bom-v1-bot-pr-user-approval.json"
RULESET_DRIFT_SENTINEL_EXTENSION = ROOT / ".github/workflow-capability-bom-v1-ruleset-drift-sentinel.json"
RULESET_RECONCILER_EXTENSION = ROOT / ".github/workflow-capability-bom-v1-ruleset-reconciler.json"
RULESET_RECONCILER_WORKFLOW = ROOT / ".github/workflows/ruleset-reconciler.yml"
RULESET_RECONCILER_ADMIN_SECRETS = [
    "PORTYU9_RULESET_ADMIN_APP_ID",
    "PORTYU9_RULESET_ADMIN_INSTALLATION_ID",
    "PORTYU9_RULESET_ADMIN_PRIVATE_KEY",
]
EXPECTED_ROOT_KEYS = {"schemaVersion", "bomId", "repository", "automationPolicyId", "workflows"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_part(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing or aliased: {path}")
    raw = path.read_text(encoding="utf-8")
    try:
        payload = automation_policy.strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"{label} JSON is invalid: {exc}") from exc
    require(isinstance(payload, dict), f"{label} root must be an object")
    require(set(payload) == EXPECTED_ROOT_KEYS, f"{label} root keys changed: {sorted(payload)}")
    require(payload.get("schemaVersion") == compiler.SCHEMA_VERSION, f"{label} schema version changed")
    require(payload.get("bomId") == compiler.BOM_ID, f"{label} BOM identity changed")
    require(payload.get("repository") == automation_policy.REPOSITORY, f"{label} repository changed")
    require(payload.get("automationPolicyId") == automation_policy.POLICY_ID,
            f"{label} Automation Policy binding changed")
    require(isinstance(payload.get("workflows"), list), f"{label} workflows must be an array")
    require(raw == compiler.canonical_json(payload), f"{label} bytes are not canonical JSON")
    return payload


def one_workflow(extension: dict[str, Any], *, identity: str, path: str, label: str) -> dict[str, Any]:
    require(len(extension["workflows"]) == 1, f"{label} must contain exactly one workflow")
    workflow = extension["workflows"][0]
    require(workflow.get("id") == identity, f"{label} workflow identity changed")
    require(workflow.get("path") == path, f"{label} workflow path changed")
    return workflow


def load_combined() -> dict[str, Any]:
    base = load_part(BASE_SNAPSHOT, "base Workflow Capability BOM snapshot")
    action_provenance_witness_extension = load_part(ACTION_PROVENANCE_WITNESS_EXTENSION, "Action provenance witness BOM extension")
    admission_extension = load_part(ADMISSION_EXTENSION, "Capability admission BOM extension")
    autofix_extension = load_part(AUTOFIX_EXTENSION, "CodeQL Autofix BOM extension")
    dependabot_extension = load_part(DEPENDABOT_EXTENSION, "Dependabot controller BOM extension")
    profile_generator_compatibility_witness_extension = load_part(PROFILE_GENERATOR_COMPATIBILITY_WITNESS_EXTENSION, "Profile generator compatibility witness BOM extension")
    bot_pr_user_approval_extension = load_part(BOT_PR_USER_APPROVAL_EXTENSION, "Bot PR user approval BOM extension")
    ruleset_drift_sentinel_extension = load_part(RULESET_DRIFT_SENTINEL_EXTENSION, "Ruleset drift sentinel BOM extension")
    ruleset_reconciler_extension = load_part(RULESET_RECONCILER_EXTENSION, "Ruleset reconciler BOM extension")
    require(len(base["workflows"]) == 5, "base Workflow Capability BOM historical workflow count changed")

    one_workflow(
        action_provenance_witness_extension,
        identity="action-provenance-witness",
        path=".github/workflows/action-provenance-witness.yml",
        label="Action provenance witness BOM extension",
    )
    one_workflow(
        admission_extension,
        identity="capability-admission",
        path=".github/workflows/capability-admission.yml",
        label="Capability admission BOM extension",
    )
    one_workflow(
        autofix_extension,
        identity="codeql-autofix",
        path=".github/workflows/codeql-autofix.yml",
        label="CodeQL Autofix BOM extension",
    )
    one_workflow(
        dependabot_extension,
        identity="dependabot-controller",
        path=".github/workflows/dependabot-controller.yml",
        label="Dependabot controller BOM extension",
    )

    one_workflow(
        profile_generator_compatibility_witness_extension,
        identity="profile-generator-compatibility-witness",
        path=".github/workflows/profile-generator-compatibility-witness.yml",
        label="Profile generator compatibility witness BOM extension",
    )

    one_workflow(
        bot_pr_user_approval_extension,
        identity="bot-pr-user-approval",
        path=".github/workflows/bot-pr-user-approval.yml",
        label="Bot PR user approval BOM extension",
    )
    one_workflow(
        ruleset_drift_sentinel_extension,
        identity="ruleset-drift-sentinel",
        path=".github/workflows/ruleset-drift-sentinel.yml",
        label="Ruleset drift sentinel BOM extension",
    )
    one_workflow(
        ruleset_reconciler_extension,
        identity="ruleset-reconciler",
        path=".github/workflows/ruleset-reconciler.yml",
        label="Ruleset reconciler BOM extension",
    )

    workflows = (
        list(base["workflows"])
        + list(action_provenance_witness_extension["workflows"])
        + list(admission_extension["workflows"])
        + list(autofix_extension["workflows"])
        + list(dependabot_extension["workflows"])
        + list(profile_generator_compatibility_witness_extension["workflows"])
        + list(bot_pr_user_approval_extension["workflows"])
        + list(ruleset_drift_sentinel_extension["workflows"])
        + list(ruleset_reconciler_extension["workflows"])
    )
    ids = [workflow.get("id") for workflow in workflows]
    paths = [workflow.get("path") for workflow in workflows]
    require(len(ids) == len(set(ids)), "composite Workflow Capability BOM contains duplicate workflow IDs")
    require(len(paths) == len(set(paths)), "composite Workflow Capability BOM contains duplicate workflow paths")
    workflows.sort(key=lambda workflow: workflow["path"])

    combined = {key: base[key] for key in base if key != "workflows"}
    combined["workflows"] = workflows
    return combined


def validate_ruleset_reconciler_safety(combined: dict[str, Any]) -> None:
    matches = [workflow for workflow in combined["workflows"] if workflow.get("id") == "ruleset-reconciler"]
    require(len(matches) == 1, "composite Workflow Capability BOM must contain exactly one ruleset reconciler")
    workflow = matches[0]
    require(
        workflow["references"]["secrets"] == RULESET_RECONCILER_ADMIN_SECRETS,
        "ruleset reconciler workflow secret inventory changed",
    )
    jobs = {job["id"]: job for job in workflow["jobs"]}
    reconcile = jobs["reconcile"]
    require(
        reconcile["references"]["secrets"] == RULESET_RECONCILER_ADMIN_SECRETS,
        "ruleset reconciler writer secret inventory changed",
    )
    require(
        reconcile["mutations"] == [
            {
                "class": "github-api-post",
                "method": "POST",
                "step": "Apply only exact reviewed predecessor to successor",
                "target": "app/installations/${ADMIN_INSTALLATION_ID}/access_tokens",
            },
            {
                "class": "github-api-put",
                "method": "PUT",
                "step": "Apply only exact reviewed predecessor to successor",
                "target": "repos/portyu9/portyu9/rulesets/22148161",
            },
        ],
        "ruleset reconciler writer mutation inventory changed",
    )
    source = RULESET_RECONCILER_WORKFLOW.read_text(encoding="utf-8")
    require("PORTYU9_BOT_REVIEW_TOKEN" not in source,
            "ruleset reconciler must never reference the bot-review credential")
    require(
        source.count(
            "    concurrency:\n"
            "      group: ruleset-reconciler-admin-write\n"
            "      cancel-in-progress: false\n"
        ) == 1,
        "ruleset reconciler admin writer lost non-cancellable serialization",
    )
    require(
        source.count('          JWT_EXP="$((ISSUED_AT + 540))"\n') == 1
        and 'JWT_EXP="$(ISSUED_AT + 540))"' not in source,
        "ruleset reconciler GitHub App JWT expiry arithmetic changed",
    )
    require(
        source.count("scripts/ruleset_transition_contract.py classify-observable --live live-plan.json") == 1
        and "needs.plan.outputs.state" not in source,
        "ruleset reconciler planning must treat admin-scope redaction as non-authorizing observable evidence",
    )
    require(
        source.count("scripts/ruleset_transition_contract.py classify --live live-prewrite.json") == 1
        and source.count("scripts/ruleset_transition_contract.py classify --live live-after.json") == 1,
        "ruleset reconciler admin writer lost exact prewrite/readback classification",
    )
    for fragment in (
        '(.app_id | type == "number" and floor == . and . == $app) and',
        '(.target_type | type == "string" and . == "User") and',
        '(.account.id | type == "number" and floor == . and . == 35150859) and',
        '(.account.login | type == "string" and . == "portyu9") and',
        '(.repository_selection | type == "string" and . == "selected") and',
        '(.permissions.administration | type == "string" and . == "write") and',
        '((.permissions | keys - ["administration", "metadata"]) | length == 0) and',
        "-f 'permissions[administration]=write' > installation-token.json",
        '(.total_count | type == "number" and floor == . and . == 1) and',
        '(.repositories[0].id | type == "number" and floor == . and . == 1355082509) and',
    ):
        require(fragment in source,
                f"ruleset reconciler least-authority installation proof changed: {fragment}")
    for fragment in (
        '[[ "$ADMIN_APP_ID" =~ ^[1-9][0-9]*$ ]]',
        '[[ "$ADMIN_INSTALLATION_ID" =~ ^[1-9][0-9]*$ ]]',
        'test -n "$ADMIN_PRIVATE_KEY"',
        'test "$TOKEN_EXPIRES_EPOCH" -gt "$((NOW + 120))"',
        'test "$TOKEN_EXPIRES_EPOCH" -le "$((NOW + 3700))"',
        'if [ "$PREWRITE_STATE" = "successor" ]; then',
        'echo "outcome=already-applied-before-write" >> "$GITHUB_OUTPUT"',
        'test "$PREWRITE_STATE" = "predecessor"',
        'ERROR: ruleset mutation did not converge to the exact reviewed successor; no automatic retry will occur.',
    ):
        require(fragment in source,
                f"ruleset reconciler transaction guard changed: {fragment}")


def self_test() -> None:
    combined = load_combined()
    validate_ruleset_reconciler_safety(combined)
    require(len(combined["workflows"]) == 13, "composite Workflow Capability BOM must contain thirteen workflows")
    require(
        [workflow["path"] for workflow in combined["workflows"]] == [
            ".github/workflows/action-provenance-witness.yml",
            ".github/workflows/bot-pr-user-approval.yml",
            ".github/workflows/capability-admission.yml",
            ".github/workflows/codeql-autofix.yml",
            ".github/workflows/codeql.yml",
            ".github/workflows/dependabot-controller.yml",
            ".github/workflows/dependency-review.yml",
            ".github/workflows/profile-generator-compatibility-witness.yml",
            ".github/workflows/profile-quality.yml",
            ".github/workflows/profile-stats.yml",
            ".github/workflows/ruleset-drift-sentinel.yml",
            ".github/workflows/ruleset-reconciler.yml",
            ".github/workflows/spotlight-link-sync.yml",
        ],
        "composite Workflow Capability BOM ordering changed",
    )
    require(any(workflow["id"] == "action-provenance-witness" for workflow in combined["workflows"]),
            "composite Workflow Capability BOM lost action provenance witness workflow")
    require(any(workflow["id"] == "codeql-autofix" for workflow in combined["workflows"]),
            "composite Workflow Capability BOM lost CodeQL Autofix workflow")
    require(any(workflow["id"] == "dependabot-controller" for workflow in combined["workflows"]),
            "composite Workflow Capability BOM lost Dependabot controller workflow")
    require(any(workflow["id"] == "profile-generator-compatibility-witness" for workflow in combined["workflows"]),
            "composite Workflow Capability BOM lost profile generator compatibility witness workflow")
    require(any(workflow["id"] == "bot-pr-user-approval" for workflow in combined["workflows"]),
            "composite Workflow Capability BOM lost bot PR user approval workflow")
    require(any(workflow["id"] == "ruleset-drift-sentinel" for workflow in combined["workflows"]),
            "composite Workflow Capability BOM lost ruleset drift sentinel workflow")
    require(any(workflow["id"] == "ruleset-reconciler" for workflow in combined["workflows"]),
            "composite Workflow Capability BOM lost ruleset reconciler workflow")


if __name__ == "__main__":
    self_test()
    print("Composite Workflow Capability BOM snapshot validation passed: 13 workflows.")
