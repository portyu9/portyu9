#!/usr/bin/env python3
"""Extend the frozen repository-governance contract with item-11 ADR jobs."""
from __future__ import annotations

import governance_contract_item10_core as core


CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"
UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
UPSTREAM_SHA = "49b5f7091182a45f3ef93923505b660c6da5f835"
ATTEST_SHA = "1e69f48acb82d1966a394da916b4c1698aa569d6"

ORIGINAL_VALIDATE_STATS = core.validate_stats
ORIGINAL_VALIDATE_QUALITY = core.validate_quality


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_action_identity_projection() -> None:
    for name, value in (
        ("CHECKOUT_SHA", CHECKOUT_SHA),
        ("SETUP_PYTHON_SHA", SETUP_PYTHON_SHA),
        ("UPLOAD_SHA", UPLOAD_SHA),
        ("DOWNLOAD_SHA", DOWNLOAD_SHA),
        ("UPSTREAM_SHA", UPSTREAM_SHA),
        ("ATTEST_SHA", ATTEST_SHA),
    ):
        require(value == getattr(core, name),
                f"Governance adapter {name} differs from frozen contract")



def validate_profile_quality_dependabot_admission_evidence(block: str) -> None:
    for fragment in (
        "validate_dependabot_pr_object() {",
        '(.number | type == "number" and . == floor and . > 0 and . == $number) and',
        '(.user | type == "object" and (.login | type == "string" and . == "dependabot[bot]")) and',
        '(.repo | type == "object" and (.full_name | type == "string" and . == $repo))) and',
        '(.repo | type == "object" and (.full_name | type == "string" and . == $head_repo))) and',
        'validate_git_ref_object() {',
        '(.ref | type == "string" and . == $ref) and',
        '(.type | type == "string" and . == "commit") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $sha) and',
        'validate_admission_check_collection() {',
        '($root.total_count | type == "number" and . == floor and . >= 0 and . <= 100) and',
        '($root.check_runs | type == "array" and length == $root.total_count) and',
        '(.name | type == "string" and . == "trusted-capability-admission-proof") and',
        '(.app | type == "object" and (.id | type == "number" and . == 15368)) and',
        '(.status | type == "string" and allowed_status) and',
        '(.external_id == null or (.external_id | type == "string")) and',
        '(.output | type == "object" and',
        '(.check_suite | type == "object" and (.id | positive_int)) and',
        '(([$root.check_runs[].id] | length) ==',
        'ERROR: malformed or mismatched PR-native Dependabot admission PR evidence.',
        'ERROR: malformed or stale PR-native Dependabot admission main-ref evidence.',
        'ERROR: malformed or stale PR-native Dependabot admission head-ref evidence.',
        'ERROR: malformed or incomplete PR-native Dependabot admission check evidence.',
    ):
        require(
            fragment in block,
            f"Profile Quality Dependabot admission evidence schema is missing: {fragment}",
        )

    for forbidden in (
        'git/ref/heads/main" --jq .object.sha',
        'git/ref/heads/${HEAD_REF}" --jq .object.sha',
    ):
        require(
            forbidden not in block,
            f"Profile Quality Dependabot admission regressed to direct ref scalar consumption: {forbidden}",
        )

    require(
        block.count('PR="$(gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}")"') == 1,
        "Profile Quality Dependabot admission PR singleton fetch count changed",
    )
    require(
        block.count('validate_dependabot_pr_object "$PR"') == 1,
        "Profile Quality Dependabot admission PR schema count changed",
    )
    require(
        block.count('validate_git_ref_object "    marker = "  governed_bot_review:\n"
    require(text.count(marker) == 1,
            "Profile Quality native governed-bot review gate must exist exactly once")
    gate = text[text.index(marker):]
    for fragment in (
        "name: trusted-governed-bot-review",
        "runs-on: ubuntu-24.04",
        "permissions:\n      contents: read\n      pull-requests: read",
        "scripts/governed_bot_review_gate.py?ref=${EVENT_BASE_SHA}",
        "EXPECTED_GATE_BLOB: e42c1a8c3204d9a83ac837bbd04743fe3907b41c",
        'python3 "$TRUSTED_GATE" --self-test',
        'python3 "$TRUSTED_GATE"',
    ):
        require(fragment in gate, f"Profile Quality native review gate contract is missing: {fragment}")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "contents: write", "pull-requests: write"):
        require(forbidden not in gate,
                f"Profile Quality native review gate acquired forbidden authority/execution surface: {forbidden}")

    legacy_quality = text[:text.index(marker)]
    validate = core.job_block(legacy_quality, "validate", "integration")
    integration = core.job_block(legacy_quality, "integration", "dependabot_admission")
    witness_permissions = (
        "permissions:\n"
        "      actions: read\n"
        "      attestations: read\n"
        "      contents: read"
    )
    require(validate.count(witness_permissions) == 1,
            "Profile Quality Action-provenance consumer must retain exact read-only authority")
    require(integration.count(witness_permissions) == 1,
            "Profile Quality generator-compatibility consumer must retain exact read-only authority")
    for forbidden in (
        "actions: write",
        "attestations: write",
        "checks: write",
        "contents: write",
        "id-token: write",
        "pull-requests: write",
    ):
        require(forbidden not in validate and forbidden not in integration,
                f"Profile Quality witness consumers acquired forbidden write authority: {forbidden}")

    dependabot_admission = core.job_block(legacy_quality, "dependabot_admission", None)
    validate_profile_quality_dependabot_admission_evidence(dependabot_admission)
    self_test_profile_quality_dependabot_admission_evidence(dependabot_admission)
    require(
        "permissions:\n      checks: read\n      contents: read\n      pull-requests: read" in dependabot_admission,
        "PR-native Dependabot admission gate must retain exact checks/contents/pull-requests read authority",
    )
    require("actions: read" not in dependabot_admission,
            "PR-native Dependabot admission gate must not acquire Actions authority")
    for forbidden in ("actions: write", "checks: write", "contents: write", "pull-requests: write",
                      "id-token: write", "attestations: write"):
        require(forbidden not in dependabot_admission,
                f"PR-native Dependabot admission gate acquired forbidden write authority: {forbidden}")
    for fragment in (
        "dependabot-delegated-admission:([1-9][0-9]*):([1-9][0-9]*):([0-9a-f]{64})",
        ".retryHistory | type == \"array\"",
        ".workflowRun ==",
        "SUMMARY_SHA256",
    ):
        require(fragment in dependabot_admission,
                f"PR-native Dependabot retry-history proof contract is missing: {fragment}")

    projected_quality = legacy_quality.replace(
        witness_permissions,
        "permissions:\n      contents: read",
        1,
    )
    projected_quality = projected_quality.replace(
        witness_permissions,
        "permissions:\n      contents: read",
        1,
    )
    projected_quality = projected_quality.replace(
        'if [[ "$EXTERNAL_ID" =~ ^dependabot-delegated-admission:([1-9][0-9]*):([1-9][0-9]*):([0-9a-f]{64}):${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}$ ]]; then',
        'EXTERNAL_ID="dependabot-delegated-admission:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
        1,
    )
    ORIGINAL_VALIDATE_QUALITY(projected_quality)


def validate_stats_item11(text: str) -> None:
    require(text.count("runs-on: ubuntu-24.04") == 11,
            "All eleven Profile Stats jobs must pin ubuntu-24.04")
    preparer = core.job_block(text, "decision_receipt", "decision_receipt_attest")
    signer = core.job_block(text, "decision_receipt_attest", None)
    require("name: prepare-automation-decision-receipt-read-only" in preparer,
            "Profile Stats ADR preparer identity changed")
    require("permissions:\n      contents: read\n      actions: read" in preparer,
            "Profile Stats ADR preparer must remain contents/actions read-only")
    require("needs: [dispatch, lease]" in preparer,
            "Profile Stats ADR preparer dependency closure changed")
    require("name: attest-automation-decision-receipt-write-only" in signer,
            "Profile Stats ADR signer identity changed")
    require("permissions:\n      contents: read\n      id-token: write\n      attestations: write" in signer,
            "Profile Stats ADR signer authority changed")
    require("needs: [decision_receipt, lease, attest]" in signer,
            "Profile Stats ADR signer dependency closure changed")
    for forbidden in ("contents: write", "actions: write", "pull-requests: write", "checks: write"):
        require(forbidden not in preparer and forbidden not in signer,
                f"Profile Stats ADR jobs acquired unrelated write authority: {forbidden}")

    marker = "  decision_receipt:\n"
    require(text.count(marker) == 1,
            "Profile Stats ADR projection cannot isolate decision receipt tail")
    tail = text[text.index(marker):]
    require(tail.count("  decision_receipt_attest:\n") == 1,
            "Profile Stats ADR projection cannot isolate signer")
    ORIGINAL_VALIDATE_STATS(text[:text.index(marker)])


def main() -> int:
    original_stats = core.validate_stats
    original_quality = core.validate_quality
    core.validate_stats = validate_stats_item11
    core.validate_quality = validate_quality_native_gate
    try:
        validate_action_identity_projection()
        return core.main()
    finally:
        core.validate_stats = original_stats
        core.validate_quality = original_quality


if __name__ == "__main__":
    raise SystemExit(main())
) == 2,
        "Profile Quality Dependabot admission must type exactly both Git-ref reads",
    )
    require(
        block.count('validate_admission_check_collection "$CHECKS"') == 1,
        "Profile Quality Dependabot admission check collection schema count changed",
    )

    boundaries = (
        (
            'PR="$(gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}")"',
            'validate_dependabot_pr_object "$PR"',
            'MAIN_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main")"',
            "PR singleton",
        ),
        (
            'MAIN_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main")"',
            'validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$BASE_SHA"',
            'HEAD_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}")"',
            "main ref",
        ),
        (
            'HEAD_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}")"',
            'validate_git_ref_object "$HEAD_REF_RESPONSE" "refs/heads/${HEAD_REF}" "$HEAD_SHA"',
            'CHECKS="$(gh api "repos/${TARGET_REPOSITORY}/commits/${HEAD_SHA}/check-runs?app_id=15368&check_name=trusted-capability-admission-proof&filter=latest&per_page=100")"',
            "head ref",
        ),
        (
            'CHECKS="$(gh api "repos/${TARGET_REPOSITORY}/commits/${HEAD_SHA}/check-runs?app_id=15368&check_name=trusted-capability-admission-proof&filter=latest&per_page=100")"',
            'validate_admission_check_collection "$CHECKS"',
            'if [ "$(jq -r .total_count <<<"$CHECKS")" = "1" ]; then',
            "check collection",
        ),
    )
    for fetch, schema, consume, label in boundaries:
        fetch_pos = block.index(fetch)
        schema_pos = block.index(schema, fetch_pos)
        consume_pos = block.index(consume, schema_pos)
        require(
            fetch_pos < schema_pos < consume_pos,
            f"Profile Quality Dependabot admission must type {label} evidence before consumption",
        )


def self_test_profile_quality_dependabot_admission_evidence(block: str) -> None:
    mutations = (
        (
            '(.number | type == "number" and . == floor and . > 0 and . == $number) and',
            '(.number | tostring == ($number | tostring)) and',
            "evidence schema is missing",
        ),
        (
            'validate_admission_check_collection "$CHECKS"',
            'true # displaced admission check schema',
            "check collection schema count changed",
        ),
        (
            'MAIN_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main")"',
            'MAIN_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main" --jq .object.sha)"',
            "direct ref scalar consumption",
        ),
    )
    for current, mutated_value, expected in mutations:
        require(current in block, f"Profile Quality admission self-test fixture anchor changed: {current}")
        mutated = block.replace(current, mutated_value, 1)
        try:
            validate_profile_quality_dependabot_admission_evidence(mutated)
        except ValueError as exc:
            require(
                expected in str(exc),
                f"Profile Quality admission self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                f"Profile Quality admission self-test accepted forbidden mutation: {expected}"
            )


def validate_quality_native_gate(text: str) -> None:
    marker = "  governed_bot_review:\n"
    require(text.count(marker) == 1,
            "Profile Quality native governed-bot review gate must exist exactly once")
    gate = text[text.index(marker):]
    for fragment in (
        "name: trusted-governed-bot-review",
        "runs-on: ubuntu-24.04",
        "permissions:\n      contents: read\n      pull-requests: read",
        "scripts/governed_bot_review_gate.py?ref=${EVENT_BASE_SHA}",
        "EXPECTED_GATE_BLOB: e42c1a8c3204d9a83ac837bbd04743fe3907b41c",
        'python3 "$TRUSTED_GATE" --self-test',
        'python3 "$TRUSTED_GATE"',
    ):
        require(fragment in gate, f"Profile Quality native review gate contract is missing: {fragment}")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "contents: write", "pull-requests: write"):
        require(forbidden not in gate,
                f"Profile Quality native review gate acquired forbidden authority/execution surface: {forbidden}")

    legacy_quality = text[:text.index(marker)]
    validate = core.job_block(legacy_quality, "validate", "integration")
    integration = core.job_block(legacy_quality, "integration", "dependabot_admission")
    witness_permissions = (
        "permissions:\n"
        "      actions: read\n"
        "      attestations: read\n"
        "      contents: read"
    )
    require(validate.count(witness_permissions) == 1,
            "Profile Quality Action-provenance consumer must retain exact read-only authority")
    require(integration.count(witness_permissions) == 1,
            "Profile Quality generator-compatibility consumer must retain exact read-only authority")
    for forbidden in (
        "actions: write",
        "attestations: write",
        "checks: write",
        "contents: write",
        "id-token: write",
        "pull-requests: write",
    ):
        require(forbidden not in validate and forbidden not in integration,
                f"Profile Quality witness consumers acquired forbidden write authority: {forbidden}")

    dependabot_admission = core.job_block(legacy_quality, "dependabot_admission", None)
    require(
        "permissions:\n      checks: read\n      contents: read\n      pull-requests: read" in dependabot_admission,
        "PR-native Dependabot admission gate must retain exact checks/contents/pull-requests read authority",
    )
    require("actions: read" not in dependabot_admission,
            "PR-native Dependabot admission gate must not acquire Actions authority")
    for forbidden in ("actions: write", "checks: write", "contents: write", "pull-requests: write",
                      "id-token: write", "attestations: write"):
        require(forbidden not in dependabot_admission,
                f"PR-native Dependabot admission gate acquired forbidden write authority: {forbidden}")
    for fragment in (
        "dependabot-delegated-admission:([1-9][0-9]*):([1-9][0-9]*):([0-9a-f]{64})",
        ".retryHistory | type == \"array\"",
        ".workflowRun ==",
        "SUMMARY_SHA256",
    ):
        require(fragment in dependabot_admission,
                f"PR-native Dependabot retry-history proof contract is missing: {fragment}")

    projected_quality = legacy_quality.replace(
        witness_permissions,
        "permissions:\n      contents: read",
        1,
    )
    projected_quality = projected_quality.replace(
        witness_permissions,
        "permissions:\n      contents: read",
        1,
    )
    projected_quality = projected_quality.replace(
        'if [[ "$EXTERNAL_ID" =~ ^dependabot-delegated-admission:([1-9][0-9]*):([1-9][0-9]*):([0-9a-f]{64}):${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}$ ]]; then',
        'EXTERNAL_ID="dependabot-delegated-admission:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
        1,
    )
    ORIGINAL_VALIDATE_QUALITY(projected_quality)


def validate_stats_item11(text: str) -> None:
    require(text.count("runs-on: ubuntu-24.04") == 11,
            "All eleven Profile Stats jobs must pin ubuntu-24.04")
    preparer = core.job_block(text, "decision_receipt", "decision_receipt_attest")
    signer = core.job_block(text, "decision_receipt_attest", None)
    require("name: prepare-automation-decision-receipt-read-only" in preparer,
            "Profile Stats ADR preparer identity changed")
    require("permissions:\n      contents: read\n      actions: read" in preparer,
            "Profile Stats ADR preparer must remain contents/actions read-only")
    require("needs: [dispatch, lease]" in preparer,
            "Profile Stats ADR preparer dependency closure changed")
    require("name: attest-automation-decision-receipt-write-only" in signer,
            "Profile Stats ADR signer identity changed")
    require("permissions:\n      contents: read\n      id-token: write\n      attestations: write" in signer,
            "Profile Stats ADR signer authority changed")
    require("needs: [decision_receipt, lease, attest]" in signer,
            "Profile Stats ADR signer dependency closure changed")
    for forbidden in ("contents: write", "actions: write", "pull-requests: write", "checks: write"):
        require(forbidden not in preparer and forbidden not in signer,
                f"Profile Stats ADR jobs acquired unrelated write authority: {forbidden}")

    marker = "  decision_receipt:\n"
    require(text.count(marker) == 1,
            "Profile Stats ADR projection cannot isolate decision receipt tail")
    tail = text[text.index(marker):]
    require(tail.count("  decision_receipt_attest:\n") == 1,
            "Profile Stats ADR projection cannot isolate signer")
    ORIGINAL_VALIDATE_STATS(text[:text.index(marker)])


def main() -> int:
    original_stats = core.validate_stats
    original_quality = core.validate_quality
    core.validate_stats = validate_stats_item11
    core.validate_quality = validate_quality_native_gate
    try:
        validate_action_identity_projection()
        return core.main()
    finally:
        core.validate_stats = original_stats
        core.validate_quality = original_quality


if __name__ == "__main__":
    raise SystemExit(main())
