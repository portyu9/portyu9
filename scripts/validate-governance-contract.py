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
        "name: Prove exact PR-native Dependabot context",
        "validate_dependabot_pr_object() {",
        '(.maintainer_can_modify | type == "boolean" and . == false) and',
        "validate_git_ref_object() {",
        "validate_contents_file_object() {",
        'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > "$RUNNER_TEMP/dependabot-pr.json"',
        'MAIN_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main")"',
        'HEAD_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}")"',
        'BASE_GATE="$(gh api "repos/${TARGET_REPOSITORY}/contents/.github/workflows/profile-quality.yml?ref=${BASE_SHA}")"',
        'HEAD_GATE="$(gh api "repos/${TARGET_REPOSITORY}/contents/.github/workflows/profile-quality.yml?ref=${HEAD_SHA}")"',
        'test "$BASE_GATE_BLOB" = "$HEAD_GATE_BLOB" || {',
        "name: Checkout exact accepted-base trusted admission source",
        "ref: ${{ github.event.pull_request.base.sha }}",
        "path: trusted-base",
        "name: Checkout exact Dependabot candidate as inert data",
        "ref: ${{ github.event.pull_request.head.sha }}",
        "path: candidate-source",
        "name: Set up Python",
        "name: Verify resolved Python runtime",
        "run: python3 scripts/verify-python-runtime.py",
        "working-directory: trusted-base",
        "name: Verify exact accepted-base admission source identity",
        'test "$(git -C trusted-base rev-parse HEAD)" = "$BASE_SHA"',
        'test "$(git -C candidate-source rev-parse HEAD)" = "$HEAD_SHA"',
        'HEAD:scripts/dependabot_capability_admission.py)" = "96107595641a0f9ff0203d9df2b684b1822b0346"',
        'HEAD:scripts/dependabot_controller.py)" = "b47cda8236412e8a051df46c80ad8520b2b56afa"',
        'HEAD:scripts/dependabot_release.py)" = "229faaf9eadb7f187b71ce5c25809258cbf0c23a"',
        'HEAD:scripts/workflow_capability_api_collection.py)" = "fd111c3aae1ecaf704e522f17a998118978aa994"',
        'HEAD:scripts/workflow_capability_tcb.py)" = "963da472bad7f0ba7270dee0393a132a20dd4cc6"',
        "name: Fetch exact candidate release evidence",
        'gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100"',
        "trusted-base/scripts/workflow_capability_api_collection.py files",
        "trusted-base/scripts/dependabot_controller.py probe",
        '--base-root trusted-base',
        '--candidate-root candidate-source',
        'git ls-remote --tags "https://github.com/${DEPENDENCY_REPOSITORY}.git"',
        'gh api "repos/${DEPENDENCY_REPOSITORY}"',
        'gh api "repos/${DEPENDENCY_REPOSITORY}/releases/tags/${CANDIDATE_TAG}"',
        "trusted-base/scripts/dependabot_release.py",
        "name: Evaluate exact accepted-base semantic admission",
        'PYTHONPATH="$GITHUB_WORKSPACE/trusted-base/scripts"',
        "trusted-base/scripts/dependabot_capability_admission.py",
        '.decision.authorizationId == "delegated-dependabot-codeql-v1"',
        "passed without cross-run proof polling",
    ):
        require(
            fragment in block,
            f"Profile Quality self-contained Dependabot admission contract is missing: {fragment}",
        )

    require(
        block.count(f"actions/checkout@{CHECKOUT_SHA}") == 2
        and block.count(f"actions/setup-python@{SETUP_PYTHON_SHA}") == 1,
        "PR-native Dependabot admission must use exactly two immutable checkouts and one exact Python setup",
    )
    require(
        block.count('PYTHONPATH="$GITHUB_WORKSPACE/trusted-base/scripts"') == 2,
        "PR-native Dependabot admission must execute both trusted Python phases from accepted-base modules",
    )
    for forbidden in (
        "trusted-capability-admission-proof",
        "check-runs?app_id=",
        "for ATTEMPT in $(seq 1 36); do",
        "sleep 5",
        "python3 candidate-source/",
        "./candidate-source/",
        "working-directory: candidate-source",
        "uses: ./candidate-source",
        "actions: write",
        "checks: write",
        "contents: write",
        "pull-requests: write",
        "id-token: write",
        "attestations: write",
    ):
        require(
            forbidden not in block,
            f"PR-native Dependabot admission acquired forbidden relay/candidate/write surface: {forbidden}",
        )

    boundaries = (
        (
            'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > "$RUNNER_TEMP/dependabot-pr.json"',
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
            'BASE_GATE="$(gh api "repos/${TARGET_REPOSITORY}/contents/.github/workflows/profile-quality.yml?ref=${BASE_SHA}")"',
            "head ref",
        ),
        (
            'BASE_GATE="$(gh api "repos/${TARGET_REPOSITORY}/contents/.github/workflows/profile-quality.yml?ref=${BASE_SHA}")"',
            'validate_contents_file_object "$BASE_GATE" ".github/workflows/profile-quality.yml"',
            'BASE_GATE_BLOB="$(jq -r .sha <<<"$BASE_GATE")"',
            "accepted-base workflow blob",
        ),
        (
            'HEAD_GATE="$(gh api "repos/${TARGET_REPOSITORY}/contents/.github/workflows/profile-quality.yml?ref=${HEAD_SHA}")"',
            'validate_contents_file_object "$HEAD_GATE" ".github/workflows/profile-quality.yml"',
            'HEAD_GATE_BLOB="$(jq -r .sha <<<"$HEAD_GATE")"',
            "candidate workflow blob",
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
            'test "$BASE_GATE_BLOB" = "$HEAD_GATE_BLOB" || {',
            'true || {',
            "contract is missing",
        ),
        (
            "ref: ${{ github.event.pull_request.base.sha }}",
            "ref: ${{ github.event.pull_request.head.sha }}",
            "contract is missing",
        ),
        (
            'PYTHONPATH="$GITHUB_WORKSPACE/trusted-base/scripts"',
            'PYTHONPATH="$GITHUB_WORKSPACE/candidate-source/scripts"',
            "contract is missing",
        ),
        (
            'echo "Exact accepted-base PR-native Dependabot semantic admission passed without cross-run proof polling."',
            'for ATTEMPT in $(seq 1 36); do sleep 5; done',
            "forbidden relay/candidate/write surface",
        ),
        (
            'HEAD:scripts/dependabot_capability_admission.py)" = "96107595641a0f9ff0203d9df2b684b1822b0346"',
            'HEAD:scripts/dependabot_capability_admission.py)" = "' + ("0" * 40) + '"',
            "contract is missing",
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
    validate_profile_quality_dependabot_admission_evidence(dependabot_admission)
    self_test_profile_quality_dependabot_admission_evidence(dependabot_admission)
    require(
        "permissions:\n      contents: read\n      pull-requests: read" in dependabot_admission,
        "PR-native Dependabot admission gate must retain exact contents/pull-requests read authority",
    )
    require("checks: read" not in dependabot_admission and "actions: read" not in dependabot_admission,
            "PR-native Dependabot admission gate must not depend on check/action read authority")

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
    projected_dependabot = core.job_block(projected_quality, "dependabot_admission", None)
    frozen_projection = """  dependabot_admission:
    if: >-
      github.event_name == 'pull_request' &&
      github.event.pull_request.user.login == 'dependabot[bot]' &&
      github.event.pull_request.head.repo.full_name == github.repository &&
      startsWith(github.event.pull_request.head.ref, 'dependabot/github_actions/')
    name: ${{ github.event_name == 'pull_request' && github.event.pull_request.user.login == 'dependabot[bot]' && github.event.pull_request.head.repo.full_name == github.repository && startsWith(github.event.pull_request.head.ref, 'dependabot/github_actions/') && 'trusted-capability-admission' || 'dependabot-admission-not-applicable' }}
    runs-on: ubuntu-24.04
    permissions:
      checks: read
      contents: read
      pull-requests: read
    steps:
      - name: Frozen item-10 Dependabot admission projection
        run: |
          EXTERNAL_ID="dependabot-delegated-admission:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"
          # check_name=trusted-capability-admission-proof
          # .name == "trusted-capability-admission-proof"
          # .app.id == 15368
          # .status == "completed"
          # .conclusion == "success"
"""
    projected_quality = projected_quality.replace(projected_dependabot, frozen_projection, 1)
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
