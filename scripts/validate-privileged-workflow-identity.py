#!/usr/bin/env python3
"""Lock privileged workflow bytes and item-10/11 terminal authorization semantics."""
from __future__ import annotations

from pathlib import Path
import sys

import privileged_workflow_identity_v21_core as v21

ROOT = Path(__file__).resolve().parents[1]
VERSION = "governed-workflow-byte-identity-v108"
EXPECTED = {
    ".github/workflows/bot-pr-user-approval.yml": "09176420becea053799334de00c7dcb1b7dfdc2f",
    ".github/workflows/profile-quality.yml": "a7d8d1ba7086992ba6aa251e50d827ca67e0bda4",
    ".github/workflows/profile-stats.yml": "12c277482657ebf7d6cf7c48047bda3cf678346a",
    ".github/workflows/spotlight-link-sync.yml": "f0a4f21670607cc7b7a55529cbe6527f07e83a2b",
}

TRUSTED_GOVERNED_BOT_REVIEW_GATE = "e42c1a8c3204d9a83ac837bbd04743fe3907b41c"
ACCEPTED_BASE_GOVERNED_BOT_REVIEW_GATE = "e42c1a8c3204d9a83ac837bbd04743fe3907b41c"
SPOTLIGHT_BUDGET_JQ_RUNTIME_TEST_BLOB = "be08b177e329343ff547b66c742e221d9cf9afed"

OLD_MERGE_IF = (
    "    if: needs.plan.outputs.changed == 'true' && needs.budget.outputs.allowed == 'true' && "
    "needs.propose.result == 'success' && needs.approve.result == 'success'\n"
    "    name: merge-readme-only-terminal-write"
)
NEW_MERGE_IF = (
    "    if: needs.plan.outputs.changed == 'true' && needs.budget.outputs.allowed == 'true' && "
    "needs.propose.result == 'success' && needs.approve.result == 'success' && "
    "needs.authorize.result == 'success' && needs.authorize_attest.result == 'success'\n"
    "    name: merge-readme-only-terminal-write"
)
ADR_PREDICATE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "automation-decision-receipt-v1.schema.json"
)
IMMUTABLE_COMMENT = "# Validate the complete candidate object before first publication or retry reuse."
IMMUTABLE_ANCHOR = (
    '          fi\n\n'
    '          CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"\n'
)
IMMUTABLE_PROJECTED = (
    '          fi\n\n'
    f'          {IMMUTABLE_COMMENT}\n'
    '          CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"\n'
)

HARDENED_RUN_BRANCH_PROOF = '                  (.head_branch != $branch) or'
LEGACY_RUN_BRANCH_PROOF = 'test "$(jq -r .head_branch <<<"$RUN")" = "$CANDIDATE_BRANCH"'


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def job_block(text: str, job: str, next_job: str | None) -> str:
    start_marker = f"  {job}:\n"
    require(text.count(start_marker) == 1, f"governed workflow must contain exactly one {job} job")
    start = text.index(start_marker)
    if next_job is None:
        return text[start:]
    end_marker = f"  {next_job}:\n"
    require(text.count(end_marker) == 1, f"governed workflow must contain exactly one {next_job} job")
    end = text.index(end_marker, start)
    return text[start:end]


def validate_spotlight_budget_artifact_history(spotlight: str) -> None:
    budget = job_block(spotlight, "budget", "quarantine")
    artifact_call = 'ARTIFACTS="$(gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${ARTIFACT_NAME}&per_page=100")"'
    schema_marker = 'jq -e --arg name "$ARTIFACT_NAME" --arg base "$BASE_SHA" --argjson repo "$GITHUB_REPOSITORY_ID"'
    schema_end_marker = '\' <<<"$ARTIFACTS" >/dev/null || {'
    total_marker = 'TOTAL="$(jq -r \'.total_count // empty\' <<<"$ARTIFACTS")"'
    count_marker = 'COUNT="$(jq \'.artifacts | length\' <<<"$ARTIFACTS")"'
    completeness_marker = 'test "$TOTAL" = "$COUNT" || {'
    invalid_marker = 'INVALID="$(jq \\'
    current_marker = 'CURRENT="$(jq --argjson run_id "$GITHUB_RUN_ID"'
    decision_marker = 'if [ "$TOTAL" -le "$MAX_ATTEMPTS" ]; then'
    allowed_output = 'echo "allowed=$ALLOWED" >> "$GITHUB_OUTPUT"'
    attempt_output = 'echo "attempt_count=$TOTAL" >> "$GITHUB_OUTPUT"'
    markers = (
        artifact_call, schema_marker, schema_end_marker, total_marker, count_marker,
        completeness_marker, invalid_marker, current_marker, decision_marker,
        allowed_output, attempt_output,
    )
    for marker in markers:
        require(
            budget.count(marker) == 1,
            f"Spotlight governed mutation-budget artifact-history anchor changed: {marker}",
        )
    positions = [budget.index(marker) for marker in markers]
    require(
        positions == sorted(positions),
        "Spotlight governed mutation-budget artifact-history ordering changed",
    )
    schema_start = budget.index(schema_marker)
    schema_end = budget.index(schema_end_marker, schema_start) + len(schema_end_marker)
    schema = budget[schema_start:schema_end]
    for fragment in (
        '            (type == "object") and\n'
        '            (.total_count | type == "number" and . == floor and . >= 0 and . <= 100) and',
        '(.artifacts | type == "array") and',
        '((.artifacts | length) == .total_count) and',
        '            (all(.artifacts[];\n'
        '              (type == "object") and\n'
        '              (.id | (type == "number") and (. == floor) and (. > 0)) and',
        '(.id | (type == "number") and (. == floor) and (. > 0)) and',
        '(.name | type == "string" and . == $name) and',
        '(.id | (type == "number") and (. > 0) and (. == floor)) and',
        '(.expired | type == "boolean" and . == false) and',
        '(.workflow_run | type == "object" and',
        '(.repository_id | type == "number" and . == floor and . == $repo) and',
        '(.head_repository_id | type == "number" and . == floor and . == $repo) and',
        '(.head_branch | type == "string" and . == "main") and',
        '(.head_sha | type == "string" and test("^[0-9a-f]{40}$") and . == $base)',
        '(([.artifacts[].id] | length) == ([.artifacts[].id] | unique | length))',
    ):
        require(
            fragment in schema,
            f"Spotlight governed mutation-budget artifact-history schema changed: {fragment}",
        )


def validate_item10_mac(spotlight: str) -> None:
    authorize = job_block(spotlight, "authorize", "authorize_attest")
    signer = job_block(spotlight, "authorize_attest", "merge")
    merge = job_block(spotlight, "merge", "decision_receipt")

    require("name: prepare-merge-authorization-read-only" in authorize,
            "Spotlight MAC preparer identity changed")
    require("needs: [plan, lease, reconcile, budget, propose, approve]" in authorize,
            "Spotlight MAC preparer dependency closure changed")
    require(
        "permissions:\n      contents: read\n      pull-requests: read\n      checks: read\n      actions: read" in authorize,
        "Spotlight MAC preparer must remain read-only",
    )
    for fragment in (
        "python3 source/scripts/prepare-spotlight-merge-authorization.py merge-authorization-state.json",
        "python3 source/scripts/build-spotlight-merge-authorization.py",
        "name: spotlight-merge-authorization-${{ needs.propose.outputs.head_sha }}",
        "retention-days: 1",
    ):
        require(fragment in authorize, f"Spotlight MAC preparer contract is missing: {fragment}")
    for forbidden in ("--method POST", "--method PUT", "--method PATCH", "--method DELETE"):
        require(forbidden not in authorize, f"Spotlight MAC preparer acquired mutation authority: {forbidden}")

    require("name: attest-merge-authorization-write-only" in signer,
            "Spotlight MAC signer identity changed")
    require("needs: [authorize, lease, plan, propose, approve]" in signer,
            "Spotlight MAC signer dependency closure changed")
    require(
        "permissions:\n      contents: read\n      id-token: write\n      attestations: write" in signer,
        "Spotlight MAC signer authority changed",
    )
    require("timeout-minutes: 2" in signer and "LEASE_MIN_REMAINING_SECONDS=180" in signer,
            "Spotlight MAC signer lease reserve no longer covers its hard timeout")
    for fragment in (
        "- name: Verify exact short-lived mutation lease",
        "- name: Download exact merge authorization artifact",
        "- name: Verify exact merge authorization artifact identity",
        "- name: Attest exact Spotlight merge authorization certificate",
        "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2",
        "subject-path: merge-authorization-input/spotlight-merge-authorization.subject.json",
        "predicate-type: https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/spotlight-merge-authorization-v1.schema.json",
        "predicate-path: merge-authorization-input/spotlight-merge-authorization.json",
    ):
        require(fragment in signer, f"Spotlight MAC signer contract is missing: {fragment}")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "gh api ", "--method "):
        require(forbidden not in signer, f"Spotlight MAC signer acquired unreviewed execution surface: {forbidden}")

    require(NEW_MERGE_IF in merge, "Spotlight terminal merge is not gated by MAC preparation/signing")
    require(
        "needs: [plan, lease, reconcile, budget, propose, approve, authorize, authorize_attest]" in merge,
        "Spotlight terminal merge MAC dependency closure changed",
    )
    require(
        "permissions:\n      actions: read\n      contents: write\n      pull-requests: read\n      checks: read\n      attestations: read" in merge,
        "Spotlight terminal merge must retain only merge authority plus read-only Actions/certificate verification",
    )
    for fragment in (
        "- name: Download attested merge authorization artifact",
        "EXPECTED_CERTIFICATE_SHA256: ${{ needs.authorize.outputs.certificate_sha256 }}",
        "EXPECTED_SUBJECT_SHA256: ${{ needs.authorize.outputs.subject_sha256 }}",
        'test "$(printf \'%s\\n\' "$CODEQL_RUN_ID" "$DEPENDENCY_RUN_ID" "$PROFILE_RUN_ID" | LC_ALL=C sort -u | wc -l)" = "3"',
        'test "$(printf \'%s\\n\' "$CODEQL_CHECK_SUITE_ID" "$DEPENDENCY_CHECK_SUITE_ID" "$PROFILE_CHECK_SUITE_ID" | LC_ALL=C sort -u | wc -l)" = "3"',
        '[[ "$CHECKS_TOTAL" =~ ^[0-9]+$ ]]',
        '[[ "$CHECKS_COUNT" =~ ^[0-9]+$ ]]',
        '[[ "$EXPECTED_CERTIFICATE_SHA256" =~ ^[0-9a-f]{64}$ ]]',
        '[[ "$EXPECTED_SUBJECT_SHA256" =~ ^[0-9a-f]{64}$ ]]',
        "gh attestation verify \"$SUBJECT\"",
        "--predicate-type https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/spotlight-merge-authorization-v1.schema.json",
        '--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/spotlight-link-sync.yml"',
        '--signer-digest "$BASE_SHA"',
        '--source-digest "$BASE_SHA"',
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
        "jq -cS '.workflowRuns | sort_by(.name)'",
        'jq -cS . <<<"$EXPECTED_CERTIFICATE_RUNS"',
        "jq -cS '.checkRuns | sort_by(.name)'",
        'jq -cS . <<<"$EXPECTED_CERTIFICATE_CHECKS"',
        'echo "Spotlight terminal stage: certificate-provenance-verified" >&2',
        '.verificationResult.statement',
        '.subject[0].digest.sha256 == $subject_digest',
        'test "$MATCHING_STATEMENTS" = "$VERIFIED_COUNT"',
        'echo "Spotlight terminal stage: attestation-cryptographic-verified" >&2',
        'echo "Spotlight terminal stage: attestation-statement-verified" >&2',
        'REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"',
        'repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100',
        '.user.login == "portyu9"',
        '.state == "APPROVED"',
        '.commit_id == $head',
        '--arg marker "$REVIEW_MARKER"',
        'contains($marker)',
        'echo "Spotlight terminal stage: exact-base-head-portyu9-approval-and-manual-veto-verified" >&2',
        'MERGE_HTTP_RESPONSE="$(gh api --include --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge" --input merge.json)"',
        'MERGE_STATUS_LINE="$(head -n 1 <<<"$MERGE_HTTP_RESPONSE" | tr -d \'\\r\')"',
        '[[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {',
        'ERROR: Spotlight terminal merge returned unexpected status:',
        'RESULT="$(sed \'1,/^[[:space:]]*$/d\' <<<"$MERGE_HTTP_RESPONSE")"',
        'MERGE_SUCCESS_FILTER=\'if type != "object" then error("Spotlight merge response must be an object")',
        'elif (.merged | type) != "boolean" or .merged != true',
        '(.sha | test("^[0-9a-f]{40}$") | not)',
        '(.message | type) != "string" or (.message | length) == 0',
        'VALIDATED_MERGE="$(jq -ce "$MERGE_SUCCESS_FILTER" <<<"$RESULT")"',
        'MERGE_SHA="$(jq -r .sha <<<"$VALIDATED_MERGE")"',
        'validate_terminal_pr_object() {',
        'validate_terminal_pr_object "$PR"',
        '((.user | type) == "object" and (.user.login | type) == "string" and (.user.login | length) > 0) and',
        '(.draft | type == "boolean") and',
        '(.merged | type == "boolean") and',
        '(.maintainer_can_modify | type == "boolean") and',
        '(type == "array") and',
        '(.status | type == "string" and . == "modified")',
        'jq -e --arg head "$HEAD_SHA"',
        '(.parents | type == "array" and length == 1',
        'validate_terminal_pr_object "$MERGED_PR"',
        'jq -e --argjson pr "$PR_NUMBER" --arg merge "$MERGE_SHA"',
        '(.number == $pr) and',
        '(.merge_commit_sha | type == "string" and test("^[0-9a-f]{40}$") and . == $merge) and',
        '(.base.ref == "main" and .base.sha == $base) and',
        '(.head.ref == $branch and .head.sha == $head and .head.repo.full_name == $repo)',
        'test "$(jq -r .merge_commit_sha <<<"$MERGED_PR")" = "$MERGE_SHA"',
    ):
        require(fragment in merge, f"Spotlight terminal MAC verification contract is missing: {fragment}")
    require("jq -c '.workflowRuns | sort_by(.name)'" not in merge and
            "jq -c '.checkRuns | sort_by(.name)'" not in merge,
            "Spotlight terminal provenance equality must canonicalize object-key order before byte comparison")
    require("[.. | objects" not in merge,
            "Spotlight terminal MAC verification must not recursively search untrusted verifier JSON")
    pre_pr_pos = merge.index('PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"')
    pre_pr_schema_pos = merge.index('validate_terminal_pr_object "$PR"', pre_pr_pos)
    files_pos = merge.index('FILES="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100")"', pre_pr_schema_pos)
    files_schema_pos = merge.index('(type == "array") and', files_pos)
    commit_pos = merge.index('CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"', files_schema_pos)
    commit_schema_pos = merge.index('jq -e --arg head "$HEAD_SHA"', commit_pos)
    provenance_pos = merge.index('echo "Spotlight terminal stage: certificate-provenance-verified" >&2')
    verify_pos = merge.index('gh attestation verify "$SUBJECT"')
    statement_pos = merge.index('.verificationResult.statement')
    merge_pos = merge.index('MERGE_HTTP_RESPONSE="$(gh api --include --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"')
    merge_status_pos = merge.index('MERGE_STATUS_LINE="$(head -n 1 <<<"$MERGE_HTTP_RESPONSE" | tr -d \'\\r\')"', merge_pos)
    merge_guard_pos = merge.index('[[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {', merge_status_pos)
    merge_body_pos = merge.index('RESULT="$(sed \'1,/^[[:space:]]*$/d\' <<<"$MERGE_HTTP_RESPONSE")"', merge_guard_pos)
    response_pos = merge.index('VALIDATED_MERGE="$(jq -ce "$MERGE_SUCCESS_FILTER" <<<"$RESULT")"', merge_body_pos)
    merged_pr_pos = merge.index('MERGED_PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"', response_pos)
    merged_pr_schema_pos = merge.index('validate_terminal_pr_object "$MERGED_PR"', merged_pr_pos)
    merged_pr_identity_pos = merge.index('jq -e --argjson pr "$PR_NUMBER" --arg merge "$MERGE_SHA"', merged_pr_schema_pos)
    merge_sha_bind_pos = merge.index('test "$(jq -r .merge_commit_sha <<<"$MERGED_PR")" = "$MERGE_SHA"', merged_pr_identity_pos)
    current_main_ref_pos = merge.index(
        'CURRENT_MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"'
    )
    current_main_validate_pos = merge.index(
        'validate_git_ref_object "$CURRENT_MAIN_REF_RESPONSE" "refs/heads/main" "$MERGE_SHA"',
        current_main_ref_pos,
    )
    current_main_pos = merge.index(
        'CURRENT_MAIN_SHA="$(jq -r .object.sha <<<"$CURRENT_MAIN_REF_RESPONSE")"',
        current_main_validate_pos,
    )
    cleanup_pos = merge.index('CANDIDATE_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"')
    require(
        pre_pr_pos < pre_pr_schema_pos < files_pos < files_schema_pos < commit_pos < commit_schema_pos
        < provenance_pos < verify_pos < statement_pos < merge_pos < merge_status_pos
        < merge_guard_pos < merge_body_pos < response_pos < merged_pr_pos
        < merged_pr_schema_pos < merged_pr_identity_pos < merge_sha_bind_pos
        < current_main_ref_pos < current_main_validate_pos < current_main_pos < cleanup_pos,
        "Spotlight terminal typed candidate/MAC/merge/post-merge/current-main/cleanup ordering changed",
    )
    require('MERGE_SHA="$(jq -r .sha <<<"$RESULT")"' not in merge,
            "Spotlight terminal merge must not consume the raw merge response SHA")
    for forbidden in ("for attempt in ", "sleep 10", "actions/checkout@", "actions/setup-python@", "python3 "):
        require(forbidden not in merge, f"Spotlight terminal merge acquired polling/authored execution surface: {forbidden}")


def validate_item11_receipts(profile: str, spotlight: str) -> None:
    profile_prepare = job_block(profile, "decision_receipt", "decision_receipt_attest")
    profile_signer = job_block(profile, "decision_receipt_attest", None)
    require("name: prepare-automation-decision-receipt-read-only" in profile_prepare,
            "Profile ADR preparer identity changed")
    require("needs: [dispatch, lease]" in profile_prepare,
            "Profile ADR preparer dependency closure changed")
    require("permissions:\n      contents: read\n      actions: read" in profile_prepare,
            "Profile ADR preparer must remain read-only")
    require("python3 source/scripts/prepare-profile-stats-decision-receipt.py" in profile_prepare and
            "python3 source/scripts/automation_decision_receipt.py" in profile_prepare,
            "Profile ADR preparer lost independent reproof/build boundary")

    require("name: attest-automation-decision-receipt-write-only" in profile_signer,
            "Profile ADR signer identity changed")
    require("needs: [decision_receipt, lease, attest]" in profile_signer,
            "Profile ADR signer dependency closure changed")
    require("permissions:\n      contents: read\n      id-token: write\n      attestations: write" in profile_signer,
            "Profile ADR signer authority changed")
    require(f"predicate-type: {ADR_PREDICATE}" in profile_signer,
            "Profile ADR signer predicate changed")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "gh api ", "--method "):
        require(forbidden not in profile_signer,
                f"Profile ADR signer acquired unreviewed execution surface: {forbidden}")

    spotlight_prepare = job_block(spotlight, "decision_receipt", "decision_receipt_attest")
    spotlight_signer = job_block(spotlight, "decision_receipt_attest", None)
    receipt_gate = (
        "if: always() && needs.lease.result == 'success' && "
        "(needs.reconcile.outputs.stale_cleanup_effect_present == 'true' || "
        "needs.propose.result == 'success' || needs.merge.result == 'success')"
    )
    require(receipt_gate in spotlight_prepare,
            "Spotlight ADR preparer lost explicit durable-effect gate")
    for fragment in (
        "stale_cleanup_effect_present: ${{ steps.reconcile.outputs.stale_cleanup_effect_present }}",
        'echo "stale_cleanup_effect_present=false" >> "$GITHUB_OUTPUT"',
        'echo "stale_cleanup_effect_present=true" >> "$GITHUB_OUTPUT"',
    ):
        require(fragment in spotlight, f"Spotlight ADR stale-effect signal contract is missing: {fragment}")
    require("needs.reconcile.outputs.stale_cleanups_json != '[]'" not in spotlight_prepare
            and "needs.approve.outputs.approval_requests_json != '[]'" not in spotlight_prepare,
            "Spotlight ADR preparer must not gate on skipped-job JSON string inequality")
    require("name: prepare-automation-decision-receipt-read-only" in spotlight_prepare,
            "Spotlight ADR preparer identity changed")
    require("needs: [plan, lease, reconcile, propose, approve, merge]" in spotlight_prepare,
            "Spotlight ADR preparer dependency closure changed")
    require("permissions:\n      contents: read\n      pull-requests: read\n      actions: read" in spotlight_prepare,
            "Spotlight ADR preparer must remain read-only")
    for fragment in (
        "python3 source/scripts/spotlight_decision_journal.py",
        "python3 source/scripts/prepare-spotlight-decision-receipt.py",
        "python3 source/scripts/automation_decision_receipt.py",
        "STALE_CLEANUPS_JSON:",
        "APPROVAL_RUNS_JSON:",
        "MERGE_EFFECT_PRESENT:",
    ):
        require(fragment in spotlight_prepare, f"Spotlight ADR recovery contract is missing: {fragment}")

    require("if: always() && needs.lease.result == 'success' && needs.decision_receipt.result == 'success'" in spotlight_signer,
            "Spotlight ADR signer lost recovery/success gate")
    require("name: attest-automation-decision-receipt-write-only" in spotlight_signer,
            "Spotlight ADR signer identity changed")
    require("needs: [decision_receipt, lease, plan]" in spotlight_signer,
            "Spotlight ADR signer dependency closure changed")
    require("permissions:\n      contents: read\n      id-token: write\n      attestations: write" in spotlight_signer,
            "Spotlight ADR signer authority changed")
    require(f"predicate-type: {ADR_PREDICATE}" in spotlight_signer,
            "Spotlight ADR signer predicate changed")
    require("EXPECTED_CANDIDATE_ID=\"$(printf '%s\\n%s\\n%s\\n'" in spotlight_signer,
            "Spotlight ADR signer must independently reconstruct the leased candidate")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "gh api ", "--method "):
        require(forbidden not in spotlight_signer,
                f"Spotlight ADR signer acquired unreviewed execution surface: {forbidden}")


def validate_leases(profile: str, spotlight: str) -> None:
    v21.validate_ordered_presence(profile, v21.MUTATION_LEASE_SEQUENCE[:7],
                                  "Profile Stats mutation-lease mint contract")
    require(profile.count("- name: Verify exact short-lived mutation lease") == 5,
            "Profile Stats write jobs must each verify the exact lease")
    guard = 'test $((LEASE_EXPIRES_AT - NOW_EPOCH)) -ge "$LEASE_MIN_REMAINING_SECONDS"'
    require(profile.count(guard) == 5,
            "Profile Stats write jobs must each reserve lease lifetime through hard timeout")

    profile_lease = job_block(profile, "lease", "attest_publish")
    profile_run_call_marker = 'RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}")"'
    profile_run_schema_marker = (
        'jq -e --argjson run "$GITHUB_RUN_ID" --argjson attempt "$GITHUB_RUN_ATTEMPT"'
    )
    profile_run_schema_end_marker = '\' <<<"$RUN" >/dev/null'
    profile_run_consume_marker = 'test "$(jq -r .id <<<"$RUN")" = "$GITHUB_RUN_ID"'
    profile_generated_ref_marker = (
        'REMOTE_GENERATED="$(git ls-remote --exit-code "https://github.com/${GITHUB_REPOSITORY}.git" refs/heads/generated)"'
    )
    profile_issued_marker = 'ISSUED_AT="$(date -u +%s)"'
    profile_lease_id_marker = 'LEASE_ID="$(printf'
    profile_output_marker = 'echo "lease_id=$LEASE_ID" >> "$GITHUB_OUTPUT"'
    for marker in (
        profile_run_call_marker, profile_run_schema_marker, profile_run_schema_end_marker,
        profile_run_consume_marker, profile_generated_ref_marker, profile_issued_marker,
        profile_lease_id_marker, profile_output_marker,
    ):
        require(profile_lease.count(marker) == 1,
                f"Profile Stats mutation-lease run evidence contract anchor is missing or ambiguous: {marker}")

    profile_run_call = profile_lease.index(profile_run_call_marker)
    profile_run_schema = profile_lease.index(profile_run_schema_marker)
    profile_run_schema_end = (
        profile_lease.index(profile_run_schema_end_marker, profile_run_schema)
        + len(profile_run_schema_end_marker)
    )
    profile_run_consume = profile_lease.index(profile_run_consume_marker)
    profile_generated_ref = profile_lease.index(profile_generated_ref_marker)
    profile_issued = profile_lease.index(profile_issued_marker)
    profile_lease_id = profile_lease.index(profile_lease_id_marker)
    profile_output = profile_lease.index(profile_output_marker)
    require(
        profile_run_call < profile_run_schema < profile_run_schema_end
        < profile_run_consume < profile_generated_ref < profile_issued
        < profile_lease_id < profile_output,
        "Profile Stats mutation-lease run evidence validation must precede scalar consumption, "
        "generated-ref reproof, and lease issuance",
    )

    profile_schema = profile_lease[profile_run_schema:profile_run_schema_end]
    for fragment in (
        '(type == "object") and',
        '(.id | type == "number" and . == floor and . == $run) and',
        '(.run_attempt | type == "number" and . == floor and . == $attempt) and',
        '(.workflow_id | type == "number" and . == floor and . > 0) and',
        '(.run_number | type == "number" and . == floor and . > 0) and',
        '(.event | type == "string" and . == $event) and',
        '((.status | type) == "string") and',
        '((.status == "queued") or (.status == "in_progress")) and',
        '(.conclusion == null) and',
        '(.head_sha | type == "string" and . == $head) and',
        '(.head_branch | type == "string" and . == "main") and',
        '(.path | type == "string" and . == ".github/workflows/profile-stats.yml") and',
        '(.repository | type == "object" and',
        '(.id | type == "number" and . == floor and . == $repo_id) and',
        '(.full_name | type == "string" and . == $repo)) and',
        '(.head_repository | type == "object" and',
        '(.full_name | type == "string" and . == $repo))',
    ):
        require(fragment in profile_schema,
                f"Profile Stats mutation-lease run evidence contract is missing: {fragment}")

    v21.validate_ordered_presence(spotlight, v21.MUTATION_LEASE_SEQUENCE,
                                  "Spotlight mutation-lease contract")

    lease = job_block(spotlight, "lease", "reconcile")
    run_call_marker = 'RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}")"'
    run_schema_marker = (
        'jq -e --argjson run "$GITHUB_RUN_ID" --argjson attempt "$GITHUB_RUN_ATTEMPT"'
    )
    run_schema_end_marker = '\' <<<"$RUN" >/dev/null'
    run_consume_marker = 'test "$(jq -r .id <<<"$RUN")" = "$GITHUB_RUN_ID"'
    issued_marker = 'ISSUED_AT="$(date -u +%s)"'
    lease_id_marker = 'LEASE_ID="$(printf'
    output_marker = 'echo "lease_id=$LEASE_ID" >> "$GITHUB_OUTPUT"'
    for marker in (
        run_call_marker, run_schema_marker, run_schema_end_marker, run_consume_marker,
        issued_marker, lease_id_marker, output_marker,
    ):
        require(lease.count(marker) == 1,
                f"Spotlight mutation-lease run evidence contract anchor is missing or ambiguous: {marker}")

    run_call = lease.index(run_call_marker)
    run_schema = lease.index(run_schema_marker)
    run_schema_end = lease.index(run_schema_end_marker, run_schema) + len(run_schema_end_marker)
    run_consume = lease.index(run_consume_marker)
    issued = lease.index(issued_marker)
    lease_id = lease.index(lease_id_marker)
    output = lease.index(output_marker)
    require(
        run_call < run_schema < run_schema_end < run_consume < issued < lease_id < output,
        "Spotlight mutation-lease run evidence validation must precede scalar consumption and lease issuance",
    )

    schema = lease[run_schema:run_schema_end]
    for fragment in (
        '(type == "object") and',
        '(.id | type == "number" and . == floor and . == $run) and',
        '(.run_attempt | type == "number" and . == floor and . == $attempt) and',
        '(.workflow_id | type == "number" and . == floor and . > 0) and',
        '(.run_number | type == "number" and . == floor and . > 0) and',
        '(.event | type == "string" and . == $event) and',
        '((.status | type) == "string") and',
        '((.status == "queued") or (.status == "in_progress")) and',
        '(.conclusion == null) and',
        '(.head_sha | type == "string" and . == $head) and',
        '(.head_branch | type == "string" and . == "main") and',
        '(.path | type == "string" and . == ".github/workflows/spotlight-link-sync.yml") and',
        '(.repository | type == "object" and .id == $repo_id and .full_name == $repo) and',
        '(.head_repository | type == "object" and .id == $repo_id and .full_name == $repo)',
    ):
        require(fragment in schema,
                f"Spotlight mutation-lease run evidence contract is missing: {fragment}")

    require(spotlight.count("# Verify exact short-lived mutation lease.") == 4,
            "Spotlight legacy mutation jobs must retain their inline exact-lease proof")
    require(spotlight.count("- name: Verify exact short-lived mutation lease") == 2,
            "Spotlight attestation signers must each retain one exact-lease proof step")
    require(spotlight.count(guard) == 6,
            "Every Spotlight writer must reserve lease lifetime through its hard timeout")
    for fragment in (
        "LEASE_MIN_REMAINING_SECONDS=240",
        "LEASE_MIN_REMAINING_SECONDS=300",
        "LEASE_MIN_REMAINING_SECONDS=780",
        "LEASE_MIN_REMAINING_SECONDS=180",
    ):
        require(fragment in spotlight, f"Spotlight mutation-lease reserve contract is missing: {fragment}")


def project_spotlight_privileged_refs_to_legacy(spotlight: str) -> str:
    helper = '''          validate_git_ref_object() {
            local payload="$1" expected_ref="$2" expected_sha="$3"
            jq -e --arg ref "$expected_ref" --arg sha "$expected_sha" '
              (type == "object") and
              (((.ref | type) == "string") and (.ref == $ref)) and
              (((.object | type) == "object") and
                (((.object.type | type) == "string") and (.object.type == "commit")) and
                (((.object.sha | type) == "string") and
                  (.object.sha | test("^[0-9a-f]{40}$")) and
                  (.object.sha == $sha)) and
                (((.object.url | type) == "string") and ((.object.url | length) > 0)))
            ' <<<"$payload" >/dev/null
          }

'''
    require(
        spotlight.count(helper) == 4,
        "Spotlight v21 projection cannot isolate four privileged Git-ref validators",
    )
    projected = spotlight.replace(helper, "")
    overlays = (
        (
            '''          MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"
          validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$BASE_SHA"
          test "$(jq -r .object.sha <<<"$MAIN_REF_RESPONSE")" = "$BASE_SHA"
''',
            '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"\n',
            5,
        ),
        (
            '''          GENERATED_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated")"
          validate_git_ref_object "$GENERATED_REF_RESPONSE" "refs/heads/generated" "$GENERATED_SHA"
          test "$(jq -r .object.sha <<<"$GENERATED_REF_RESPONSE")" = "$GENERATED_SHA"
''',
            '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated" --jq .object.sha)" = "$GENERATED_SHA"\n',
            4,
        ),
        (
            '''          CANDIDATE_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}")"
          validate_git_ref_object "$CANDIDATE_REF_RESPONSE" "refs/heads/${CANDIDATE_BRANCH}" "$HEAD_SHA"
          test "$(jq -r .object.sha <<<"$CANDIDATE_REF_RESPONSE")" = "$HEAD_SHA"
''',
            '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha)" = "$HEAD_SHA"\n',
            5,
        ),
        (
            '''          MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"
          validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$SOURCE_SHA"
          test "$(jq -r .object.sha <<<"$MAIN_REF_RESPONSE")" = "$SOURCE_SHA"
''',
            '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$SOURCE_SHA"\n',
            1,
        ),
        (
            '''          CURRENT_MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"
          validate_git_ref_object "$CURRENT_MAIN_REF_RESPONSE" "refs/heads/main" "$MERGE_SHA"
          CURRENT_MAIN_SHA="$(jq -r .object.sha <<<"$CURRENT_MAIN_REF_RESPONSE")"
''',
            '          CURRENT_MAIN_SHA="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)"\n',
            1,
        ),
    )
    for hardened, legacy, expected_count in overlays:
        require(
            projected.count(hardened) == expected_count,
            f"Spotlight v21 Git-ref projection topology changed for: {legacy.strip()}",
        )
        projected = projected.replace(hardened, legacy)
    return projected



def project_spotlight_readme_contents_to_legacy(spotlight: str) -> str:
    candidate_digest = (
        "          test \"$(sha256sum candidate-readme.md | cut -d' ' -f1)\" "
        "= \"$README_SHA256_AFTER\""
    )
    current_digest = (
        "          test \"$(sha256sum current-readme.md | cut -d' ' -f1)\" "
        "= \"$(jq -r .readme_sha256_before \"$PLAN\")\""
    )
    overlays = (
        (
            "          MAIN_README_CONTENTS_RESPONSE=\"$(gh api "
            "\"repos/${GITHUB_REPOSITORY}/contents/README.md?ref=main\")\"",
            current_digest,
            (
                "          gh api \"repos/${GITHUB_REPOSITORY}/contents/README.md?ref=main\" "
                "--jq .content \\\n"
                "            | tr -d '\\n' | base64 --decode > current-readme.md\n"
                + current_digest
            ),
        ),
        (
            "          README_BLOB_SHA=\"$(jq -r '.files[0].sha' <<<\"$COMPARE\")\"",
            candidate_digest,
            (
                "          gh api \"repos/${GITHUB_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}\" "
                "--jq .content \\\n"
                "            | tr -d '\\n' | base64 --decode > candidate-readme.md\n"
                + candidate_digest
            ),
        ),
        (
            "          README_BLOB_SHA=\"$(jq -r '.[0].sha' <<<\"$FILES\")\"",
            candidate_digest,
            (
                "          gh api \"repos/${GITHUB_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}\" "
                "--jq .content | tr -d '\\n' | base64 --decode > candidate-readme.md\n"
                + candidate_digest
            ),
        ),
    )
    projected = spotlight
    for start_marker, end_marker, legacy in overlays:
        require(
            projected.count(start_marker) == 1,
            f"Spotlight README Contents projection start anchor changed: {start_marker}",
        )
        start = projected.index(start_marker)
        end_start = projected.index(end_marker, start)
        end = end_start + len(end_marker)
        projected = projected[:start] + legacy + projected[end:]
    return projected


def validate_spotlight_readme_contents_evidence(
    spotlight: str, *, run_self_test: bool = True
) -> None:
    propose = job_block(spotlight, "propose", "approve")
    merge = job_block(spotlight, "merge", "decision_receipt")
    candidate_fetch = (
        "README_CONTENTS_RESPONSE=\"$(gh api "
        "\"repos/${GITHUB_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}\")\""
    )
    candidate_consume = "jq -er '.content' <<<\"$README_CONTENTS_RESPONSE\""
    candidate_digest = (
        "test \"$(sha256sum candidate-readme.md | cut -d' ' -f1)\" "
        "= \"$README_SHA256_AFTER\""
    )
    common_schema = (
        '(type == "object") and',
        '(.type | type == "string" and . == "file") and',
        '(.name | type == "string" and . == "README.md") and',
        '(.path | type == "string" and . == "README.md") and',
        '(.size | type == "number" and . == floor and . >= 0) and',
        '(.encoding | type == "string" and . == "base64") and',
        '(.content | type == "string" and length > 0)',
    )

    main_fetch = (
        "MAIN_README_CONTENTS_RESPONSE=\"$(gh api "
        "\"repos/${GITHUB_REPOSITORY}/contents/README.md?ref=main\")\""
    )
    main_consume = "jq -er '.content' <<<\"$MAIN_README_CONTENTS_RESPONSE\""
    main_digest = (
        "test \"$(sha256sum current-readme.md | cut -d' ' -f1)\" "
        "= \"$(jq -r .readme_sha256_before \"$PLAN\")\""
    )
    for marker in (
        main_fetch,
        main_consume,
        main_digest,
        "malformed Spotlight proposal current-main README Contents evidence",
    ):
        require(
            propose.count(marker) == 1,
            f"Spotlight proposal current-main README Contents anchor changed: {marker}",
        )
    main_ref_validate = (
        'validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$SOURCE_SHA"'
    )
    main_fetch_pos = propose.index(main_fetch)
    main_consume_pos = propose.index(main_consume)
    main_digest_pos = propose.index(main_digest)
    require(
        propose.index(main_ref_validate) < main_fetch_pos < main_consume_pos < main_digest_pos,
        "Spotlight proposal current-main README Contents evidence must follow typed main-ref proof and validate before content consumption",
    )
    main_schema = propose[main_fetch_pos:main_consume_pos]
    for fragment in common_schema + (
        '(.sha | type == "string" and test("^[0-9a-f]{40}$")) and',
    ):
        require(
            fragment in main_schema,
            f"Spotlight proposal current-main README Contents schema changed: {fragment}",
        )

    specs = (
        (
            "proposal candidate",
            propose,
            "README_BLOB_SHA=\"$(jq -r '.files[0].sha' <<<\"$COMPARE\")\"",
            "malformed or mismatched Spotlight proposal README Contents evidence",
        ),
        (
            "terminal candidate",
            merge,
            "README_BLOB_SHA=\"$(jq -r '.[0].sha' <<<\"$FILES\")\"",
            "malformed or mismatched Spotlight terminal README Contents evidence",
        ),
    )
    for label, evidence, blob, error_text in specs:
        for marker in (blob, candidate_fetch, candidate_consume, candidate_digest, error_text):
            require(
                evidence.count(marker) == 1,
                f"Spotlight {label} README Contents evidence anchor changed: {marker}",
            )
        blob_pos = evidence.index(blob)
        fetch_pos = evidence.index(candidate_fetch)
        consume_pos = evidence.index(candidate_consume)
        digest_pos = evidence.index(candidate_digest)
        require(
            blob_pos < fetch_pos < consume_pos < digest_pos,
            f"Spotlight {label} README Contents evidence must validate before content consumption",
        )
        schema_block = evidence[fetch_pos:consume_pos]
        for fragment in common_schema + (
            '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $blob) and',
            'jq -e --arg blob "$README_BLOB_SHA"',
        ):
            require(
                fragment in schema_block,
                f"Spotlight {label} README Contents schema changed: {fragment}",
            )
        require(
            '[[ "$README_BLOB_SHA" =~ ^[0-9a-f]{40}$ ]]'
            in evidence[blob_pos:fetch_pos],
            f"Spotlight {label} README blob identity must be canonical before Contents lookup",
        )

    require(
        "--jq .content" not in spotlight,
        "Spotlight privileged README evidence regressed to raw Contents scalar consumption",
    )
    require(
        spotlight.count(
            'gh api "repos/${GITHUB_REPOSITORY}/contents/README.md?ref=main"'
        ) == 1
        and spotlight.count(
            'gh api "repos/${GITHUB_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}"'
        ) == 2,
        "Spotlight privileged README Contents endpoint/call-count contract changed",
    )

    if run_self_test:
        for job, next_job in (("propose", "approve"), ("merge", "decision_receipt")):
            start_marker = f"  {job}:\n"
            end_marker = f"  {next_job}:\n"
            start = spotlight.index(start_marker)
            end = spotlight.index(end_marker, start)
            evidence = spotlight[start:end]
            current = '(.encoding | type == "string" and . == "base64") and'
            expected_count = 2 if job == "propose" else 1
            require(
                evidence.count(current) == expected_count,
                f"Spotlight {job} README Contents self-test schema topology changed",
            )
            for occurrence in range(expected_count):
                positions = []
                cursor = 0
                while True:
                    pos = evidence.find(current, cursor)
                    if pos < 0:
                        break
                    positions.append(pos)
                    cursor = pos + len(current)
                target = positions[occurrence]
                mutated_evidence = (
                    evidence[:target]
                    + '(.encoding | tostring == "base64") and'
                    + evidence[target + len(current):]
                )
                mutated = spotlight[:start] + mutated_evidence + spotlight[end:]
                try:
                    validate_spotlight_readme_contents_evidence(
                        mutated, run_self_test=False
                    )
                except ValueError as exc:
                    require(
                        "README Contents schema changed" in str(exc),
                        f"Spotlight {job} README Contents self-test failed for wrong reason: {exc}",
                    )
                else:
                    raise ValueError(
                        f"Spotlight {job} README Contents self-test accepted type-coercing encoding evidence"
                    )

        terminal_start = spotlight.index("  merge:\n")
        terminal_end = spotlight.index("  decision_receipt:\n", terminal_start)
        terminal = spotlight[terminal_start:terminal_end]
        current = (
            '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $blob) and'
        )
        replacement = (
            '(.sha | type == "string" and test("^[0-9a-f]{40}$")) and'
        )
        require(
            terminal.count(current) == 1,
            "Spotlight terminal README Contents self-test blob-binding anchor changed",
        )
        weakened_terminal = terminal.replace(current, replacement, 1)
        weakened = (
            spotlight[:terminal_start] + weakened_terminal + spotlight[terminal_end:]
        )
        try:
            validate_spotlight_readme_contents_evidence(
                weakened, run_self_test=False
            )
        except ValueError as exc:
            require(
                "README Contents schema changed" in str(exc),
                f"Spotlight terminal README blob-binding self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                "Spotlight terminal README Contents self-test accepted unbound blob identity"
            )



def validate_spotlight_pr_response_evidence(
    spotlight: str, *, run_self_test: bool = True
) -> None:
    propose = job_block(spotlight, "propose", "approve")
    approve = job_block(spotlight, "approve", "authorize")
    helper_marker = "          validate_spotlight_open_pr_object() {"
    reviewer_helper_marker = "          validate_spotlight_reviewer_request_response() {"
    require(
        propose.count(helper_marker) == 1 and approve.count(helper_marker) == 1,
        "Spotlight proposer/approval PR response helper count changed",
    )
    require(
        propose.count(reviewer_helper_marker) == 1
        and approve.count(reviewer_helper_marker) == 0,
        "Spotlight reviewer-request response helper count changed",
    )
    reviewer_helper_start = propose.index(reviewer_helper_marker)
    reviewer_helper_end = propose.index("\n\n          REF_CREATED=false", reviewer_helper_start)
    reviewer_helper = propose[reviewer_helper_start:reviewer_helper_end]
    reviewer_schema_fragments = (
        '(.number | type == "number" and . == floor and . > 0 and . == $pr) and',
        '(.state | type == "string" and . == "open") and',
        '(.draft | type == "boolean" and . == false) and',
        '(.ref | type == "string" and . == "main") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $base) and',
        '(.ref | type == "string" and . == $branch) and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $head) and',
        '(.full_name | type == "string" and . == $repo))) and',
        '(.requested_reviewers | type == "array" and length <= 100) and',
        '(all(.requested_reviewers[];',
        '(.id | type == "number" and . == floor and . > 0) and',
        '(.login | type == "string" and length > 0))) and',
        '([.requested_reviewers[].id] | unique | length)) and',
        '([.requested_reviewers[].login] | unique | length)) and',
        '(([.requested_reviewers[] | select(.login == "portyu9")] | length) == 1)',
    )
    for fragment in reviewer_schema_fragments:
        require(
            fragment in reviewer_helper,
            f"Spotlight reviewer-request response schema changed: {fragment}",
        )
    for forbidden in (
        '(.merged | type == "boolean" and . == false) and',
        '(.maintainer_can_modify | type == "boolean" and . == false) and',
        '(.title | type == "string" and . == $title) and',
        '(.body | type == "string" and . == $body) and',
    ):
        require(
            forbidden not in reviewer_helper,
            f"Spotlight reviewer-request response regained full-GET-only field: {forbidden}",
        )
    pull_list_helper_marker = "          validate_spotlight_pull_list_item() {"
    require(
        propose.count(pull_list_helper_marker) == 0
        and approve.count(pull_list_helper_marker) == 1,
        "Spotlight approval-list response helper count changed",
    )
    pull_list_helper_start = approve.index(pull_list_helper_marker)
    pull_list_helper_end = approve.index(
        "\n\n          APPROVAL_REQUESTS_JSON='[]'", pull_list_helper_start
    )
    pull_list_helper = approve[pull_list_helper_start:pull_list_helper_end]
    pull_list_schema_fragments = (
        '(type == "object") and',
        '(.number | type == "number" and . == floor and . > 0 and . == $pr) and',
        '(.user | type == "object" and (.login | type == "string" and . == "github-actions[bot]")) and',
        '(.state | type == "string" and . == "open") and',
        '(.draft | type == "boolean" and . == false) and',
        '(.title | type == "string" and . == $title) and',
        '(.body | type == "string" and . == $body) and',
        '(.ref | type == "string" and . == "main") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $base) and',
        '(.ref | type == "string" and . == $branch) and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $head) and',
        '(.full_name | type == "string" and . == $repo))) and',
        '(.requested_reviewers | type == "array" and length <= 100) and',
        '(all(.requested_reviewers[];',
        '(.id | (type == "number") and (. == floor) and (. > 0)) and',
        '(.login | type == "string" and length > 0))) and',
        '([.requested_reviewers[].id] | unique | length)) and',
        '([.requested_reviewers[].login] | unique | length)) and',
        '(.url | type == "string" and length > 0) and',
        '(.html_url | type == "string" and length > 0)',
    )
    for fragment in pull_list_schema_fragments:
        require(
            fragment in pull_list_helper,
            f"Spotlight approval-list response schema changed: {fragment}",
        )
    require(
        pull_list_helper.count(
            '(.full_name | type == "string" and . == $repo))) and'
        ) == 2,
        "Spotlight approval-list response must bind both base/head repository identity",
    )
    require(
        pull_list_helper.count(
            '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $base) and'
        ) == 1
        and pull_list_helper.count(
            '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $head) and'
        ) == 1,
        "Spotlight approval-list response must bind exact base/head SHA identity",
    )
    for forbidden in (
        '(.merged | type == "boolean" and . == false) and',
        '(.maintainer_can_modify | type == "boolean" and . == false) and',
    ):
        require(
            forbidden not in pull_list_helper,
            f"Spotlight approval-list response regained full-GET-only field: {forbidden}",
        )

    schema_fragments = (
        '(.number | type == "number" and . == floor and . > 0 and . == $pr) and',
        '(.user | type == "object" and (.login | type == "string" and . == "github-actions[bot]")) and',
        '(.state | (type == "string") and (. == "open")) and',
        '(.draft | type == "boolean" and . == false) and',
        '(.merged | type == "boolean" and . == false) and',
        '(.maintainer_can_modify | type == "boolean" and . == false) and',
        '(.title | type == "string" and . == $title) and',
        '(.body | type == "string" and . == $body) and',
        '(.ref | type == "string" and . == "main") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $base)) and',
        '(.ref | type == "string" and . == $branch) and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $head) and',
        '(.full_name | type == "string" and . == $repo))) and',
        '(.requested_reviewers | type == "array" and length <= 100) and',
        '(all(.requested_reviewers[];',
        '(.id | (type == "number") and (. == floor) and (. > 0)) and',
        '(.login | type == "string" and length > 0))) and',
        '([.requested_reviewers[].id] | unique | length)) and',
        '([.requested_reviewers[].login] | unique | length)) and',
        '((.url | type) == "string" and (.url | length) > 0) and',
        '((.html_url | type) == "string" and (.html_url | length) > 0)',
    )
    for label, job in (("proposer", propose), ("approval", approve)):
        for fragment in schema_fragments:
            require(fragment in job, f"Spotlight {label} PR response schema changed: {fragment}")

    proposer_fetch = 'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"'
    proposer_schema = (
        'validate_spotlight_open_pr_object "$PR" "$PR_NUMBER" "$SOURCE_SHA" '
        '"$CANDIDATE_BRANCH" "$HEAD_SHA"'
    )
    proposer_consume = 'test "$(jq -r .state <<<"$PR")" = "open"'
    reviewer_mutation = 'REQUESTED_REVIEWER_HTTP_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers"'
    reviewer_response_capture = 'REQUESTED_REVIEWER_RESPONSE="$(cat requested-reviewer.json)"'
    reviewer_schema = (
        'validate_spotlight_reviewer_request_response "$REQUESTED_REVIEWER_RESPONSE" '
        '"$PR_NUMBER" "$SOURCE_SHA" "$CANDIDATE_BRANCH" "$HEAD_SHA"'
    )
    reviewer_consume = '<<<"$REQUESTED_REVIEWER_RESPONSE")" = "1"'
    for boundary_marker in (
        proposer_fetch, proposer_schema, proposer_consume, reviewer_mutation,
        reviewer_response_capture, reviewer_schema, reviewer_consume,
    ):
        require(
            propose.count(boundary_marker) == 1,
            f"Spotlight proposer PR response boundary anchor changed: {boundary_marker}",
        )
    require(
        propose.index(proposer_fetch) < propose.index(proposer_schema)
        < propose.index(proposer_consume) < propose.index(reviewer_mutation)
        < propose.index(reviewer_response_capture) < propose.index(reviewer_schema)
        < propose.index(reviewer_consume),
        "Spotlight reviewer mutation must use endpoint-specific schema before consumption",
    )
    require(
        'validate_spotlight_open_pr_object "$REQUESTED_REVIEWER_RESPONSE"' not in propose,
        "Spotlight reviewer mutation response regained incompatible full-GET PR schema",
    )
    require(
        "requested_reviewers[]?" not in propose,
        "Spotlight proposer regained permissive requested-reviewer traversal",
    )

    approval_fetch = 'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"'
    approval_schema = (
        'validate_spotlight_open_pr_object "$PR" "$PR_NUMBER" "$BASE_SHA" '
        '"$CANDIDATE_BRANCH" "$HEAD_SHA"'
    )
    approval_consume = 'test "$(jq -r .user.login <<<"$PR")" = "$BOT_NAME"'
    approval_collection_fetch = (
        'PRS="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:'
        '${CANDIDATE_BRANCH}&base=main&per_page=10")"'
    )
    approval_collection_envelope = (
        'jq -e \'(type == "array") and (length == 1)\' <<<"$PRS" >/dev/null'
    )
    approval_collection_extract = 'APPROVAL_PR="$(jq -c \'.[0]\' <<<"$PRS")"'
    approval_collection_schema = (
        'validate_spotlight_pull_list_item "$APPROVAL_PR" "$PR_NUMBER" "$BASE_SHA" '
        '"$CANDIDATE_BRANCH" "$HEAD_SHA"'
    )
    approval_collection_consume = (
        'test "$(jq -r .number <<<"$APPROVAL_PR")" = "$PR_NUMBER"'
    )
    post_review_fetch = 'PR_AFTER_REVIEW="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"'
    post_review_schema = (
        'validate_spotlight_open_pr_object "$PR_AFTER_REVIEW" "$PR_NUMBER" "$BASE_SHA" '
        '"$CANDIDATE_BRANCH" "$HEAD_SHA"'
    )
    post_review_consume = 'test "$(jq -r .state <<<"$PR_AFTER_REVIEW")" = "open"'
    for boundary_marker in (
        approval_fetch, approval_schema, approval_consume,
        approval_collection_fetch, approval_collection_envelope,
        approval_collection_extract, approval_collection_schema,
        approval_collection_consume,
        post_review_fetch, post_review_schema, post_review_consume,
    ):
        require(
            approve.count(boundary_marker) == 1,
            f"Spotlight approval PR response boundary anchor changed: {boundary_marker}",
        )
    require(
        'validate_spotlight_open_pr_object "$APPROVAL_PR"' not in approve,
        "Spotlight approval-list item regained incompatible full-GET PR schema",
    )
    require(
        approve.index(approval_fetch) < approve.index(approval_schema)
        < approve.index(approval_consume) < approve.index(approval_collection_fetch)
        < approve.index(approval_collection_envelope)
        < approve.index(approval_collection_extract)
        < approve.index(approval_collection_schema)
        < approve.index(approval_collection_consume)
        < approve.index(post_review_fetch)
        < approve.index(post_review_schema) < approve.index(post_review_consume),
        "Spotlight approval PR snapshots/collection must be typed before authorization consumption",
    )
    require(
        spotlight.count("validate_spotlight_open_pr_object() {") == 2
        and spotlight.count('validate_spotlight_open_pr_object "$') == 3
        and spotlight.count("validate_spotlight_reviewer_request_response() {") == 1
        and spotlight.count('validate_spotlight_reviewer_request_response "$') == 1
        and spotlight.count("validate_spotlight_pull_list_item() {") == 1
        and spotlight.count('validate_spotlight_pull_list_item "$') == 1,
        "Spotlight PR response schema/call cardinality changed",
    )

    if run_self_test:
        weakened = spotlight.replace(
            post_review_schema, 'true # adversarially removed post-review PR schema', 1
        )
        try:
            validate_spotlight_pr_response_evidence(weakened, run_self_test=False)
        except ValueError as exc:
            require(
                "approval PR response boundary anchor changed" in str(exc),
                f"Spotlight post-review PR schema self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError("Spotlight PR response self-test accepted an untyped post-review snapshot")
        for current_boundary, replacement_boundary, label in (
            (
                approval_collection_envelope,
                'jq -e \'(type == "object") and (length == 1)\' <<<"$PRS" >/dev/null',
                "collection-non-array",
            ),
            (
                approval_collection_envelope,
                'jq -e \'(type == "array") and (length <= 1)\' <<<"$PRS" >/dev/null',
                "collection-cardinality",
            ),
            (
                approval_collection_schema,
                'true # adversarially removed approval PR collection object schema',
                "collection-object",
            ),
            (
                approval_collection_schema,
                'validate_spotlight_open_pr_object "$APPROVAL_PR" "$PR_NUMBER" "$BASE_SHA" '
                '"$CANDIDATE_BRANCH" "$HEAD_SHA"',
                "collection-full-get-schema",
            ),
        ):
            require(
                approve.count(current_boundary) == 1,
                f"Spotlight approval PR {label} self-test anchor changed",
            )
            approve_start = spotlight.index("  approve:\n")
            approve_end = spotlight.index("  authorize:\n", approve_start)
            weakened = (
                spotlight[:approve_start]
                + approve.replace(current_boundary, replacement_boundary, 1)
                + spotlight[approve_end:]
            )
            try:
                validate_spotlight_pr_response_evidence(weakened, run_self_test=False)
            except ValueError as exc:
                require(
                    "approval PR response boundary anchor changed" in str(exc)
                    or "incompatible full-GET PR schema" in str(exc),
                    f"Spotlight approval PR {label} self-test failed for wrong reason: {exc}",
                )
            else:
                raise ValueError(
                    f"Spotlight PR response self-test accepted weakened approval PR {label}"
                )

        list_helper_mutations = (
            (
                '(type == "object") and',
                '(type == "array") and',
                "list-item-object",
            ),
            (
                '(.number | type == "number" and . == floor and . > 0 and . == $pr) and',
                '(.number | type == "number" and . == floor and . > 0) and',
                "list-item-pr-number",
            ),
            (
                '(.requested_reviewers | type == "array" and length <= 100) and',
                '(.requested_reviewers | tostring | length <= 100) and',
                "list-item-reviewer-array",
            ),
            (
                '([.requested_reviewers[].login] | unique | length)) and',
                '([.requested_reviewers[].login] | length)) and',
                "list-item-reviewer-uniqueness",
            ),
        )
        approve_start = spotlight.index("  approve:\n")
        approve_end = spotlight.index("  authorize:\n", approve_start)
        for helper_current, helper_replacement, label in list_helper_mutations:
            require(
                pull_list_helper.count(helper_current) == 1,
                f"Spotlight approval-list {label} self-test anchor changed",
            )
            mutated_helper = pull_list_helper.replace(
                helper_current, helper_replacement, 1
            )
            weakened_approve = (
                approve[:pull_list_helper_start]
                + mutated_helper
                + approve[pull_list_helper_end:]
            )
            weakened = (
                spotlight[:approve_start] + weakened_approve + spotlight[approve_end:]
            )
            try:
                validate_spotlight_pr_response_evidence(weakened, run_self_test=False)
            except ValueError as exc:
                require(
                    "approval-list response schema changed" in str(exc),
                    f"Spotlight approval-list {label} self-test failed for wrong reason: {exc}",
                )
            else:
                raise ValueError(
                    f"Spotlight PR response self-test accepted weakened approval-list {label}"
                )

        ordered_collection_pair = (
            approval_collection_schema + "\n          " + approval_collection_consume
        )
        require(
            approve.count(ordered_collection_pair) == 1,
            "Spotlight approval PR collection ordering self-test anchor changed",
        )
        reordered_approve = approve.replace(
            ordered_collection_pair,
            approval_collection_consume + "\n          " + approval_collection_schema,
            1,
        )
        approve_start = spotlight.index("  approve:\n")
        approve_end = spotlight.index("  authorize:\n", approve_start)
        weakened = spotlight[:approve_start] + reordered_approve + spotlight[approve_end:]
        try:
            validate_spotlight_pr_response_evidence(weakened, run_self_test=False)
        except ValueError as exc:
            require(
                "snapshots/collection must be typed before authorization consumption" in str(exc),
                f"Spotlight approval PR collection ordering self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                "Spotlight PR response self-test accepted approval collection schema after consumption"
            )

        current = '(.requested_reviewers | type == "array" and length <= 100) and'
        replacement = '(.requested_reviewers | tostring | length <= 100) and'
        require(
            reviewer_helper.count(current) == 1,
            "Spotlight reviewer-request reviewer-array self-test anchor changed",
        )
        propose_start = spotlight.index("  propose:\n")
        propose_end = spotlight.index("  approve:\n", propose_start)
        mutated_helper = reviewer_helper.replace(current, replacement, 1)
        weakened_propose = (
            propose[:reviewer_helper_start]
            + mutated_helper
            + propose[reviewer_helper_end:]
        )
        weakened = spotlight[:propose_start] + weakened_propose + spotlight[propose_end:]
        try:
            validate_spotlight_pr_response_evidence(weakened, run_self_test=False)
        except ValueError as exc:
            require(
                "reviewer-request response schema changed" in str(exc),
                f"Spotlight reviewer-request array self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                "Spotlight PR response self-test accepted type-coercing reviewer mutation evidence"
            )

        helper_mutations = (
            (
                '(([.requested_reviewers[] | select(.login == "portyu9")] | length) == 1)',
                '(([.requested_reviewers[] | select(.login == "portyu9")] | length) >= 1)',
                "reviewer-cardinality",
            ),
            (
                '([.requested_reviewers[].login] | unique | length)) and',
                '([.requested_reviewers[].login] | length)) and',
                "reviewer-uniqueness",
            ),
        )
        for helper_current, helper_replacement, label in helper_mutations:
            require(
                reviewer_helper.count(helper_current) == 1,
                f"Spotlight reviewer-request {label} self-test anchor changed",
            )
            mutated_helper = reviewer_helper.replace(helper_current, helper_replacement, 1)
            weakened_propose = (
                propose[:reviewer_helper_start]
                + mutated_helper
                + propose[reviewer_helper_end:]
            )
            weakened = spotlight[:propose_start] + weakened_propose + spotlight[propose_end:]
            try:
                validate_spotlight_pr_response_evidence(weakened, run_self_test=False)
            except ValueError as exc:
                require(
                    "reviewer-request response schema changed" in str(exc),
                    f"Spotlight reviewer-request {label} self-test failed for wrong reason: {exc}",
                )
            else:
                raise ValueError(
                    f"Spotlight PR response self-test accepted weakened reviewer mutation {label}"
                )

        for current_boundary, replacement_boundary, label in (
            (
                reviewer_schema,
                'validate_spotlight_open_pr_object "$REQUESTED_REVIEWER_RESPONSE" "$PR_NUMBER" '
                '"$SOURCE_SHA" "$CANDIDATE_BRANCH" "$HEAD_SHA"',
                "full-get-schema-on-mutation",
            ),
            (
                reviewer_schema,
                "true # adversarially removed reviewer mutation response schema",
                "missing-mutation-schema",
            ),
        ):
            require(
                propose.count(current_boundary) == 1,
                f"Spotlight reviewer mutation {label} self-test anchor changed",
            )
            weakened_propose = propose.replace(current_boundary, replacement_boundary, 1)
            weakened = spotlight[:propose_start] + weakened_propose + spotlight[propose_end:]
            try:
                validate_spotlight_pr_response_evidence(weakened, run_self_test=False)
            except ValueError as exc:
                require(
                    "boundary anchor changed" in str(exc)
                    or "incompatible full-GET PR schema" in str(exc),
                    f"Spotlight reviewer mutation {label} self-test failed for wrong reason: {exc}",
                )
            else:
                raise ValueError(
                    f"Spotlight PR response self-test accepted reviewer mutation weakening: {label}"
                )

        reviewer_consume_line = (
            'test "$(jq \'[.requested_reviewers[] | select(.login == "portyu9")] | length\' '
            '<<<"$REQUESTED_REVIEWER_RESPONSE")" = "1"'
        )
        ordered_reviewer_pair = reviewer_schema + "\n            " + reviewer_consume_line
        require(
            propose.count(ordered_reviewer_pair) == 1,
            "Spotlight reviewer mutation ordering self-test anchor changed",
        )
        reordered_propose = propose.replace(
            ordered_reviewer_pair,
            reviewer_consume_line + "\n            " + reviewer_schema,
            1,
        )
        weakened = spotlight[:propose_start] + reordered_propose + spotlight[propose_end:]
        try:
            validate_spotlight_pr_response_evidence(weakened, run_self_test=False)
        except ValueError as exc:
            require(
                "endpoint-specific schema before consumption" in str(exc),
                f"Spotlight reviewer mutation ordering self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                "Spotlight PR response self-test accepted reviewer mutation schema after consumption"
            )

def project_spotlight_git_publication_status_to_legacy(spotlight: str) -> str:
    overlays = (
        (
            '            BLOB_HTTP_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/git/blobs" --input blob.json)"\n'
            '            BLOB_STATUS_LINE="$(head -n 1 <<<"$BLOB_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '            [[ "$BLOB_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
            '              echo "ERROR: Spotlight Git blob creation returned unexpected status: ${BLOB_STATUS_LINE}" >&2\n'
            '              exit 1\n'
            '            }\n'
            '            BLOB="$(sed \'1,/^[[:space:]]*$/d\' <<<"$BLOB_HTTP_RESPONSE")"\n',
            '            BLOB="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/blobs" --input blob.json)"\n',
        ),
        (
            '            TREE_HTTP_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/git/trees" --input tree.json)"\n'
            '            TREE_STATUS_LINE="$(head -n 1 <<<"$TREE_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '            [[ "$TREE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
            '              echo "ERROR: Spotlight Git tree creation returned unexpected status: ${TREE_STATUS_LINE}" >&2\n'
            '              exit 1\n'
            '            }\n'
            '            TREE="$(sed \'1,/^[[:space:]]*$/d\' <<<"$TREE_HTTP_RESPONSE")"\n',
            '            TREE="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/trees" --input tree.json)"\n',
        ),
        (
            '            CANDIDATE_COMMIT_HTTP_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/git/commits" --input commit.json)"\n'
            '            CANDIDATE_COMMIT_STATUS_LINE="$(head -n 1 <<<"$CANDIDATE_COMMIT_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '            [[ "$CANDIDATE_COMMIT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
            '              echo "ERROR: Spotlight Git commit creation returned unexpected status: ${CANDIDATE_COMMIT_STATUS_LINE}" >&2\n'
            '              exit 1\n'
            '            }\n'
            '            CANDIDATE_COMMIT="$(sed \'1,/^[[:space:]]*$/d\' <<<"$CANDIDATE_COMMIT_HTTP_RESPONSE")"\n',
            '            CANDIDATE_COMMIT="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/commits" --input commit.json)"\n',
        ),
        (
            '            CREATED_REF_HTTP_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/git/refs" --input ref.json)"\n'
            '            CREATED_REF_STATUS_LINE="$(head -n 1 <<<"$CREATED_REF_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '            [[ "$CREATED_REF_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
            '              echo "ERROR: Spotlight Git ref creation returned unexpected status: ${CREATED_REF_STATUS_LINE}" >&2\n'
            '              exit 1\n'
            '            }\n'
            '            CREATED_REF="$(sed \'1,/^[[:space:]]*$/d\' <<<"$CREATED_REF_HTTP_RESPONSE")"\n',
            '            CREATED_REF="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" --input ref.json)"\n',
        ),
    )
    for hardened, legacy in overlays:
        require(
            spotlight.count(hardened) == 1,
            "Spotlight v21 projection cannot isolate Git publication HTTP-status wrapper",
        )
        require(
            legacy not in spotlight,
            "Spotlight v21 projection found both hardened and legacy Git publication mutation",
        )
        spotlight = spotlight.replace(hardened, legacy, 1)
    return spotlight


def validate_v21_spotlight_invariants(spotlight: str) -> None:
    spotlight = project_spotlight_git_publication_status_to_legacy(spotlight)
    legacy = project_spotlight_privileged_refs_to_legacy(
        project_spotlight_readme_contents_to_legacy(
            project_spotlight_terminal_protected_runs_to_legacy(
                spotlight[:spotlight.index("  decision_receipt:\n")]
            )
        )
    )
    reconcile = job_block(legacy, "reconcile", "budget")
    commit_schema_start_marker = (
        '            jq -e --arg head "$HEAD_SHA" --arg name "$BOT_NAME" --arg email "$BOT_EMAIL" \'\n'
    )
    commit_schema_end_marker = '            \' <<<"$CANDIDATE_COMMIT" >/dev/null\n'
    require(reconcile.count(commit_schema_start_marker) == 1
            and reconcile.count(commit_schema_end_marker) == 1,
            "Spotlight v21 reconciliation projection cannot isolate the independently validated stale commit schema")
    commit_schema_start = legacy.index(commit_schema_start_marker)
    commit_schema_end = legacy.index(commit_schema_end_marker, commit_schema_start) + len(commit_schema_end_marker)
    v21_reconciliation = legacy[:commit_schema_start] + legacy[commit_schema_end:]

    ancestry_counter = '          ANCESTRY_PROVEN_STALE=0\n'
    require(v21_reconciliation.count(ancestry_counter) == 1,
            "Spotlight v21 projection cannot isolate ancestry stale counter")
    v21_reconciliation = v21_reconciliation.replace(ancestry_counter, "", 1)

    ancestry_classify_start = '            SAME_BASE_SUPERSEDED=false\n'
    ancestry_classify_end = '            COMMITTER_DATE="$(jq -r .committer.date <<<"$CANDIDATE_COMMIT")"\n'
    require(v21_reconciliation.count(ancestry_classify_start) == 1
            and v21_reconciliation.count(ancestry_classify_end) == 1,
            "Spotlight v21 projection cannot isolate ancestry classification block")
    ancestry_start = v21_reconciliation.index(ancestry_classify_start)
    ancestry_end = v21_reconciliation.index(ancestry_classify_end, ancestry_start)
    ancestry_block = v21_reconciliation[ancestry_start:ancestry_end]
    for fragment in (
        '            ANCESTRY_PROVEN_SUPERSEDED=false\n',
        '              ANCESTRY_COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${PARENT_SHA}...${BASE_SHA}")"\n',
        '                ANCESTRY_PROVEN_SUPERSEDED=true\n',
    ):
        require(fragment in ancestry_block,
                f"Spotlight v21 projection lost ancestry overlay fragment: {fragment}")
    same_base_block = (
        '            SAME_BASE_SUPERSEDED=false\n'
        '            if [ "$PARENT_SHA" = "$BASE_SHA" ]; then\n'
        '              SAME_BASE_SUPERSEDED=true\n'
        '            fi\n\n'
    )
    v21_reconciliation = (
        v21_reconciliation[:ancestry_start]
        + same_base_block
        + v21_reconciliation[ancestry_end:]
    )

    ancestry_age_guard = (
        'if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ] &&\n'
        '               [ "$SAME_BASE_SUPERSEDED" != "true" ] &&\n'
        '               [ "$ANCESTRY_PROVEN_SUPERSEDED" != "true" ]; then'
    )
    same_base_age_guard = (
        'if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ] && '
        '[ "$SAME_BASE_SUPERSEDED" != "true" ]; then'
    )
    require(v21_reconciliation.count(ancestry_age_guard) == 1,
            "Spotlight v21 projection cannot isolate ancestry-aware age guard")
    v21_reconciliation = v21_reconciliation.replace(
        ancestry_age_guard, same_base_age_guard, 1
    )

    ancestry_cleanup_counter = (
        '            if [ "$ANCESTRY_PROVEN_SUPERSEDED" = "true" ]; then\n'
        '              ANCESTRY_PROVEN_STALE=$((ANCESTRY_PROVEN_STALE + 1))\n'
        '            fi\n'
    )
    require(v21_reconciliation.count(ancestry_cleanup_counter) == 1,
            "Spotlight v21 projection cannot isolate ancestry cleanup counter")
    v21_reconciliation = v21_reconciliation.replace(ancestry_cleanup_counter, "", 1)

    ancestry_summary = (
        '            echo "- ancestry-proven old-base candidates cleaned immediately: '
        '**$ANCESTRY_PROVEN_STALE**"\n'
    )
    ancestry_young_summary = (
        '            echo "- unproven/divergent candidates below 30-minute stale floor preserved: '
        '**$PRESERVED_YOUNG**"\n'
    )
    same_base_young_summary = (
        '            echo "- different-base candidates below 30-minute stale floor preserved: '
        '**$PRESERVED_YOUNG**"\n'
    )
    require(v21_reconciliation.count(ancestry_summary) == 1
            and v21_reconciliation.count(ancestry_young_summary) == 1,
            "Spotlight v21 projection cannot isolate ancestry summary overlay")
    v21_reconciliation = v21_reconciliation.replace(ancestry_summary, "", 1)
    v21_reconciliation = v21_reconciliation.replace(
        ancestry_young_summary, same_base_young_summary, 1
    )

    current_age_guard = (
        'if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ] && '
        '[ "$SAME_BASE_SUPERSEDED" != "true" ]; then'
    )
    legacy_age_guard = 'if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ]; then'
    require(v21_reconciliation.count(current_age_guard) == 1,
            "Spotlight v21 reconciliation projection cannot isolate same-base supersession age guard")
    v21_reconciliation = v21_reconciliation.replace(current_age_guard, legacy_age_guard, 1)
    v21.validate_spotlight_reconciliation(v21_reconciliation)
    require(
        'PR_NUMBER="$(jq -r \'.[0].number\' <<<"$PRS")"' in legacy and
        'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"' in legacy,
        "Spotlight stale reconciliation must use list results only for bounded PR discovery and re-fetch the exact full PR object",
    )
    refs_call_marker = (
        'REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${BOT_BRANCH_PREFIX}")"'
    )
    refs_schema_marker = '(all(.[]; (type == "object") and'
    refs_consume_marker = 'REF_COUNT="$(jq \'length\' <<<"$REFS")"'
    commit_call_marker = 'CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"'
    commit_schema_marker = 'jq -e --arg head "$HEAD_SHA" --arg name "$BOT_NAME" --arg email "$BOT_EMAIL"'
    commit_consume_marker = 'PARENT_SHA="$(jq -r \'.parents[0].sha\' <<<"$CANDIDATE_COMMIT")"'
    compare_call_marker = 'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${PARENT_SHA}...${HEAD_SHA}")"'
    compare_schema_marker = 'jq -e --arg parent "$PARENT_SHA" --arg head "$HEAD_SHA"'
    compare_consume_marker = 'test "$(jq -r .status <<<"$COMPARE")" = "ahead"'

    for marker in (
        refs_call_marker, refs_schema_marker, refs_consume_marker,
        commit_call_marker, commit_schema_marker, commit_consume_marker,
        compare_call_marker, compare_schema_marker, compare_consume_marker,
    ):
        require(reconcile.count(marker) == 1,
                f"Spotlight stale-topology evidence contract anchor is missing or ambiguous: {marker}")

    refs_call = reconcile.index(refs_call_marker)
    refs_schema = reconcile.index(refs_schema_marker, refs_call)
    refs_consume = reconcile.index(refs_consume_marker, refs_schema)
    commit_call = reconcile.index(commit_call_marker, refs_consume)
    commit_schema = reconcile.index(commit_schema_marker, commit_call)
    commit_consume = reconcile.index(commit_consume_marker, commit_schema)
    compare_call = reconcile.index(compare_call_marker, commit_consume)
    compare_schema = reconcile.index(compare_schema_marker, compare_call)
    compare_consume = reconcile.index(compare_consume_marker, compare_schema)

    refs_block = reconcile[refs_call:refs_consume]
    for fragment in (
        '(type == "array") and',
        '(length <= 20) and',
        '(.ref | type == "string" and test("^refs/heads/automation/spotlight-links/[0-9a-f]{64}$")) and',
        '(.object | type == "object" and',
        '(.type | type == "string" and . == "commit") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$"))',
    ):
        require(fragment in refs_block,
                f"Spotlight stale-topology refs contract is missing: {fragment}")

    commit_block = reconcile[commit_call:commit_consume]
    for fragment in (
        '(.sha | type == "string" and . == $head) and',
        '(.tree | type == "object" and (.sha | type == "string" and test("^[0-9a-f]{40}$"))) and',
        '(.parents | type == "array" and length == 1 and',
        '(.author | type == "object" and .name == $name and .email == $email) and',
        '(.committer | type == "object" and .name == $name and .email == $email and',
        '(.date | type == "string" and length > 0)) and',
        '(.message == "chore: sync rotating Spotlight links")',
    ):
        require(fragment in commit_block,
                f"Spotlight stale-topology commit contract is missing: {fragment}")

    compare_block = reconcile[compare_call:compare_consume]
    for fragment in (
        '(.status == "ahead") and',
        '(.base_commit | type == "object" and .sha == $parent) and',
        '(.merge_base_commit | type == "object" and .sha == $parent) and',
        '(.ahead_by | type == "number" and . == floor and . == 1) and',
        '(.behind_by | type == "number" and . == floor and . == 0) and',
        '(.total_commits | type == "number" and . == floor and . == 1) and',
        '(.commits | type == "array" and length == 1 and',
        '(.filename | type == "string" and . == "README.md") and',
        '(.status | type == "string" and . == "modified") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$")) and',
        '(.additions | type == "number" and . == floor and . >= 0) and',
        '(.deletions | type == "number" and . == floor and . >= 0) and',
        '(.changes | type == "number" and . == floor and . >= 0)',
    ):
        require(fragment in compare_block,
                f"Spotlight stale-topology compare contract is missing: {fragment}")

    require(
        refs_call < refs_schema < refs_consume < commit_call < commit_schema < commit_consume
        < compare_call < compare_schema < compare_consume,
        "Spotlight stale-topology evidence validation must precede downstream consumption",
    )

    prs_call_marker = (
        'PRS="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${BRANCH}&base=main&per_page=2")"'
    )
    prs_schema_marker = (
        'jq -e --arg branch "$BRANCH" --arg head "$HEAD_SHA" --arg repo "$GITHUB_REPOSITORY"'
    )
    prs_count_marker = 'PR_COUNT="$(jq \'length\' <<<"$PRS")"'
    pr_number_marker = 'PR_NUMBER="$(jq -r \'.[0].number\' <<<"$PRS")"'
    pr_call_marker = 'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"'
    pr_schema_marker = '<<<"$PR" >/dev/null'
    pr_consume_marker = 'test "$(jq -r .state <<<"$PR")" = "open"'
    for marker in (
        prs_call_marker, prs_schema_marker, prs_count_marker, pr_number_marker,
        pr_call_marker, pr_schema_marker, pr_consume_marker,
    ):
        require(reconcile.count(marker) == 1,
                f"Spotlight stale-PR evidence contract anchor is missing or ambiguous: {marker}")

    prs_call = reconcile.index(prs_call_marker)
    prs_schema = reconcile.index(prs_schema_marker, prs_call)
    prs_count = reconcile.index(prs_count_marker, prs_schema)
    pr_number = reconcile.index(pr_number_marker, prs_count)
    pr_call = reconcile.index(pr_call_marker, pr_number)
    pr_schema = reconcile.index(pr_schema_marker, pr_call)
    pr_consume = reconcile.index(pr_consume_marker, pr_schema)

    prs_block = reconcile[prs_call:prs_count]
    for fragment in (
        '(type == "array") and',
        '(length <= 1) and',
        '(all(.[];',
        '(.number | type == "number" and . == floor and . > 0) and',
        '(.user | type == "object" and .login == "github-actions[bot]") and',
        '(.state == "open") and',
        '(.draft | type == "boolean" and . == false) and',
        '(.title == $title) and',
        '(.body == $body) and',
        '(.base | type == "object" and .ref == "main" and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$")) and',
        '(.head | type == "object" and .ref == $branch and .sha == $head and',
        'has("merge_commit_sha")',
    ):
        require(fragment in prs_block,
                f"Spotlight stale-PR discovery contract is missing: {fragment}")

    pr_block = reconcile[pr_call:pr_consume]
    for fragment in (
        'jq -e --argjson pr "$PR_NUMBER" --arg branch "$BRANCH" --arg head "$HEAD_SHA" --arg repo "$GITHUB_REPOSITORY"',
        '(type == "object") and',
        '(.number | type == "number" and . == floor and . == $pr) and',
        '(.user | type == "object" and .login == "github-actions[bot]") and',
        '(.state == "open") and',
        '(.draft | type == "boolean" and . == false) and',
        '(.merged | type == "boolean" and . == false) and',
        '(.maintainer_can_modify | type == "boolean" and . == false) and',
        '(.title == $title) and',
        '(.body == $body) and',
        '(.base | type == "object" and .ref == "main" and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$")) and',
        '(.head | type == "object" and .ref == $branch and .sha == $head and',
        'has("merge_commit_sha")',
    ):
        require(fragment in pr_block,
                f"Spotlight stale-PR hydrated contract is missing: {fragment}")

    require(
        compare_consume < prs_call < prs_schema < prs_count < pr_number < pr_call < pr_schema < pr_consume,
        "Spotlight stale-PR discovery/hydration validation must precede field consumption",
    )

    close_call_marker = (
        'CLOSED_PR="$(gh api --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}" --input close-pr.json)"'
    )
    close_schema_marker = '<<<"$CLOSED_PR" >/dev/null'
    close_consume_marker = 'test "$(jq -r .state <<<"$CLOSED_PR")" = "closed"'
    close_delete_marker = (
        'gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BRANCH}" >/dev/null'
    )
    for marker in (close_call_marker, close_schema_marker, close_consume_marker, close_delete_marker):
        require(reconcile.count(marker) == 1,
                f"Spotlight stale-close response contract anchor is missing or ambiguous: {marker}")
    close_call = reconcile.index(close_call_marker)
    close_schema = reconcile.index(close_schema_marker, close_call)
    close_consume = reconcile.index(close_consume_marker, close_schema)
    close_delete = reconcile.index(close_delete_marker, close_consume)
    close_block = reconcile[close_call:close_consume]
    for fragment in (
        'jq -e --argjson pr "$PR_NUMBER" --arg branch "$BRANCH" --arg head "$HEAD_SHA" --arg repo "$GITHUB_REPOSITORY"',
        '((type) == "object") and',
        '(.number | type == "number" and . == floor and . == $pr) and',
        '(.user | type == "object" and .login == "github-actions[bot]") and',
        '(.state == "closed") and',
        '(.draft | type == "boolean" and . == false) and',
        '(.merged | type == "boolean" and . == false) and',
        '(.maintainer_can_modify | type == "boolean" and . == false) and',
        '(.title == $title) and',
        '(.body == $body) and',
        '(.base | type == "object" and .ref == "main" and',
        '(.head | type == "object" and .ref == $branch and .sha == $head and',
        'has("merge_commit_sha")',
    ):
        require(fragment in close_block,
                f"Spotlight stale-close response contract is missing: {fragment}")
    require(
        pr_consume < close_call < close_schema < close_consume < close_delete,
        "Spotlight stale PR evidence and close response validation must precede close/ref deletion effects",
    )

    readback_call_marker = (
        'REMAINING_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${BRANCH}")"'
    )
    readback_schema_marker = (
        'jq -e \'(type == "array") and (length == 0)\' <<<"$REMAINING_REFS" >/dev/null'
    )
    readback_consume_marker = (
        'REMAINING_EXACT="$(jq --arg ref "refs/heads/${BRANCH}" \'[.[] | select(.ref == $ref)] | length\' <<<"$REMAINING_REFS")"'
    )
    cleanup_journal_marker = 'CLEANUP_ENTRY="$(jq -cn \\'
    cleanup_effect_marker = 'echo "stale_cleanup_effect_present=true" >> "$GITHUB_OUTPUT"'
    for marker in (
        readback_call_marker, readback_schema_marker, readback_consume_marker,
        cleanup_journal_marker, cleanup_effect_marker,
    ):
        require(reconcile.count(marker) == 1,
                f"Spotlight stale-delete readback contract anchor is missing or ambiguous: {marker}")

    readback_call = reconcile.index(readback_call_marker)
    readback_schema = reconcile.index(readback_schema_marker)
    readback_consume = reconcile.index(readback_consume_marker)
    cleanup_journal = reconcile.index(cleanup_journal_marker)
    cleanup_effect = reconcile.index(cleanup_effect_marker)
    require(
        close_delete < readback_call < readback_schema < readback_consume < cleanup_journal < cleanup_effect,
        "Spotlight stale-delete readback validation must precede cleanup journal/output evidence",
    )
    for fragment in (
        'CANDIDATE_ID="$(printf \'%s\\n%s\\n%s\\n\' "$SOURCE_SHA" "$GENERATED_SHA" "$README_SHA256_AFTER" | sha256sum | cut -d\' \' -f1)"',
        'MATCHING_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"',
        'CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"',
        'test "$(jq -r .message <<<"$CANDIDATE_COMMIT")" = "chore: sync rotating Spotlight links"',
        'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${SOURCE_SHA}...${HEAD_SHA}")"',
        'test "$(jq -r .total_commits <<<"$COMPARE")" = "1"',
        'test "$(jq -r \'.files[0].filename\' <<<"$COMPARE")" = "README.md"',
        'CREATED_REF="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" --input ref.json)"',
        'BLOB="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/blobs" --input blob.json)"',
        '(.url | type == "string" and length > 0)',
        'BASE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${SOURCE_SHA}")"',
        'jq -e --arg source "$SOURCE_SHA"',
        'TREE="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/trees" --input tree.json)"',
        '(.truncated | type == "boolean")',
        'CANDIDATE_COMMIT="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/commits" --input commit.json)"',
        'jq -e --arg tree "$CANDIDATE_TREE_SHA" --arg parent "$SOURCE_SHA" --arg name "$BOT_NAME" --arg email "$BOT_EMAIL"',
        'jq -e --arg ref "refs/heads/${CANDIDATE_BRANCH}" --arg head "$HEAD_SHA"',
        '(.type | type == "string" and . == "commit")',
        'gh api --method POST "repos/${GITHUB_REPOSITORY}/pulls" --input pr.json > pr-response.json',
        'jq -e --arg title "chore: sync rotating Spotlight links"',
        '(.number | type == "number" and . == floor and . > 0) and',
    ):
        require(fragment in legacy, f"Spotlight current immutable-candidate proof is missing: {fragment}")
    propose = job_block(legacy, "propose", "approve")

    proposal_refs_call_marker = (
        'MATCHING_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"'
    )
    proposal_refs_schema_marker = '\' <<<"$MATCHING_REFS" >/dev/null'
    proposal_refs_consume_marker = (
        'EXACT_REF_COUNT="$(jq --arg ref "refs/heads/${CANDIDATE_BRANCH}" '
        '\'[.[] | select(.ref == $ref)] | length\' <<<"$MATCHING_REFS")"'
    )
    for marker in (
        proposal_refs_call_marker, proposal_refs_schema_marker, proposal_refs_consume_marker,
    ):
        require(propose.count(marker) == 1,
                f"Spotlight proposer candidate-ref collection contract anchor is missing or ambiguous: {marker}")
    proposal_refs_call = propose.index(proposal_refs_call_marker)
    proposal_refs_schema = propose.index(proposal_refs_schema_marker)
    proposal_refs_consume = propose.index(proposal_refs_consume_marker)
    proposal_refs_block = propose[proposal_refs_call:proposal_refs_consume]
    for fragment in (
        'jq -e --arg ref "refs/heads/${CANDIDATE_BRANCH}"',
        '(type == "array") and',
        '(length <= 1) and',
        '(.ref | type == "string" and . == $ref) and',
        '(.object | type == "object" and',
        '(.type | type == "string" and . == "commit") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$"))',
    ):
        require(fragment in proposal_refs_block,
                f"Spotlight proposer candidate-ref collection contract is missing: {fragment}")
    require(
        proposal_refs_call < proposal_refs_schema < proposal_refs_consume,
        "Spotlight proposer candidate-ref collection validation must precede reuse/create cardinality consumption",
    )

    blob_call = propose.index('BLOB="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/blobs" --input blob.json)"')
    blob_schema = propose.index('(.url | type == "string" and length > 0)', blob_call)
    blob_consume = propose.index('README_BLOB_SHA="$(jq -r .sha <<<"$BLOB")"', blob_schema)
    base_call = propose.index('BASE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${SOURCE_SHA}")"', blob_consume)
    base_schema = propose.index('jq -e --arg source "$SOURCE_SHA"', base_call)
    base_consume = propose.index('BASE_TREE_SHA="$(jq -r .tree.sha <<<"$BASE_COMMIT")"', base_schema)
    tree_call = propose.index('TREE="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/trees" --input tree.json)"', base_consume)
    tree_schema = propose.index('(.truncated | type == "boolean")', tree_call)
    tree_consume = propose.index('CANDIDATE_TREE_SHA="$(jq -r .sha <<<"$TREE")"', tree_schema)
    commit_call = propose.index('CANDIDATE_COMMIT="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/commits" --input commit.json)"', tree_consume)
    commit_schema = propose.index('jq -e --arg tree "$CANDIDATE_TREE_SHA"', commit_call)
    commit_consume = propose.index('HEAD_SHA="$(jq -r .sha <<<"$CANDIDATE_COMMIT")"', commit_schema)

    topology_commit_call_marker = (
        'CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"'
    )
    topology_commit_schema_marker = (
        'jq -e --arg head "$HEAD_SHA" --arg parent "$SOURCE_SHA" --arg name "$BOT_NAME" --arg email "$BOT_EMAIL"'
    )
    topology_commit_consume_marker = 'test "$(jq \' .parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"'.replace("' .parents", "'.parents")
    topology_compare_call_marker = (
        'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${SOURCE_SHA}...${HEAD_SHA}")"'
    )
    topology_compare_schema_marker = 'jq -e --arg source "$SOURCE_SHA" --arg head "$HEAD_SHA"'
    topology_compare_consume_marker = 'test "$(jq -r .status <<<"$COMPARE")" = "ahead"'
    candidate_content_marker = (
        'gh api "repos/${GITHUB_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}" --jq .content'
    )
    for marker in (
        topology_commit_call_marker, topology_commit_schema_marker, topology_commit_consume_marker,
        topology_compare_call_marker, topology_compare_schema_marker, topology_compare_consume_marker,
        candidate_content_marker,
    ):
        require(propose.count(marker) == 1,
                f"Spotlight proposer candidate-topology contract anchor is missing or ambiguous: {marker}")

    topology_commit_call = propose.index(topology_commit_call_marker)
    topology_commit_schema = propose.index(topology_commit_schema_marker)
    topology_commit_consume = propose.index(topology_commit_consume_marker)
    topology_compare_call = propose.index(topology_compare_call_marker)
    topology_compare_schema = propose.index(topology_compare_schema_marker)
    topology_compare_consume = propose.index(topology_compare_consume_marker)
    candidate_content = propose.index(candidate_content_marker)

    topology_commit_block = propose[topology_commit_call:topology_commit_consume]
    for fragment in (
        '(type == "object") and',
        '(.sha | type == "string" and . == $head) and',
        '(.tree | type == "object" and (.sha | type == "string" and test("^[0-9a-f]{40}$"))) and',
        '(.parents | type == "array" and length == 1 and',
        '(.[0] | type == "object" and .sha == $parent)) and',
        '(.author | type == "object" and .name == $name and .email == $email) and',
        '(.committer | type == "object" and .name == $name and .email == $email and',
        '(.date | type == "string" and length > 0)) and',
        '(.message == "chore: sync rotating Spotlight links")',
    ):
        require(fragment in topology_commit_block,
                f"Spotlight proposer candidate-commit readback contract is missing: {fragment}")

    topology_compare_block = propose[topology_compare_call:topology_compare_consume]
    for fragment in (
        '(type == "object") and',
        '(.status == "ahead") and',
        '(.base_commit | type == "object" and .sha == $source) and',
        '(.merge_base_commit | type == "object" and .sha == $source) and',
        '(.ahead_by | type == "number" and . == floor and . == 1) and',
        '(.behind_by | type == "number" and . == floor and . == 0) and',
        '(.total_commits | type == "number" and . == floor and . == 1) and',
        '(.commits | type == "array" and length == 1 and',
        '(.[0] | type == "object" and .sha == $head)) and',
        '(.files | type == "array" and length == 1 and',
        '(.filename | type == "string" and . == "README.md") and',
        '(.status | type == "string" and . == "modified") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$")) and',
        '(.additions | type == "number" and . == floor and . >= 0) and',
        '(.deletions | type == "number" and . == floor and . >= 0) and',
        '(.changes | type == "number" and . == floor and . >= 0)',
    ):
        require(fragment in topology_compare_block,
                f"Spotlight proposer candidate-compare readback contract is missing: {fragment}")

    ref_call = propose.index('CREATED_REF="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" --input ref.json)"', candidate_content)
    ref_schema = propose.index('jq -e --arg ref "refs/heads/${CANDIDATE_BRANCH}" --arg head "$HEAD_SHA"', ref_call)
    ref_consume = propose.index('test "$(jq -r .ref <<<"$CREATED_REF")"', ref_schema)
    pr_call = propose.index('gh api --method POST "repos/${GITHUB_REPOSITORY}/pulls" --input pr.json > pr-response.json', ref_consume)
    pr_schema = propose.index('jq -e --arg title "chore: sync rotating Spotlight links"', pr_call)
    pr_consume = propose.index('PR_NUMBER="$(jq -r .number pr-response.json)"', pr_schema)
    require(
        blob_call < blob_schema < blob_consume < base_call < base_schema < base_consume
        < tree_call < tree_schema < tree_consume < commit_call < commit_schema < commit_consume
        < topology_commit_call < topology_commit_schema < topology_commit_consume
        < topology_compare_call < topology_compare_schema < topology_compare_consume
        < candidate_content < ref_call < ref_schema < ref_consume < pr_call < pr_schema < pr_consume,
        "Spotlight proposal mutation/readback validation must precede each downstream publication field consumption",
    )

    merge = job_block(legacy, "merge", None)
    terminal_refs_call_marker = (
        'CANDIDATE_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"'
    )
    terminal_refs_schema_marker = (
        'jq -e --arg ref "refs/heads/${CANDIDATE_BRANCH}" --arg head "$HEAD_SHA"'
    )
    terminal_refs_consume_marker = (
        'EXACT_REF_COUNT="$(jq --arg ref "refs/heads/${CANDIDATE_BRANCH}" '
        '\'[.[] | select(.ref == $ref)] | length\' <<<"$CANDIDATE_REFS")"'
    )
    terminal_delete_marker = (
        'gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CANDIDATE_BRANCH}" >/dev/null'
    )
    terminal_after_call_marker = (
        'AFTER_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"'
    )
    terminal_after_schema_marker = (
        'jq -e \'(type == "array") and (length == 0)\' <<<"$AFTER_REFS" >/dev/null'
    )
    terminal_after_consume_marker = (
        'AFTER_EXACT="$(jq --arg ref "refs/heads/${CANDIDATE_BRANCH}" '
        '\'[.[] | select(.ref == $ref)] | length\' <<<"$AFTER_REFS")"'
    )
    terminal_output_marker = 'echo "merge_sha=$MERGE_SHA" >> "$GITHUB_OUTPUT"'
    cleanup_verified_marker = 'echo "Spotlight terminal stage: cleanup-verified" >&2'
    for marker in (
        terminal_refs_call_marker, terminal_refs_schema_marker, terminal_refs_consume_marker,
        terminal_delete_marker, terminal_after_call_marker, terminal_after_schema_marker,
        terminal_after_consume_marker, terminal_output_marker, cleanup_verified_marker,
    ):
        require(merge.count(marker) == 1,
                f"Spotlight terminal candidate-ref collection contract anchor is missing or ambiguous: {marker}")

    terminal_refs_call = merge.index(terminal_refs_call_marker)
    terminal_refs_schema = merge.index(terminal_refs_schema_marker)
    terminal_refs_consume = merge.index(terminal_refs_consume_marker)
    terminal_delete = merge.index(terminal_delete_marker)
    terminal_after_call = merge.index(terminal_after_call_marker)
    terminal_after_schema = merge.index(terminal_after_schema_marker)
    terminal_after_consume = merge.index(terminal_after_consume_marker)
    terminal_output = merge.index(terminal_output_marker)
    cleanup_verified = merge.index(cleanup_verified_marker)

    terminal_refs_block = merge[terminal_refs_call:terminal_refs_consume]
    for fragment in (
        '(type == "array") and',
        '(length <= 1) and',
        '(.ref | type == "string" and . == $ref) and',
        '(.object | type == "object" and',
        '(.type | type == "string" and . == "commit") and',
        '(.sha | type == "string" and . == $head)',
    ):
        require(fragment in terminal_refs_block,
                f"Spotlight terminal candidate-ref collection contract is missing: {fragment}")
    require(
        terminal_refs_call < terminal_refs_schema < terminal_refs_consume < terminal_delete
        < terminal_after_call < terminal_after_schema < terminal_after_consume
        < terminal_output < cleanup_verified,
        "Spotlight terminal candidate-ref cleanup validation must precede delete/output/cleanup-complete evidence",
    )

    require(legacy.count(IMMUTABLE_ANCHOR) == 1,
            "Spotlight v21 immutable-candidate projection anchor changed")
    projected_immutable = legacy.replace(IMMUTABLE_ANCHOR, IMMUTABLE_PROJECTED, 1)
    require(
        projected_immutable.count(HARDENED_RUN_BRANCH_PROOF) == 1,
        "Spotlight hardened protected workflow candidate-branch proof changed",
    )
    require(
        LEGACY_RUN_BRANCH_PROOF not in projected_immutable,
        "Spotlight production workflow regained raw protected workflow branch consumption",
    )
    v21_immutable = projected_immutable.replace(
        HARDENED_RUN_BRANCH_PROOF,
        LEGACY_RUN_BRANCH_PROOF,
        1,
    )
    v21.validate_spotlight_immutable_candidates(v21_immutable)
    projected = projected_immutable.replace(NEW_MERGE_IF, OLD_MERGE_IF, 1)
    require(projected != projected_immutable,
            "Spotlight v21 mutation-budget projection could not isolate item-10 merge gating")
    v21.validate_spotlight_mutation_budget(projected)



def validate_native_bot_review_gate(profile_quality: str, evaluator: str) -> None:
    gate = job_block(profile_quality, "governed_bot_review", None)
    for fragment in (
        "if: github.event_name == 'pull_request'",
        "name: trusted-governed-bot-review",
        "runs-on: ubuntu-24.04",
        "timeout-minutes: 20",
        "permissions:\n      contents: read\n      pull-requests: read",
        "- name: Run exact accepted-base governed bot review gate",
        "GH_TOKEN: ${{ github.token }}",
        "GITHUB_TOKEN: ${{ github.token }}",
        "EXPECTED_GATE_BLOB: e42c1a8c3204d9a83ac837bbd04743fe3907b41c",
        'gh api -H "Accept: application/vnd.github.raw+json" "repos/${TARGET_REPOSITORY}/contents/scripts/governed_bot_review_gate.py?ref=${EVENT_BASE_SHA}" > "$TRUSTED_GATE"',
        'GATE_BLOB="$( { printf \'blob %s\\0\' "$GATE_SIZE"; cat "$TRUSTED_GATE"; } | sha1sum | cut -d\' \' -f1 )"',
        'test "$GATE_BLOB" = "$EXPECTED_GATE_BLOB"',
        'python3 "$TRUSTED_GATE" --self-test',
        'python3 "$TRUSTED_GATE"',
    ):
        require(fragment in gate, f"native governed-bot review gate contract is missing: {fragment}")
    require(gate.count("gh api ") == 1,
            "native governed-bot review gate must have exactly one GitHub API surface")
    for forbidden in (
        "actions/checkout@",
        "actions/setup-python@",
        "uses:",
        "--method POST",
        "--method PUT",
        "--method PATCH",
        "--method DELETE",
        "git push",
        "/pulls/${PR_NUMBER}/reviews",
        "/actions/workflows/",
    ):
        require(forbidden not in gate,
                f"native governed-bot review gate acquired forbidden candidate or mutation surface: {forbidden}")

    actual = v21.git_blob_sha(ROOT / "scripts/governed_bot_review_gate.py")
    require(
        actual == TRUSTED_GOVERNED_BOT_REVIEW_GATE,
        "trusted governed-bot review evaluator bytes changed without an explicit byte-lock update",
    )
    require(
        f"EXPECTED_GATE_BLOB: {ACCEPTED_BASE_GOVERNED_BOT_REVIEW_GATE}" in gate,
        "Profile Quality staging phase must execute only the exact accepted-base governed-bot evaluator",
    )
    for fragment in (
        'REPOSITORY = "portyu9/portyu9"',
        'REVIEW_LOGIN = "portyu9"',
        'method="GET"',
        'return "dependabot"',
        'return "codeql-autofix"',
        'return "spotlight"',
        'return "veto"',
        'return "revoked"',
        'return "approved"',
        'review_decision(api.all_reviews(pr_number), event_base_sha, event_head_sha) == "approved"',
        'raise GateError("latest manual exact-head portyu9 review requests changes")',
        'raise GateError("the exact marker-bound portyu9 review was dismissed or revoked")',
        'REVIEW_STATES = frozenset({"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING"})',
        'def validate_review_entries(reviews: list[Any]) -> list[dict[str, Any]]:',
        'review response contains a duplicate id',
        'review response contains an invalid user login',
        'review response contains an invalid state',
        'review response is missing commit_id',
        'review response contains an invalid commit_id',
        'review response is missing body',
        'review response contains an invalid body',
        'def flatten_review_pages(payload: Any) -> list[dict[str, Any]]:',
        'slurped review response must be a non-empty page array',
        'non-final review page is incomplete',
        'mode.add_argument("--validate-review-pages", action="store_true")',
        'reviews = validate_review_entries(reviews)',
        'READ_ATTEMPTS = 3',
        'READ_TIMEOUT_SECONDS = 20',
        'READ_BACKOFF_SECONDS = (1.0, 2.0)',
        'READ_MAX_RETRY_AFTER_SECONDS = 5.0',
        'READ_RETRYABLE_HTTP_STATUS = frozenset({408, 429, 500, 502, 503, 504})',
        'def retryable_read_http_error(exc: urllib.error.HTTPError) -> bool:',
        'headers.get("X-RateLimit-Remaining") == "0" or bool(headers.get("Retry-After"))',
        'for attempt in range(READ_ATTEMPTS):',
        'attempt + 1 >= READ_ATTEMPTS or not retryable_read_http_error(exc)',
        'except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:',
        'raise GateError("GitHub API GET returned malformed JSON")',
    ):
        require(fragment in evaluator, f"trusted governed-bot review evaluator contract is missing: {fragment}")
    for forbidden in ('method="POST"', 'method="PUT"', 'method="PATCH"', 'method="DELETE"', "subprocess"):
        require(forbidden not in evaluator,
                f"trusted governed-bot review evaluator acquired mutation/external execution surface: {forbidden}")


def validate_pull_review_evidence_schema(workflow: str, label: str, expected_reads: int) -> None:
    require(
        workflow.count('/reviews?per_page=100') == expected_reads,
        f"{label} pull-review endpoint count changed",
    )
    require(
        workflow.count('REVIEW_PAGES="$(gh api --paginate --slurp') == expected_reads,
        f"{label} must capture each paginated review response before filtering",
    )
    require(
        workflow.count('REVIEWS="$(jq -c \'[.[][]]\' <<<"$REVIEW_PAGES")"') == expected_reads,
        f"{label} must flatten only a validated paginated review response",
    )
    require(
        workflow.count('ERROR: malformed or incomplete paginated pull-review evidence.') == expected_reads,
        f"{label} must fail closed at every pull-review evidence read",
    )
    for fragment in (
        '(type == "array") and (length >= 1) and (length <= 20)',
        '(all(.[]; type == "array" and length <= 100))',
        '(all(.[0:-1][]; length == 100))',
        '(.id | type == "number" and . == floor and . > 0)',
        '(.user | type == "object" and (.login | type == "string" and length > 0))',
        '(. == "APPROVED" or . == "CHANGES_REQUESTED" or . == "COMMENTED" or . == "DISMISSED" or . == "PENDING")',
        '(.state | type == "string" and',
        'has("commit_id") and',
        '(.commit_id == null or (.commit_id | type == "string" and test("^[0-9a-f]{40}$")))',
        'has("body") and',
        '(.body == null or (.body | type == "string"))',
        '(([.[][] | .id] | length) == ([.[][] | .id] | unique | length))',
    ):
        require(
            workflow.count(fragment) == expected_reads,
            f"{label} strict review schema contract is missing or duplicated: {fragment}",
        )
    require(
        'REVIEWS="$(gh api --paginate --slurp' not in workflow,
        f"{label} must not filter raw paginated review evidence directly",
    )
    require(
        '.[][] | select(.user.login == "portyu9"' not in workflow,
        f"{label} approval/veto selection must consume the validated flattened review set",
    )




def validate_bot_review_single_object_evidence_schema(bot_review: str) -> None:
    for fragment in (
        'validate_governed_pr_object() {',
        '--argjson number "$number"',
        '(.number | type == "number" and . == floor and . > 0 and . == $number) and',
        '(.user | (type == "object") and (.login | (type == "string") and length > 0)) and',
        '(.draft | type == "boolean") and',
        '(.base | type == "object" and',
        '(.head | type == "object" and',
        '(.repo | type == "object" and',
        'ERROR: malformed governed bot PR evidence for #${PR_NUMBER}.',
        'ERROR: malformed governed bot PR race evidence for #${PR_NUMBER}.',
        'ERROR: malformed or mismatched governed bot review response for PR #${PR_NUMBER}.',
        '(.commit_id | type == "string" and test("^[0-9a-f]{40}$") and . == $head) and',
        '(.body | type == "string" and . == $body)',
    ):
        require(
            fragment in bot_review,
            f"Bot PR reviewer single-object evidence schema contract is missing: {fragment}",
        )

    initial_fetch = 'PR="$(gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}")"'
    initial_schema = 'validate_governed_pr_object "$PR" "$PR_NUMBER"'
    initial_consumer = 'test "$(jq -r .state <<<"$PR")" = "open"'
    require(
        bot_review.index(initial_fetch) < bot_review.index(initial_schema) < bot_review.index(initial_consumer),
        "Bot PR reviewer must validate initial hydrated PR evidence before field consumption",
    )

    race_fetch = 'PR_NOW="$(gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}")"'
    race_schema = 'validate_governed_pr_object "$PR_NOW" "$PR_NUMBER"'
    race_consumer = 'if [ "$(jq -r .state <<<"$PR_NOW")" != "open" ] ||'
    require(
        bot_review.index(race_fetch) < bot_review.index(race_schema) < bot_review.index(race_consumer),
        "Bot PR reviewer must validate the final PR race snapshot before authorization comparisons",
    )
    require(
        bot_review.count('validate_governed_pr_object "$PR" "$PR_NUMBER"') == 1
        and bot_review.count('validate_governed_pr_object "$PR_NOW" "$PR_NUMBER"') == 1,
        "Bot PR reviewer must schema-validate exactly both privileged single-PR reads",
    )

    review_mutation = 'REVIEW_HTTP_RESPONSE="$(GH_TOKEN="$REVIEW_TOKEN" gh api --include --method POST'
    review_schema = '(.id | ((type == "number") and . == floor and . > 0)) and'
    review_success = 'Submitted exact-base/head marker-bound portyu9 approval for governed bot PR #${PR_NUMBER}'
    mutation_pos = bot_review.index(review_mutation)
    schema_pos = bot_review.index(review_schema, mutation_pos)
    success_pos = bot_review.index(review_success, schema_pos)
    require(
        mutation_pos < schema_pos < success_pos,
        "Bot PR reviewer must validate the review-creation response before treating the mutation as successful",
    )
    require(
        bot_review.count('(.id | ((type == "number") and . == floor and . > 0)) and') == 1,
        "Bot PR reviewer review-response positive-id guard must be syntactically distinct and unique",
    )
    require(
        bot_review.count("malformed governed bot PR evidence") == 1
        and bot_review.count("malformed governed bot PR race evidence") == 1
        and bot_review.count("malformed or mismatched governed bot review response") == 1,
        "Bot PR reviewer must retain one fail-closed error boundary for each single-object evidence use",
    )


def validate_bot_review_identity_ref_evidence_schema(bot_review: str) -> None:
    for fragment in (
        'validate_git_ref_object() {',
        'local response="$1" expected_branch="$2"',
        '--arg ref "refs/heads/${expected_branch}"',
        '(.ref | type == "string" and . == $ref) and',
        '(.type | type == "string" and . == "commit") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$")) and',
        '(.url | type == "string" and length > 0)',
        'REVIEW_IDENTITY_RESPONSE="$(GH_TOKEN="$REVIEW_TOKEN" gh api user)"',
        '(.login | type == "string" and . == "portyu9")',
        'ERROR: malformed or mismatched portyu9 review-token identity response.',
        'ERROR: malformed governed reviewer initial main-ref evidence.',
        'ERROR: malformed governed reviewer current-main ref evidence.',
        'ERROR: malformed governed reviewer current-head ref evidence for #${PR_NUMBER}.',
        'ERROR: malformed governed reviewer final-main ref evidence.',
        'ERROR: malformed governed reviewer final-head ref evidence for #${PR_NUMBER}.',
    ):
        require(
            fragment in bot_review,
            f"Bot PR reviewer identity/ref evidence schema contract is missing: {fragment}",
        )

    require(
        bot_review.count('validate_git_ref_object "$') == 5,
        "Bot PR reviewer must schema-validate exactly five authority-relevant Git-ref reads",
    )
    for forbidden in (
        'gh api user --jq .login',
        'git/ref/heads/main" --jq .object.sha',
        'git/ref/heads/${HEAD_REF}" --jq .object.sha',
    ):
        require(
            forbidden not in bot_review,
            f"Bot PR reviewer regressed to direct singleton scalar consumption: {forbidden}",
        )

    identity_fetch = 'REVIEW_IDENTITY_RESPONSE="$(GH_TOKEN="$REVIEW_TOKEN" gh api user)"'
    identity_schema = '(.login | type == "string" and . == "portyu9")'
    identity_consume = 'REVIEW_LOGIN="$(jq -r .login <<<"$REVIEW_IDENTITY_RESPONSE")"'
    require(
        bot_review.index(identity_fetch)
        < bot_review.index(identity_schema, bot_review.index(identity_fetch))
        < bot_review.index(identity_consume),
        "Bot PR reviewer must type the review-token user response before login consumption",
    )

    boundaries = (
        (
            'MAIN_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main")"',
            'validate_git_ref_object "$MAIN_REF_RESPONSE" "main"',
            'MAIN_SHA="$(jq -r .object.sha <<<"$MAIN_REF_RESPONSE")"',
            "initial main-ref",
        ),
        (
            'CURRENT_MAIN_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main")"',
            'validate_git_ref_object "$CURRENT_MAIN_REF_RESPONSE" "main"',
            'if [ "$(jq -r .object.sha <<<"$CURRENT_MAIN_REF_RESPONSE")" != "$MAIN_SHA" ]; then',
            "current-main ref",
        ),
        (
            'CURRENT_HEAD_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}")"',
            'validate_git_ref_object "$CURRENT_HEAD_REF_RESPONSE" "$HEAD_REF"',
            'if [ "$(jq -r .object.sha <<<"$CURRENT_HEAD_REF_RESPONSE")" != "$HEAD_SHA" ]; then',
            "current-head ref",
        ),
        (
            'FINAL_MAIN_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main")"',
            'validate_git_ref_object "$FINAL_MAIN_REF_RESPONSE" "main"',
            'if [ "$(jq -r .object.sha <<<"$FINAL_MAIN_REF_RESPONSE")" != "$MAIN_SHA" ]; then',
            "final-main ref",
        ),
        (
            'FINAL_HEAD_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}")"',
            'validate_git_ref_object "$FINAL_HEAD_REF_RESPONSE" "$HEAD_REF"',
            'if [ "$(jq -r .object.sha <<<"$FINAL_HEAD_REF_RESPONSE")" != "$HEAD_SHA" ]; then',
            "final-head ref",
        ),
    )
    for fetch, schema, consume, label in boundaries:
        require(
            fetch in bot_review and schema in bot_review and consume in bot_review,
            f"Bot PR reviewer {label} fetch/schema/consumer identity changed",
        )
        fetch_pos = bot_review.index(fetch)
        schema_pos = bot_review.index(schema)
        consume_pos = bot_review.index(consume)
        require(
            fetch_pos < schema_pos < consume_pos,
            f"Bot PR reviewer must validate {label} evidence before SHA consumption",
        )


def validate_bot_review_run_check_evidence_schema(bot_review: str) -> None:
    for fragment in (
        '(.check_runs | type == "array" and length <= 100) and',
        '(.name == $name) and',
        '(.app | type == "object" and (.id == 15368)) and',
        '(([.check_runs[] | .id] | length) == ([.check_runs[] | .id] | unique | length))',
        'ERROR: malformed or incomplete required-check evidence for ${name} on ${head}.',
        '(.workflow_runs | type == "array" and length <= 100) and',
        '(.head_repository | type == "object" and',
        '(([.workflow_runs[] | .id] | length) == ([.workflow_runs[] | .id] | unique | length))',
        'ERROR: malformed or incomplete workflow-run quiescence evidence for ${head}.',
    ):
        require(
            fragment in bot_review,
            f"Bot PR reviewer run/check schema contract is missing: {fragment}",
        )
    require(
        bot_review.count('(.total_count | type == "number" and . == floor and . >= 0 and . <= 100) and') == 2,
        "Bot PR reviewer must strictly validate both bounded REST collection totals",
    )
    require(
        bot_review.count(
            '. == "queued" or . == "in_progress" or . == "requested" or'
        ) == 2
        and bot_review.count(
            '. == "waiting" or . == "pending" or . == "completed"'
        ) == 2,
        "Bot PR reviewer must lock the documented six-state check/workflow-run status set at both evidence boundaries",
    )
    require(
        bot_review.count('select(.status != "completed")') == 3,
        "Bot PR reviewer must classify every validated non-completed check/run as active",
    )
    old_partial_active = (
        'select(.status == "queued" or .status == "in_progress" or '
        '.status == "waiting" or .status == "pending")'
    )
    require(
        old_partial_active not in bot_review,
        "Bot PR reviewer must not let requested/unknown workflow-run status disappear from quiescence",
    )
    require(
        bot_review.count("malformed or incomplete required-check evidence") == 1
        and bot_review.count("malformed or incomplete workflow-run quiescence evidence") == 1,
        "Bot PR reviewer must retain exactly one fail-closed schema boundary for each run/check collection",
    )

    check_fetch = 'checks="$(gh api "repos/${TARGET_REPOSITORY}/commits/${head}/check-runs?app_id=15368&check_name=${name}&filter=latest&per_page=100")"'
    check_schema = '(.check_runs | type == "array" and length <= 100) and'
    check_ready = 'if [ "$count" = "0" ]; then'
    require(
        bot_review.index(check_fetch) < bot_review.index(check_schema) < bot_review.index(check_ready),
        "Bot PR reviewer must validate required-check evidence before readiness decisions",
    )

    run_fetch = 'runs="$(gh api "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${head}&per_page=100")"'
    run_schema = '(.workflow_runs | type == "array" and length <= 100) and'
    active_profile = 'active_profile="$(jq --arg head "$head"'
    require(
        bot_review.index(run_fetch) < bot_review.index(run_schema) < bot_review.index(active_profile),
        "Bot PR reviewer must validate workflow-run evidence before quiescence filtering",
    )




def validate_dependabot_readiness_run_check_evidence_schema(dependabot: str) -> None:
    for fragment in (
        '(.check_runs | type == "array" and length <= 100) and',
        '(.name == $name) and',
        '(.app | type == "object" and (.id == 15368)) and',
        '(([.check_runs[] | .id] | length) == ([.check_runs[] | .id] | unique | length))',
        'ERROR: malformed or incomplete required-check evidence for ${NAME} on ${HEAD_SHA}.',
        '(.workflow_runs | type == "array" and length <= 100) and',
        '(.event == "workflow_dispatch") and',
        '(.head_sha == $head) and',
        '(.head_branch == $head_ref) and',
        '(.repository | type == "object" and (.full_name == $repo)) and',
        '(.head_repository | type == "object" and (.full_name == $repo)) and',
        '(([.workflow_runs[] | .id] | length) == ([.workflow_runs[] | .id] | unique | length))',
        'ERROR: malformed or incomplete exact-head workflow-dispatch run evidence for ${HEAD_SHA}.',
    ):
        require(
            fragment in dependabot,
            f"Dependabot readiness run/check schema contract is missing: {fragment}",
        )
    require(
        dependabot.count('(.total_count | type == "number" and . == floor and . >= 0 and . <= 100) and') == 2,
        "Dependabot readiness must strictly validate both bounded REST collection totals",
    )
    require(
        dependabot.count('(.id | (type == "number") and . == floor and . > 0) and') == 2,
        "Dependabot readiness must require positive integer ids at both run/check evidence boundaries",
    )
    require(
        dependabot.count(
            '. == "queued" or . == "in_progress" or . == "requested" or'
        ) == 2
        and dependabot.count(
            '. == "waiting" or . == "pending" or . == "completed"'
        ) == 2,
        "Dependabot readiness must lock the documented six-state check/workflow-run status set at both evidence boundaries",
    )
    old_partial_active = (
        'select(.status == "queued" or .status == "in_progress" or '
        '.status == "waiting" or .status == "pending")'
    )
    require(
        old_partial_active not in dependabot,
        "Dependabot readiness must not let requested/unknown workflow-run status disappear from quiescence",
    )
    require(
        dependabot.count('select(.status != "completed")') >= 2,
        "Dependabot readiness and dispatch suppression must classify every validated non-completed run as active",
    )
    require(
        dependabot.count("malformed or incomplete required-check evidence") == 1
        and dependabot.count("malformed or incomplete exact-head workflow-dispatch run evidence") == 1,
        "Dependabot readiness must retain exactly one fail-closed schema boundary for each run/check collection",
    )

    check_fetch = 'CHECKS="$(gh api "repos/${TARGET_REPOSITORY}/commits/${HEAD_SHA}/check-runs?app_id=15368&check_name=${NAME}&filter=latest&per_page=100")"'
    check_schema = '(.check_runs | type == "array" and length <= 100) and'
    check_ready = 'count="$(jq -r .total_count <<<"$CHECKS")"'
    require(
        dependabot.index(check_fetch) < dependabot.index(check_schema) < dependabot.index(check_ready),
        "Dependabot must validate required-check evidence before readiness decisions",
    )

    run_fetch = 'runs="$(gh api "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=workflow_dispatch&per_page=100")"'
    run_schema = '(.workflow_runs | type == "array" and length <= 100) and'
    first_run_consumer = 'if ! active="$(workflow_dispatch_runs)"; then'
    require(
        dependabot.index(run_fetch) < dependabot.index(run_schema) < dependabot.index(first_run_consumer),
        "Dependabot must validate workflow-dispatch evidence before quiescence filtering",
    )
    downstream_runs = 'ACTIVE="$(workflow_dispatch_runs)"'
    downstream_active = 'select(.status != "completed")'
    require(
        dependabot.index(downstream_runs) < dependabot.index(downstream_active, dependabot.index(downstream_runs)),
        "Dependabot dispatch suppression must consume validated run evidence before activity classification",
    )


def validate_dependabot_protected_workflow_evidence_schema(dependabot: str) -> None:
    start_marker = "          approve_exact_pr_workflows() {\n"
    end_marker = "\n\n          assert_transaction\n          approve_exact_pr_workflows\n"
    require(
        dependabot.count(start_marker) == 1 and dependabot.count(end_marker) == 1,
        "Dependabot protected workflow approval identity anchors changed",
    )
    start = dependabot.index(start_marker)
    block = dependabot[start:dependabot.index(end_marker, start)]

    workflow_validator = "python3 scripts/dependabot_controller.py workflow-definition-response"
    run_validator = "python3 scripts/dependabot_controller.py protected-workflow-runs-response"
    require(
        block.count(workflow_validator) == 3 and block.count(run_validator) == 1,
        "Dependabot protected workflow schema validator identity changed",
    )
    for forbidden in (
        'actions/workflows/codeql.yml" --jq .id',
        'actions/workflows/dependency-review.yml" --jq .id',
        'actions/workflows/profile-quality.yml" --jq .id',
        'runs="$(gh api "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100")"',
        "'.total_count // empty' <<<\"$runs\"",
        'jq -r .head_sha <<<"$run"',
        'jq -r .head_branch <<<"$run"',
        'jq -r .repository.full_name <<<"$run"',
        'jq -r .head_repository.full_name <<<"$run"',
    ):
        require(
            forbidden not in block,
            f"Dependabot protected workflow evidence regressed to raw consumption: {forbidden}",
        )

    workflow_contracts = (
        (
            'gh api "repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml"',
            '--expected-path ".github/workflows/codeql.yml"',
            'codeql_workflow_id="$(jq -r .id "$RUNNER_TEMP/dependabot-codeql-workflow-definition-normalized.json")"',
        ),
        (
            'gh api "repos/${TARGET_REPOSITORY}/actions/workflows/dependency-review.yml"',
            '--expected-path ".github/workflows/dependency-review.yml"',
            'dependency_workflow_id="$(jq -r .id "$RUNNER_TEMP/dependabot-dependency-workflow-definition-normalized.json")"',
        ),
        (
            'gh api "repos/${TARGET_REPOSITORY}/actions/workflows/profile-quality.yml"',
            '--expected-path ".github/workflows/profile-quality.yml"',
            'profile_workflow_id="$(jq -r .id "$RUNNER_TEMP/dependabot-profile-workflow-definition-normalized.json")"',
        ),
    )
    cursor = -1
    for fetch, expected_path, consume in workflow_contracts:
        fetch_pos = block.index(fetch, cursor + 1)
        validate_pos = block.index(workflow_validator, fetch_pos)
        consume_pos = block.index(consume, validate_pos)
        require(
            expected_path in block[validate_pos:consume_pos],
            f"Dependabot protected workflow definition identity changed: {expected_path}",
        )
        require(
            fetch_pos < validate_pos < consume_pos,
            "Dependabot protected workflow definition must be typed before ID use",
        )
        cursor = consume_pos

    run_fetch = (
        'gh api "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}'
        '&event=pull_request&per_page=100"'
    )
    run_consume = (
        'total="$(jq -r .totalCount "$RUNNER_TEMP/dependabot-protected-workflow-runs-normalized.json")"'
    )
    for fragment in (
        '--response "$RUNNER_TEMP/dependabot-protected-workflow-runs.json"',
        '--head-sha "$HEAD_SHA"',
        '--branch "$HEAD_REF"',
        '--codeql-workflow-id "$codeql_workflow_id"',
        '--dependency-workflow-id "$dependency_workflow_id"',
        '--profile-workflow-id "$profile_workflow_id"',
        '--out "$RUNNER_TEMP/dependabot-protected-workflow-runs-normalized.json"',
        run_consume,
        'runs="$(jq -c .runs "$RUNNER_TEMP/dependabot-protected-workflow-runs-normalized.json")"',
        '.workflowId == $workflow_id',
        '.checkSuiteId',
        '.runAttempt',
    ):
        require(
            fragment in block,
            f"Dependabot protected workflow-run identity changed: {fragment}",
        )
    fetch_pos = block.index(run_fetch)
    validate_pos = block.index(run_validator, fetch_pos)
    consume_pos = block.index(run_consume, validate_pos)
    require(
        fetch_pos < validate_pos < consume_pos,
        "Dependabot protected workflow-run collection must be typed before scalar use",
    )


def validate_spotlight_privileged_ref_evidence_schema(spotlight: str) -> None:
    helper_marker = "          validate_git_ref_object() {\n"
    helper_schema = (
        'local payload="$1" expected_ref="$2" expected_sha="$3"',
        '(type == "object") and',
        '(((.ref | type) == "string") and (.ref == $ref)) and',
        '(((.object | type) == "object") and',
        '(((.object.type | type) == "string") and (.object.type == "commit")) and',
        '((.object.sha | type) == "string") and',
        '(.object.sha | test("^[0-9a-f]{40}$")) and',
        '(.object.sha == $sha)) and',
        '(((.object.url | type) == "string") and ((.object.url | length) > 0))',
    )
    jobs = {
        "reconcile": "budget",
        "propose": "approve",
        "approve": "authorize",
        "merge": "decision_receipt",
    }
    blocks: dict[str, str] = {}
    for job, next_job in jobs.items():
        block = job_block(spotlight, job, next_job)
        blocks[job] = block
        require(
            block.count(helper_marker) == 1,
            f"Spotlight {job} must define exactly one privileged Git-ref validator",
        )
        helper_start = block.index(helper_marker)
        helper_end = block.index("          }\n\n", helper_start) + len("          }\n")
        helper = block[helper_start:helper_end]
        for fragment in helper_schema:
            require(fragment in helper, f"Spotlight {job} Git-ref schema changed: {fragment}")
        for forbidden in (
            'git/ref/heads/main" --jq .object.sha',
            'git/ref/heads/generated" --jq .object.sha',
            'git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha',
        ):
            require(
                forbidden not in block,
                f"Spotlight {job} regained raw singleton Git-ref scalar consumption: {forbidden}",
            )

    contracts = {
        "reconcile": (
            ('MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"',
             'validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$BASE_SHA"',
             'test "$(jq -r .object.sha <<<"$MAIN_REF_RESPONSE")" = "$BASE_SHA"'),
            ('GENERATED_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated")"',
             'validate_git_ref_object "$GENERATED_REF_RESPONSE" "refs/heads/generated" "$GENERATED_SHA"',
             'test "$(jq -r .object.sha <<<"$GENERATED_REF_RESPONSE")" = "$GENERATED_SHA"'),
        ),
        "propose": (
            ('MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"',
             'validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$SOURCE_SHA"',
             'test "$(jq -r .object.sha <<<"$MAIN_REF_RESPONSE")" = "$SOURCE_SHA"'),
            ('CANDIDATE_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}")"',
             'validate_git_ref_object "$CANDIDATE_REF_RESPONSE" "refs/heads/${CANDIDATE_BRANCH}" "$HEAD_SHA"',
             'test "$(jq -r .object.sha <<<"$CANDIDATE_REF_RESPONSE")" = "$HEAD_SHA"'),
        ),
        "approve": (
            ('MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"',
             'validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$BASE_SHA"',
             'test "$(jq -r .object.sha <<<"$MAIN_REF_RESPONSE")" = "$BASE_SHA"'),
            ('GENERATED_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated")"',
             'validate_git_ref_object "$GENERATED_REF_RESPONSE" "refs/heads/generated" "$GENERATED_SHA"',
             'test "$(jq -r .object.sha <<<"$GENERATED_REF_RESPONSE")" = "$GENERATED_SHA"'),
            ('CANDIDATE_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}")"',
             'validate_git_ref_object "$CANDIDATE_REF_RESPONSE" "refs/heads/${CANDIDATE_BRANCH}" "$HEAD_SHA"',
             'test "$(jq -r .object.sha <<<"$CANDIDATE_REF_RESPONSE")" = "$HEAD_SHA"'),
            ('MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"',
             'validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$BASE_SHA"',
             'test "$(jq -r .object.sha <<<"$MAIN_REF_RESPONSE")" = "$BASE_SHA"'),
            ('CANDIDATE_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}")"',
             'validate_git_ref_object "$CANDIDATE_REF_RESPONSE" "refs/heads/${CANDIDATE_BRANCH}" "$HEAD_SHA"',
             'test "$(jq -r .object.sha <<<"$CANDIDATE_REF_RESPONSE")" = "$HEAD_SHA"'),
        ),
        "merge": (
            ('MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"',
             'validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$BASE_SHA"',
             'test "$(jq -r .object.sha <<<"$MAIN_REF_RESPONSE")" = "$BASE_SHA"'),
            ('GENERATED_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated")"',
             'validate_git_ref_object "$GENERATED_REF_RESPONSE" "refs/heads/generated" "$GENERATED_SHA"',
             'test "$(jq -r .object.sha <<<"$GENERATED_REF_RESPONSE")" = "$GENERATED_SHA"'),
            ('CANDIDATE_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}")"',
             'validate_git_ref_object "$CANDIDATE_REF_RESPONSE" "refs/heads/${CANDIDATE_BRANCH}" "$HEAD_SHA"',
             'test "$(jq -r .object.sha <<<"$CANDIDATE_REF_RESPONSE")" = "$HEAD_SHA"'),
            ('MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"',
             'validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$BASE_SHA"',
             'test "$(jq -r .object.sha <<<"$MAIN_REF_RESPONSE")" = "$BASE_SHA"'),
            ('GENERATED_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated")"',
             'validate_git_ref_object "$GENERATED_REF_RESPONSE" "refs/heads/generated" "$GENERATED_SHA"',
             'test "$(jq -r .object.sha <<<"$GENERATED_REF_RESPONSE")" = "$GENERATED_SHA"'),
            ('CANDIDATE_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}")"',
             'validate_git_ref_object "$CANDIDATE_REF_RESPONSE" "refs/heads/${CANDIDATE_BRANCH}" "$HEAD_SHA"',
             'test "$(jq -r .object.sha <<<"$CANDIDATE_REF_RESPONSE")" = "$HEAD_SHA"'),
            ('CURRENT_MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"',
             'validate_git_ref_object "$CURRENT_MAIN_REF_RESPONSE" "refs/heads/main" "$MERGE_SHA"',
             'CURRENT_MAIN_SHA="$(jq -r .object.sha <<<"$CURRENT_MAIN_REF_RESPONSE")"'),
        ),
    }
    for job, specs in contracts.items():
        block = blocks[job]
        cursor = -1
        for fetch, validate, consume in specs:
            fetch_pos = block.find(fetch, cursor + 1)
            require(fetch_pos > cursor, f"Spotlight {job} Git-ref fetch disappeared: {fetch}")
            validate_pos = block.find(validate, fetch_pos)
            consume_pos = block.find(consume, validate_pos)
            require(
                fetch_pos < validate_pos < consume_pos,
                f"Spotlight {job} Git-ref evidence must validate before SHA consumption",
            )
            cursor = consume_pos
    require(
        spotlight.count(helper_marker) == 4
        and spotlight.count('validate_git_ref_object "$MAIN_REF_RESPONSE"') == 6
        and spotlight.count('validate_git_ref_object "$GENERATED_REF_RESPONSE"') == 4
        and spotlight.count('validate_git_ref_object "$CANDIDATE_REF_RESPONSE"') == 5
        and spotlight.count('validate_git_ref_object "$CURRENT_MAIN_REF_RESPONSE"') == 1,
        "Spotlight privileged Git-ref validation topology changed",
    )


def validate_codeql_autofix_constructive_response_schemas(autofix: str) -> None:
    created_ref = "python3 scripts/codeql_autofix_controller.py created-ref-response"
    reviewer = "python3 scripts/codeql_autofix_controller.py reviewer-request-response"
    require(autofix.count(created_ref) == 1,
            "CodeQL Autofix created-ref response validator identity changed")
    require(autofix.count(reviewer) == 1,
            "CodeQL Autofix reviewer-request response validator identity changed")
    for fragment in (
        "--response-file created-ref.json",
        '--expected-sha "$BASE_SHA"',
        "--out created-ref-normalized.json",
        'test "$(jq -r .ref created-ref-normalized.json)" = "$TARGET_REF"',
        'test "$(jq -r .sha created-ref-normalized.json)" = "$BASE_SHA"',
        "--response-file requested-reviewer.json",
        '--pr-number "$PR_NUMBER"',
        '--repository "$TARGET_REPOSITORY"',
        '--base-sha "$BASE_SHA"',
        '--branch "$BRANCH"',
        '--head-sha "$HEAD_SHA"',
        "--out requested-reviewer-normalized.json",
        'test "$(jq -r .reviewer requested-reviewer-normalized.json)" = "portyu9"',
        'test "$(jq -r .headSha requested-reviewer-normalized.json)" = "$HEAD_SHA"',
        '[[ "$AUTOFIX_CREATE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+(200|202)([[:space:]]|$) ]] || {',
        '[[ "$UNSUPPORTED_EVIDENCE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        '[[ "$CREATED_REF_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        '[[ "$AUTOFIX_COMMIT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        '[[ "$CREATED_PR_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
    ):
        require(fragment in autofix,
                f"CodeQL Autofix constructive response/status identity is missing: {fragment}")
    for forbidden in (
        'jq -r .ref created-ref.json',
        'jq -r .object.sha created-ref.json',
        '.requested_reviewers[]? | select(.login == "portyu9")',
        'gh api -X POST "repos/${TARGET_REPOSITORY}/git/refs"',
        'gh api -X POST \\\n            "repos/${TARGET_REPOSITORY}/code-scanning/alerts/${ALERT_NUMBER}/autofix/commits"',
        'gh api -X POST "repos/${TARGET_REPOSITORY}/pulls"',
    ):
        require(forbidden not in autofix,
                f"CodeQL Autofix constructive path regressed to untyped/response-blind mutation evidence: {forbidden}")

    request_post = autofix.index(
        'gh api --include --method POST \\\n'
        '            "repos/${TARGET_REPOSITORY}/code-scanning/alerts/${ALERT_NUMBER}/autofix"'
    )
    request_status = autofix.index('AUTOFIX_CREATE_STATUS_LINE=', request_post)
    request_guard = autofix.index(
        '[[ "$AUTOFIX_CREATE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+(200|202)([[:space:]]|$) ]] || {',
        request_status,
    )
    request_extract = autofix.index(
        'sed \'1,/^[[:space:]]*$/d\' "$AUTOFIX_CREATE_HTTP_RESPONSE" > autofix-create.json',
        request_guard,
    )
    unsupported_post = autofix.index(
        'gh api --include --method POST \\\n'
        '                "repos/${TARGET_REPOSITORY}/commits/${BASE_SHA}/comments"',
        request_extract,
    )
    unsupported_guard = autofix.index(
        '[[ "$UNSUPPORTED_EVIDENCE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        unsupported_post,
    )
    unsupported_extract = autofix.index(
        'unsupported-evidence-created.json',
        unsupported_guard,
    )

    ref_post = autofix.index('gh api --include --method POST "repos/${TARGET_REPOSITORY}/git/refs"')
    ref_guard = autofix.index(
        '[[ "$CREATED_REF_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        ref_post,
    )
    ref_extract = autofix.index(
        'sed \'1,/^[[:space:]]*$/d\' "$CREATED_REF_HTTP_RESPONSE" > created-ref.json',
        ref_guard,
    )
    ref_validate = autofix.index(created_ref, ref_extract)
    ref_consume = autofix.index(
        'test "$(jq -r .ref created-ref-normalized.json)" = "$TARGET_REF"',
        ref_validate,
    )
    autofix_commit = autofix.index(
        'gh api --include --method POST \\\n'
        '            "repos/${TARGET_REPOSITORY}/code-scanning/alerts/${ALERT_NUMBER}/autofix/commits"',
        ref_consume,
    )
    commit_guard = autofix.index(
        '[[ "$AUTOFIX_COMMIT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        autofix_commit,
    )
    commit_extract = autofix.index(
        'sed \'1,/^[[:space:]]*$/d\' "$AUTOFIX_COMMIT_HTTP_RESPONSE" > autofix-commit.json',
        commit_guard,
    )
    commit_validate = autofix.index("python3 scripts/codeql_autofix_controller.py commit", commit_extract)
    pr_create = autofix.index('gh api --include --method POST "repos/${TARGET_REPOSITORY}/pulls"', commit_validate)
    pr_guard = autofix.index(
        '[[ "$CREATED_PR_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        pr_create,
    )
    pr_extract = autofix.index(
        'sed \'1,/^[[:space:]]*$/d\' "$CREATED_PR_HTTP_RESPONSE" > created-pr.json',
        pr_guard,
    )
    receipt = autofix.index("python3 scripts/codeql_autofix_controller.py receipt", pr_extract)
    reviewer_post = autofix.index(
        'repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers',
        receipt,
    )
    reviewer_validate = autofix.index(reviewer, reviewer_post)
    reviewer_consume = autofix.index(
        'test "$(jq -r .headSha requested-reviewer-normalized.json)" = "$HEAD_SHA"',
        reviewer_validate,
    )
    require(
        request_post < request_status < request_guard < request_extract
        < unsupported_post < unsupported_guard < unsupported_extract
        < ref_post < ref_guard < ref_extract < ref_validate < ref_consume
        < autofix_commit < commit_guard < commit_extract < commit_validate
        < pr_create < pr_guard < pr_extract < receipt
        < reviewer_post < reviewer_validate < reviewer_consume,
        "CodeQL Autofix constructive response/status ordering changed",
    )


def validate_codeql_autofix_read_singleton_evidence(autofix: str) -> None:
    read_validator = "python3 scripts/codeql_autofix_controller.py read-ref-response"
    workflow_validator = "python3 scripts/codeql_autofix_controller.py workflow-definition-response"
    pr_validator = "python3 scripts/codeql_autofix_controller.py pull-request-response"
    run_validator = "python3 scripts/codeql_autofix_controller.py protected-workflow-runs-response"
    require(
        autofix.count(read_validator) == 4,
        "CodeQL Autofix read-ref response validator identity changed",
    )
    require(
        autofix.count(workflow_validator) == 3,
        "CodeQL Autofix workflow-definition response validator identity changed",
    )
    require(
        autofix.count(pr_validator) == 4,
        "CodeQL Autofix pull-request singleton response validator identity changed",
    )
    require(
        autofix.count(run_validator) == 1,
        "CodeQL Autofix protected workflow-run collection validator identity changed",
    )
    require(
        autofix.count("assert_main_sha() {") == 3
        and autofix.count("assert_head_sha() {") == 1,
        "CodeQL Autofix static ref assertion helper identity changed",
    )
    require(
        autofix.count('assert_main_sha "$BASE_SHA"') == 4
        and autofix.count('assert_head_sha "$HEAD_SHA"') == 1
        and autofix.count('assert_main_sha "$ADMITTED_BASE_SHA"') == 1
        and autofix.count('assert_main_sha "$MERGE_SHA"') == 4,
        "CodeQL Autofix expected-SHA ref assertion topology changed",
    )
    for forbidden in (
        'git/ref/heads/main" --jq .object.sha',
        'git/ref/heads/${BRANCH}" --jq .object.sha',
        'actions/workflows/codeql.yml" --jq .id',
        'actions/workflows/dependency-review.yml" --jq .id',
        'actions/workflows/profile-quality.yml" --jq .id',
        'pulls/${PR_NUMBER}" --jq',
        'jq -r .head.sha pr.json',
        'jq -r .state final-pr.json',
        'RUNS="$(gh api "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}',
        'jq -r .total_count <<<"$RUNS"',
        "final-main-ref.json",
        "assert_main_is_merge_sha",
    ):
        require(
            forbidden not in autofix,
            f"CodeQL Autofix regained untyped singleton evidence consumption: {forbidden}",
        )

    main_fetch = (
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main" '
        '> "$RUNNER_TEMP/codeql-autofix-main-ref.json"'
    )
    main_consume = (
        'test "$(jq -r .sha "$RUNNER_TEMP/codeql-autofix-main-ref-normalized.json")" '
        '= "$expected_sha"'
    )
    require(
        autofix.count(main_fetch) == 3
        and autofix.count('--expected-ref "refs/heads/main"') == 3
        and autofix.count(main_consume) == 3,
        "CodeQL Autofix typed main-ref identity changed",
    )
    head_fetch = (
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${BRANCH}" '
        '> "$RUNNER_TEMP/codeql-autofix-head-ref.json"'
    )
    require(
        autofix.count(head_fetch) == 1
        and autofix.count('--expected-ref "refs/heads/${BRANCH}"') == 1,
        "CodeQL Autofix exact candidate-ref identity changed",
    )

    workflow_fragments = (
        (
            'repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml',
            '--expected-path ".github/workflows/codeql.yml"',
            'CODEQL_WORKFLOW_ID="$(jq -r .id "$RUNNER_TEMP/codeql-workflow-definition-normalized.json")"',
        ),
        (
            'repos/${TARGET_REPOSITORY}/actions/workflows/dependency-review.yml',
            '--expected-path ".github/workflows/dependency-review.yml"',
            'DEPENDENCY_WORKFLOW_ID="$(jq -r .id "$RUNNER_TEMP/dependency-workflow-definition-normalized.json")"',
        ),
        (
            'repos/${TARGET_REPOSITORY}/actions/workflows/profile-quality.yml',
            '--expected-path ".github/workflows/profile-quality.yml"',
            'PROFILE_WORKFLOW_ID="$(jq -r .id "$RUNNER_TEMP/profile-workflow-definition-normalized.json")"',
        ),
    )
    cursor = -1
    for endpoint, expected_path, consume in workflow_fragments:
        fetch = f'gh api "{endpoint}"'
        require(
            autofix.count(fetch) == 1
            and expected_path in autofix
            and consume in autofix,
            f"CodeQL Autofix workflow-definition identity changed: {endpoint}",
        )
        fetch_pos = autofix.index(fetch, cursor + 1)
        validate_pos = autofix.index(workflow_validator, fetch_pos)
        consume_pos = autofix.index(consume, validate_pos)
        require(
            fetch_pos < validate_pos < consume_pos,
            "CodeQL Autofix workflow-definition evidence must be typed before ID use",
        )
        cursor = consume_pos

    pr_contracts = (
        (
            'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > "$RUNNER_TEMP/codeql-autofix-candidate-pr.json"',
            '--response-file "$RUNNER_TEMP/codeql-autofix-candidate-pr.json"',
            '--base-sha "$BASE_SHA"',
            '--head-sha "$HEAD_SHA"',
            '--out "$RUNNER_TEMP/codeql-autofix-candidate-pr-normalized.json"',
            'test "$(jq -r .headSha "$RUNNER_TEMP/codeql-autofix-candidate-pr-normalized.json")" = "$HEAD_SHA"',
        ),
        (
            'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > "$RUNNER_TEMP/codeql-autofix-continuation-pr.json"',
            '--response-file "$RUNNER_TEMP/codeql-autofix-continuation-pr.json"',
            '--base-sha "$BASE_SHA"',
            '--head-sha "$HEAD_SHA"',
            '--out "$RUNNER_TEMP/codeql-autofix-continuation-pr-normalized.json"',
            'test "$(jq -r .headSha "$RUNNER_TEMP/codeql-autofix-continuation-pr-normalized.json")" = "$HEAD_SHA"',
        ),
        (
            'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > pr.json',
            '--response-file pr.json',
            '--base-sha "$BASE_SHA"',
            '--head-sha "$EXPECTED_HEAD_SHA"',
            '--out pr-normalized.json',
            'test "$(jq -r .headSha pr-normalized.json)" = "$EXPECTED_HEAD_SHA"',
        ),
        (
            'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > final-pr.json',
            '--response-file final-pr.json',
            '--base-sha "$ADMITTED_BASE_SHA"',
            '--head-sha "$ADMITTED_HEAD_SHA"',
            '--out final-pr-normalized.json',
            'test "$(jq -r .headSha final-pr-normalized.json)" = "$ADMITTED_HEAD_SHA"',
        ),
    )
    cursor = -1
    for fetch, response, base_arg, head_arg, output, consume in pr_contracts:
        fetch_pos = autofix.index(fetch, cursor + 1)
        validate_pos = autofix.index(pr_validator, fetch_pos)
        consume_pos = autofix.index(consume, validate_pos)
        block = autofix[validate_pos:consume_pos]
        for fragment in (
            response,
            '--pr-number "$PR_NUMBER"',
            '--repository "$TARGET_REPOSITORY"',
            base_arg,
            '--branch "$BRANCH"',
            head_arg,
            output,
        ):
            require(
                fragment in block,
                f"CodeQL Autofix pull-request singleton identity changed: {fragment}",
            )
        require(
            fetch_pos < validate_pos < consume_pos,
            "CodeQL Autofix pull-request singleton must be typed before scalar use",
        )
        cursor = consume_pos

    run_fetch = (
        'gh api "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100" \\'
        '\n              > "$RUNNER_TEMP/codeql-autofix-protected-runs.json"'
    )
    run_consume = (
        'RUN_COUNT="$(jq -r .totalCount "$RUNNER_TEMP/codeql-autofix-protected-runs-normalized.json")"'
    )
    for fragment in (
        run_fetch,
        '--response-file "$RUNNER_TEMP/codeql-autofix-protected-runs.json"',
        '--head-sha "$HEAD_SHA"',
        '--branch "$BRANCH"',
        '--codeql-workflow-id "$CODEQL_WORKFLOW_ID"',
        '--dependency-workflow-id "$DEPENDENCY_WORKFLOW_ID"',
        '--profile-workflow-id "$PROFILE_WORKFLOW_ID"',
        '--out "$RUNNER_TEMP/codeql-autofix-protected-runs-normalized.json"',
        run_consume,
        'MATCHES="$(jq -c .runs "$RUNNER_TEMP/codeql-autofix-protected-runs-normalized.json")"',
        'test "$(jq \'[.[].workflowId] | unique | length\' <<<"$MATCHES")" = "3"',
    ):
        require(
            fragment in autofix,
            f"CodeQL Autofix protected workflow-run collection identity changed: {fragment}",
        )
    run_fetch_pos = autofix.index(run_fetch)
    run_validate_pos = autofix.index(run_validator, run_fetch_pos)
    run_consume_pos = autofix.index(run_consume, run_validate_pos)
    require(
        run_fetch_pos < run_validate_pos < run_consume_pos,
        "CodeQL Autofix protected workflow-run collection must be typed before scalar use",
    )


def validate_codeql_autofix_approval_comment_evidence(autofix: str) -> None:
    get_endpoint = 'repos/${TARGET_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100'
    post_endpoint = 'gh api --include --method POST "repos/${TARGET_REPOSITORY}/issues/${PR_NUMBER}/comments"'
    post_status = 'APPROVAL_COMMENT_STATUS_LINE="$(head -n 1 <<<"$APPROVAL_COMMENT_HTTP_RESPONSE" | tr -d \'\\r\')"'
    post_guard = '[[ "$APPROVAL_COMMENT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {'
    post_extract = 'sed \'1,/^[[:space:]]*$/d\' <<<"$APPROVAL_COMMENT_HTTP_RESPONSE" > approval-comment.json'
    evidence_validator = "python3 scripts/codeql_autofix_controller.py approval-comment-evidence"
    created_validator = "python3 scripts/codeql_autofix_controller.py approval-comment-created"

    require(
        autofix.count(get_endpoint) == 1
        and autofix.count(post_endpoint) == 1
        and autofix.count(post_status) == 1
        and autofix.count(post_guard) == 1
        and autofix.count(post_extract) == 1
        and autofix.count(evidence_validator) == 1
        and autofix.count(created_validator) == 1,
        "CodeQL Autofix approval-comment evidence/status topology changed",
    )
    for forbidden in (
        'COMMENTS="$(gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100")"',
        '[.[][] | select(.body | contains($marker))] | length > 0',
        'jq -r .body approval-comment.json',
    ):
        require(
            forbidden not in autofix,
            f"CodeQL Autofix approval-comment evidence regressed to raw consumption: {forbidden}",
        )

    marker_pos = autofix.index(
        'APPROVAL_MARKER="<!-- portyu9-automation-approval:v1 head=${ADMITTED_HEAD_SHA} -->"'
    )
    get_pos = autofix.index(get_endpoint, marker_pos)
    validate_pos = autofix.index(evidence_validator, get_pos)
    consume_pos = autofix.index(
        'APPROVAL_COMMENT_EXISTS="$(jq -r .exists approval-comment-evidence.json)"',
        validate_pos,
    )
    post_pos = autofix.index(post_endpoint, consume_pos)
    post_status_pos = autofix.index(post_status)
    post_guard_pos = autofix.index(post_guard)
    post_extract_pos = autofix.index(post_extract)
    created_pos = autofix.index(created_validator, post_extract_pos)
    actor_pos = autofix.index(
        'test "$(jq -r .actor approval-comment-normalized.json)" = "github-actions[bot]"',
        created_pos,
    )
    merge_pos = autofix.index(
        'gh api --include --method PUT "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/merge"',
        actor_pos,
    )
    require(
        marker_pos < get_pos < validate_pos < consume_pos < post_pos
        < post_status_pos < post_guard_pos < post_extract_pos
        < created_pos < actor_pos < merge_pos,
        "CodeQL Autofix approval-comment evidence/status must be typed before mutation/merge",
    )
    for fragment in (
        '--comments-file approval-comment-pages.json',
        '--pr-number "$PR_NUMBER"',
        '--marker "$APPROVAL_MARKER"',
        '--out approval-comment-evidence.json',
        'if [ "$APPROVAL_COMMENT_EXISTS" = "false" ]; then',
        '--comment-file approval-comment.json',
        '--expected-body "$APPROVAL_BODY"',
        '--out approval-comment-normalized.json',
        'test "$(jq -r .prNumber approval-comment-normalized.json)" = "$PR_NUMBER"',
    ):
        require(
            fragment in autofix,
            f"CodeQL Autofix approval-comment identity changed: {fragment}",
        )


def project_spotlight_reviewer_request_helper_to_legacy(spotlight: str) -> str:
    """Remove the independently validated reviewer-request helper from frozen review-schema counts."""
    start_marker = "          validate_spotlight_reviewer_request_response() {\n"
    end_marker = "\n\n          REF_CREATED=false"
    require(
        spotlight.count(start_marker) == 1 and spotlight.count(end_marker) >= 1,
        "Spotlight reviewer-request compatibility projection anchors changed",
    )
    start = spotlight.index(start_marker)
    end = spotlight.index(end_marker, start)
    require(start < end, "Spotlight reviewer-request compatibility projection ordering changed")
    return spotlight[:start] + spotlight[end:]


def project_spotlight_approval_list_helper_to_legacy(spotlight: str) -> str:
    """Remove the independently validated approval-list helper from frozen review-schema counts."""
    start_marker = "          validate_spotlight_pull_list_item() {\n"
    end_marker = "\n\n          APPROVAL_REQUESTS_JSON='[]'"
    require(
        spotlight.count(start_marker) == 1 and spotlight.count(end_marker) == 1,
        "Spotlight approval-list compatibility projection anchors changed",
    )
    start = spotlight.index(start_marker)
    end = spotlight.index(end_marker, start)
    require(start < end, "Spotlight approval-list compatibility projection ordering changed")
    projected = spotlight[:start] + spotlight[end:]
    require(
        "validate_spotlight_pull_list_item() {" not in projected,
        "Spotlight approval-list compatibility projection left helper definition bytes behind",
    )
    return projected


def validate_bot_review_liveness(bot_review: str, dependabot: str, autofix: str, spotlight: str) -> None:
    validate_bot_review_single_object_evidence_schema(bot_review)
    validate_bot_review_identity_ref_evidence_schema(bot_review)
    validate_bot_review_run_check_evidence_schema(bot_review)
    validate_dependabot_readiness_run_check_evidence_schema(dependabot)
    validate_dependabot_protected_workflow_evidence_schema(dependabot)
    validate_pull_review_evidence_schema(bot_review, "Bot PR reviewer", 2)
    validate_pull_review_evidence_schema(dependabot, "Dependabot terminal merge", 1)
    validate_pull_review_evidence_schema(autofix, "CodeQL Autofix terminal merge", 1)
    spotlight_review_projection = project_spotlight_reviewer_request_helper_to_legacy(spotlight)
    spotlight_review_projection = project_spotlight_approval_list_helper_to_legacy(
        spotlight_review_projection
    )
    validate_pull_review_evidence_schema(
        spotlight_review_projection, "Spotlight authorization/terminal merge", 2
    )
    for fragment in (
        'local -a required=(validate-contracts integration-pinned-upstream analyze-actions analyze-python dependency-review)',
        'spotlight|dependabot|codeql-autofix)',
        'required+=(trusted-capability-admission)',
        'LANE="dependabot"',
        'LANE="codeql-autofix"',
        'LANE="spotlight"',
        'Skipping governed bot PR #${PR_NUMBER}: base is stale relative to current main.',
        'check_required_contexts "$HEAD_SHA" "$LANE"',
        'all lane-required protected gates completed successfully',
        'REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${MAIN_SHA} head=${HEAD_SHA} -->"',
        'for HISTORY_ATTEMPT in $(seq 1 20); do',
        'actions/runs/${GITHUB_RUN_ID}/attempts/${HISTORY_ATTEMPT}',
        'bot-review-prior-attempts.json',
        'kind:"portyu9-bot-review-provenance"',
        'runId:$runId',
        'runAttempt:$runAttempt',
        'retryHistory:$retryHistory[0]',
        'REVIEW_PROVENANCE_SHA256',
        'portyu9-bot-review-provenance:v1 sha256=',
        '--arg marker "$REVIEW_MARKER"',
        'contains($marker)',
        'exact-base/head marker-bound portyu9 approval',
        'return 2',
        'lane-required checks are not ready yet.',
        'exact head is not quiescent yet.',
        'completed unsuccessfully on ${head}.',
        '::error::PORTYU9_BOT_REVIEW_TOKEN is required in the portyu9-review-identity environment',
        'MARKER_REVIEW_COUNT=',
        'LATEST_MANUAL_DECISIVE_STATE=',
        'RACE_MANUAL_DECISIVE_STATE=',
        '(.state == "APPROVED" or .state == "CHANGES_REQUESTED")',
        'contains($marker)) | not',
        'a later manual exact-head CHANGES_REQUESTED veto by portyu9 is active.',
        'the exact marker-bound portyu9 review was revoked or dismissed and will not be auto-reissued.',
        'a manual exact-head CHANGES_REQUESTED veto appeared before the review mutation.',
        'exit 1',
        'group: bot-pr-user-approval',
        'cancel-in-progress: true',
        'Re-dispatched idempotent post-review convergence wake for governed bot PR #${PR_NUMBER} (${LANE}).',
        'local head="$1" head_ref="$2" runs total count active_profile unexpected_active',
        '.name == "Profile quality" and',
        '.path == ".github/workflows/profile-quality.yml" and',
        '.event == "pull_request" and',
        '.head_sha == $head and',
        '.head_branch == $head_ref and',
        '.repository.full_name == $repo and',
        '.head_repository.full_name == $repo',
        '[ "$active_profile" -le 1 ] || {',
        'multiple canonical active Profile Quality runs exist for ${head}.',
        'non-Profile-Quality workflow run(s) remain active.',
        '(.errors == null) and',
        '(.data.repository.pullRequest.reviewThreads.pageInfo.hasNextPage | type == "boolean") and',
        '(.data.repository.pullRequest.reviewThreads.pageInfo.hasNextPage == false) and',
        '(.data.repository.pullRequest.reviewThreads.nodes | type == "array") and',
        '(type == "object") and (.isResolved | type == "boolean")',
        'PR_PAGES="$(gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&per_page=100")"',
        '(type == "array") and (length >= 1) and (length <= 30) and',
        '(all(.[]; (type == "array") and (length <= 100))) and',
        '(all(.[0:-1][]; (length == 100))) and',
        '(.number | type == "number" and . == floor and . > 0) and',
        '(.state == "open") and',
        '(.draft | type == "boolean") and',
        '(.ref == "main") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$"))',
        '(.full_name | type == "string" and length > 0)',
        '(([.[][] | .number] | length) == ([.[][] | .number] | unique | length))',
        '(has("body")) and',
        '(.body == null or ((.body | type) == "string"))',
        'ERROR: malformed or incomplete paginated open-PR evidence.',
    ):
        require(fragment in bot_review, f"Bot PR user approval liveness/proof contract is missing: {fragment}")
    for fragment in (
        'wait_for_spotlight_readiness() {',
        'for attempt in $(seq 1 48); do',
        'check_required_contexts "$head" "$lane"',
        'check_quiescent_runs "$head" "$head_ref"',
        'Spotlight reviewer readiness converged for ${head} on bounded attempt ${attempt}/48.',
        'Spotlight reviewer bounded-wait: exact-head checks/quiescence are not ready yet',
        'Spotlight reviewer readiness did not converge inside the bounded 48-attempt window.',
        'if [ "$LANE" = "spotlight" ]; then',
        'wait_for_spotlight_readiness "$HEAD_SHA" "$HEAD_REF" "$LANE"',
        'Spotlight readiness did not converge inside the bounded reviewer window.',
    ):
        require(fragment in bot_review, f"Bot PR Spotlight bounded-review liveness contract is missing: {fragment}")
    spotlight_wait_pos = bot_review.index('wait_for_spotlight_readiness "$HEAD_SHA" "$HEAD_REF" "$LANE"')
    thread_read_pos = bot_review.index('THREADS="$(gh api graphql', spotlight_wait_pos)
    marker_read_pos = bot_review.index('REVIEW_MARKER="<!-- portyu9-bot-review:v2', thread_read_pos)
    require(
        spotlight_wait_pos < thread_read_pos < marker_read_pos,
        "Bot PR reviewer must converge Spotlight readiness before fresh review-thread and review-state evidence",
    )
    nonspot_guard_pos = bot_review.index('if [ "$LANE" != "spotlight" ]; then', thread_read_pos)
    nonspot_readiness_pos = bot_review.index('check_required_contexts "$HEAD_SHA" "$LANE"', nonspot_guard_pos)
    require(
        thread_read_pos < nonspot_guard_pos < nonspot_readiness_pos < marker_read_pos,
        "Non-Spotlight lanes must retain fresh thread evidence before their original one-shot readiness checks",
    )

    open_pr_fetch = 'PR_PAGES="$(gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&per_page=100")"'
    require(
        bot_review.count(open_pr_fetch) == 1,
        "Bot PR reviewer open-main PR discovery endpoint count changed",
    )
    open_pr_schema = '(type == "array") and (length >= 1) and (length <= 30) and'
    candidate_filter = 'CANDIDATES="$(jq -c --arg repo "$TARGET_REPOSITORY"'
    require(
        bot_review.index(open_pr_fetch) < bot_review.index(open_pr_schema) < bot_review.index(candidate_filter),
        "Bot PR reviewer must validate the complete open-PR collection before governed candidate filtering",
    )
    require(
        bot_review.count("malformed or incomplete paginated open-PR evidence") == 1,
        "Bot PR reviewer must have exactly one fail-closed open-PR collection schema boundary",
    )
    require(
        'for name in validate-contracts integration-pinned-upstream analyze-actions analyze-python dependency-review trusted-capability-admission; do'
        not in bot_review,
        "Bot PR user approval regressed to one global six-check set instead of lane-specific gates",
    )
    require(
        bot_review.count('check_required_contexts "$HEAD_SHA" "$LANE"') == 2,
        "Bot PR user approval must re-prove the lane-specific gate set before and immediately before review mutation",
    )
    require(
        bot_review.count('check_quiescent_runs "$HEAD_SHA" "$HEAD_REF"') == 2,
        "Bot PR user approval must re-prove exact-head quiescence with immutable head-ref binding before and immediately before review mutation",
    )
    require(
        'if check_quiescent_runs "$HEAD_SHA"; then' not in bot_review,
        "Bot PR quiescence proof must bind the exact governed head ref instead of head SHA alone",
    )
    require(
        'active="$(jq \'[.workflow_runs[] | select(.status == "queued"' not in bot_review,
        "Bot PR reviewer must not globally wait on the review-dependent Profile Quality run",
    )
    require(
        bot_review.count('wake_governed_lane_after_review "$LANE" "$HEAD_REF"') == 2,
        "Bot PR reviewer must wake once on an already-valid marker review and once after a newly-created review",
    )
    require(
        'test "$(jq -r .base.sha <<<"$PR")" = "$MAIN_SHA"' not in bot_review,
        "Bot PR user approval must skip stale-base candidates instead of globally failing the reviewer pass",
    )
    require(
        '.state == "APPROVED" and .commit_id == $head)] | length' not in bot_review,
        "Bot PR user approval must not treat GitHub commit_id alone as immutable exact-head proof",
    )
    require(
        '::notice::PORTYU9_BOT_REVIEW_TOKEN is not configured' not in bot_review
        and 'no user review was submitted.\n            exit 0' not in bot_review,
        "Bot PR user approval must fail closed instead of reporting success when the real-user credential is absent",
    )

    require(
        bot_review.count("actions: write") == 2 and "actions: read" not in bot_review,
        "Bot PR user approval must retain Actions-only wake authority at workflow and job scope",
    )
    require("contents: write" not in bot_review,
            "Bot PR user approval must not acquire repository-contents write authority")
    for fragment in (
        'wake_governed_lane_after_review "$LANE" "$HEAD_REF"',
        'repos/${TARGET_REPOSITORY}/actions/workflows/dependabot-controller.yml/dispatches',
        'repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml/dispatches',
        'Spotlight parent workflow bounded-waits for the exact review; no post-review recovery wake is required.',
        'Dispatched event-driven post-review convergence wake',
    ):
        require(fragment in bot_review, f"Bot PR post-review event-driven wake contract is missing: {fragment}")
    require('repos/${TARGET_REPOSITORY}/dispatches' not in bot_review,
            "Bot PR reviewer must not gain generic repository-dispatch authority")
    require(
        'repos/${TARGET_REPOSITORY}/actions/workflows/spotlight-link-sync.yml/dispatches' not in bot_review,
        "Spotlight reviewer must not reintroduce the redundant post-review recovery wake",
    )
    marker_approved_pos = bot_review.index('if [ "$MARKER_STATE" = "APPROVED" ]; then')
    recovery_wake_pos = bot_review.index('wake_governed_lane_after_review "$LANE" "$HEAD_REF"', marker_approved_pos)
    continue_pos = bot_review.index('              continue', recovery_wake_pos)
    require(marker_approved_pos < recovery_wake_pos < continue_pos,
            "Bot PR existing-marker recovery wake must occur before the reviewer skips the already-approved candidate")
    review_mutation_pos = bot_review.index('REVIEW_HTTP_RESPONSE="$(GH_TOKEN="$REVIEW_TOKEN" gh api --include --method POST')
    post_mutation_wake_pos = bot_review.rindex('wake_governed_lane_after_review "$LANE" "$HEAD_REF"')
    require(review_mutation_pos < post_mutation_wake_pos,
            "Bot PR new-review controller wake must occur only after the real-user exact-base/head approval mutation")
    require(
        'repos/${TARGET_REPOSITORY}/actions/workflows/dependabot-controller.yml/dispatches" -f ref=main' in bot_review,
        "Dependabot post-review wake must dispatch the trusted controller on main",
    )
    for fragment in (
        "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'",
        'test "$WAKE_REF" = "refs/heads/main"',
        'test "$WAKE_ACTOR" = "github-actions[bot]"',
        "startsWith(github.ref, 'refs/heads/dependabot/github_actions/')",
        'MERGE_HTTP_RESPONSE="$RUNNER_TEMP/dependabot-merge-http-response.txt"',
        'MERGE_BODY="$RUNNER_TEMP/dependabot-merge-response.json"',
        'MERGE_ERR="$RUNNER_TEMP/dependabot-merge-error.txt"',
        'gh api --include --method PUT "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/merge"',
        'MERGE_STATUS=$?',
        'if [ "$MERGE_STATUS" -ne 0 ]; then',
        'MERGE_STATUS_LINE="$(head -n 1 "$MERGE_HTTP_RESPONSE" | tr -d \'\\r\')"',
        '[[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {',
        'Dependabot terminal merge returned unexpected status:',
        'Dependabot merge API request failed: ${MERGE_MESSAGE}',
        'Dependabot merge API rejected exact-head merge: ${MERGE_MESSAGE}',
    ):
        require(fragment in dependabot, f"Dependabot trusted post-review dispatch contract is missing: {fragment}")

    consumers = (
        ("Dependabot", dependabot, 'REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"'),
        ("CodeQL Autofix", autofix, 'REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${ADMITTED_BASE_SHA} head=${ADMITTED_HEAD_SHA} -->"'),
        ("Spotlight", spotlight, 'REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"'),
    )
    for label, workflow, marker in consumers:
        for fragment in (
            marker,
            '--arg marker "$REVIEW_MARKER"',
            '.user.login == "portyu9"',
            '.state == "APPROVED"',
            '.commit_id == $head',
            'contains($marker)',
            'marker-bound APPROVED review by portyu9',
        ):
            require(fragment in workflow, f"{label} marker-bound portyu9 review proof is missing: {fragment}")
        require(
            '.state == "APPROVED" and .commit_id == $head)] | length' not in workflow,
            f"{label} regressed to mutable GitHub commit_id-only review proof",
        )
        for fragment in (
            'LATEST_MANUAL_DECISIVE_STATE=',
            '(.state == "APPROVED" or .state == "CHANGES_REQUESTED")',
            'contains($marker)) | not',
            'test "$PORTYU9_APPROVAL_COUNT" = "1"',
            'latest manual exact-head portyu9 review requests changes; autonomous ',
            ' merge is vetoed.',
        ):
            require(fragment in workflow, f"{label} manual portyu9 veto contract is missing: {fragment}")


def validate_spotlight_event_admission(spotlight: str, capability: str) -> None:
    capability_fragments = (
        "workflow_dispatch:",
        "workflow_dispatch|schedule)",
        'test "$ACTOR" = "github-actions[bot]"',
        'SPOTLIGHT_MODE="delegated"',
        'DISCOVERED_PR="$(jq -c \'.[0]\' <<<"$MATCHES")"',
        'PR="$(gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}")"',
        'test "$(jq -r .maintainer_can_modify <<<"$PR")" = "false"',
        '[[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ ]]',
        '[[ "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]',
        'EXTERNAL_ID="spotlight-admission:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
        '-f details_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"',
    )
    for fragment in capability_fragments:
        require(fragment in capability, f"Capability Admission lost event-driven Spotlight proof binding: {fragment}")
    require("spotlight-scheduled-admission:" not in capability,
            "Capability Admission regressed to schedule-specific Spotlight proof identity")

    spotlight_fragments = (
        'actions/workflows/capability-admission.yml/dispatches',
        'Capability Admission independently binds the unique current-main candidate.',
        "TRUSTED_RUN_ID=\"$(jq -r '.trustedAdmission.workflowRun.runId' \"$CERTIFICATE\")\"",
        "TRUSTED_RUN_ATTEMPT=\"$(jq -r '.trustedAdmission.workflowRun.runAttempt' \"$CERTIFICATE\")\"",
        "TRUSTED_CHECK_RUN_ID=\"$(jq -r '.trustedAdmission.checkRun.checkRunId' \"$CERTIFICATE\")\"",
        'test "$(jq -r .run_attempt <<<"$TRUSTED_RUN")" = "$TRUSTED_RUN_ATTEMPT"',
        'test "$(jq -r .event <<<"$TRUSTED_RUN")" = "workflow_dispatch"',
        'test "$(jq -r .head_branch <<<"$TRUSTED_RUN")" = "main"',
        'EXPECTED_TRUSTED_EXTERNAL_ID="spotlight-admission:${TRUSTED_RUN_ID}:${TRUSTED_RUN_ATTEMPT}:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
        'test "$(jq -r .external_id <<<"$TRUSTED_CHECK")" = "$EXPECTED_TRUSTED_EXTERNAL_ID"',
        'CERTIFIED_TRUSTED_DETAILS_URL="$(jq -r \'.trustedAdmission.checkRun.detailsUrl\' "$CERTIFICATE")"',
        'test "$(jq -r .details_url <<<"$TRUSTED_CHECK")" = "$CERTIFIED_TRUSTED_DETAILS_URL"',
        'actions/workflows/bot-pr-user-approval.yml/dispatches',
        'Dispatched exact pre-convergence portyu9 review evaluation from trusted main.',
        'for REVIEW_ATTEMPT in $(seq 1 24); do',
        'exact-base/head portyu9 review did not materialize after the pre-convergence dispatch.',
        'Observed exact-base/head marker-bound portyu9 approval before merge authorization.',
        'Spotlight terminal stage: trusted-admission-live-reproof-verified',
        'error("Spotlight automation-approval comment pages must be a bounded slurped page array")',
        '.login == "github-actions[bot]" and (.body | contains($marker))',
        'error("duplicate trusted Spotlight automation-approval comments exist")',
        'exists:(($matches | length) == 1)',
        'APPROVAL_COMMENT_HTTP_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments"',
        'APPROVAL_COMMENT_STATUS_LINE="$(head -n 1 <<<"$APPROVAL_COMMENT_HTTP_RESPONSE" | tr -d \'\\r\')"',
        '[[ "$APPROVAL_COMMENT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        'Spotlight automation-approval comment returned unexpected status:',
        'sed \'1,/^[[:space:]]*$/d\' <<<"$APPROVAL_COMMENT_HTTP_RESPONSE" > "$RUNNER_TEMP/spotlight-approval-comment-created.json"',
        'error("created Spotlight automation-approval comment actor mismatch")',
        'test "$(jq -r .actor "$RUNNER_TEMP/spotlight-approval-comment-created-normalized.json")" = "github-actions[bot]"',
        'error("Spotlight protected workflow definition must be an object")',
        'error("Spotlight protected workflow definition id is invalid")',
        'error("Spotlight protected workflow definition identity changed")',
        'error("Spotlight protected workflow definition URLs are invalid")',
        'error("Spotlight protected workflow-run response must be an object")',
        'error("Spotlight protected workflow-run total_count is invalid")',
        'error("Spotlight protected workflow_runs shape changed")',
        'error("Spotlight protected workflow-run response is incomplete")',
        'error("Spotlight protected workflow-run set is ambiguous")',
        'error("Spotlight protected workflow-run item schema changed")',
        'error("Spotlight protected workflow run ids are not unique")',
        'error("Spotlight protected workflow ids are not unique")',
        'error("Spotlight protected workflow check-suite ids are not unique")',
        '> "$RUNNER_TEMP/spotlight-protected-workflow-runs-normalized.json"',
        'RUNS_TOTAL="$(jq -r .totalCount "$RUNNER_TEMP/spotlight-protected-workflow-runs-normalized.json")"',
        'RUNS="$(jq -c .runs "$RUNNER_TEMP/spotlight-protected-workflow-runs-normalized.json")"',
        'CHECK_SUITE_ID="$(jq -r .checkSuiteId <<<"$RUN")"',
        'RUN_ATTEMPT="$(jq -r .runAttempt <<<"$RUN")"',
    )
    for fragment in spotlight_fragments:
        require(fragment in spotlight, f"Spotlight event-driven admission proof contract is missing: {fragment}")

    capability_dispatch = 'actions/workflows/capability-admission.yml/dispatches'
    reviewer_dispatch = 'actions/workflows/bot-pr-user-approval.yml/dispatches'
    convergence_start = '          APPROVAL_REQUESTED_RUN_IDS=""\n          for attempt in $(seq 1 60); do'
    require(spotlight.count(reviewer_dispatch) == 1,
            "Spotlight must dispatch exactly one trusted reviewer pass per approve run")
    require(
        spotlight.index(capability_dispatch) < spotlight.index(reviewer_dispatch) < spotlight.index(convergence_start),
        "Spotlight trusted reviewer dispatch must occur after admission dispatch and before whole-workflow convergence",
    )
    require('grep -Fxc "$APPROVAL_BODY"' not in spotlight,
            "Spotlight approval comment verification must compare the complete multiline body atomically")
    require("'.body == $body' approval-comment.json" not in spotlight,
            "Spotlight approval comment verification must not trust a raw body-only response")
    require('COMMENTS="$(gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100")"' not in spotlight,
            "Spotlight approval comment dedupe must not consume raw paginated comments")
    require("python3 scripts/automation_approval_comment.py" not in spotlight,
            "Spotlight approval job must not acquire runner-resident Python authority")
    approve = job_block(spotlight, "approve", "authorize")
    for forbidden in (
        'CODEQL_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/codeql.yml" --jq .id)"',
        'DEPENDENCY_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/dependency-review.yml" --jq .id)"',
        'PROFILE_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/profile-quality.yml" --jq .id)"',
        'RUNS="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100")"',
        'jq -r .head_sha <<<"$RUN"',
        'jq -r .head_branch <<<"$RUN"',
        'jq -r .repository.full_name <<<"$RUN"',
        'jq -r .head_repository.full_name <<<"$RUN"',
    ):
        require(
            forbidden not in approve,
            f"Spotlight protected workflow evidence regressed to raw scalar consumption: {forbidden}",
        )
    require(
        approve.count('gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/codeql.yml"') == 1
        and approve.count('gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/dependency-review.yml"') == 1
        and approve.count('gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/profile-quality.yml"') == 1
        and approve.count('repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100') == 1,
        "Spotlight protected workflow evidence endpoint inventory changed",
    )





def project_spotlight_terminal_protected_runs_to_legacy(spotlight: str) -> str:
    start_marker = "          normalize_protected_certificate_run() {\n"
    end_marker = "          EXPECTED_CERTIFICATE_RUNS="
    require(
        spotlight.count(start_marker) == 1 and spotlight.count(end_marker) == 1,
        "Spotlight terminal protected-run projection anchors changed",
    )
    start = spotlight.index(start_marker)
    end_start = spotlight.index(end_marker, start)
    end = spotlight.index("\n", end_start) + 1
    legacy = (
        '          CODEQL_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${CODEQL_RUN_ID}")"\n'
        '          DEPENDENCY_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${DEPENDENCY_RUN_ID}")"\n'
        '          PROFILE_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${PROFILE_RUN_ID}")"\n'
        '          EXPECTED_CERTIFICATE_RUNS="$(jq -cn --argjson codeql "$CODEQL_RUN" --argjson dependency "$DEPENDENCY_RUN" --argjson profile "$PROFILE_RUN" \'[{name:"CodeQL",workflowId:$codeql.workflow_id,runId:$codeql.id,runAttempt:$codeql.run_attempt,checkSuiteId:$codeql.check_suite_id,event:$codeql.event,headBranch:$codeql.head_branch,headSha:$codeql.head_sha,repository:$codeql.repository.full_name,headRepository:$codeql.head_repository.full_name,status:$codeql.status,conclusion:$codeql.conclusion},{name:"Dependency review",workflowId:$dependency.workflow_id,runId:$dependency.id,runAttempt:$dependency.run_attempt,checkSuiteId:$dependency.check_suite_id,event:$dependency.event,headBranch:$dependency.head_branch,headSha:$dependency.head_sha,repository:$dependency.repository.full_name,headRepository:$dependency.head_repository.full_name,status:$dependency.status,conclusion:$dependency.conclusion},{name:"Profile quality",workflowId:$profile.workflow_id,runId:$profile.id,runAttempt:$profile.run_attempt,checkSuiteId:$profile.check_suite_id,event:$profile.event,headBranch:$profile.head_branch,headSha:$profile.head_sha,repository:$profile.repository.full_name,headRepository:$profile.head_repository.full_name,status:$profile.status,conclusion:$profile.conclusion}] | sort_by(.name)\')"\n'
    )
    return spotlight[:start] + legacy + spotlight[end:]


def validate_spotlight_terminal_required_check_collection(
    spotlight: str, *, run_self_test: bool = True
) -> None:
    terminal = job_block(spotlight, "merge", "decision_receipt")
    fetch = (
        'CHECKS="$(gh api -H \'Accept: application/vnd.github+json\' '
        '"repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs?filter=latest&per_page=100")"'
    )
    scalar_consume = 'CHECKS_TOTAL="$(jq -r \'.total_count // empty\' <<<"$CHECKS")"'
    observed_consume = 'OBSERVED_CHECKS="$(jq -c \'[.check_runs[] | select(.app.id == 15368'
    schema_start = 'jq -e --arg head "$HEAD_SHA" \''
    schema_error = "ERROR: malformed or incomplete Spotlight terminal check-run evidence."

    require(terminal.count(fetch) == 1, "Spotlight terminal required-check fetch topology changed")
    require(terminal.count(scalar_consume) == 1,
            "Spotlight terminal check-run total-count consumption topology changed")
    require(terminal.count(observed_consume) == 1,
            "Spotlight terminal required-check selection topology changed")
    fetch_pos = terminal.index(fetch)
    schema_pos = terminal.index(schema_start, fetch_pos)
    scalar_pos = terminal.index(scalar_consume, fetch_pos)
    observed_pos = terminal.index(observed_consume, scalar_pos)
    require(
        fetch_pos < schema_pos < scalar_pos < observed_pos,
        "Spotlight terminal check-run evidence must be schema-validated before scalar/filter consumption",
    )
    schema_block = terminal[schema_pos:scalar_pos]
    for fragment in (
        '(type == "object") and',
        '(.total_count | type == "number" and . == floor and . >= 0 and . <= 100) and',
        '(.check_runs | type == "array" and length <= 100) and',
        '(.total_count == (.check_runs | length)) and',
        '(all(.check_runs[];',
        '(.id | (type == "number") and (. == floor) and (. > 0)) and',
        '(.name | type == "string" and length > 0) and',
        '(.status | type == "string" and',
        '((. == "queued") or (. == "in_progress") or (. == "completed") or',
        '(. == "waiting") or (. == "requested") or (. == "pending"))) and',
        'if .status == "completed"',
        'then (.conclusion | type == "string" and',
        '((. == "action_required") or (. == "cancelled") or (. == "failure") or',
        '(. == "startup_failure") or (. == "success") or (. == "timed_out")))',
        'else .conclusion == null end',
        '(.head_sha | type == "string" and test("^[0-9a-f]{40}$") and . == $head) and',
        '(.app | type == "object" and',
        '(.id | (type == "number") and (. == floor) and (. > 0)) and',
        '(.slug | type == "string" and length > 0)) and',
        '(.check_suite | type == "object" and',
        '(.id | (type == "number") and (. == floor) and (. > 0)))',
        '(([.check_runs[].id] | length) == ([.check_runs[].id] | unique | length))',
        schema_error,
    ):
        require(
            fragment in schema_block,
            f"Spotlight terminal required-check response schema changed: {fragment}",
        )

    equality = 'test "$OBSERVED_CHECKS" = "$EXPECTED_CHECKS"'
    require(
        equality in terminal,
        "Spotlight terminal exact required-check provenance equality changed",
    )
    equality_pos = terminal.index(equality, observed_pos)
    check_set_block = terminal[scalar_pos:equality_pos]
    for required in (
        "analyze-actions",
        "analyze-python",
        "dependency-review",
        "integration-pinned-upstream",
        "trusted-governed-bot-review",
        "validate-contracts",
    ):
        require(
            check_set_block.count(f'.name == "{required}"') == 1
            and check_set_block.count(f'name:"{required}"') == 1,
            f"Spotlight terminal required-check set changed for {required}",
        )

    if run_self_test:
        mutations = (
            (
                '(.total_count | type == "number" and . == floor and . >= 0 and . <= 100) and',
                '(.total_count | tostring | length > 0) and',
            ),
            (
                '(.head_sha | type == "string" and test("^[0-9a-f]{40}$") and . == $head) and',
                '(.head_sha | tostring | test("^[0-9a-f]{40}$")) and',
            ),
            (
                '(.check_suite | type == "object" and\n                (.id | (type == "number") and (. == floor) and (. > 0)))',
                '(.check_suite.id | (type == "number") and (. == floor) and (. > 0))',
            ),
        )
        terminal_start = spotlight.index("  merge:\n")
        terminal_end = spotlight.index("  decision_receipt:\n", terminal_start)
        terminal_source = spotlight[terminal_start:terminal_end]
        for current, replacement in mutations:
            require(
                current in terminal_source,
                f"Spotlight terminal required-check self-test anchor changed: {current}",
            )
            weakened_terminal = terminal_source.replace(current, replacement, 1)
            weakened = spotlight[:terminal_start] + weakened_terminal + spotlight[terminal_end:]
            try:
                validate_spotlight_terminal_required_check_collection(
                    weakened, run_self_test=False
                )
            except ValueError as exc:
                require(
                    "required-check response schema changed" in str(exc),
                    f"Spotlight terminal required-check self-test failed for wrong reason: {exc}",
                )
            else:
                raise ValueError(
                    f"Spotlight terminal required-check self-test accepted forbidden mutation: {current}"
                )

        duplicate_consume = terminal_source.replace(
            fetch,
            fetch + "\n          " + scalar_consume,
            1,
        )
        weakened = spotlight[:terminal_start] + duplicate_consume + spotlight[terminal_end:]
        try:
            validate_spotlight_terminal_required_check_collection(
                weakened, run_self_test=False
            )
        except ValueError as exc:
            require(
                "total-count consumption topology changed" in str(exc),
                f"Spotlight terminal required-check ordering self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                "Spotlight terminal required-check self-test accepted scalar consumption before schema validation"
            )


def validate_spotlight_terminal_protected_run_evidence(
    spotlight: str, *, run_self_test: bool = True
) -> None:
    terminal = job_block(spotlight, "merge", "decision_receipt")
    helper = "          normalize_protected_certificate_run() {\n"
    consume = '          EXPECTED_CERTIFICATE_RUNS="$(jq -cn --argjson codeql "$CODEQL_RUN" --argjson dependency "$DEPENDENCY_RUN" --argjson profile "$PROFILE_RUN" \'[$codeql,$dependency,$profile] | sort_by(.name)\')"'
    require(terminal.count(helper) == 1, "Spotlight terminal protected-run normalizer topology changed")
    require(terminal.count(consume) == 1, "Spotlight terminal protected-run certificate consumption changed")
    helper_start = terminal.index(helper)
    helper_end = terminal.index("          }\n          CODEQL_RUN_RAW=", helper_start)
    helper_block = terminal[helper_start:helper_end]
    for fragment in (
        'local payload="$1" expected_run="$2" expected_suite="$3" expected_name="$4" expected_path="$5"',
        '--argjson run "$expected_run"',
        '--argjson suite "$expected_suite"',
        '--arg name "$expected_name"',
        '--arg path "$expected_path"',
        '--arg branch "$CANDIDATE_BRANCH"',
        '--arg head "$HEAD_SHA"',
        '--arg repo "$GITHUB_REPOSITORY"',
        '--argjson repo_id "$GITHUB_REPOSITORY_ID"',
        'if type != "object" then',
        '((.id | positive_int) | not) or .id != $run or',
        '((.node_id | type) != "string") or ((.node_id | length) == 0) or',
        '((.workflow_id | positive_int) | not) or',
        '.name != $name or .path != $path',
        '.event != "pull_request" or .head_branch != $branch or',
        '.head_sha != $head',
        '((.run_number | positive_int) | not) or',
        '((.run_attempt | positive_int) | not) or',
        '((.check_suite_id | positive_int) | not) or .check_suite_id != $suite or',
        '((.check_suite_node_id | type) != "string") or',
        '.repository.id != $repo_id or',
        '.repository.full_name != $repo or',
        '.head_repository.id != $repo_id or',
        '.head_repository.full_name != $repo',
        '.status != "completed" or .conclusion != "success"',
        '((.url | type) != "string") or ((.url | length) == 0) or',
        '((.html_url | type) != "string") or ((.html_url | length) == 0) or',
        '((.created_at | type) != "string") or ((.created_at | length) == 0) or',
        '((.updated_at | type) != "string") or ((.updated_at | length) == 0) or',
        '((.run_started_at | type) != "string") or ((.run_started_at | length) == 0)',
        'workflowId:.workflow_id',
        'runId:.id',
        'runAttempt:.run_attempt',
        'checkSuiteId:.check_suite_id',
        'headBranch:.head_branch',
        'headSha:.head_sha',
        'repository:.repository.full_name',
        'headRepository:.head_repository.full_name',
    ):
        require(fragment in helper_block, f"Spotlight terminal protected-run response schema changed: {fragment}")

    specs = (
        (
            'CODEQL_RUN_RAW="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${CODEQL_RUN_ID}")"',
            'CODEQL_RUN="$(normalize_protected_certificate_run "$CODEQL_RUN_RAW" "$CODEQL_RUN_ID" "$CODEQL_CHECK_SUITE_ID" "CodeQL" ".github/workflows/codeql.yml")"',
            "CodeQL",
        ),
        (
            'DEPENDENCY_RUN_RAW="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${DEPENDENCY_RUN_ID}")"',
            'DEPENDENCY_RUN="$(normalize_protected_certificate_run "$DEPENDENCY_RUN_RAW" "$DEPENDENCY_RUN_ID" "$DEPENDENCY_CHECK_SUITE_ID" "Dependency review" ".github/workflows/dependency-review.yml")"',
            "Dependency review",
        ),
        (
            'PROFILE_RUN_RAW="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${PROFILE_RUN_ID}")"',
            'PROFILE_RUN="$(normalize_protected_certificate_run "$PROFILE_RUN_RAW" "$PROFILE_RUN_ID" "$PROFILE_CHECK_SUITE_ID" "Profile quality" ".github/workflows/profile-quality.yml")"',
            "Profile quality",
        ),
    )
    consume_pos = terminal.index(consume)
    previous = helper_end
    for fetch, normalize, label in specs:
        require(terminal.count(fetch) == 1 and terminal.count(normalize) == 1,
                f"Spotlight terminal {label} protected-run evidence topology changed")
        fetch_pos = terminal.index(fetch)
        normalize_pos = terminal.index(normalize, fetch_pos)
        require(previous < fetch_pos < normalize_pos < consume_pos,
                f"Spotlight terminal {label} run must fetch then normalize before certificate consumption")
        previous = normalize_pos

    require(
        terminal.count('gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${CODEQL_RUN_ID}"') == 1
        and terminal.count('gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${DEPENDENCY_RUN_ID}"') == 1
        and terminal.count('gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${PROFILE_RUN_ID}"') == 1,
        "Spotlight terminal protected-run endpoint/call-count contract changed",
    )
    for forbidden in (
        'CODEQL_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${CODEQL_RUN_ID}")"',
        'DEPENDENCY_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${DEPENDENCY_RUN_ID}")"',
        'PROFILE_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${PROFILE_RUN_ID}")"',
        '$codeql.workflow_id',
        '$dependency.workflow_id',
        '$profile.workflow_id',
    ):
        require(forbidden not in terminal,
                f"Spotlight terminal protected-run evidence regressed to raw response consumption: {forbidden}")

    if run_self_test:
        mutations = (
            ('.name != $name or .path != $path', '.name != $name'),
            (
                '((.check_suite_id | positive_int) | not) or .check_suite_id != $suite or',
                '((.check_suite_id | positive_int) | not) or',
            ),
            (
                '.repository.id != $repo_id or',
                '(.repository.id | tostring) != ($repo_id | tostring) or',
            ),
        )
        terminal_start = spotlight.index("  merge:\n")
        terminal_end = spotlight.index("  decision_receipt:\n", terminal_start)
        terminal_source = spotlight[terminal_start:terminal_end]
        for current, replacement in mutations:
            require(current in terminal_source,
                    f"Spotlight terminal protected-run self-test anchor changed: {current}")
            weakened_terminal = terminal_source.replace(current, replacement, 1)
            weakened = spotlight[:terminal_start] + weakened_terminal + spotlight[terminal_end:]
            try:
                validate_spotlight_terminal_protected_run_evidence(weakened, run_self_test=False)
            except ValueError as exc:
                require("response schema changed" in str(exc),
                        f"Spotlight terminal protected-run self-test failed for wrong reason: {exc}")
            else:
                raise ValueError(
                    f"Spotlight terminal protected-run self-test accepted forbidden mutation: {current}"
                )


def validate_spotlight_terminal_trusted_admission_evidence(
    spotlight: str, *, run_self_test: bool = True
) -> None:
    terminal = job_block(spotlight, "merge", "decision_receipt")
    workflow_fetch = (
        'TRUSTED_WORKFLOW_RAW="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/'
        'capability-admission.yml")"'
    )
    workflow_schema = 'error("Spotlight trusted-admission workflow definition must be an object")'
    workflow_consume = "TRUSTED_WORKFLOW_ID=\"$(jq -er '"
    run_fetch = (
        'TRUSTED_RUN_RAW="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/'
        '${TRUSTED_RUN_ID}")"'
    )
    run_schema = 'error("Spotlight trusted-admission run must be an object")'
    run_normalized = "TRUSTED_RUN=\"$(jq -ce \\"
    run_consume = 'test "$(jq -r .workflow_id <<<"$TRUSTED_RUN")" = "$TRUSTED_WORKFLOW_ID"'
    check_fetch = (
        'TRUSTED_CHECK_RAW="$(gh api "repos/${GITHUB_REPOSITORY}/check-runs/'
        '${TRUSTED_CHECK_RUN_ID}")"'
    )
    check_schema = 'error("Spotlight trusted-admission check run must be an object")'
    check_normalized = "TRUSTED_CHECK=\"$(jq -ce \\"
    check_consume = 'test "$(jq -r .external_id <<<"$TRUSTED_CHECK")" = "$EXPECTED_TRUSTED_EXTERNAL_ID"'
    terminal_stage = 'echo "Spotlight terminal stage: trusted-admission-live-reproof-verified" >&2'

    for marker in (
        workflow_fetch,
        workflow_schema,
        workflow_consume,
        run_fetch,
        run_schema,
        run_normalized,
        run_consume,
        check_fetch,
        check_schema,
        check_normalized,
        check_consume,
        terminal_stage,
    ):
        require(
            terminal.count(marker) == 1,
            f"Spotlight terminal trusted-admission evidence anchor changed: {marker}",
        )

    positions = (
        terminal.index(workflow_fetch),
        terminal.index(workflow_consume),
        terminal.index(workflow_schema),
        terminal.index(run_fetch),
        terminal.index(run_normalized),
        terminal.index(run_schema),
        terminal.index(run_consume),
        terminal.index(check_fetch),
        terminal.index(check_normalized),
        terminal.index(check_schema),
        terminal.index(check_consume),
        terminal.index(terminal_stage),
    )
    require(
        list(positions) == sorted(positions) and len(set(positions)) == len(positions),
        "Spotlight terminal trusted-admission evidence must remain fetch-validate-normalize-consume ordered",
    )

    for fragment in (
        '((.id | positive_int) | not)',
        '((.node_id | type) != "string") or ((.node_id | length) == 0)',
        '.name != "Capability admission" or',
        '.path != ".github/workflows/capability-admission.yml" or',
        '.state != "active"',
        '((.badge_url | type) != "string") or ((.badge_url | length) == 0)',
        '((.created_at | type) != "string") or ((.created_at | length) == 0)',
        '((.updated_at | type) != "string") or ((.updated_at | length) == 0)',
        'error("Spotlight trusted-admission workflow metadata is invalid")',
    ):
        require(
            fragment in terminal[terminal.index(workflow_consume):terminal.index(run_fetch)],
            f"Spotlight terminal trusted workflow schema changed: {fragment}",
        )

    run_block = terminal[terminal.index(run_normalized):terminal.index(run_consume)]
    for fragment in (
        '--argjson run "$TRUSTED_RUN_ID"',
        '--argjson workflow "$TRUSTED_WORKFLOW_ID"',
        '--argjson attempt "$TRUSTED_RUN_ATTEMPT"',
        '--arg base "$BASE_SHA"',
        '--arg repo "$GITHUB_REPOSITORY"',
        '.id != $run or',
        '.workflow_id != $workflow or',
        '.name != "Capability admission" or',
        '.path != ".github/workflows/capability-admission.yml"',
        '.event != "workflow_dispatch" or .head_branch != "main" or',
        '.head_sha != $base',
        '.run_attempt != $attempt or',
        '((.check_suite_id | positive_int) | not) or',
        '((.check_suite_node_id | type) != "string") or',
        '.repository.full_name != $repo or',
        '.head_repository.id != .repository.id or',
        '.head_repository.full_name != $repo',
        '.actor.login != "github-actions[bot]" or',
        '.triggering_actor.id != .actor.id or',
        '.triggering_actor.login != "github-actions[bot]"',
        '.status != "completed" or .conclusion != "success"',
        'run_started_at',
        'error("Spotlight trusted-admission run metadata is invalid")',
    ):
        require(
            fragment in run_block,
            f"Spotlight terminal trusted run schema changed: {fragment}",
        )

    check_block = terminal[terminal.index(check_normalized):terminal.index(check_consume)]
    for fragment in (
        '--argjson check "$TRUSTED_CHECK_RUN_ID"',
        '--arg head "$HEAD_SHA"',
        '--arg external "$EXPECTED_TRUSTED_EXTERNAL_ID"',
        '--arg details "$CERTIFIED_TRUSTED_DETAILS_URL"',
        '--argjson suite "$CERTIFIED_TRUSTED_CHECK_SUITE_ID"',
        '.id != $check or',
        '.name != "trusted-capability-admission" or',
        '.head_sha != $head',
        '.app.id != 15368',
        '.status != "completed" or .conclusion != "success"',
        '.external_id != $external or',
        '.details_url != $details',
        '.check_suite.id != $suite',
        '((.started_at | type) != "string") or ((.started_at | length) == 0)',
        '((.completed_at | type) != "string") or ((.completed_at | length) == 0)',
        '((.output | type) != "object") or',
        '((.pull_requests | type) != "array") or ((.pull_requests | length) > 100)',
        'error("Spotlight trusted-admission check metadata is invalid")',
    ):
        require(
            fragment in check_block,
            f"Spotlight terminal trusted check schema changed: {fragment}",
        )

    require(
        terminal.count(
            'gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/capability-admission.yml"'
        ) == 1
        and terminal.count(
            'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${TRUSTED_RUN_ID}"'
        ) == 1
        and terminal.count(
            'gh api "repos/${GITHUB_REPOSITORY}/check-runs/${TRUSTED_CHECK_RUN_ID}"'
        ) == 1,
        "Spotlight terminal trusted-admission endpoint/call-count contract changed",
    )
    for forbidden in (
        'TRUSTED_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/capability-admission.yml" --jq .id)"',
        'TRUSTED_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${TRUSTED_RUN_ID}")"',
        'TRUSTED_CHECK="$(gh api "repos/${GITHUB_REPOSITORY}/check-runs/${TRUSTED_CHECK_RUN_ID}")"',
    ):
        require(
            forbidden not in terminal,
            f"Spotlight terminal trusted-admission regressed to raw scalar/object consumption: {forbidden}",
        )

    if run_self_test:
        mutations = (
            (
                '.path != ".github/workflows/capability-admission.yml" or',
                '(.path | tostring) != ".github/workflows/capability-admission.yml" or',
                "trusted workflow schema changed",
            ),
            (
                '.head_repository.id != .repository.id or',
                '(.head_repository.id | tostring) != (.repository.id | tostring) or',
                "trusted run schema changed",
            ),
            (
                '.triggering_actor.id != .actor.id or',
                '(.triggering_actor.id | tostring) != (.actor.id | tostring) or',
                "trusted run schema changed",
            ),
            (
                '.external_id != $external or',
                '(.external_id | tostring) != $external or',
                "trusted check schema changed",
            ),
            (
                '.check_suite.id != $suite',
                '(.check_suite.id | tostring) != ($suite | tostring)',
                "trusted check schema changed",
            ),
        )
        for current, replacement, expected in mutations:
            require(
                current in spotlight,
                f"Spotlight terminal trusted-admission self-test fixture anchor changed: {current}",
            )
            require(
                current in terminal,
                f"Spotlight terminal trusted-admission self-test target escaped terminal block: {current}",
            )
            mutated_terminal = terminal.replace(current, replacement, 1)
            mutated = spotlight.replace(terminal, mutated_terminal, 1)
            try:
                validate_spotlight_terminal_trusted_admission_evidence(
                    mutated, run_self_test=False
                )
            except ValueError as exc:
                require(
                    expected in str(exc),
                    f"Spotlight terminal trusted-admission self-test failed for wrong reason: {exc}",
                )
            else:
                raise ValueError(
                    "Spotlight terminal trusted-admission self-test accepted forbidden mutation: "
                    f"{expected}"
                )


def classify_spotlight_reconciliation_candidate(
    *,
    expected_current: bool,
    parent_matches_current_base: bool,
    ancestry_proven_superseded: bool,
    age_seconds: int,
    stale_after_seconds: int = 1800,
) -> str:
    """Pure policy model for deterministic Spotlight stale-candidate reconciliation."""
    require(type(expected_current) is bool, "Spotlight expected-current flag must be boolean")
    require(type(parent_matches_current_base) is bool,
            "Spotlight parent/base flag must be boolean")
    require(type(ancestry_proven_superseded) is bool,
            "Spotlight ancestry-proven flag must be boolean")
    require(type(age_seconds) is int and age_seconds >= 0,
            "Spotlight candidate age must be a nonnegative integer")
    require(type(stale_after_seconds) is int and stale_after_seconds > 0,
            "Spotlight stale floor must be a positive integer")
    if expected_current:
        return "preserve-current"
    if parent_matches_current_base:
        return "cleanup-same-base-superseded"
    if ancestry_proven_superseded:
        return "cleanup-ancestry-proven-stale"
    if age_seconds < stale_after_seconds:
        return "preserve-young-unproven"
    return "cleanup-aged-stale"


def validate_spotlight_same_base_supersession(spotlight: str) -> None:
    reconcile = job_block(spotlight, "reconcile", "budget")
    expected_marker = ('            if [ -n "$EXPECTED_CANDIDATE_BRANCH" ] && '
                       '[ "$BRANCH" = "$EXPECTED_CANDIDATE_BRANCH" ]; then')
    parent_marker = "            PARENT_SHA=\"$(jq -r '.parents[0].sha' <<<\"$CANDIDATE_COMMIT\")\""
    same_base_marker = (
        '            SAME_BASE_SUPERSEDED=false\n'
        '            ANCESTRY_PROVEN_SUPERSEDED=false\n'
        '            if [ "$PARENT_SHA" = "$BASE_SHA" ]; then\n'
        '              SAME_BASE_SUPERSEDED=true\n'
        '            else'
    )
    ancestry_call = (
        '              ANCESTRY_COMPARE="$(gh api '
        '"repos/${GITHUB_REPOSITORY}/compare/${PARENT_SHA}...${BASE_SHA}")"'
    )
    ancestry_schema = '              jq -e --arg parent "$PARENT_SHA" --arg base "$BASE_SHA" \''
    ancestry_consume = '              test "$(jq -r .base_commit.sha <<<"$ANCESTRY_COMPARE")" = "$PARENT_SHA"'
    ancestry_classify = (
        '              if [ "$(jq -r .status <<<"$ANCESTRY_COMPARE")" = "ahead" ] &&\n'
        '                 [ "$(jq -r .merge_base_commit.sha <<<"$ANCESTRY_COMPARE")" = "$PARENT_SHA" ] &&\n'
        '                 [ "$(jq -r .behind_by <<<"$ANCESTRY_COMPARE")" = "0" ] &&\n'
        '                 [ "$(jq -r .ahead_by <<<"$ANCESTRY_COMPARE")" -gt 0 ]; then\n'
        '                ANCESTRY_PROVEN_SUPERSEDED=true'
    )
    age_marker = '            AGE_SECONDS=$((NOW_EPOCH - COMMIT_EPOCH))'
    age_guard = (
        '            if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ] &&\n'
        '               [ "$SAME_BASE_SUPERSEDED" != "true" ] &&\n'
        '               [ "$ANCESTRY_PROVEN_SUPERSEDED" != "true" ]; then'
    )
    topology_compare = (
        '            COMPARE="$(gh api '
        '"repos/${GITHUB_REPOSITORY}/compare/${PARENT_SHA}...${HEAD_SHA}")"'
    )
    prs_marker = (
        '            PRS="$(gh api '
        '"repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${BRANCH}&base=main&per_page=2")"'
    )
    close_marker = (
        '              CLOSED_PR="$(gh api --method PATCH '
        '"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}" --input close-pr.json)"'
    )
    delete_marker = (
        '            gh api --method DELETE '
        '"repos/${GITHUB_REPOSITORY}/git/refs/heads/${BRANCH}" >/dev/null'
    )

    for marker in (
        expected_marker, parent_marker, same_base_marker, ancestry_call, ancestry_schema,
        ancestry_consume, ancestry_classify, age_marker, age_guard, topology_compare,
        prs_marker, close_marker, delete_marker,
    ):
        require(reconcile.count(marker) == 1,
                f"Spotlight ancestry supersession contract anchor changed: {marker}")

    ancestry_start = reconcile.index(ancestry_schema)
    ancestry_end = reconcile.index('              \' <<<"$ANCESTRY_COMPARE" >/dev/null', ancestry_start)
    ancestry_block = reconcile[ancestry_start:ancestry_end]
    for fragment in (
        '(type == "object") and',
        '(.status | type == "string" and',
        '(. == "ahead" or . == "behind" or . == "diverged" or . == "identical")) and',
        '(.base_commit | type == "object" and .sha == $parent) and',
        '(.merge_base_commit | type == "object" and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$"))) and',
        '(.ahead_by | type == "number" and . == floor and . >= 0) and',
        '(.behind_by | type == "number" and . == floor and . >= 0) and',
        '(.total_commits | type == "number" and . == floor and . >= 0)',
    ):
        require(fragment in ancestry_block,
                f"Spotlight ancestry compare schema is missing: {fragment}")

    positions = [
        reconcile.index(expected_marker),
        reconcile.index(parent_marker),
        reconcile.index(same_base_marker),
        reconcile.index(ancestry_call),
        reconcile.index(ancestry_schema),
        reconcile.index(ancestry_consume),
        reconcile.index(ancestry_classify),
        reconcile.index(age_marker),
        reconcile.index(age_guard),
        reconcile.index(topology_compare),
        reconcile.index(prs_marker),
        reconcile.index(close_marker),
        reconcile.index(delete_marker),
    ]
    require(positions == sorted(positions),
            "Spotlight ancestry supersession evidence/effect ordering changed")
    require(
        '- ancestry-proven old-base candidates cleaned immediately: **$ANCESTRY_PROVEN_STALE**'
        in reconcile,
        "Spotlight summary lost ancestry-proven stale cleanup evidence",
    )
    require(
        '- unproven/divergent candidates below 30-minute stale floor preserved: **$PRESERVED_YOUNG**'
        in reconcile,
        "Spotlight summary lost young unproven/divergent preservation evidence",
    )


def self_test_spotlight_same_base_supersession() -> None:
    cases = (
        (
            dict(expected_current=True, parent_matches_current_base=True,
                 ancestry_proven_superseded=False, age_seconds=1),
            "preserve-current",
        ),
        (
            dict(expected_current=False, parent_matches_current_base=True,
                 ancestry_proven_superseded=False, age_seconds=1),
            "cleanup-same-base-superseded",
        ),
        (
            dict(expected_current=False, parent_matches_current_base=False,
                 ancestry_proven_superseded=True, age_seconds=1),
            "cleanup-ancestry-proven-stale",
        ),
        (
            dict(expected_current=False, parent_matches_current_base=False,
                 ancestry_proven_superseded=False, age_seconds=1799),
            "preserve-young-unproven",
        ),
        (
            dict(expected_current=False, parent_matches_current_base=False,
                 ancestry_proven_superseded=False, age_seconds=1800),
            "cleanup-aged-stale",
        ),
    )
    for kwargs, expected in cases:
        observed = classify_spotlight_reconciliation_candidate(**kwargs)
        require(observed == expected,
                f"Spotlight ancestry supersession classifier mismatch: {kwargs} -> {observed}")

    for kwargs in (
        dict(expected_current=False, parent_matches_current_base=False,
             ancestry_proven_superseded=False, age_seconds=-1),
        dict(expected_current=False, parent_matches_current_base=False,
             ancestry_proven_superseded=False, age_seconds=0, stale_after_seconds=0),
    ):
        try:
            classify_spotlight_reconciliation_candidate(**kwargs)
        except ValueError:
            pass
        else:
            raise ValueError(
                f"Spotlight ancestry supersession classifier accepted malformed input: {kwargs}"
            )



def validate_bot_review_dispatch_status_contract(bot_review: str) -> None:
    dependabot_dispatch = (
        'wake_response="$(gh api --include --method POST '
        '"repos/${TARGET_REPOSITORY}/actions/workflows/dependabot-controller.yml/dispatches" -f ref=main)"'
    )
    codeql_dispatch = (
        'wake_response="$(gh api --include --method POST '
        '"repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml/dispatches" -f ref=main)"'
    )
    status_guard = (
        '[[ "$wake_status_line" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {'
    )
    for label, fragment in (
        ("Dependabot", dependabot_dispatch),
        ("CodeQL", codeql_dispatch),
    ):
        require(
            bot_review.count(fragment) == 1,
            f"Bot PR reviewer {label} recovery dispatch must capture one --include response for status validation",
        )
    require(
        bot_review.count(status_guard) == 1,
        "Bot PR reviewer recovery dispatches must share one exact HTTP 204 status guard",
    )
    require(
        'recovery dispatch returned unexpected status: ${wake_status_line}' in bot_review,
        "Bot PR reviewer recovery dispatch status failure must be explicit and fail closed",
    )
    for forbidden in (
        'dependabot-controller.yml/dispatches" -f ref=main >/dev/null',
        'codeql.yml/dispatches" -f ref=main >/dev/null',
    ):
        require(
            forbidden not in bot_review,
            f"Bot PR reviewer must not discard privileged workflow-dispatch responses: {forbidden}",
        )
    status_pos = bot_review.index(status_guard)
    require(
        bot_review.index(dependabot_dispatch) < status_pos
        and bot_review.index(codeql_dispatch) < status_pos,
        "Bot PR reviewer must validate the dispatch status only after the selected lane mutation returns",
    )



def validate_bot_review_creation_status_contract(bot_review: str) -> None:
    response = (
        'REVIEW_HTTP_RESPONSE="$(GH_TOKEN="$REVIEW_TOKEN" gh api --include --method POST'
        '               "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/reviews"'
        '               --input review-request.json)"'
    )
    status = 'REVIEW_STATUS_LINE="$(head -n 1 <<<"$REVIEW_HTTP_RESPONSE" | tr -d \'\\r\')"'
    guard = '[[ "$REVIEW_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {'
    body = 'REVIEW_RESPONSE="$(sed \'1,/^[[:space:]]*$/d\' <<<"$REVIEW_HTTP_RESPONSE")"'
    body_guard = 'test "$REVIEW_RESPONSE" != "$REVIEW_HTTP_RESPONSE"'
    schema = '(.id | ((type == "number") and . == floor and . > 0)) and'
    success = (
        'Submitted exact-base/head marker-bound portyu9 approval for governed bot PR '
        '#${PR_NUMBER} at ${HEAD_SHA}.'
    )

    require(
        bot_review.count(response) == 1,
        "Bot PR reviewer review creation must capture exactly one --include response",
    )
    require(
        bot_review.count(status) == 1,
        "Bot PR reviewer review creation status extraction changed",
    )
    require(
        bot_review.count(guard) == 1,
        "Bot PR reviewer review creation must require exact HTTP 200",
    )
    require(
        "governed bot review creation returned unexpected status:" in bot_review,
        "Bot PR reviewer review creation status failure must be explicit and fail closed",
    )
    require(
        bot_review.count(body) == 1 and bot_review.count(body_guard) == 1,
        "Bot PR reviewer review creation body extraction changed",
    )
    require(
        'REVIEW_RESPONSE="$(GH_TOKEN="$REVIEW_TOKEN" gh api --method POST'
        not in bot_review,
        "Bot PR reviewer must not consume a response-blind review creation mutation",
    )

    response_pos = bot_review.index(response)
    status_pos = bot_review.index(status, response_pos)
    guard_pos = bot_review.index(guard, response_pos)
    body_pos = bot_review.index(body, response_pos)
    body_guard_pos = bot_review.index(body_guard, response_pos)
    schema_pos = bot_review.index(schema, response_pos)
    success_pos = bot_review.index(success, response_pos)
    require(
        response_pos < status_pos < guard_pos < body_pos < body_guard_pos < schema_pos < success_pos,
        "Bot PR reviewer must prove HTTP 200 and extract the body before validating/accepting the review response",
    )




def validate_spotlight_reviewer_request_status(spotlight: str) -> None:
    response = (
        'REQUESTED_REVIEWER_HTTP_RESPONSE="$(gh api --include --method POST '
        '"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers" \\'
    )
    status = (
        'REQUESTED_REVIEWER_STATUS_LINE="$(head -n 1 <<<"$REQUESTED_REVIEWER_HTTP_RESPONSE" '
        '| tr -d \'\\r\')"'
    )
    guard = (
        '[[ "$REQUESTED_REVIEWER_STATUS_LINE" =~ '
        '^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {'
    )
    body = (
        'sed \'1,/^[[:space:]]*$/d\' <<<"$REQUESTED_REVIEWER_HTTP_RESPONSE" '
        '> requested-reviewer.json'
    )
    capture = 'REQUESTED_REVIEWER_RESPONSE="$(cat requested-reviewer.json)"'
    schema = (
        'validate_spotlight_reviewer_request_response "$REQUESTED_REVIEWER_RESPONSE" '
        '"$PR_NUMBER" "$SOURCE_SHA" "$CANDIDATE_BRANCH" "$HEAD_SHA"'
    )
    consume = '<<<"$REQUESTED_REVIEWER_RESPONSE")" = "1"'

    require(
        spotlight.count(response) == 1,
        "Spotlight reviewer request must capture exactly one --include response",
    )
    require(
        spotlight.count(status) == 1,
        "Spotlight reviewer-request status extraction changed",
    )
    require(
        spotlight.count(guard) == 1,
        "Spotlight reviewer request must require exact HTTP 201",
    )
    require(
        "Spotlight reviewer request returned unexpected status:" in spotlight,
        "Spotlight reviewer-request status failure must be explicit and fail closed",
    )
    require(
        spotlight.count(body) == 1,
        "Spotlight reviewer-request body extraction changed",
    )
    require(
        'gh api --method POST "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers"'
        not in spotlight,
        "Spotlight must not use a response-blind reviewer-request mutation",
    )

    response_pos = spotlight.index(response)
    status_pos = spotlight.index(status, response_pos)
    guard_pos = spotlight.index(guard, response_pos)
    body_pos = spotlight.index(body, response_pos)
    capture_pos = spotlight.index(capture, body_pos)
    schema_pos = spotlight.index(schema, capture_pos)
    consume_pos = spotlight.index(consume, schema_pos)
    require(
        response_pos < status_pos < guard_pos < body_pos < capture_pos < schema_pos < consume_pos,
        "Spotlight reviewer request must prove HTTP 201 before body/schema consumption",
    )


def validate_spotlight_dispatch_status_contract(spotlight: str) -> None:
    capability_dispatch = (
        'CAPABILITY_DISPATCH_RESPONSE="$(gh api --include --method POST '
        '"repos/${GITHUB_REPOSITORY}/actions/workflows/capability-admission.yml/dispatches" \\'
    )
    reviewer_dispatch = (
        'REVIEW_DISPATCH_RESPONSE="$(gh api --include --method POST '
        '"repos/${GITHUB_REPOSITORY}/actions/workflows/bot-pr-user-approval.yml/dispatches" \\'
    )
    capability_guard = (
        '[[ "$CAPABILITY_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {'
    )
    reviewer_guard = (
        '[[ "$REVIEW_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {'
    )
    for label, fragment in (
        ("Capability Admission", capability_dispatch),
        ("governed reviewer", reviewer_dispatch),
    ):
        require(
            spotlight.count(fragment) == 1,
            f"Spotlight {label} dispatch must capture exactly one --include response",
        )
    for label, guard in (
        ("Capability Admission", capability_guard),
        ("governed reviewer", reviewer_guard),
    ):
        require(
            spotlight.count(guard) == 1,
            f"Spotlight {label} dispatch must require exact HTTP 204 status",
        )
    for fragment in (
        'CAPABILITY_DISPATCH_STATUS_LINE="$(head -n 1 <<<"$CAPABILITY_DISPATCH_RESPONSE" | tr -d \'\\r\')"',
        'REVIEW_DISPATCH_STATUS_LINE="$(head -n 1 <<<"$REVIEW_DISPATCH_RESPONSE" | tr -d \'\\r\')"',
        'ERROR: Spotlight Capability Admission dispatch returned unexpected status: ${CAPABILITY_DISPATCH_STATUS_LINE}',
        'ERROR: Spotlight governed-reviewer dispatch returned unexpected status: ${REVIEW_DISPATCH_STATUS_LINE}',
    ):
        require(fragment in spotlight, f"Spotlight dispatch response-status contract is missing: {fragment}")
    for forbidden in (
        'capability-admission.yml/dispatches" \\\n            -f ref=main >/dev/null',
        'bot-pr-user-approval.yml/dispatches" \\\n            -f ref=main >/dev/null',
    ):
        require(
            forbidden not in spotlight,
            f"Spotlight must not discard privileged workflow-dispatch responses: {forbidden}",
        )
    capability_status = spotlight.index(capability_guard)
    capability_success = spotlight.index(
        'Dispatched event-driven Spotlight admission proof from trusted main;'
    )
    reviewer_status = spotlight.index(reviewer_guard)
    reviewer_success = spotlight.index(
        'Dispatched exact pre-convergence portyu9 review evaluation from trusted main.'
    )
    convergence = spotlight.index('          APPROVAL_REQUESTED_RUN_IDS=""\n          for attempt in $(seq 1 60); do')
    require(
        spotlight.index(capability_dispatch) < capability_status < capability_success
        < spotlight.index(reviewer_dispatch) < reviewer_status < reviewer_success < convergence,
        "Spotlight dispatches must prove HTTP 204 before success markers and convergence waits",
    )



def validate_spotlight_workflow_run_approval_status(spotlight: str) -> None:
    endpoint = 'repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve'
    response = (
        'APPROVAL_RESPONSE="$(gh api --include --method POST '
        '"repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve")"'
    )
    status = 'APPROVAL_STATUS_LINE="$(head -n 1 <<<"$APPROVAL_RESPONSE" | tr -d \'\\r\')"'
    guard = '[[ "$APPROVAL_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {'
    downstream = 'APPROVAL_REQUESTED_RUN_IDS="${APPROVAL_REQUESTED_RUN_IDS} ${RUN_ID}"'
    evidence = 'APPROVAL_REQUESTS_JSON="$(jq -c --argjson entry "$APPROVAL_ENTRY" \'. + [$entry]\' <<<"$APPROVAL_REQUESTS_JSON")"'

    require(
        spotlight.count(endpoint) == 1,
        "Spotlight protected-run approval endpoint inventory changed",
    )
    require(
        spotlight.count(response) == 1,
        "Spotlight protected-run approval must capture exactly one --include response",
    )
    require(
        spotlight.count(status) == 1,
        "Spotlight protected-run approval status extraction changed",
    )
    require(
        spotlight.count(guard) == 1,
        "Spotlight protected-run approval must require exact HTTP 201",
    )
    require(
        "Spotlight protected-run approval returned unexpected status:" in spotlight,
        "Spotlight protected-run approval failure must be explicit and fail closed",
    )
    require(
        'gh api --method POST "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve" >/dev/null'
        not in spotlight,
        "Spotlight must not discard the protected-run approval response",
    )
    response_pos = spotlight.index(response)
    status_pos = spotlight.index(status, response_pos)
    guard_pos = spotlight.index(guard, status_pos)
    downstream_pos = spotlight.index(downstream, guard_pos)
    evidence_pos = spotlight.index(evidence, downstream_pos)
    require(
        response_pos < status_pos < guard_pos < downstream_pos < evidence_pos,
        "Spotlight must prove HTTP 201 before recording protected-run approval state/evidence",
    )


def self_test() -> None:
    v21.self_test()
    self_test_spotlight_same_base_supersession()

    bot_review = (ROOT / ".github/workflows/bot-pr-user-approval.yml").read_text(encoding="utf-8")
    validate_bot_review_identity_ref_evidence_schema(bot_review)
    validate_bot_review_dispatch_status_contract(bot_review)
    validate_bot_review_creation_status_contract(bot_review)

    spotlight = (ROOT / ".github/workflows/spotlight-link-sync.yml").read_text(encoding="utf-8")
    validate_spotlight_reviewer_request_status(spotlight)

    reviewer_missing_include = spotlight.replace(
        'gh api --include --method POST "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers"',
        'gh api --method POST "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers"',
        1,
    )
    try:
        validate_spotlight_reviewer_request_status(reviewer_missing_include)
    except ValueError as exc:
        require(
            "--include response" in str(exc),
            f"Spotlight reviewer-request response self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("Spotlight reviewer-request self-test accepted a response-blind mutation")

    reviewer_wrong_status = spotlight.replace(
        '[[ "$REQUESTED_REVIEWER_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        '[[ "$REQUESTED_REVIEWER_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {',
        1,
    )
    try:
        validate_spotlight_reviewer_request_status(reviewer_wrong_status)
    except ValueError as exc:
        require(
            "exact HTTP 201" in str(exc),
            f"Spotlight reviewer-request status self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("Spotlight reviewer-request self-test accepted non-201 success class")

    reviewer_status_line = '            REQUESTED_REVIEWER_STATUS_LINE="$(head -n 1 <<<"$REQUESTED_REVIEWER_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
    reviewer_guard_block = (
        '            [[ "$REQUESTED_REVIEWER_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
        '              echo "ERROR: Spotlight reviewer request returned unexpected status: ${REQUESTED_REVIEWER_STATUS_LINE}" >&2\n'
        '              exit 1\n'
        '            }\n'
    )
    reviewer_body_line = (
        '            sed \'1,/^[[:space:]]*$/d\' <<<"$REQUESTED_REVIEWER_HTTP_RESPONSE" '
        '> requested-reviewer.json\n'
    )
    reviewer_ordered = reviewer_status_line + reviewer_guard_block + reviewer_body_line
    require(reviewer_ordered in spotlight, "Spotlight reviewer-request ordering fixture anchor changed")
    reviewer_reordered = spotlight.replace(
        reviewer_ordered,
        reviewer_body_line + reviewer_status_line + reviewer_guard_block,
        1,
    )
    try:
        validate_spotlight_reviewer_request_status(reviewer_reordered)
    except ValueError as exc:
        require(
            "prove HTTP 201 before body/schema consumption" in str(exc),
            f"Spotlight reviewer-request ordering self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("Spotlight reviewer-request self-test accepted body extraction before status proof")

    missing_include = bot_review.replace(
        'gh api --include --method POST "repos/${TARGET_REPOSITORY}/actions/workflows/dependabot-controller.yml/dispatches"',
        'gh api --method POST "repos/${TARGET_REPOSITORY}/actions/workflows/dependabot-controller.yml/dispatches"',
        1,
    )
    try:
        validate_bot_review_dispatch_status_contract(missing_include)
    except ValueError as exc:
        require(
            "--include response" in str(exc),
            f"bot-review dispatch-status self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("bot-review dispatch-status self-test accepted a response-blind Dependabot wake")

    wrong_status = bot_review.replace(
        '^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$)',
        '^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$)',
        1,
    )
    try:
        validate_bot_review_dispatch_status_contract(wrong_status)
    except ValueError as exc:
        require(
            "HTTP 204 status guard" in str(exc),
            f"bot-review dispatch-status-code self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("bot-review dispatch-status self-test accepted a non-204 success class")


    review_missing_include = bot_review.replace(
        'gh api --include --method POST               "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/reviews"',
        'gh api --method POST               "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/reviews"',
        1,
    )
    try:
        validate_bot_review_creation_status_contract(review_missing_include)
    except ValueError as exc:
        require(
            "--include response" in str(exc),
            f"bot-review creation-status response self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("bot-review creation-status self-test accepted a response-blind review mutation")

    review_wrong_status = bot_review.replace(
        '[[ "$REVIEW_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {',
        '[[ "$REVIEW_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        1,
    )
    try:
        validate_bot_review_creation_status_contract(review_wrong_status)
    except ValueError as exc:
        require(
            "exact HTTP 200" in str(exc),
            f"bot-review creation-status code self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("bot-review creation-status self-test accepted a non-200 success class")

    review_status = 'REVIEW_STATUS_LINE="$(head -n 1 <<<"$REVIEW_HTTP_RESPONSE" | tr -d \'\\r\')"'
    review_guard = '[[ "$REVIEW_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {'
    review_error = '              echo "ERROR: governed bot review creation returned unexpected status: ${REVIEW_STATUS_LINE}" >&2\n'
    review_exit = '              exit 1\n            }\n'
    review_body = '            REVIEW_RESPONSE="$(sed \'1,/^[[:space:]]*$/d\' <<<"$REVIEW_HTTP_RESPONSE")"\n'
    review_body_guard = '            test "$REVIEW_RESPONSE" != "$REVIEW_HTTP_RESPONSE"\n'
    status_block = (
        "            " + review_status + "\n"
        + "            " + review_guard + "\n"
        + review_error
        + review_exit
    )
    body_block = review_body + review_body_guard
    ordered_block = status_block + body_block
    require(ordered_block in bot_review, "bot-review review-status fixture anchor changed")
    review_reordered = bot_review.replace(ordered_block, body_block + status_block, 1)
    try:
        validate_bot_review_creation_status_contract(review_reordered)
    except ValueError as exc:
        require(
            "prove HTTP 200 and extract the body" in str(exc),
            f"bot-review creation-status ordering self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("bot-review creation-status self-test accepted body extraction before status proof")

    initial_schema = 'validate_git_ref_object "$MAIN_REF_RESPONSE" "main"'
    initial_consume = 'MAIN_SHA="$(jq -r .object.sha <<<"$MAIN_REF_RESPONSE")"'
    reordered = bot_review.replace(initial_schema, "true # displaced initial main-ref schema", 1)
    reordered = reordered.replace(
        initial_consume,
        initial_consume + "\n          " + initial_schema,
        1,
    )
    try:
        validate_bot_review_identity_ref_evidence_schema(reordered)
    except ValueError as exc:
        require("initial main-ref" in str(exc),
                f"bot-review ref-order self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("bot-review ref-order self-test accepted schema-after-consumption reordering")

    weakened_identity = bot_review.replace(
        '(.login | type == "string" and . == "portyu9")',
        '(.login | tostring == "portyu9")',
        1,
    )
    try:
        validate_bot_review_identity_ref_evidence_schema(weakened_identity)
    except ValueError as exc:
        require("identity/ref" in str(exc),
                f"bot-review identity-schema self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("bot-review identity-schema self-test accepted type-coercing login evidence")

    validate_spotlight_dispatch_status_contract(spotlight)
    validate_spotlight_workflow_run_approval_status(spotlight)

    weakened_spotlight_approval_response = spotlight.replace(
        'gh api --include --method POST "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve"',
        'gh api --method POST "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve"',
        1,
    )
    try:
        validate_spotlight_workflow_run_approval_status(weakened_spotlight_approval_response)
    except ValueError as exc:
        require(
            "--include response" in str(exc),
            f"Spotlight protected-run approval response self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("Spotlight protected-run approval self-test accepted a response-blind mutation")

    weakened_spotlight_approval_status = spotlight.replace(
        '[[ "$APPROVAL_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        '[[ "$APPROVAL_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {',
        1,
    )
    try:
        validate_spotlight_workflow_run_approval_status(weakened_spotlight_approval_status)
    except ValueError as exc:
        require(
            "exact HTTP 201" in str(exc),
            f"Spotlight protected-run approval status self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("Spotlight protected-run approval self-test accepted a non-201 success class")


    weakened_spotlight_dispatch = spotlight.replace(
        'gh api --include --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/capability-admission.yml/dispatches"',
        'gh api --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/capability-admission.yml/dispatches"',
        1,
    )
    try:
        validate_spotlight_dispatch_status_contract(weakened_spotlight_dispatch)
    except ValueError as exc:
        require(
            "--include response" in str(exc),
            f"Spotlight dispatch-response self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("Spotlight dispatch-response self-test accepted a response-blind admission wake")

    weakened_spotlight_status = spotlight.replace(
        '^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$)',
        '^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$)',
        1,
    )
    try:
        validate_spotlight_dispatch_status_contract(weakened_spotlight_status)
    except ValueError as exc:
        require(
            "exact HTTP 204 status" in str(exc),
            f"Spotlight dispatch-status self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("Spotlight dispatch-status self-test accepted a non-204 admission response")

    profile = (ROOT / ".github/workflows/profile-stats.yml").read_text(encoding="utf-8")
    validate_leases(profile, spotlight)

    profile_lease_start = profile.index("  lease:\n")
    profile_lease_end = profile.index("  attest_publish:\n", profile_lease_start)
    profile_lease = profile[profile_lease_start:profile_lease_end]
    for current, replacement, label in (
        (
            '            (type == "object") and',
            '            (type == "array") and',
            "object envelope",
        ),
        (
            '            (.id | type == "number" and . == floor and . == $run) and',
            '            (.id | tostring == ($run | tostring)) and',
            "run-id primitive",
        ),
        (
            '            ((.status == "queued") or (.status == "in_progress")) and',
            '            ((.status == "queued") or (.status == "in_progress") or (.status == "completed")) and',
            "terminal status expansion",
        ),
        (
            '            (.conclusion == null) and',
            '            (has("conclusion")) and',
            "null-conclusion binding",
        ),
        (
            '              (.full_name | type == "string" and . == $repo))',
            '              (.full_name | type == "string"))',
            "repository identity",
        ),
    ):
        require(
            profile_lease.count(current) >= 1,
            f"Profile Stats lease run-evidence self-test anchor changed: {label}",
        )
        weakened_lease = profile_lease.replace(current, replacement, 1)
        weakened_profile = (
            profile[:profile_lease_start] + weakened_lease + profile[profile_lease_end:]
        )
        try:
            validate_leases(weakened_profile, spotlight)
        except ValueError as exc:
            require(
                "Profile Stats mutation-lease run evidence contract" in str(exc),
                f"Profile Stats lease run-evidence self-test failed for wrong reason ({label}): {exc}",
            )
        else:
            raise ValueError(
                f"Profile Stats lease run-evidence self-test accepted forbidden mutation: {label}"
            )

    profile_schema_start = profile_lease.index(
        '          jq -e --argjson run "$GITHUB_RUN_ID" --argjson attempt "$GITHUB_RUN_ATTEMPT"'
    )
    profile_schema_end_marker = '\' <<<"$RUN" >/dev/null'
    profile_schema_end = (
        profile_lease.index(profile_schema_end_marker, profile_schema_start)
        + len(profile_schema_end_marker)
    )
    profile_schema_block = profile_lease[profile_schema_start:profile_schema_end]
    without_profile_schema = (
        profile_lease[:profile_schema_start] + profile_lease[profile_schema_end:]
    )
    profile_consume = '          test "$(jq -r .id <<<"$RUN")" = "$GITHUB_RUN_ID"\n'
    profile_consume_pos = without_profile_schema.index(profile_consume) + len(profile_consume)
    reordered_profile_lease = (
        without_profile_schema[:profile_consume_pos]
        + profile_schema_block + "\n"
        + without_profile_schema[profile_consume_pos:]
    )
    reordered_profile = (
        profile[:profile_lease_start] + reordered_profile_lease + profile[profile_lease_end:]
    )
    try:
        validate_leases(reordered_profile, spotlight)
    except ValueError as exc:
        require(
            "Profile Stats mutation-lease run evidence validation must precede scalar consumption" in str(exc),
            f"Profile Stats lease ordering self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError(
            "Profile Stats lease run-evidence self-test accepted schema after scalar consumption"
        )

    for current, replacement, label in (
        (
            '            ((.status == "queued") or (.status == "in_progress")) and',
            '            (.status == "in_progress") and',
            "queued liveness state",
        ),
        (
            '            ((.status == "queued") or (.status == "in_progress")) and',
            '            ((.status == "queued") or (.status == "in_progress") or (.status == "completed")) and',
            "terminal status expansion",
        ),
        (
            '            (.conclusion == null) and',
            '            (has("conclusion")) and',
            "null-conclusion binding",
        ),
    ):
        lease_start = spotlight.index("  lease:\n")
        lease_end = spotlight.index("  reconcile:\n", lease_start)
        lease = spotlight[lease_start:lease_end]
        require(
            lease.count(current) == 1,
            f"Spotlight lease liveness self-test anchor changed: {label}",
        )
        mutated_lease = lease.replace(current, replacement, 1)
        mutated = spotlight[:lease_start] + mutated_lease + spotlight[lease_end:]
        try:
            validate_leases(profile, mutated)
        except ValueError as exc:
            require(
                "mutation-lease run evidence contract is missing" in str(exc),
                f"Spotlight lease liveness self-test failed for wrong reason ({label}): {exc}",
            )
        else:
            raise ValueError(
                f"Spotlight lease liveness self-test accepted forbidden mutation: {label}"
            )
    validate_spotlight_same_base_supersession(spotlight)
    validate_spotlight_budget_artifact_history(spotlight)
    budget_start = spotlight.index("  budget:\n")
    budget_end = spotlight.index("  quarantine:\n", budget_start)
    budget = spotlight[budget_start:budget_end]
    schema_start = budget.index(
        '          jq -e --arg name "$ARTIFACT_NAME" --arg base "$BASE_SHA" --argjson repo "$GITHUB_REPOSITORY_ID"'
    )
    total_pos = budget.index('          TOTAL="$(jq -r \'.total_count // empty\' <<<"$ARTIFACTS")"', schema_start)
    schema_block = budget[schema_start:total_pos]
    without_schema = budget[:schema_start] + budget[total_pos:]
    output = '          echo "attempt_count=$TOTAL" >> "$GITHUB_OUTPUT"\n'
    output_pos = without_schema.index(output) + len(output)
    reordered_budget = without_schema[:output_pos] + schema_block + without_schema[output_pos:]
    reordered = spotlight[:budget_start] + reordered_budget + spotlight[budget_end:]
    try:
        validate_spotlight_budget_artifact_history(reordered)
    except ValueError as exc:
        require("artifact-history" in str(exc),
                f"governed artifact-history self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("governed artifact-history self-test accepted schema-after-output reordering")


def validate_profile_stats_spotlight_dispatch_evidence(
    profile: str, *, run_self_test: bool = True
) -> None:
    dispatch = job_block(profile, "dispatch", "decision_receipt")
    workflow_fetch = (
        'WORKFLOW="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/'
        'spotlight-link-sync.yml")"'
    )
    workflow_schema = '(.state | type == "string" and . == "active") and'
    workflow_schema_end = "' <<<\"$WORKFLOW\" >/dev/null || {"
    workflow_consume = 'WORKFLOW_ID="$(jq -r .id <<<"$WORKFLOW")"'
    runs_fetch = (
        'RUNS="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/'
        'spotlight-link-sync.yml/runs?event=workflow_dispatch&branch=main&per_page=1")"'
    )
    runs_schema = '--argjson workflow "$WORKFLOW_ID"'
    runs_schema_end = "' <<<\"$RUNS\" >/dev/null || {"
    runs_consume = 'TOTAL="$(jq -r .total_count <<<"$RUNS")"'
    high_water = "PREVIOUS_RUN_HIGH_WATER=\"$(jq -r '.workflow_runs[0].id' <<<\"$RUNS\")\""
    dispatch_post = (
        'gh api --include --method POST \\\n'
        '            "repos/${GITHUB_REPOSITORY}/actions/workflows/'
        'spotlight-link-sync.yml/dispatches"'
    )

    for marker in (
        workflow_fetch, workflow_schema, workflow_schema_end, workflow_consume,
        runs_fetch, runs_schema, runs_schema_end, runs_consume, high_water,
        dispatch_post,
    ):
        require(
            dispatch.count(marker) == 1,
            f"Profile Stats Spotlight dispatch evidence anchor changed: {marker}",
        )

    positions = (
        dispatch.index(workflow_fetch),
        dispatch.index(workflow_schema),
        dispatch.index(workflow_schema_end),
        dispatch.index(workflow_consume),
        dispatch.index(runs_fetch),
        dispatch.index(runs_schema),
        dispatch.index(runs_schema_end),
        dispatch.index(runs_consume),
        dispatch.index(dispatch_post),
    )
    require(
        list(positions) == sorted(positions) and len(set(positions)) == len(positions),
        "Profile Stats Spotlight dispatch evidence must be typed before scalar consumption/write",
    )

    workflow_block = dispatch[
        dispatch.index(workflow_fetch):dispatch.index(workflow_schema_end)
    ]
    for fragment in (
        '(.id | positive_int) and',
        '(.node_id | type == "string" and length > 0) and',
        '(.name | type == "string" and . == "Sync Spotlight profile links") and',
        '(.path | type == "string" and . == ".github/workflows/spotlight-link-sync.yml") and',
        '(.state | type == "string" and . == "active") and',
        '(.url | type == "string" and length > 0) and',
        '(.html_url | type == "string" and length > 0) and',
        '(.badge_url | type == "string" and length > 0) and',
        '(.created_at | type == "string" and length > 0) and',
        '(.updated_at | type == "string" and length > 0)',
    ):
        require(
            fragment in workflow_block,
            f"Profile Stats Spotlight workflow singleton schema changed: {fragment}",
        )

    runs_block = dispatch[dispatch.index(runs_schema):dispatch.index(runs_schema_end)]
    for fragment in (
        '($root.total_count | type == "number" and . == floor and . >= 0) and',
        '($root.workflow_runs | type == "array" and length <= 1) and',
        'then ($root.workflow_runs | length) == 0',
        'else ($root.workflow_runs | length) == 1',
        '(.id | positive_int) and',
        '(.node_id | type == "string" and length > 0) and',
        '(.workflow_id | type == "number" and . == floor and . == $workflow) and',
        '(.name | type == "string" and . == "Sync Spotlight profile links") and',
        '(.path | type == "string" and . == ".github/workflows/spotlight-link-sync.yml") and',
        '(.event | type == "string" and . == "workflow_dispatch") and',
        '(.head_branch | type == "string" and . == "main") and',
        '(.head_sha | type == "string" and test("^[0-9a-f]{40}$")) and',
        '(.run_number | positive_int) and',
        '(.run_attempt | positive_int) and',
        '(.check_suite_id | positive_int) and',
        '(.check_suite_node_id | type == "string" and length > 0) and',
        '(.repository | type == "object" and',
        '(.id | type == "number" and . == floor and . == $repo) and',
        '(.full_name | type == "string" and . == $repo_name)) and',
        '(.head_repository | type == "object" and',
        '(.status | type == "string" and allowed_status) and',
        'then (.conclusion | type == "string" and allowed_conclusion)',
        'else .conclusion == null',
        '(.url | type == "string" and length > 0) and',
        '(.html_url | type == "string" and length > 0)',
    ):
        require(
            fragment in runs_block,
            f"Profile Stats Spotlight run collection schema changed: {fragment}",
        )

    for fragment in (
        '(. == "queued") or (. == "in_progress") or (. == "requested") or',
        '(. == "waiting") or (. == "pending") or (. == "completed");',
        '(. == "success") or (. == "failure") or (. == "neutral") or',
        '(. == "cancelled") or (. == "skipped") or (. == "timed_out") or',
        '(. == "action_required") or (. == "stale") or (. == "startup_failure");',
    ):
        require(
            fragment in runs_block,
            f"Profile Stats Spotlight run status/conclusion allowlist changed: {fragment}",
        )
    require(
        runs_block.count('(.id | type == "number" and . == floor and . == $repo) and') == 2
        and runs_block.count('(.full_name | type == "string" and . == $repo_name)) and') == 2,
        "Profile Stats Spotlight run repository/head-repository identity binding changed",
    )

    require(
        dispatch.count(
            'actions/workflows/spotlight-link-sync.yml/runs?event=workflow_dispatch&branch=main&per_page=1'
        ) == 1
        and dispatch.count(
            'actions/workflows/spotlight-link-sync.yml/dispatches'
        ) == 1,
        "Profile Stats Spotlight dispatch endpoint/call-count contract changed",
    )
    require(
        "STATUS_LINE=\"$(head -n 1 <<<\"$RESPONSE\" | tr -d '\\r')\"" in dispatch
        and '[[ "$STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]]' in dispatch,
        "Profile Stats Spotlight dispatch must retain exact HTTP 204 acceptance proof",
    )

    if run_self_test:
        for current, replacement, expected in (
            (
                '(.state | type == "string" and . == "active") and',
                '(.state | tostring == "active") and',
                "dispatch evidence anchor changed",
            ),
            (
                '(.run_attempt | positive_int) and',
                '(.run_attempt | tostring | length > 0) and',
                "run collection schema changed",
            ),
            (
                '(.check_suite_node_id | type == "string" and length > 0) and',
                '(.check_suite_node_id | tostring | length > 0) and',
                "run collection schema changed",
            ),
            (
                '(.full_name | type == "string" and . == $repo_name)) and',
                '(.full_name | tostring == $repo_name)) and',
                "repository/head-repository identity binding changed",
            ),
            (
                '(. == "waiting") or (. == "pending") or (. == "completed");',
                '(. == "waiting") or (. == "pending") or (. == "made_up");',
                "status/conclusion allowlist changed",
            ),
        ):
            require(
                current in profile,
                f"Profile Stats dispatch self-test fixture anchor changed: {current}",
            )
            mutated = profile.replace(current, replacement, 1)
            try:
                validate_profile_stats_spotlight_dispatch_evidence(
                    mutated, run_self_test=False
                )
            except ValueError as exc:
                require(
                    expected in str(exc),
                    f"Profile Stats dispatch self-test failed for wrong reason: {exc}",
                )
            else:
                raise ValueError(
                    f"Profile Stats dispatch self-test accepted forbidden mutation: {expected}"
                )


def validate_profile_quality_portfolio_liveness_boundary(
    profile_quality: str, profile_stats: str, *, run_self_test: bool = True
) -> None:
    integration = job_block(profile_quality, "integration", "dependabot_admission")
    generation_anchor = (
        'python3 scripts/generate-profile-evidence.py \\\n'
        '            --signal-field-dir "$READY_DIR" \\\n'
        '            --portfolio-ledger-dir integration-portfolio-evidence \\\n'
        '            --spotlight-dir integration-engineering-spotlight \\\n'
        '            --offline'
    )
    require(
        generation_anchor in integration,
        "Profile Quality integration must use deterministic offline Portfolio/Spotlight generation",
    )

    boundary_anchor = (
        'python3 scripts/validate-profile-evidence-boundary.py \\\n'
        '            --signal-field-dir "$SIGNAL_FIELD_DIR" \\\n'
        '            --spotlight-dir integration-engineering-spotlight \\\n'
        '            --portfolio-ledger-dir integration-portfolio-evidence \\\n'
        '            --offline'
    )
    require(
        boundary_anchor in integration,
        "Profile Quality integration must use the canonical validation boundary in offline mode",
    )
    require(
        integration.count("python3 scripts/generate-profile-evidence.py") == 1
        and integration.count("python3 scripts/validate-profile-evidence-boundary.py") == 1
        and integration.count("--offline") == 2,
        "Profile Quality integration must have exactly one offline generation and one offline validation boundary",
    )
    for duplicated in (
        "python3 scripts/validate-portfolio-evidence-ledger.py integration-portfolio-evidence",
        "python3 scripts/validate-engineering-spotlight.py integration-engineering-spotlight",
    ):
        require(
            duplicated not in integration,
            f"Profile Quality integration must not duplicate canonical boundary sequencing: {duplicated}",
        )

    live_generation_anchor = (
        'python3 source/scripts/generate-profile-evidence.py \\\n'
        '            --signal-field-dir "$READY_DIR" \\\n'
        '            --portfolio-ledger-dir portfolio-ledger-ready \\\n'
        '            --spotlight-dir spotlight-ready'
    )
    require(
        live_generation_anchor in profile_stats,
        "Profile Stats must retain canonical live Portfolio/Spotlight evidence generation",
    )
    require(
        '--spotlight-dir spotlight-ready \\\n            --offline' not in profile_stats,
        "Profile Stats publication must not downgrade Portfolio/Spotlight generation to offline mode",
    )
    require(
        profile_stats.count("python3 source/scripts/validate-profile-evidence-boundary.py") == 2,
        "Profile Stats must retain both canonical live candidate validation boundaries",
    )
    require(
        "python3 source/scripts/validate-profile-evidence-boundary.py --offline" not in profile_stats
        and "--portfolio-ledger-dir portfolio-evidence \\\n            --offline" not in profile_stats
        and "--portfolio-ledger-dir portfolio-ledger-publish-input \\\n            --offline" not in profile_stats,
        "Profile Stats candidate validation boundaries must remain strict-live",
    )

    if run_self_test:
        weakened_generation = profile_quality.replace(
            '            --spotlight-dir integration-engineering-spotlight \\\n'
            '            --offline',
            '            --spotlight-dir integration-engineering-spotlight',
            1,
        )
        try:
            validate_profile_quality_portfolio_liveness_boundary(
                weakened_generation, profile_stats, run_self_test=False
            )
        except ValueError as exc:
            require(
                "deterministic offline Portfolio/Spotlight generation" in str(exc),
                f"Profile Quality generation-boundary self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                "Profile Quality generation-boundary self-test accepted live external portfolio merge authority"
            )

        weakened_boundary = profile_quality.replace(
            '            --portfolio-ledger-dir integration-portfolio-evidence \\\n'
            '            --offline',
            '            --portfolio-ledger-dir integration-portfolio-evidence',
            1,
        )
        try:
            validate_profile_quality_portfolio_liveness_boundary(
                weakened_boundary, profile_stats, run_self_test=False
            )
        except ValueError as exc:
            require(
                "canonical validation boundary in offline mode" in str(exc),
                f"Profile Quality validation-boundary self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                "Profile Quality validation-boundary self-test accepted live external portfolio merge authority"
            )

        weakened_stats = profile_stats.replace(
            '            --spotlight-dir spotlight-ready',
            '            --spotlight-dir spotlight-ready \\\n            --offline',
            1,
        )
        try:
            validate_profile_quality_portfolio_liveness_boundary(
                profile_quality, weakened_stats, run_self_test=False
            )
        except ValueError as exc:
            require(
                "must not downgrade Portfolio/Spotlight generation to offline mode" in str(exc),
                f"Profile Stats live-generation self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                "Profile Stats live-generation self-test accepted offline production evidence"
            )


def main() -> int:
    try:
        self_test()
        observed: dict[str, str] = {}
        for relative, expected in EXPECTED.items():
            actual = v21.git_blob_sha(ROOT / relative)
            require(actual == expected,
                    f"{relative}: governed workflow bytes changed; expected Git blob {expected}, got {actual}")
            observed[relative] = actual
        require(set(observed) == set(EXPECTED), "governed workflow identity inventory changed")
        runtime_test_blob = v21.git_blob_sha(ROOT / "scripts/spotlight_budget_jq_schema_runtime_test.py")
        require(
            runtime_test_blob == SPOTLIGHT_BUDGET_JQ_RUNTIME_TEST_BLOB,
            "Spotlight mutation-budget jq runtime-test bytes changed; "
            f"expected Git blob {SPOTLIGHT_BUDGET_JQ_RUNTIME_TEST_BLOB}, got {runtime_test_blob}",
        )

        profile_quality = (ROOT / ".github/workflows/profile-quality.yml").read_text(encoding="utf-8")
        governed_bot_review_gate = (ROOT / "scripts/governed_bot_review_gate.py").read_text(encoding="utf-8")
        validate_native_bot_review_gate(profile_quality, governed_bot_review_gate)

        bot_review = (ROOT / ".github/workflows/bot-pr-user-approval.yml").read_text(encoding="utf-8")
        validate_bot_review_dispatch_status_contract(bot_review)
        validate_bot_review_creation_status_contract(bot_review)
        dependabot = (ROOT / ".github/workflows/dependabot-controller.yml").read_text(encoding="utf-8")
        autofix = (ROOT / ".github/workflows/codeql-autofix.yml").read_text(encoding="utf-8")
        spotlight = (ROOT / ".github/workflows/spotlight-link-sync.yml").read_text(encoding="utf-8")
        validate_spotlight_reviewer_request_status(spotlight)
        validate_spotlight_dispatch_status_contract(spotlight)
        validate_spotlight_workflow_run_approval_status(spotlight)
        capability = (ROOT / ".github/workflows/capability-admission.yml").read_text(encoding="utf-8")
        validate_codeql_autofix_constructive_response_schemas(autofix)
        validate_codeql_autofix_read_singleton_evidence(autofix)
        validate_codeql_autofix_approval_comment_evidence(autofix)
        validate_bot_review_liveness(bot_review, dependabot, autofix, spotlight)
        validate_spotlight_event_admission(spotlight, capability)
        validate_spotlight_terminal_required_check_collection(spotlight)
        validate_spotlight_terminal_protected_run_evidence(spotlight)
        validate_spotlight_terminal_trusted_admission_evidence(spotlight)
        validate_spotlight_same_base_supersession(spotlight)
        validate_spotlight_privileged_ref_evidence_schema(spotlight)
        validate_spotlight_readme_contents_evidence(spotlight)
        validate_spotlight_pr_response_evidence(spotlight)

        validate_spotlight_budget_artifact_history(spotlight)

        profile = (ROOT / ".github/workflows/profile-stats.yml").read_text(encoding="utf-8")
        validate_profile_quality_portfolio_liveness_boundary(profile_quality, profile)
        v21.validate_profile_stats_freshness(profile)
        v21.validate_profile_stats_lease_binding(profile)
        v21.validate_profile_stats_receipt(profile)
        validate_profile_stats_spotlight_dispatch_evidence(profile)

        validate_v21_spotlight_invariants(spotlight)
        validate_item10_mac(spotlight)
        validate_item11_receipts(profile, spotlight)
        validate_leases(profile, spotlight)

        print(
            f"Governed workflow byte identity passed: {VERSION} · {len(observed)} exact reviewed workflow blobs · "
            "v21 profile/publication and Spotlight reconciliation/immutable-candidate invariants preserved · "
            "native PR required-check accepted-base trust bootstrap plus staged next-evaluator byte identity and classified read-only transient retry locked · CodeQL Autofix constructive mutation-response schema plus exact HTTP-200/202/201 transport ordering locked · bot-review credential/ref response schema ordering, exact workflow-dispatch HTTP 204 validation, and exact review-creation HTTP 200 validation locked · bot-review lane-specific liveness, stale-wake collapse, bounded Spotlight readiness retry, canonical Profile-Quality quiescence exemption, fresh post-wait thread/review evidence, idempotent recovery wake, and immutable base/head marker proof locked · event-driven Spotlight main-push reconciliation plus exact-201 reviewer-request, exact-204 admission/reviewer dispatch, and exact-201 protected-run approval status validation, pre-convergence reviewer wake, proof/live-reproof and jq-only protected workflow evidence locked · post-review native governed-bot required gate consumption byte-locked · item-10 MAC ordering and terminal proof guards retained · "
            "item-11 ADR recovery/preparation/signing boundaries byte-locked with exact lease closure and no signer-side authored execution surface · Spotlight proposal/terminal README Contents evidence typed before content consumption · Spotlight terminal required-check collection and protected workflow-run certificate provenance typed before merge/MAC consumption · Profile Stats mutation-lease current-run evidence is typed before scalar consumption/generated-ref reproof/lease issuance · Profile Stats Spotlight workflow/run dispatch evidence is typed before high-water/write consumption · Spotlight terminal trusted-admission workflow/run/check evidence is typed before live-reproof consumption · Spotlight lease current-run status permits only queued/in-progress with null conclusion before lease issuance · Spotlight mutation-budget artifact-history envelope schema and pre-admission ordering locked · Profile Quality external Portfolio/Spotlight liveness is excluded from protected merge authority through the canonical validation boundary's explicit offline mode while Profile Stats retains both strict-live boundary executions · Profile Quality executable jq runtime fixture step and exact runtime-test script bytes locked."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
