#!/usr/bin/env python3
"""Lock privileged workflow bytes and item-10/11 terminal authorization semantics."""
from __future__ import annotations

from pathlib import Path
import json
import subprocess
import sys

import privileged_workflow_identity_v21_core as v21

ROOT = Path(__file__).resolve().parents[1]
VERSION = "governed-workflow-byte-identity-v72"
EXPECTED = {
    ".github/workflows/bot-pr-user-approval.yml": "df5f75635d678c6c48221f60dbb9653cb10900fc",
    ".github/workflows/profile-quality.yml": "c4a48f9ccaaf79ee2e7a82e057e9788a216e6049",
    ".github/workflows/profile-stats.yml": "627ecd3d7a5d9ca4e7051acf3c64d3edab914af0",
    ".github/workflows/spotlight-link-sync.yml": "4f3333733312135d2254a19b830a4840ab9e852f",
}

TRUSTED_GOVERNED_BOT_REVIEW_GATE = "844026bd8a752433dd8b01477e7e1b56b587d0b1"
ACCEPTED_BASE_GOVERNED_BOT_REVIEW_GATE = "844026bd8a752433dd8b01477e7e1b56b587d0b1"

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


def validate_spotlight_budget_artifact_history_runtime(spotlight: str) -> None:
    """Execute the exact embedded jq schema against valid and adversarial fixtures."""
    budget = job_block(spotlight, "budget", "quarantine")
    schema_marker = 'jq -e --arg name "$ARTIFACT_NAME" --arg base "$BASE_SHA" --argjson repo "$GITHUB_REPOSITORY_ID"'
    program_open = "\n            '\n"
    program_close = "\n          ' <<<\"$ARTIFACTS\" >/dev/null || {"
    schema_start = budget.index(schema_marker)
    program_start = budget.index(program_open, schema_start) + len(program_open)
    program_end = budget.index(program_close, program_start)
    jq_program = budget[program_start:program_end]

    base = "a" * 40
    generated = "b" * 40
    artifact_name = f"spotlight-link-plan-{base}-{generated}"
    repo_id = 35150859
    valid = {
        "total_count": 2,
        "artifacts": [
            {
                "id": 101,
                "name": artifact_name,
                "expired": False,
                "workflow_run": {
                    "id": 1001,
                    "repository_id": repo_id,
                    "head_repository_id": repo_id,
                    "head_branch": "main",
                    "head_sha": base,
                },
            },
            {
                "id": 102,
                "name": artifact_name,
                "expired": False,
                "workflow_run": {
                    "id": 1002,
                    "repository_id": repo_id,
                    "head_repository_id": repo_id,
                    "head_branch": "main",
                    "head_sha": base,
                },
            },
        ],
    }

    def execute(payload: dict[str, object]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "jq", "-e",
                "--arg", "name", artifact_name,
                "--arg", "base", base,
                "--argjson", "repo", str(repo_id),
                jq_program,
            ],
            input=json.dumps(payload, separators=(",", ":")),
            text=True,
            capture_output=True,
            check=False,
        )

    accepted = execute(valid)
    require(
        accepted.returncode == 0 and accepted.stdout.strip() == "true",
        "Spotlight mutation-budget jq schema must compile and accept the exact valid fixture; "
        f"rc={accepted.returncode}, stderr={accepted.stderr.strip()!r}",
    )

    invalid_fixtures: list[tuple[str, dict[str, object]]] = []

    mismatched_count = json.loads(json.dumps(valid))
    mismatched_count["total_count"] = 1
    invalid_fixtures.append(("mismatched total_count", mismatched_count))

    duplicate_id = json.loads(json.dumps(valid))
    duplicate_id["artifacts"][1]["id"] = duplicate_id["artifacts"][0]["id"]
    invalid_fixtures.append(("duplicate artifact id", duplicate_id))

    wrong_head = json.loads(json.dumps(valid))
    wrong_head["artifacts"][0]["workflow_run"]["head_sha"] = "c" * 40
    invalid_fixtures.append(("wrong nested head sha", wrong_head))

    for label, payload in invalid_fixtures:
        rejected = execute(payload)
        require(
            rejected.returncode == 1,
            f"Spotlight mutation-budget jq schema must reject {label} with jq predicate failure; "
            f"rc={rejected.returncode}, stdout={rejected.stdout.strip()!r}, stderr={rejected.stderr.strip()!r}",
        )


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
        'RESULT="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge" --input merge.json)"',
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
    merge_pos = merge.index('RESULT="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"')
    response_pos = merge.index('VALIDATED_MERGE="$(jq -ce "$MERGE_SUCCESS_FILTER" <<<"$RESULT")"')
    merged_pr_pos = merge.index('MERGED_PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"', response_pos)
    merged_pr_schema_pos = merge.index('validate_terminal_pr_object "$MERGED_PR"', merged_pr_pos)
    merged_pr_identity_pos = merge.index('jq -e --argjson pr "$PR_NUMBER" --arg merge "$MERGE_SHA"', merged_pr_schema_pos)
    merge_sha_bind_pos = merge.index('test "$(jq -r .merge_commit_sha <<<"$MERGED_PR")" = "$MERGE_SHA"', merged_pr_identity_pos)
    current_main_pos = merge.index('CURRENT_MAIN_SHA="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)"')
    cleanup_pos = merge.index('CANDIDATE_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"')
    require(
        pre_pr_pos < pre_pr_schema_pos < files_pos < files_schema_pos < commit_pos < commit_schema_pos
        < provenance_pos < verify_pos < statement_pos < merge_pos < response_pos < merged_pr_pos
        < merged_pr_schema_pos < merged_pr_identity_pos < merge_sha_bind_pos < current_main_pos < cleanup_pos,
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
        '(.status | type == "string" and . == "in_progress") and',
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


def validate_v21_spotlight_invariants(spotlight: str) -> None:
    legacy = spotlight[:spotlight.index("  decision_receipt:\n")]
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
    v21.validate_spotlight_immutable_candidates(projected_immutable)
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
        "EXPECTED_GATE_BLOB: 844026bd8a752433dd8b01477e7e1b56b587d0b1",
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

    review_mutation = 'REVIEW_RESPONSE="$(GH_TOKEN="$REVIEW_TOKEN" gh api --method POST'
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


def validate_bot_review_liveness(bot_review: str, dependabot: str, autofix: str, spotlight: str) -> None:
    validate_bot_review_single_object_evidence_schema(bot_review)
    validate_bot_review_run_check_evidence_schema(bot_review)
    validate_dependabot_readiness_run_check_evidence_schema(dependabot)
    validate_pull_review_evidence_schema(bot_review, "Bot PR reviewer", 2)
    validate_pull_review_evidence_schema(dependabot, "Dependabot terminal merge", 1)
    validate_pull_review_evidence_schema(autofix, "CodeQL Autofix terminal merge", 1)
    validate_pull_review_evidence_schema(spotlight, "Spotlight authorization/terminal merge", 2)
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
    review_mutation_pos = bot_review.index('REVIEW_RESPONSE="$(GH_TOKEN="$REVIEW_TOKEN" gh api --method POST')
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
        'MERGE_BODY="$RUNNER_TEMP/dependabot-merge-response.json"',
        'MERGE_ERR="$RUNNER_TEMP/dependabot-merge-error.txt"',
        'MERGE_STATUS=$?',
        'if [ "$MERGE_STATUS" -ne 0 ]; then',
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
        '-f ref=main >/dev/null',
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
        'Dispatched exact post-check portyu9 review evaluation from trusted main.',
        'for REVIEW_ATTEMPT in $(seq 1 24); do',
        'exact-base/head portyu9 review did not materialize after the post-check dispatch.',
        'Observed exact-base/head marker-bound portyu9 approval before merge authorization.',
        'Spotlight terminal stage: trusted-admission-live-reproof-verified',
        'jq -e --arg body "$APPROVAL_BODY" \'.body == $body\' approval-comment.json >/dev/null',
    )
    for fragment in spotlight_fragments:
        require(fragment in spotlight, f"Spotlight event-driven admission proof contract is missing: {fragment}")
    require('grep -Fxc "$APPROVAL_BODY"' not in spotlight,
            "Spotlight approval comment verification must compare the complete multiline body atomically")


def self_test() -> None:
    v21.self_test()
    spotlight = (ROOT / ".github/workflows/spotlight-link-sync.yml").read_text(encoding="utf-8")
    validate_spotlight_budget_artifact_history(spotlight)
    validate_spotlight_budget_artifact_history_runtime(spotlight)
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

        profile_quality = (ROOT / ".github/workflows/profile-quality.yml").read_text(encoding="utf-8")
        governed_bot_review_gate = (ROOT / "scripts/governed_bot_review_gate.py").read_text(encoding="utf-8")
        validate_native_bot_review_gate(profile_quality, governed_bot_review_gate)

        bot_review = (ROOT / ".github/workflows/bot-pr-user-approval.yml").read_text(encoding="utf-8")
        dependabot = (ROOT / ".github/workflows/dependabot-controller.yml").read_text(encoding="utf-8")
        autofix = (ROOT / ".github/workflows/codeql-autofix.yml").read_text(encoding="utf-8")
        spotlight = (ROOT / ".github/workflows/spotlight-link-sync.yml").read_text(encoding="utf-8")
        capability = (ROOT / ".github/workflows/capability-admission.yml").read_text(encoding="utf-8")
        validate_bot_review_liveness(bot_review, dependabot, autofix, spotlight)
        validate_spotlight_event_admission(spotlight, capability)

        validate_spotlight_budget_artifact_history(spotlight)

        profile = (ROOT / ".github/workflows/profile-stats.yml").read_text(encoding="utf-8")
        v21.validate_profile_stats_freshness(profile)
        v21.validate_profile_stats_lease_binding(profile)
        v21.validate_profile_stats_receipt(profile)

        validate_v21_spotlight_invariants(spotlight)
        validate_item10_mac(spotlight)
        validate_item11_receipts(profile, spotlight)
        validate_leases(profile, spotlight)

        print(
            f"Governed workflow byte identity passed: {VERSION} · {len(observed)} exact reviewed workflow blobs · "
            "v21 profile/publication and Spotlight reconciliation/immutable-candidate invariants preserved · "
            "native PR required-check accepted-base trust bootstrap plus staged next-evaluator byte identity locked · bot-review lane-specific liveness, stale-wake collapse, bounded Spotlight readiness retry, canonical Profile-Quality quiescence exemption, fresh post-wait thread/review evidence, idempotent recovery wake, and immutable base/head marker proof locked · event-driven Spotlight main-push reconciliation plus admission dispatch/proof/live-reproof locked · post-review native governed-bot required gate consumption byte-locked · item-10 MAC ordering and terminal proof guards retained · "
            "item-11 ADR recovery/preparation/signing boundaries byte-locked with exact lease closure and no signer-side authored execution surface · Spotlight mutation-budget artifact-history envelope schema and pre-admission ordering locked."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
