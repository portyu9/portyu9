#!/usr/bin/env python3
"""Lock privileged workflow bytes and item-10/11 terminal authorization semantics."""
from __future__ import annotations

from pathlib import Path
import sys

import privileged_workflow_identity_v21_core as v21

ROOT = Path(__file__).resolve().parents[1]
VERSION = "governed-workflow-byte-identity-v49"
EXPECTED = {
    ".github/workflows/bot-pr-user-approval.yml": "7a9058d07ce47c7848c061d6799fa0eb26c66cfb",
    ".github/workflows/profile-quality.yml": "6e38fc41f61edac8fe1b0fb0dd0f1be2bd8f366c",
    ".github/workflows/profile-stats.yml": "627ecd3d7a5d9ca4e7051acf3c64d3edab914af0",
    ".github/workflows/spotlight-link-sync.yml": "3a2cae6fd4eecc295323a1ac329f7175ddc4c406",
}

TRUSTED_GOVERNED_BOT_REVIEW_GATE = "0158284c833051fa9a1152a3314b906038ec6a28"

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
    '          test "$(jq \'.parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"\n'
)
IMMUTABLE_PROJECTED = (
    '          fi\n\n'
    f'          {IMMUTABLE_COMMENT}\n'
    '          CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"\n'
    '          test "$(jq \'.parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"\n'
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
    ):
        require(fragment in merge, f"Spotlight terminal MAC verification contract is missing: {fragment}")
    require("jq -c '.workflowRuns | sort_by(.name)'" not in merge and
            "jq -c '.checkRuns | sort_by(.name)'" not in merge,
            "Spotlight terminal provenance equality must canonicalize object-key order before byte comparison")
    require("[.. | objects" not in merge,
            "Spotlight terminal MAC verification must not recursively search untrusted verifier JSON")
    provenance_pos = merge.index('echo "Spotlight terminal stage: certificate-provenance-verified" >&2')
    verify_pos = merge.index('gh attestation verify "$SUBJECT"')
    statement_pos = merge.index('.verificationResult.statement')
    merge_pos = merge.index('RESULT="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"')
    require(provenance_pos < verify_pos < statement_pos < merge_pos,
            "Spotlight terminal merge mutation moved before canonical provenance and verified-statement MAC binding")
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
    v21.validate_spotlight_reconciliation(legacy)
    require(
        'PR_NUMBER="$(jq -r \'.[0].number\' <<<"$PRS")"' in legacy and
        'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"' in legacy,
        "Spotlight stale reconciliation must use list results only for bounded PR discovery and re-fetch the exact full PR object",
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
    ):
        require(fragment in legacy, f"Spotlight current immutable-candidate proof is missing: {fragment}")
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
        "EXPECTED_GATE_BLOB: 0158284c833051fa9a1152a3314b906038ec6a28",
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
    ):
        require(fragment in evaluator, f"trusted governed-bot review evaluator contract is missing: {fragment}")
    for forbidden in ('method="POST"', 'method="PUT"', 'method="PATCH"', 'method="DELETE"', "subprocess"):
        require(forbidden not in evaluator,
                f"trusted governed-bot review evaluator acquired mutation/external execution surface: {forbidden}")


def validate_bot_review_liveness(bot_review: str, dependabot: str, autofix: str, spotlight: str) -> None:
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
        '--arg marker "$REVIEW_MARKER"',
        'contains($marker)',
        'exact-base/head marker-bound portyu9 approval',
        'return 2',
        'lane-required checks are not ready yet.',
        'exact head is not quiescent yet.',
        'completed unsuccessfully on ${head}.',
        'jq -e --arg body "$BODY" \'.body == $body\' <<<"$REVIEW_RESPONSE" >/dev/null',
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
    ):
        require(fragment in bot_review, f"Bot PR user approval liveness/proof contract is missing: {fragment}")
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
            "native PR required-check trust bootstrap plus evaluator byte identity locked · bot-review lane-specific liveness, stale-wake collapse, canonical Profile-Quality quiescence exemption, idempotent recovery wake, and immutable base/head marker proof locked · event-driven Spotlight main-push reconciliation plus admission dispatch/proof/live-reproof locked · post-review native governed-bot required gate consumption byte-locked · item-10 MAC ordering and terminal proof guards retained · "
            "item-11 ADR recovery/preparation/signing boundaries byte-locked with exact lease closure and no signer-side authored execution surface."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
