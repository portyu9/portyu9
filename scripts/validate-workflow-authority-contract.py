#!/usr/bin/env python3
"""Adapt the item-11 workflow authority proof to stabilized item-9/item-10 source bytes."""
from __future__ import annotations

import json

import workflow_authority_contract_item11_core as core


core.ITEM10_CANDIDATE_REPROOF = (
    '          test "$(jq -r .message <<<"$CANDIDATE_COMMIT")" = "chore: sync rotating Spotlight links"\n'
    '          gh api "repos/${GITHUB_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}" --jq .content | '
    "tr -d '\\n' | base64 --decode > candidate-readme.md\n"
    '          test "$(sha256sum candidate-readme.md | cut -d\' \' -f1)" = "$README_SHA256_AFTER"\n'
)

ORIGINAL_STRIP_ADR_TAIL = core.strip_adr_tail
ORIGINAL_PROJECT_ITEM9_SYNC = core.project_item9_sync
LEGACY_PROFILE_DISPATCH = '''  dispatch:
    name: dispatch-spotlight-link-sync
    needs: [receipt_attest, lease, attest]
    runs-on: ubuntu-24.04
    timeout-minutes: 2
    concurrency:
      group: profile-stats-terminal
      cancel-in-progress: false
      queue: max
    permissions:
      actions: write

    steps:
      - name: Verify exact short-lived mutation lease
        env:
          LEASE_ID: ${{ needs.lease.outputs.lease_id }}
          LEASE_ISSUED_AT: ${{ needs.lease.outputs.issued_at }}
          LEASE_EXPIRES_AT: ${{ needs.lease.outputs.expires_at }}
          LEASE_BASE_SHA: ${{ needs.lease.outputs.base_sha }}
          LEASE_CANDIDATE_ID: ${{ needs.lease.outputs.candidate_id }}
          EXPECTED_BASE_SHA: ${{ github.sha }}
          EXPECTED_CANDIDATE_ID: ${{ needs.attest.outputs.candidate_id }}
        run: |
          set -euo pipefail
          LEASE_TTL_SECONDS=1800
          LEASE_MIN_REMAINING_SECONDS=180
          [[ "$LEASE_ID" =~ ^[0-9a-f]{64}$ ]]
          [[ "$LEASE_ISSUED_AT" =~ ^[1-9][0-9]*$ ]]
          [[ "$LEASE_EXPIRES_AT" =~ ^[1-9][0-9]*$ ]]
          test "$LEASE_BASE_SHA" = "$EXPECTED_BASE_SHA"
          test "$LEASE_CANDIDATE_ID" = "$EXPECTED_CANDIDATE_ID"
          EXPECTED_WORKFLOW_REF="${GITHUB_REPOSITORY}/.github/workflows/profile-stats.yml@refs/heads/main"
          test "$GITHUB_WORKFLOW_REF" = "$EXPECTED_WORKFLOW_REF"
          [[ "$GITHUB_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]
          test "$GITHUB_WORKFLOW_SHA" = "$EXPECTED_BASE_SHA"
          test "$LEASE_EXPIRES_AT" -eq $((LEASE_ISSUED_AT + LEASE_TTL_SECONDS))
          NOW_EPOCH="$(date -u +%s)"
          test "$NOW_EPOCH" -ge "$LEASE_ISSUED_AT"
          test "$NOW_EPOCH" -lt "$LEASE_EXPIRES_AT"
          test $((LEASE_EXPIRES_AT - NOW_EPOCH)) -ge "$LEASE_MIN_REMAINING_SECONDS"
          EXPECTED_LEASE_ID="$(printf '%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n' \\
            "$GITHUB_REPOSITORY" "$GITHUB_REPOSITORY_ID" ".github/workflows/profile-stats.yml" \\
            "$GITHUB_WORKFLOW_REF" "$GITHUB_WORKFLOW_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" \\
            "$LEASE_BASE_SHA" "$LEASE_CANDIDATE_ID" "$LEASE_ISSUED_AT" "$LEASE_EXPIRES_AT" | sha256sum | cut -d' ' -f1)"
          test "$EXPECTED_LEASE_ID" = "$LEASE_ID"

      - name: Dispatch exact Spotlight reconciliation workflow
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          gh api --method POST \\
            "repos/${GITHUB_REPOSITORY}/actions/workflows/spotlight-link-sync.yml/dispatches" \\
            -f ref=main
'''
IMMUTABLE_ANCHOR = (
    '          fi\n\n'
    '          CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"\n'
    '          test "$(jq \'.parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"\n'
)
IMMUTABLE_PROJECTED = (
    '          fi\n\n'
    '          # Validate the complete candidate object before first publication or retry reuse.\n'
    '          CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"\n'
    '          test "$(jq \'.parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"\n'
)
CURRENT_MAIN_CAPTURE = (
    '          CURRENT_MAIN_SHA="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)"\n'
    '          test "$CURRENT_MAIN_SHA" = "$MERGE_SHA"\n'
)
LEGACY_MAIN_PROOF = (
    '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$MERGE_SHA"\n'
)
CURRENT_MAIN_OUTPUT = '      current_main_sha: ${{ steps.merge.outputs.current_main_sha }}\n'
CURRENT_MAIN_ECHO = '          echo "current_main_sha=$CURRENT_MAIN_SHA" >> "$GITHUB_OUTPUT"\n'
SPOTLIGHT_REVIEWER_STEWARDSHIP = "          REQUESTED=\"$(jq '[.requested_reviewers[]? | select(.login == \"portyu9\")] | length' <<<\"$PR\")\"\n          [[ \"$REQUESTED\" =~ ^[0-9]+$ ]]\n          if [ \"$REQUESTED\" = \"0\" ]; then\n            gh api --method POST \"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers\" \\\n              -f 'reviewers[]=portyu9' > requested-reviewer.json\n            test \"$(jq '[.requested_reviewers[]? | select(.login == \"portyu9\")] | length' requested-reviewer.json)\" = \"1\"\n          fi\n"
SPOTLIGHT_APPROVE_PERMISSIONS = "    permissions:\n      contents: read\n      actions: write\n      pull-requests: write\n"
LEGACY_SPOTLIGHT_APPROVE_PERMISSIONS = "    permissions:\n      contents: read\n      actions: write\n"
SPOTLIGHT_APPROVAL_AUDIT = "          PRS=\"$(gh api \"repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${CANDIDATE_BRANCH}&base=main&per_page=10\")\"\n          test \"$(jq 'length' <<<\"$PRS\")\" = \"1\"\n          PR_NUMBER=\"$(jq -r '.[0].number' <<<\"$PRS\")\"\n          [[ \"$PR_NUMBER\" =~ ^[1-9][0-9]*$ ]]\n          APPROVAL_MARKER=\"<!-- portyu9-automation-approval:v1 head=${HEAD_SHA} -->\"\n          COMMENTS=\"$(gh api --paginate --slurp \"repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100\")\"\n          if ! jq -e --arg marker \"$APPROVAL_MARKER\" '[.[][] | select(.body | contains($marker))] | length > 0' <<<\"$COMMENTS\" >/dev/null; then\n            printf -v APPROVAL_BODY '%s\\n%s' \"$APPROVAL_MARKER\" \"Automation-approved: the exact Spotlight head \\`${HEAD_SHA}\\` passed all three protected PR workflows. An exact-head APPROVED review by @portyu9 is required before terminal merge; no manual workflow approval is required. Continuing through the governed merge-authorization and attestation path.\"\n            gh api --method POST \"repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments\" -f body=\"$APPROVAL_BODY\" > approval-comment.json\n            test \"$(jq -r .body approval-comment.json | grep -Fxc \"$APPROVAL_BODY\")\" = \"1\"\n          fi\n\n"
SPOTLIGHT_EXACT_HEAD_REVIEW_PROOF = """          REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"
          REVIEWS="$(gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100")"
          PORTYU9_APPROVAL_COUNT="$(jq --arg head "$HEAD_SHA" --arg marker "$REVIEW_MARKER" '[.[][] | select(.user.login == "portyu9" and .state == "APPROVED" and .commit_id == $head and ((.body // "") | contains($marker)))] | length' <<<"$REVIEWS")"
          [[ "$PORTYU9_APPROVAL_COUNT" =~ ^[0-9]+$ ]]
          test "$PORTYU9_APPROVAL_COUNT" -ge 1 || {
            echo "ERROR: exact-base/head marker-bound APPROVED review by portyu9 is required before autonomous Spotlight merge." >&2
            exit 1
          }
          echo "Spotlight terminal stage: exact-base-head-portyu9-approval-verified" >&2

"""



def strip_item11_tail(workflow: str, label: str) -> str:
    projected = ORIGINAL_STRIP_ADR_TAIL(workflow, label)
    if label != "Profile Stats":
        return projected
    marker = "  dispatch:\n"
    if projected.count(marker) != 1:
        raise ValueError("Profile Stats item-9 dispatcher projection cannot isolate dispatch job")
    return projected[:projected.index(marker)] + LEGACY_PROFILE_DISPATCH


def project_item9_sync_with_marker(sync: str) -> str:
    projected = ORIGINAL_PROJECT_ITEM9_SYNC(sync)
    if projected.count(SPOTLIGHT_REVIEWER_STEWARDSHIP) != 1:
        raise ValueError("Spotlight item-9 reviewer-stewardship projection anchor changed")
    projected = projected.replace(SPOTLIGHT_REVIEWER_STEWARDSHIP, "", 1)
    if projected.count(SPOTLIGHT_APPROVE_PERMISSIONS) != 1:
        raise ValueError("Spotlight item-9 approval-permission projection anchor changed")
    projected = projected.replace(
        SPOTLIGHT_APPROVE_PERMISSIONS, LEGACY_SPOTLIGHT_APPROVE_PERMISSIONS, 1
    )
    if projected.count(SPOTLIGHT_APPROVAL_AUDIT) != 1:
        raise ValueError("Spotlight item-9 approval-audit projection anchor changed")
    projected = projected.replace(SPOTLIGHT_APPROVAL_AUDIT, "", 1)
    if projected.count(SPOTLIGHT_EXACT_HEAD_REVIEW_PROOF) != 1:
        raise ValueError("Spotlight item-9 marker-bound review projection anchor changed")
    projected = projected.replace(SPOTLIGHT_EXACT_HEAD_REVIEW_PROOF, "", 1)
    if projected.count(IMMUTABLE_ANCHOR) != 1:
        raise ValueError("Spotlight item-9 immutable-candidate projection anchor changed")
    projected = projected.replace(IMMUTABLE_ANCHOR, IMMUTABLE_PROJECTED, 1)
    if projected.count(CURRENT_MAIN_CAPTURE) != 1:
        raise ValueError("Spotlight item-9 current-main observation projection changed")
    projected = projected.replace(CURRENT_MAIN_CAPTURE, LEGACY_MAIN_PROOF, 1)
    if projected.count(CURRENT_MAIN_OUTPUT) != 1 or projected.count(CURRENT_MAIN_ECHO) != 1:
        raise ValueError("Spotlight item-9 current-main output projection changed")
    projected = projected.replace(CURRENT_MAIN_OUTPUT, "", 1)
    projected = projected.replace(CURRENT_MAIN_ECHO, "", 1)
    return projected


core.strip_adr_tail = strip_item11_tail
core.project_item9_sync = project_item9_sync_with_marker


def validate_policy_cross_contracts_with_trusted_admission(
    policy: dict[str, object], profile_stats: str, sync: str
) -> None:
    item9 = core.item9
    ruleset_relative = policy["rulesetContract"]
    item9.require(isinstance(ruleset_relative, str), "Automation Policy IR ruleset contract path is malformed")
    ruleset_path = item9.ROOT / ruleset_relative
    item9.require(ruleset_path.is_file() and not ruleset_path.is_symlink(),
                  "Automation Policy IR ruleset contract is missing or aliased")
    try:
        rulesets = item9.automation_policy.strict_json_loads(ruleset_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        item9.fail(f"Automation Policy IR ruleset cross-contract JSON is invalid: {exc}")
    item9.require(isinstance(rulesets, dict) and rulesets.get("repository") == policy["repository"],
                  "Automation Policy IR repository differs from ruleset desired state")
    main = rulesets.get("rulesets", {}).get("Protect Main", {})
    required = main.get("rules", {}).get("required_status_checks", {})
    item9.require(required.get("integration_id") == policy["githubActionsAppId"],
                  "Automation Policy IR GitHub Actions app id differs from Protect Main")
    policy_contexts = [entry["context"] for entry in policy["requiredChecks"]]
    item9.require(required.get("contexts") == policy_contexts,
                  "Automation Policy IR required-check order/identity differs from Protect Main")
    generated = rulesets.get("rulesets", {}).get("Protect generated", {})
    item9.require(generated.get("include") == [f"refs/heads/{policy['branches']['generated']}"],
                  "Automation Policy IR generated branch differs from Protect generated")

    main_branch = policy["branches"]["main"]
    generated_branch = policy["branches"]["generated"]
    candidate_prefix = policy["branches"]["spotlightCandidatePrefix"]
    item9.require(f'BOT_BRANCH_PREFIX: "{candidate_prefix}"' in sync,
                  "Automation Policy IR Spotlight candidate prefix differs from workflow authority")
    item9.require('BOT_BRANCH: "automation/spotlight-links"' not in sync,
                  "Spotlight workflow retained the retired shared mutable bot branch")
    item9.require(f"ref: {generated_branch}" in sync,
                  "Automation Policy IR generated branch differs from Spotlight evidence checkout")
    item9.require(f"refs/heads/{main_branch}" in sync,
                  "Automation Policy IR main branch differs from Spotlight source authority")
    item9.require(f"refs/heads/{main_branch}" in profile_stats,
                  "Automation Policy IR main branch differs from profile publication freshness authority")
    item9.require(f"HEAD:{generated_branch}" in profile_stats,
                  "Automation Policy IR generated branch differs from terminal publication target")

    merge = item9.core.job_block(sync, "merge", None)
    trusted_context = "trusted-capability-admission"
    item9.require(policy_contexts.count(trusted_context) == 1,
                  "Automation Policy IR must contain exactly one trusted capability-admission required check")
    for context in policy_contexts:
        if context != trusted_context:
            item9.require(context in merge,
                          f"Automation Policy IR required check is not consumed by Spotlight terminal merge: {context}")

    prepare_path = item9.ROOT / "scripts/prepare-spotlight-merge-authorization.py"
    builder_path = item9.ROOT / "scripts/spotlight_merge_authorization.py"
    schema_path = item9.ROOT / ".github/attestation/spotlight-merge-authorization-v1.schema.json"
    for path in (prepare_path, builder_path, schema_path):
        item9.require(path.is_file() and not path.is_symlink(),
                      f"trusted capability-admission consumption input is missing or aliased: {path.relative_to(item9.ROOT)}")
    prepare = prepare_path.read_text(encoding="utf-8")
    builder = builder_path.read_text(encoding="utf-8")
    schema = schema_path.read_text(encoding="utf-8")
    authorize = item9.core.job_block(sync, "authorize", "authorize_attest")
    signer = item9.core.job_block(sync, "authorize_attest", "merge")

    for fragment in (
        'TRUSTED_CHECK_NAME = "trusted-capability-admission"',
        'TRUSTED_WORKFLOW_NAME = "Capability admission"',
        'event=pull_request_target',
        '"trustedAdmission"',
    ):
        item9.require(fragment in prepare,
                      f"Spotlight read-only authorization lost trusted admission proof: {fragment}")
    for fragment in (
        '"trustedAdmission"',
        '"pull_request_target"',
        '"trusted-capability-admission"',
        'server-side required-check enforcement',
    ):
        item9.require(fragment in builder,
                      f"Spotlight certificate builder lost trusted admission binding: {fragment}")
    for fragment in (
        '"trustedAdmission"',
        '"pull_request_target"',
        '"trusted-capability-admission"',
        '"appId": {"const": 15368}',
    ):
        item9.require(fragment in schema,
                      f"Spotlight certificate schema lost trusted admission binding: {fragment}")
    item9.require(
        "python3 source/scripts/prepare-spotlight-merge-authorization.py merge-authorization-state.json" in authorize
        and "python3 source/scripts/build-spotlight-merge-authorization.py" in authorize,
        "Spotlight trusted admission proof is not rooted in the read-only authorization job",
    )
    item9.require(
        "uses: actions/attest@" in signer
        and "predicate-path: merge-authorization-input/spotlight-merge-authorization.json" in signer,
        "Spotlight trusted admission proof is not sealed by the merge-authorization signer",
    )
    item9.require(
        "needs.authorize.result == 'success' && needs.authorize_attest.result == 'success'" in merge
        and 'gh attestation verify "$SUBJECT"' in merge
        and ".verificationResult.statement" in merge,
        "Spotlight terminal merge does not cryptographically consume the trusted admission certificate",
    )


core.item9.validate_policy_cross_contracts = validate_policy_cross_contracts_with_trusted_admission


def main() -> int:
    return core.main()


if __name__ == "__main__":
    raise SystemExit(main())
