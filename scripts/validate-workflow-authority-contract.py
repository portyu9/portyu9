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
)
IMMUTABLE_PROJECTED = (
    '          fi\n\n'
    '          # Validate the complete candidate object before first publication or retry reuse.\n'
    '          CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"\n'
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
SPOTLIGHT_APPROVAL_AUDIT = "          PRS=\"$(gh api \"repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${CANDIDATE_BRANCH}&base=main&per_page=10\")\"\n          test \"$(jq 'length' <<<\"$PRS\")\" = \"1\"\n          test \"$(jq -r '.[0].number' <<<\"$PRS\")\" = \"$PR_NUMBER\"\n          APPROVAL_MARKER=\"<!-- portyu9-automation-approval:v1 head=${HEAD_SHA} -->\"\n          gh api --paginate --slurp \\\n            \"repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100\" \\\n            > \"$RUNNER_TEMP/spotlight-approval-comment-pages.json\"\n          jq -ce \\\n            --arg repo \"$GITHUB_REPOSITORY\" \\\n            --argjson pr \"$PR_NUMBER\" \\\n            --arg marker \"$APPROVAL_MARKER\" '\n              if type != \"array\" or length < 1 or length > 20 then\n                error(\"Spotlight automation-approval comment pages must be a bounded slurped page array\")\n              elif any(.[]; type != \"array\" or length > 100) then\n                error(\"Spotlight automation-approval comment page shape changed\")\n              elif (length > 1 and any(.[0:-1][]; length != 100)) then\n                error(\"Spotlight automation-approval comment pagination is incomplete\")\n              elif any(.[][];\n                (type != \"object\") or\n                ((.id | type) != \"number\") or ((.id | floor) != .id) or (.id <= 0) or\n                (.issue_url != (\"https://api.github.com/repos/\" + $repo + \"/issues/\" + ($pr | tostring))) or\n                (.url != (\"https://api.github.com/repos/\" + $repo + \"/issues/comments/\" + (.id | tostring))) or\n                ((.body | type) != \"string\") or\n                ((.user | type) != \"object\") or\n                ((.user.login | type) != \"string\") or\n                ((.user.login | length) == 0) or\n                ((.html_url | type) != \"string\") or\n                ((.html_url | length) == 0)\n              ) then\n                error(\"Spotlight automation-approval comment item schema changed\")\n              elif ([.[][] | .id] | length) != ([.[][] | .id] | unique | length) then\n                error(\"Spotlight automation-approval comment ids are not unique\")\n              else\n                [.[][] | {id,login:.user.login,body}] as $comments\n                | [$comments[] | select(.login == \"github-actions[bot]\" and (.body | contains($marker)))] as $matches\n                | if ($matches | length) > 1 then\n                    error(\"duplicate trusted Spotlight automation-approval comments exist\")\n                  else\n                    {\n                      exists:(($matches | length) == 1),\n                      commentId:(if ($matches | length) == 1 then $matches[0].id else null end),\n                      prNumber:$pr,\n                      repository:$repo,\n                      marker:$marker\n                    }\n                  end\n              end\n            ' \"$RUNNER_TEMP/spotlight-approval-comment-pages.json\" \\\n            > \"$RUNNER_TEMP/spotlight-approval-comment-evidence.json\"\n          APPROVAL_COMMENT_EXISTS=\"$(jq -r .exists \"$RUNNER_TEMP/spotlight-approval-comment-evidence.json\")\"\n          test \"$APPROVAL_COMMENT_EXISTS\" = \"true\" -o \"$APPROVAL_COMMENT_EXISTS\" = \"false\"\n          if [ \"$APPROVAL_COMMENT_EXISTS\" = \"false\" ]; then\n            printf -v APPROVAL_BODY '%s\\n%s' \"$APPROVAL_MARKER\" \"Automation-approved: the exact Spotlight head \\`${HEAD_SHA}\\` passed all three protected PR workflows. An exact-head APPROVED review by @portyu9 is required before terminal merge; no manual workflow approval is required. Continuing through the governed merge-authorization and attestation path.\"\n            gh api --method POST \"repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments\" \\\n              -f body=\"$APPROVAL_BODY\" \\\n              > \"$RUNNER_TEMP/spotlight-approval-comment-created.json\"\n            jq -ce \\\n              --arg repo \"$GITHUB_REPOSITORY\" \\\n              --argjson pr \"$PR_NUMBER\" \\\n              --arg body \"$APPROVAL_BODY\" '\n                if type != \"object\" then\n                  error(\"created Spotlight automation-approval comment must be an object\")\n                elif ((.id | type) != \"number\") or ((.id | floor) != .id) or (.id <= 0) then\n                  error(\"created Spotlight automation-approval comment id is invalid\")\n                elif .issue_url != (\"https://api.github.com/repos/\" + $repo + \"/issues/\" + ($pr | tostring)) then\n                  error(\"created Spotlight automation-approval comment issue URL mismatch\")\n                elif .url != (\"https://api.github.com/repos/\" + $repo + \"/issues/comments/\" + (.id | tostring)) then\n                  error(\"created Spotlight automation-approval comment URL mismatch\")\n                elif .body != $body then\n                  error(\"created Spotlight automation-approval comment body mismatch\")\n                elif ((.user | type) != \"object\") or .user.login != \"github-actions[bot]\" then\n                  error(\"created Spotlight automation-approval comment actor mismatch\")\n                elif ((.html_url | type) != \"string\") or ((.html_url | length) == 0) then\n                  error(\"created Spotlight automation-approval comment html_url is invalid\")\n                else\n                  {id:.id,prNumber:$pr,repository:$repo,actor:.user.login}\n                end\n              ' \"$RUNNER_TEMP/spotlight-approval-comment-created.json\" \\\n              > \"$RUNNER_TEMP/spotlight-approval-comment-created-normalized.json\"\n            test \"$(jq -r .actor \"$RUNNER_TEMP/spotlight-approval-comment-created-normalized.json\")\" = \"github-actions[bot]\"\n            test \"$(jq -r .prNumber \"$RUNNER_TEMP/spotlight-approval-comment-created-normalized.json\")\" = \"$PR_NUMBER\"\n          fi\n\n"
SPOTLIGHT_PRE_CONVERGENCE_REVIEW_WAKE = """          gh api --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/bot-pr-user-approval.yml/dispatches" \\
            -f ref=main >/dev/null
          echo "Dispatched exact pre-convergence portyu9 review evaluation from trusted main."

"""
SPOTLIGHT_PRE_CONVERGENCE_REVIEW_WAIT = """          REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"
          PORTYU9_APPROVAL_COUNT=0
          for REVIEW_ATTEMPT in $(seq 1 24); do
            REVIEW_PAGES="$(gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100")"
            jq -e '
              (type == "array") and (length >= 1) and (length <= 20) and
              (all(.[]; type == "array" and length <= 100)) and
              (all(.[0:-1][]; length == 100)) and
              (all(.[][];
                type == "object" and
                (.id | type == "number" and . == floor and . > 0) and
                (.user | type == "object" and (.login | type == "string" and length > 0)) and
                (.state | type == "string" and
                  (. == "APPROVED" or . == "CHANGES_REQUESTED" or . == "COMMENTED" or . == "DISMISSED" or . == "PENDING")) and
                has("commit_id") and
                (.commit_id == null or (.commit_id | type == "string" and test("^[0-9a-f]{40}$"))) and
                has("body") and
                (.body == null or (.body | type == "string"))
              )) and
              (([.[][] | .id] | length) == ([.[][] | .id] | unique | length))
            ' <<<"$REVIEW_PAGES" >/dev/null || {
              echo "ERROR: malformed or incomplete paginated pull-review evidence." >&2
              exit 1
            }
            REVIEWS="$(jq -c '[.[][]]' <<<"$REVIEW_PAGES")"
            PORTYU9_APPROVAL_COUNT="$(jq --arg head "$HEAD_SHA" --arg marker "$REVIEW_MARKER" '[.[] | select(.user.login == "portyu9" and .state == "APPROVED" and .commit_id == $head and ((.body // "") | contains($marker)))] | length' <<<"$REVIEWS")"
            [[ "$PORTYU9_APPROVAL_COUNT" =~ ^[0-9]+$ ]]
            if [ "$PORTYU9_APPROVAL_COUNT" -ge 1 ]; then
              break
            fi
            if [ "$REVIEW_ATTEMPT" -lt 24 ]; then
              sleep 5
            fi
          done
          test "$PORTYU9_APPROVAL_COUNT" -ge 1 || {
            echo "ERROR: exact-base/head portyu9 review did not materialize after the pre-convergence dispatch." >&2
            exit 1
          }
          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"
          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha)" = "$HEAD_SHA"
          PR_AFTER_REVIEW="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"
          test "$(jq -r .state <<<"$PR_AFTER_REVIEW")" = "open"
          test "$(jq -r .base.sha <<<"$PR_AFTER_REVIEW")" = "$BASE_SHA"
          test "$(jq -r .head.sha <<<"$PR_AFTER_REVIEW")" = "$HEAD_SHA"
          echo "Observed exact-base/head marker-bound portyu9 approval before merge authorization."

"""

SPOTLIGHT_EXACT_HEAD_REVIEW_PROOF = """          REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"
          REVIEW_PAGES="$(gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100")"
          jq -e '
            (type == "array") and (length >= 1) and (length <= 20) and
            (all(.[]; type == "array" and length <= 100)) and
            (all(.[0:-1][]; length == 100)) and
            (all(.[][];
              type == "object" and
              (.id | type == "number" and . == floor and . > 0) and
              (.user | type == "object" and (.login | type == "string" and length > 0)) and
              (.state | type == "string" and
                (. == "APPROVED" or . == "CHANGES_REQUESTED" or . == "COMMENTED" or . == "DISMISSED" or . == "PENDING")) and
              has("commit_id") and
              (.commit_id == null or (.commit_id | type == "string" and test("^[0-9a-f]{40}$"))) and
              has("body") and
              (.body == null or (.body | type == "string"))
            )) and
            (([.[][] | .id] | length) == ([.[][] | .id] | unique | length))
          ' <<<"$REVIEW_PAGES" >/dev/null || {
            echo "ERROR: malformed or incomplete paginated pull-review evidence." >&2
            exit 1
          }
          REVIEWS="$(jq -c '[.[][]]' <<<"$REVIEW_PAGES")"
          PORTYU9_APPROVAL_COUNT="$(jq --arg head "$HEAD_SHA" --arg marker "$REVIEW_MARKER" '[.[] | select(.user.login == "portyu9" and .state == "APPROVED" and .commit_id == $head and ((.body // "") | contains($marker)))] | length' <<<"$REVIEWS")"
          LATEST_MANUAL_DECISIVE_STATE="$(jq -r --arg head "$HEAD_SHA" --arg marker "$REVIEW_MARKER" '[.[] | select(.user.login == "portyu9" and .commit_id == $head and (.state == "APPROVED" or .state == "CHANGES_REQUESTED") and (((.body // "") | contains($marker)) | not))] | sort_by(.id) | if length == 0 then "" else .[-1].state end' <<<"$REVIEWS")"
          [[ "$PORTYU9_APPROVAL_COUNT" =~ ^[0-9]+$ ]]
          test "$PORTYU9_APPROVAL_COUNT" = "1" || {
            echo "ERROR: exactly one exact-base/head marker-bound APPROVED review by portyu9 is required before autonomous Spotlight merge." >&2
            exit 1
          }
          if [ "$LATEST_MANUAL_DECISIVE_STATE" = "CHANGES_REQUESTED" ]; then
            echo "ERROR: latest manual exact-head portyu9 review requests changes; autonomous Spotlight merge is vetoed." >&2
            exit 1
          fi
          echo "Spotlight terminal stage: exact-base-head-portyu9-approval-and-manual-veto-verified" >&2

"""



def strip_item11_tail(workflow: str, label: str) -> str:
    projected = ORIGINAL_STRIP_ADR_TAIL(workflow, label)
    if label != "Profile Stats":
        return projected
    marker = "  dispatch:\n"
    if projected.count(marker) != 1:
        raise ValueError("Profile Stats item-9 dispatcher projection cannot isolate dispatch job")
    return projected[:projected.index(marker)] + LEGACY_PROFILE_DISPATCH


def project_native_review_gate_to_legacy_order(sync: str) -> str:
    """Project the item-44 post-review native gate back to the frozen pre-item-44 ordering."""
    native_expected = (
        '{name:"trusted-governed-bot-review",check_suite_id:$profile,status:"completed",'
        'conclusion:"success",head_sha:$head},'
    )
    native_selector = (
        ' or .name == "trusted-governed-bot-review"'
    )
    core.require(sync.count(native_expected) == 1,
            "Spotlight item-44 projection lost the exact native review-gate expected-check entry")
    core.require(sync.count(native_selector) == 1,
            "Spotlight item-44 projection lost the exact native review-gate selector")
    projected = sync.replace(native_expected, "", 1)
    projected = projected.replace(native_selector, "", 1)
    core.require(
        projected.count('Spotlight terminal stage: required-checks-and-native-review-gate-verified') == 1,
        "Spotlight item-44 projection lost the post-review native-gate stage marker",
    )
    projected = projected.replace(
        'Spotlight terminal stage: required-checks-and-native-review-gate-verified',
        'Spotlight terminal stage: required-checks-verified',
        1,
    )

    checks_start_marker = (
        '          CHECKS="$(gh api -H \'Accept: application/vnd.github+json\' '
        '"repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs?filter=latest&per_page=100")"\n'
    )
    checks_end_marker = '          echo "Spotlight terminal stage: required-checks-verified" >&2\n\n'
    core.require(projected.count(checks_start_marker) == 1 and projected.count(checks_end_marker) == 1,
            "Spotlight item-44 projection cannot isolate the canonical required-check proof")
    checks_start = projected.index(checks_start_marker)
    checks_end = projected.index(checks_end_marker, checks_start) + len(checks_end_marker)
    checks_block = projected[checks_start:checks_end]
    projected = projected[:checks_start] + projected[checks_end:]

    certificate_marker = '          CERTIFICATE="merge-authorization-input/spotlight-merge-authorization.json"\n'
    core.require(projected.count(certificate_marker) == 1,
            "Spotlight item-44 projection cannot restore the pre-certificate required-check proof")
    projected = projected.replace(certificate_marker, checks_block + certificate_marker, 1)

    roots_block = (
        '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"\n'
        '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated" --jq .object.sha)" = "$GENERATED_SHA"\n'
        '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha)" = "$HEAD_SHA"\n'
        '          echo "Spotlight terminal stage: pre-merge-roots-verified" >&2\n\n'
    )
    core.require(projected.count(roots_block) == 1,
            "Spotlight item-44 projection cannot isolate the relocated pre-merge root proof")
    projected = projected.replace(roots_block, "", 1)
    review_marker = '          REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"\n'
    merge_start = projected.index("  merge:\n")
    review_pos = projected.index(review_marker, merge_start)
    core.require(review_pos > merge_start,
            "Spotlight item-44 projection cannot restore the legacy pre-review root proof")
    projected = projected[:review_pos] + roots_block + projected[review_pos:]
    return projected



def project_ancestry_reconcile_to_same_base(sync: str) -> str:
    """Validate the ancestry-read overlay, then project it to accepted #910 authority."""
    counter = '          ANCESTRY_PROVEN_STALE=0\n'
    core.require(sync.count(counter) == 1,
                 "Spotlight authority projection cannot isolate ancestry stale counter")
    sync = sync.replace(counter, "", 1)

    start_marker = '            SAME_BASE_SUPERSEDED=false\n'
    end_marker = '            COMMITTER_DATE="$(jq -r .committer.date <<<"$CANDIDATE_COMMIT")"\n'
    core.require(sync.count(start_marker) == 1 and sync.count(end_marker) == 1,
                 "Spotlight authority projection cannot isolate ancestry classification")
    start = sync.index(start_marker)
    end = sync.index(end_marker, start)
    block = sync[start:end]
    for fragment in (
        '            ANCESTRY_PROVEN_SUPERSEDED=false\n',
        '              ANCESTRY_COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${PARENT_SHA}...${BASE_SHA}")"\n',
        '              jq -e --arg parent "$PARENT_SHA" --arg base "$BASE_SHA" \'\n',
        '                ANCESTRY_PROVEN_SUPERSEDED=true\n',
    ):
        core.require(fragment in block,
                     f"Spotlight authority ancestry overlay lost reviewed fragment: {fragment}")
    core.require(block.count('gh api ') == 1 and '--method ' not in block,
                 "Spotlight ancestry overlay must add exactly one read-only gh api surface")
    accepted = (
        '            SAME_BASE_SUPERSEDED=false\n'
        '            if [ "$PARENT_SHA" = "$BASE_SHA" ]; then\n'
        '              SAME_BASE_SUPERSEDED=true\n'
        '            fi\n\n'
    )
    sync = sync[:start] + accepted + sync[end:]

    current_guard = (
        'if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ] &&\n'
        '               [ "$SAME_BASE_SUPERSEDED" != "true" ] &&\n'
        '               [ "$ANCESTRY_PROVEN_SUPERSEDED" != "true" ]; then'
    )
    accepted_guard = (
        'if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ] && '
        '[ "$SAME_BASE_SUPERSEDED" != "true" ]; then'
    )
    core.require(sync.count(current_guard) == 1,
                 "Spotlight authority projection cannot isolate ancestry age guard")
    sync = sync.replace(current_guard, accepted_guard, 1)

    cleanup = (
        '            if [ "$ANCESTRY_PROVEN_SUPERSEDED" = "true" ]; then\n'
        '              ANCESTRY_PROVEN_STALE=$((ANCESTRY_PROVEN_STALE + 1))\n'
        '            fi\n'
    )
    core.require(sync.count(cleanup) == 1,
                 "Spotlight authority projection cannot isolate ancestry cleanup counter")
    sync = sync.replace(cleanup, "", 1)

    summary = (
        '            echo "- ancestry-proven old-base candidates cleaned immediately: '
        '**$ANCESTRY_PROVEN_STALE**"\n'
    )
    young = (
        '            echo "- unproven/divergent candidates below 30-minute stale floor preserved: '
        '**$PRESERVED_YOUNG**"\n'
    )
    accepted_young = (
        '            echo "- different-base candidates below 30-minute stale floor preserved: '
        '**$PRESERVED_YOUNG**"\n'
    )
    core.require(sync.count(summary) == 1 and sync.count(young) == 1,
                 "Spotlight authority projection cannot isolate ancestry summary")
    sync = sync.replace(summary, "", 1)
    sync = sync.replace(young, accepted_young, 1)
    return sync


def project_item9_sync_with_marker(sync: str) -> str:
    reviewer_dispatch = 'actions/workflows/bot-pr-user-approval.yml/dispatches'
    reviewer_marker = 'Dispatched exact pre-convergence portyu9 review evaluation from trusted main.'
    capability_dispatch = 'actions/workflows/capability-admission.yml/dispatches'
    convergence_anchor = '          APPROVAL_REQUESTED_RUN_IDS=""\n          for attempt in $(seq 1 60); do\n'
    core.require(sync.count(reviewer_dispatch) == 1 and sync.count(reviewer_marker) == 1,
            "Spotlight must contain exactly one pre-convergence reviewer wake")
    core.require(sync.count(capability_dispatch) == 1 and sync.count(convergence_anchor) == 1,
            "Spotlight pre-convergence reviewer ordering anchors changed")
    core.require(
        sync.index(capability_dispatch) < sync.index(reviewer_dispatch) < sync.index(convergence_anchor),
        "Spotlight reviewer wake must stay after trusted admission dispatch and before whole-workflow convergence",
    )

    sync = project_ancestry_reconcile_to_same_base(sync)
    sync = project_native_review_gate_to_legacy_order(sync)
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
    if projected.count(SPOTLIGHT_PRE_CONVERGENCE_REVIEW_WAKE) != 1:
        raise ValueError("Spotlight item-9 pre-convergence review-wake projection anchor changed")
    projected = projected.replace(SPOTLIGHT_PRE_CONVERGENCE_REVIEW_WAKE, "", 1)
    if projected.count(SPOTLIGHT_PRE_CONVERGENCE_REVIEW_WAIT) != 1:
        raise ValueError("Spotlight item-9 pre-convergence review-wait projection anchor changed")
    projected = projected.replace(SPOTLIGHT_PRE_CONVERGENCE_REVIEW_WAIT, "", 1)
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
        'trusted_run.get("event") == "workflow_dispatch"',
        'trusted_run.get("head_branch") == "main"',
        'trusted_external_pattern = re.compile(',
        'check-runs?filter=all&per_page=100',
        'trusted_matches.sort(key=lambda check: check["id"], reverse=True)',
        'candidate_run.get("event") == "workflow_dispatch"',
        'candidate_run.get("head_branch") == "main"',
        'candidate_run.get("head_sha") == base',
        'Spotlight trusted workflow-dispatch admission proof did not materialize',
        'trusted_run_attempt = int(trusted_identity_match.group(2))',
        '"trustedAdmission"',
    ):
        item9.require(fragment in prepare,
                      f"Spotlight read-only authorization lost trusted admission proof: {fragment}")
    for fragment in (
        '"trustedAdmission"',
        '"workflow_dispatch"',
        '"trusted-capability-admission"',
        'f"spotlight-admission:{workflow[\'runId\']}:{workflow[\'runAttempt\']}:{pr_number}:{base}:{head}"',
        'server-side required-check enforcement',
    ):
        item9.require(fragment in builder,
                      f"Spotlight certificate builder lost trusted admission binding: {fragment}")
    for fragment in (
        '"trustedAdmission"',
        '"workflow_dispatch"',
        '"trusted-capability-admission"',
        '"externalId"',
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
