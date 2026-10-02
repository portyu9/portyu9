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
ORIGINAL_VALIDATE_ITEM10_AUTHORITY = core.validate_item10_authority
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

HARDENED_RUN_BRANCH_PROOF = '                  (.head_branch != $branch) or'
LEGACY_RUN_BRANCH_PROOF = 'test "$(jq -r .head_branch <<<"$RUN")" = "$CANDIDATE_BRANCH"'
CURRENT_MAIN_CAPTURE = (
    '          CURRENT_MAIN_SHA="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)"\n'
    '          test "$CURRENT_MAIN_SHA" = "$MERGE_SHA"\n'
)
LEGACY_MAIN_PROOF = (
    '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$MERGE_SHA"\n'
)
CURRENT_MAIN_OUTPUT = '      current_main_sha: ${{ steps.merge.outputs.current_main_sha }}\n'
CURRENT_MAIN_ECHO = '          echo "current_main_sha=$CURRENT_MAIN_SHA" >> "$GITHUB_OUTPUT"\n'

SPOTLIGHT_SOURCE_EPOCH_MAIN_SCHEMA = """            jq -e --arg ref "refs/heads/main" '
              (type == "object") and
              (.ref | type == "string" and . == $ref) and
              (.object | type == "object" and
                (.type | type == "string" and . == "commit") and
                (.sha | type == "string" and test("^[0-9a-f]{40}$")) and
                (.url | type == "string" and length > 0))
            ' <<<"$main_response" >/dev/null || return 1
"""
SPOTLIGHT_SOURCE_EPOCH_GENERATED_SCHEMA = """            jq -e --arg ref "refs/heads/generated" '
              (type == "object") and
              (.ref | type == "string" and . == $ref) and
              (.object | type == "object" and
                (.type | type == "string" and . == "commit") and
                (.sha | type == "string" and test("^[0-9a-f]{40}$")) and
                (.url | type == "string" and length > 0))
            ' <<<"$generated_response" >/dev/null || return 1
"""

SPOTLIGHT_MERGE_HTTP_STATUS = (
    '          MERGE_HTTP_RESPONSE="$(gh api --include --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge" --input merge.json)"\n'
    '          MERGE_STATUS_LINE="$(head -n 1 <<<"$MERGE_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
    '          [[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {\n'
    '            echo "ERROR: Spotlight terminal merge returned unexpected status: ${MERGE_STATUS_LINE}" >&2\n'
    '            exit 1\n'
    '          }\n'
    '          RESULT="$(sed \'1,/^[[:space:]]*$/d\' <<<"$MERGE_HTTP_RESPONSE")"\n'
)
SPOTLIGHT_MERGE_LEGACY = (
    '          RESULT="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge" --input merge.json)"\n'
)

SPOTLIGHT_APPROVAL_COMMENT_STATUS = (
    '            APPROVAL_COMMENT_HTTP_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \\\n'
    '              -f body="$APPROVAL_BODY")"\n'
    '            APPROVAL_COMMENT_STATUS_LINE="$(head -n 1 <<<"$APPROVAL_COMMENT_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
    '            [[ "$APPROVAL_COMMENT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
    '              echo "ERROR: Spotlight automation-approval comment returned unexpected status: ${APPROVAL_COMMENT_STATUS_LINE}" >&2\n'
    '              exit 1\n'
    '            }\n'
    '            sed \'1,/^[[:space:]]*$/d\' <<<"$APPROVAL_COMMENT_HTTP_RESPONSE" > "$RUNNER_TEMP/spotlight-approval-comment-created.json"\n'
)
SPOTLIGHT_APPROVAL_COMMENT_LEGACY = (
    '            gh api --method POST "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \\\n'
    '              -f body="$APPROVAL_BODY" \\\n'
    '              > "$RUNNER_TEMP/spotlight-approval-comment-created.json"\n'
)
SPOTLIGHT_APPROVE_PERMISSIONS = "    permissions:\n      contents: read\n      actions: write\n      pull-requests: write\n"
LEGACY_SPOTLIGHT_APPROVE_PERMISSIONS = "    permissions:\n      contents: read\n      actions: write\n"
SPOTLIGHT_APPROVAL_AUDIT = "          PRS=\"$(gh api \"repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${CANDIDATE_BRANCH}&base=main&per_page=10\")\"\n          test \"$(jq 'length' <<<\"$PRS\")\" = \"1\"\n          test \"$(jq -r '.[0].number' <<<\"$PRS\")\" = \"$PR_NUMBER\"\n          APPROVAL_MARKER=\"<!-- portyu9-automation-approval:v1 head=${HEAD_SHA} -->\"\n          gh api --paginate --slurp \\\n            \"repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100\" \\\n            > \"$RUNNER_TEMP/spotlight-approval-comment-pages.json\"\n          jq -ce \\\n            --arg repo \"$GITHUB_REPOSITORY\" \\\n            --argjson pr \"$PR_NUMBER\" \\\n            --arg marker \"$APPROVAL_MARKER\" '\n              if type != \"array\" or length < 1 or length > 20 then\n                error(\"Spotlight automation-approval comment pages must be a bounded slurped page array\")\n              elif any(.[]; type != \"array\" or length > 100) then\n                error(\"Spotlight automation-approval comment page shape changed\")\n              elif (length > 1 and any(.[0:-1][]; length != 100)) then\n                error(\"Spotlight automation-approval comment pagination is incomplete\")\n              elif any(.[][];\n                (type != \"object\") or\n                ((.id | type) != \"number\") or ((.id | floor) != .id) or (.id <= 0) or\n                (.issue_url != (\"https://api.github.com/repos/\" + $repo + \"/issues/\" + ($pr | tostring))) or\n                (.url != (\"https://api.github.com/repos/\" + $repo + \"/issues/comments/\" + (.id | tostring))) or\n                ((.body | type) != \"string\") or\n                ((.user | type) != \"object\") or\n                ((.user.login | type) != \"string\") or\n                ((.user.login | length) == 0) or\n                ((.html_url | type) != \"string\") or\n                ((.html_url | length) == 0)\n              ) then\n                error(\"Spotlight automation-approval comment item schema changed\")\n              elif ([.[][] | .id] | group_by(.) | any(length > 1)) then\n                error(\"Spotlight automation-approval comment ids are not unique\")\n              else\n                [.[][] | {id,login:.user.login,body}] as $comments\n                | [$comments[] | select(.login == \"github-actions[bot]\" and (.body | contains($marker)))] as $matches\n                | if ($matches | length) > 1 then\n                    error(\"duplicate trusted Spotlight automation-approval comments exist\")\n                  else\n                    {\n                      exists:(($matches | length) == 1),\n                      commentId:(if ($matches | length) == 1 then $matches[0].id else null end),\n                      prNumber:$pr,\n                      repository:$repo,\n                      marker:$marker\n                    }\n                  end\n              end\n            ' \"$RUNNER_TEMP/spotlight-approval-comment-pages.json\" \\\n            > \"$RUNNER_TEMP/spotlight-approval-comment-evidence.json\"\n          APPROVAL_COMMENT_EXISTS=\"$(jq -r .exists \"$RUNNER_TEMP/spotlight-approval-comment-evidence.json\")\"\n          test \"$APPROVAL_COMMENT_EXISTS\" = \"true\" -o \"$APPROVAL_COMMENT_EXISTS\" = \"false\"\n          if [ \"$APPROVAL_COMMENT_EXISTS\" = \"false\" ]; then\n            printf -v APPROVAL_BODY '%s\\n%s' \"$APPROVAL_MARKER\" \"Automation-approved: the exact Spotlight head \\`${HEAD_SHA}\\` passed all three protected PR workflows. An exact-head APPROVED review by @portyu9 is required before terminal merge; no manual workflow approval is required. Continuing through the governed merge-authorization and attestation path.\"\n            gh api --method POST \"repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments\" \\\n              -f body=\"$APPROVAL_BODY\" \\\n              > \"$RUNNER_TEMP/spotlight-approval-comment-created.json\"\n            jq -ce \\\n              --arg repo \"$GITHUB_REPOSITORY\" \\\n              --argjson pr \"$PR_NUMBER\" \\\n              --arg body \"$APPROVAL_BODY\" '\n                if type != \"object\" then\n                  error(\"created Spotlight automation-approval comment must be an object\")\n                elif ((.id | type) != \"number\") or ((.id | floor) != .id) or (.id <= 0) then\n                  error(\"created Spotlight automation-approval comment id is invalid\")\n                elif .issue_url != (\"https://api.github.com/repos/\" + $repo + \"/issues/\" + ($pr | tostring)) then\n                  error(\"created Spotlight automation-approval comment issue URL mismatch\")\n                elif .url != (\"https://api.github.com/repos/\" + $repo + \"/issues/comments/\" + (.id | tostring)) then\n                  error(\"created Spotlight automation-approval comment URL mismatch\")\n                elif .body != $body then\n                  error(\"created Spotlight automation-approval comment body mismatch\")\n                elif ((.user | type) != \"object\") or .user.login != \"github-actions[bot]\" then\n                  error(\"created Spotlight automation-approval comment actor mismatch\")\n                elif ((.html_url | type) != \"string\") or ((.html_url | length) == 0) then\n                  error(\"created Spotlight automation-approval comment html_url is invalid\")\n                else\n                  {id:.id,prNumber:$pr,repository:$repo,actor:.user.login}\n                end\n              ' \"$RUNNER_TEMP/spotlight-approval-comment-created.json\" \\\n              > \"$RUNNER_TEMP/spotlight-approval-comment-created-normalized.json\"\n            test \"$(jq -r .actor \"$RUNNER_TEMP/spotlight-approval-comment-created-normalized.json\")\" = \"github-actions[bot]\"\n            test \"$(jq -r .prNumber \"$RUNNER_TEMP/spotlight-approval-comment-created-normalized.json\")\" = \"$PR_NUMBER\"\n          fi\n\n"
SPOTLIGHT_CAPABILITY_DISPATCH_STATUS = """          CAPABILITY_DISPATCH_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/capability-admission.yml/dispatches" \\
            -f ref=main)"
          CAPABILITY_DISPATCH_STATUS_LINE="$(head -n 1 <<<"$CAPABILITY_DISPATCH_RESPONSE" | tr -d '\\r')"
          [[ "$CAPABILITY_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {
            echo "ERROR: Spotlight Capability Admission dispatch returned unexpected status: ${CAPABILITY_DISPATCH_STATUS_LINE}" >&2
            exit 1
          }
"""
SPOTLIGHT_CAPABILITY_DISPATCH_LEGACY = """          gh api --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/capability-admission.yml/dispatches" \\
            -f ref=main >/dev/null
"""
SPOTLIGHT_CANDIDATE_REVIEWER_DISPATCH = """          REVIEW_DISPATCH_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/bot-pr-user-approval.yml/dispatches" \\
            -f ref=main)"
          REVIEW_DISPATCH_STATUS_LINE="$(head -n 1 <<<"$REVIEW_DISPATCH_RESPONSE" | tr -d '\\r')"
          [[ "$REVIEW_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {
            echo "ERROR: Spotlight governed-reviewer dispatch returned unexpected status: ${REVIEW_DISPATCH_STATUS_LINE}" >&2
            exit 1
          }
          echo "Dispatched bounded singleton Spotlight reviewer evaluation from trusted main."

"""
SPOTLIGHT_PRE_CONVERGENCE_REVIEW_WAKE = """          REVIEW_DISPATCH_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/bot-pr-user-approval.yml/dispatches" \\
            -f ref=main)"
          REVIEW_DISPATCH_STATUS_LINE="$(head -n 1 <<<"$REVIEW_DISPATCH_RESPONSE" | tr -d '\\r')"
          [[ "$REVIEW_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {
            echo "ERROR: Spotlight governed-reviewer dispatch returned unexpected status: ${REVIEW_DISPATCH_STATUS_LINE}" >&2
            exit 1
          }
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



def project_spotlight_readme_contents_to_legacy(sync: str) -> str:
    """Project v89 typed README Contents reads back to the frozen item-9/item-10 scalar shape."""
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
    projected = sync
    for start_marker, end_marker, legacy in overlays:
        core.require(
            projected.count(start_marker) == 1,
            f"Spotlight authority README Contents projection start anchor changed: {start_marker}",
        )
        start = projected.index(start_marker)
        end_start = projected.index(end_marker, start)
        end = end_start + len(end_marker)
        projected = projected[:start] + legacy + projected[end:]
    return projected



def project_spotlight_reconcile_shell_reads_to_raw(sync: str) -> str:
    """Project reconciler-only shell retry transport to the accepted raw-GET semantic shape."""
    reconcile_start = sync.index("  reconcile:\n")
    reconcile_end = sync.index("  budget:\n", reconcile_start)
    reconcile = sync[reconcile_start:reconcile_end]
    helper_start_marker = "          spotlight_reconcile_get() {\n"
    helper_end_marker = "          STALE_CLEANUPS_JSON='[]'\n"
    core.require(
        reconcile.count(helper_start_marker) == 1 and reconcile.count(helper_end_marker) == 1,
        "Spotlight reconciler shell-read projection anchors changed",
    )
    helper_start = reconcile.index(helper_start_marker)
    helper_end = reconcile.index(helper_end_marker, helper_start)
    projected = reconcile[:helper_start] + reconcile[helper_end:]
    overlays = (
        ('MAIN_REF_RESPONSE="$(spotlight_reconcile_get main-ref)"',
         'MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"'),
        ('GENERATED_REF_RESPONSE="$(spotlight_reconcile_get generated-ref)"',
         'GENERATED_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated")"'),
        ('REFS="$(spotlight_reconcile_get candidate-refs)"',
         'REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${BOT_BRANCH_PREFIX}")"'),
        ('CANDIDATE_COMMIT="$(spotlight_reconcile_get candidate-commit)"',
         'CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"'),
        ('ANCESTRY_COMPARE="$(spotlight_reconcile_get ancestry-compare)"',
         'ANCESTRY_COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${PARENT_SHA}...${BASE_SHA}")"'),
        ('COMPARE="$(spotlight_reconcile_get candidate-compare)"',
         'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${PARENT_SHA}...${HEAD_SHA}")"'),
        ('PRS="$(spotlight_reconcile_get open-prs)"',
         'PRS="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${BRANCH}&base=main&per_page=2")"'),
        ('PR="$(spotlight_reconcile_get pr)"',
         'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"'),
        ('REMAINING_REFS="$(spotlight_reconcile_get remaining-refs)"',
         'REMAINING_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${BRANCH}")"'),
    )
    for hardened, legacy in overlays:
        core.require(
            projected.count(hardened) == 1,
            f"Spotlight reconciler shell-read projection topology changed: {hardened}",
        )
        projected = projected.replace(hardened, legacy, 1)
    core.require(
        "spotlight_reconcile_get" not in projected,
        "Spotlight reconciler shell-read projection left retry transport bytes behind",
    )
    return sync[:reconcile_start] + projected + sync[reconcile_end:]


def project_spotlight_propose_shell_reads_to_raw(sync: str) -> str:
    """Project proposer-only shell retry transport to the accepted raw-GET semantic shape."""
    propose_start = sync.index("  propose:\n")
    propose_end = sync.index("  approve:\n", propose_start)
    propose = sync[propose_start:propose_end]
    helper_start_marker = "          spotlight_propose_get() {\n"
    helper_end_marker = "          REF_CREATED=false\n"
    core.require(
        propose.count(helper_start_marker) == 1 and propose.count(helper_end_marker) == 1,
        "Spotlight proposer shell-read projection anchors changed",
    )
    helper_start = propose.index(helper_start_marker)
    helper_end = propose.index(helper_end_marker, helper_start)
    projected = propose[:helper_start] + propose[helper_end:]
    overlays = (
        ('MAIN_REF_RESPONSE="$(spotlight_propose_get main-ref)"',
         'MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"'),
        ('MAIN_README_CONTENTS_RESPONSE="$(spotlight_propose_get main-readme)"',
         'MAIN_README_CONTENTS_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/contents/README.md?ref=main")"'),
        ('MATCHING_REFS="$(spotlight_propose_get candidate-refs)"',
         'MATCHING_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"'),
        ('BASE_COMMIT="$(spotlight_propose_get base-commit)"',
         'BASE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${SOURCE_SHA}")"'),
        ('CANDIDATE_COMMIT="$(spotlight_propose_get candidate-commit)"',
         'CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"'),
        ('COMPARE="$(spotlight_propose_get compare)"',
         'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${SOURCE_SHA}...${HEAD_SHA}")"'),
        ('README_CONTENTS_RESPONSE="$(spotlight_propose_get candidate-readme)"',
         'README_CONTENTS_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}")"'),
        ('CANDIDATE_REF_RESPONSE="$(spotlight_propose_get candidate-ref)"',
         'CANDIDATE_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}")"'),
        ('PRS="$(spotlight_propose_get open-prs)"',
         'PRS="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${CANDIDATE_BRANCH}&base=main&per_page=10")"'),
        ('PR="$(spotlight_propose_get pr)"',
         'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"'),
    )
    for hardened, legacy in overlays:
        core.require(
            projected.count(hardened) == 1,
            f"Spotlight proposer shell-read projection topology changed: {hardened}",
        )
        projected = projected.replace(hardened, legacy, 1)
    core.require(
        "spotlight_propose_get" not in projected,
        "Spotlight proposer shell-read projection left retry transport bytes behind",
    )
    return sync[:propose_start] + projected + sync[propose_end:]


def project_spotlight_merge_shell_reads_to_raw(sync: str) -> str:
    """Project merge-only shell retry transport to the accepted raw-GET semantic shape."""
    merge_start = sync.index("  merge:\n")
    merge_end = sync.find("  decision_receipt:\n", merge_start)
    if merge_end < 0:
        # Item-10/item-9 authority validation receives the workflow after the item-11 tail is stripped.
        merge_end = len(sync)
    merge = sync[merge_start:merge_end]
    helper_start_marker = "          spotlight_merge_get() {\n"
    helper_end_marker = "          # Verify exact short-lived mutation lease.\n"
    core.require(
        merge.count(helper_start_marker) == 1 and merge.count(helper_end_marker) == 1,
        "Spotlight authority terminal shell-read projection anchors changed",
    )
    helper_start = merge.index(helper_start_marker)
    helper_end = merge.index(helper_end_marker, helper_start)
    projected = merge[:helper_start] + merge[helper_end:]
    overlays = (
        ("PR=\"$(spotlight_merge_get pr-initial)\"", "PR=\"$(gh api \"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}\")\""),
        ("MAIN_REF_RESPONSE=\"$(spotlight_merge_get main-initial)\"", "MAIN_REF_RESPONSE=\"$(gh api \"repos/${GITHUB_REPOSITORY}/git/ref/heads/main\")\""),
        ("GENERATED_REF_RESPONSE=\"$(spotlight_merge_get generated-initial)\"", "GENERATED_REF_RESPONSE=\"$(gh api \"repos/${GITHUB_REPOSITORY}/git/ref/heads/generated\")\""),
        ("CANDIDATE_REF_RESPONSE=\"$(spotlight_merge_get candidate-initial)\"", "CANDIDATE_REF_RESPONSE=\"$(gh api \"repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}\")\""),
        ("FILES=\"$(spotlight_merge_get files)\"", "FILES=\"$(gh api \"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100\")\""),
        ("CANDIDATE_COMMIT=\"$(spotlight_merge_get candidate-commit)\"", "CANDIDATE_COMMIT=\"$(gh api \"repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}\")\""),
        ("README_CONTENTS_RESPONSE=\"$(spotlight_merge_get candidate-readme)\"", "README_CONTENTS_RESPONSE=\"$(gh api \"repos/${GITHUB_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}\")\""),
        ("CODEQL_RUN_RAW=\"$(spotlight_merge_get codeql-run)\"", "CODEQL_RUN_RAW=\"$(gh api \"repos/${GITHUB_REPOSITORY}/actions/runs/${CODEQL_RUN_ID}\")\""),
        ("DEPENDENCY_RUN_RAW=\"$(spotlight_merge_get dependency-run)\"", "DEPENDENCY_RUN_RAW=\"$(gh api \"repos/${GITHUB_REPOSITORY}/actions/runs/${DEPENDENCY_RUN_ID}\")\""),
        ("PROFILE_RUN_RAW=\"$(spotlight_merge_get profile-run)\"", "PROFILE_RUN_RAW=\"$(gh api \"repos/${GITHUB_REPOSITORY}/actions/runs/${PROFILE_RUN_ID}\")\""),
        ("TRUSTED_WORKFLOW_RAW=\"$(spotlight_merge_get trusted-workflow)\"", "TRUSTED_WORKFLOW_RAW=\"$(gh api \"repos/${GITHUB_REPOSITORY}/actions/workflows/capability-admission.yml\")\""),
        ("TRUSTED_RUN_RAW=\"$(spotlight_merge_get trusted-run)\"", "TRUSTED_RUN_RAW=\"$(gh api \"repos/${GITHUB_REPOSITORY}/actions/runs/${TRUSTED_RUN_ID}\")\""),
        ("TRUSTED_CHECK_RAW=\"$(spotlight_merge_get trusted-check)\"", "TRUSTED_CHECK_RAW=\"$(gh api \"repos/${GITHUB_REPOSITORY}/check-runs/${TRUSTED_CHECK_RUN_ID}\")\""),
        ("REVIEW_PAGES=\"$(spotlight_merge_paginated_get owner-reviews)\"", "REVIEW_PAGES=\"$(gh api --paginate --slurp \"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100\")\""),
        ("CHECKS=\"$(spotlight_merge_get exact-head-checks)\"", "CHECKS=\"$(gh api -H 'Accept: application/vnd.github+json' \"repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs?filter=latest&per_page=100\")\""),
        ("MAIN_REF_RESPONSE=\"$(spotlight_merge_get main-premerge)\"", "MAIN_REF_RESPONSE=\"$(gh api \"repos/${GITHUB_REPOSITORY}/git/ref/heads/main\")\""),
        ("GENERATED_REF_RESPONSE=\"$(spotlight_merge_get generated-premerge)\"", "GENERATED_REF_RESPONSE=\"$(gh api \"repos/${GITHUB_REPOSITORY}/git/ref/heads/generated\")\""),
        ("CANDIDATE_REF_RESPONSE=\"$(spotlight_merge_get candidate-premerge)\"", "CANDIDATE_REF_RESPONSE=\"$(gh api \"repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}\")\""),
        ("MERGED_PR=\"$(spotlight_merge_get pr-postmerge)\"", "MERGED_PR=\"$(gh api \"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}\")\""),
        ("CURRENT_MAIN_REF_RESPONSE=\"$(spotlight_merge_get main-postmerge)\"", "CURRENT_MAIN_REF_RESPONSE=\"$(gh api \"repos/${GITHUB_REPOSITORY}/git/ref/heads/main\")\""),
        ("CANDIDATE_REFS=\"$(spotlight_merge_get candidate-refs-postmerge)\"", "CANDIDATE_REFS=\"$(gh api \"repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}\")\""),
        ("AFTER_REFS=\"$(spotlight_merge_get candidate-refs-after-delete)\"", "AFTER_REFS=\"$(gh api \"repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}\")\""),
    )
    for hardened, legacy in overlays:
        core.require(
            projected.count(hardened) == 1,
            f"Spotlight authority terminal shell-read projection topology changed: {hardened}",
        )
        projected = projected.replace(hardened, legacy, 1)
    core.require(
        "spotlight_merge_get" not in projected and "spotlight_merge_paginated_get" not in projected,
        "Spotlight authority terminal shell-read projection left retry transport bytes behind",
    )
    return sync[:merge_start] + projected + sync[merge_end:]



def project_spotlight_source_epoch_ref_schema_to_legacy(sync: str) -> str:
    approve_start = sync.index("  approve:\n")
    approve_end = sync.index("  authorize:\n", approve_start)
    approve = sync[approve_start:approve_end]
    state_start = approve.index("          spotlight_source_epoch_state() {\n")
    state_end = approve.index("          spotlight_require_current_source_epoch() {\n", state_start)
    state = approve[state_start:state_end]
    for schema in (
        SPOTLIGHT_SOURCE_EPOCH_MAIN_SCHEMA,
        SPOTLIGHT_SOURCE_EPOCH_GENERATED_SCHEMA,
    ):
        core.require(
            state.count(schema) == 1,
            "Spotlight source-epoch ref-schema projection anchor changed",
        )
        state = state.replace(schema, "", 1)
    projected_approve = approve[:state_start] + state + approve[state_end:]
    return sync[:approve_start] + projected_approve + sync[approve_end:]


def project_spotlight_initial_compare_schema_to_legacy(sync: str) -> str:
    """Project the current typed initial-compare boundary out of frozen historical proofs."""
    approve_start = sync.index("  approve:\n")
    approve_end = sync.index("  authorize:\n", approve_start)
    approve = sync[approve_start:approve_end]
    fetch = '          COMPARE="$(spotlight_singleton_get compare-initial)"\n'
    consume = '          test "$(jq -r .status <<<"$COMPARE")" = "ahead"\n'
    schema_start = '          jq -e --arg base "$BASE_SHA" --arg head "$HEAD_SHA" \'\n'
    schema_end = '          \' <<<"$COMPARE" >/dev/null\n'
    core.require(approve.count(fetch) == 1 and approve.count(consume) == 1,
            "Spotlight initial-compare projection anchors changed")
    fetch_pos = approve.index(fetch)
    consume_pos = approve.index(consume, fetch_pos)
    schema_pos = approve.index(schema_start, fetch_pos + len(fetch), consume_pos)
    schema_end_pos = approve.index(schema_end, schema_pos, consume_pos) + len(schema_end)
    core.require(fetch_pos + len(fetch) == schema_pos and schema_end_pos == consume_pos,
            "Spotlight initial-compare schema is not the exact pre-consumption overlay")
    projected = approve[:schema_pos] + approve[consume_pos:]
    return sync[:approve_start] + projected + sync[approve_end:]

def project_spotlight_approve_shell_singleton_reads_to_raw(sync: str) -> str:
    """Project approve-only singleton retry transport to the accepted raw-GET semantic shape."""
    approve_start = sync.index("  approve:\n")
    approve_end = sync.index("  authorize:\n", approve_start)
    approve = sync[approve_start:approve_end]
    helper_start_marker = "          spotlight_validate_reviewer_checks_snapshot() {\n"
    helper_end_marker = "          APPROVAL_REQUESTS_JSON='[]'\n"
    core.require(
        approve.count(helper_start_marker) == 1 and approve.count(helper_end_marker) == 1,
        "Spotlight authority shell-read projection anchors changed",
    )
    helper_start = approve.index(helper_start_marker)
    helper_end = approve.index(helper_end_marker, helper_start)
    helper = approve[helper_start:helper_end]
    for fragment in (
        '                .total_count as $total_count |',
        '($total_count | type == "number" and . == floor and . >= 0 and . <= 100) and',
        '(.check_runs | type == "array" and length == $total_count and length <= 100) and',
        '(.head_sha == $head) and',
        '(.app | type == "object" and .id == 15368) and',
        'if [ "$request" = "reviewer-checks" ] &&',
        '! spotlight_validate_reviewer_checks_snapshot "$body"; then',
        'ERROR: Spotlight reviewer-checks HTTP 200 body remained schema-incompatible after 3 attempts.',
    ):
        core.require(
            helper.count(fragment) == 1,
            f"Spotlight authority reviewer-read semantic retry contract changed: {fragment}",
        )
    core.require(
        'length == .total_count' not in helper,
        "Spotlight authority reviewer snapshot must retain root-scoped total_count binding",
    )
    projected = approve[:helper_start] + approve[helper_end:]
    source_epoch_guards = (
        '          spotlight_require_current_source_epoch "before initial protected-check proof"\n',
        '            spotlight_require_current_source_epoch "during protected-check convergence"\n',
        '          spotlight_require_current_source_epoch "after protected-check convergence"\n',
    )
    for guard in source_epoch_guards:
        core.require(
            projected.count(guard) == 1,
            f"Spotlight authority superseded-source projection anchor changed: {guard.strip()}",
        )
        projected = projected.replace(guard, "", 1)
    overlays = (
        ('MAIN_REF_RESPONSE="$(spotlight_singleton_get main-initial)"',
         'MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"'),
        ('GENERATED_REF_RESPONSE="$(spotlight_singleton_get generated-initial)"',
         'GENERATED_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated")"'),
        ('CANDIDATE_REF_RESPONSE="$(spotlight_singleton_get candidate-initial)"',
         'CANDIDATE_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}")"'),
        ('COMPARE="$(spotlight_singleton_get compare-initial)"',
         'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${BASE_SHA}...${HEAD_SHA}")"'),
        ('PR="$(spotlight_singleton_get pr-initial)"',
         'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"'),
        ('          spotlight_singleton_get codeql-workflow \\\n            > "$RUNNER_TEMP/spotlight-codeql-workflow-definition.json"',
         '          gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/codeql.yml" \\\n            > "$RUNNER_TEMP/spotlight-codeql-workflow-definition.json"'),
        ('          spotlight_singleton_get dependency-workflow \\\n            > "$RUNNER_TEMP/spotlight-dependency-workflow-definition.json"',
         '          gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/dependency-review.yml" \\\n            > "$RUNNER_TEMP/spotlight-dependency-workflow-definition.json"'),
        ('          spotlight_singleton_get profile-workflow \\\n            > "$RUNNER_TEMP/spotlight-profile-workflow-definition.json"',
         '          gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/profile-quality.yml" \\\n            > "$RUNNER_TEMP/spotlight-profile-workflow-definition.json"'),
        ('            spotlight_singleton_get protected-runs \\\n              > "$RUNNER_TEMP/spotlight-protected-workflow-runs.json"',
         '            gh api "repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100" \\\n              > "$RUNNER_TEMP/spotlight-protected-workflow-runs.json"'),
        ('REVIEW_CHECKS="$(spotlight_singleton_get reviewer-checks)"',
         'REVIEW_CHECKS="$(gh api "repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs?app_id=15368&filter=latest&per_page=100")"'),
        ('PRS="$(spotlight_singleton_get open-pr-list)"',
         'PRS="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${CANDIDATE_BRANCH}&base=main&per_page=10")"'),
        ('          spotlight_paginated_get approval-comments \\\n            > "$RUNNER_TEMP/spotlight-approval-comment-pages.json"',
         '          gh api --paginate --slurp \\\n            "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100" \\\n            > "$RUNNER_TEMP/spotlight-approval-comment-pages.json"'),
        ('REVIEW_PAGES="$(spotlight_paginated_get owner-reviews)"',
         'REVIEW_PAGES="$(gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100")"'),
        ('MAIN_REF_RESPONSE="$(spotlight_singleton_get main-final)"',
         'MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"'),
        ('CANDIDATE_REF_RESPONSE="$(spotlight_singleton_get candidate-final)"',
         'CANDIDATE_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}")"'),
        ('PR_AFTER_REVIEW="$(spotlight_singleton_get pr-final)"',
         'PR_AFTER_REVIEW="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"'),
    )
    for hardened, legacy in overlays:
        core.require(
            projected.count(hardened) == 1,
            f"Spotlight authority shell-read projection topology changed: {hardened}",
        )
        projected = projected.replace(hardened, legacy, 1)
    core.require(
        "spotlight_singleton_get" not in projected and "spotlight_paginated_get" not in projected,
        "Spotlight authority shell-read projection left retry transport bytes behind",
    )
    return sync[:approve_start] + projected + sync[approve_end:]


def project_spotlight_privileged_refs_to_legacy(sync: str) -> str:
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
    core.require(
        sync.count(helper) == 4,
        "Spotlight authority projection cannot isolate four privileged Git-ref validators",
    )
    projected = sync.replace(helper, "")
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
        core.require(
            projected.count(hardened) == expected_count,
            f"Spotlight authority Git-ref projection topology changed for: {legacy.strip()}",
        )
        projected = projected.replace(hardened, legacy)
    return projected



def project_spotlight_terminal_merge_status_to_legacy(sync: str) -> str:
    core.require(
        sync.count(SPOTLIGHT_MERGE_HTTP_STATUS) == 1,
        "Spotlight authority terminal merge-status projection cannot isolate exact HTTP wrapper",
    )
    core.require(
        SPOTLIGHT_MERGE_LEGACY not in sync,
        "Spotlight production workflow regained response-blind terminal merge",
    )
    return sync.replace(SPOTLIGHT_MERGE_HTTP_STATUS, SPOTLIGHT_MERGE_LEGACY, 1)


def project_spotlight_terminal_protected_runs_to_legacy(sync: str) -> str:
    start_marker = "          normalize_protected_certificate_run() {\n"
    end_marker = "          EXPECTED_CERTIFICATE_RUNS="
    core.require(
        sync.count(start_marker) == 1 and sync.count(end_marker) == 1,
        "Spotlight authority terminal protected-run projection anchors changed",
    )
    start = sync.index(start_marker)
    end_start = sync.index(end_marker, start)
    end = sync.index("\n", end_start) + 1
    legacy = (
        '          CODEQL_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${CODEQL_RUN_ID}")"\n'
        '          DEPENDENCY_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${DEPENDENCY_RUN_ID}")"\n'
        '          PROFILE_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${PROFILE_RUN_ID}")"\n'
        '          EXPECTED_CERTIFICATE_RUNS="$(jq -cn --argjson codeql "$CODEQL_RUN" --argjson dependency "$DEPENDENCY_RUN" --argjson profile "$PROFILE_RUN" \'[{name:"CodeQL",workflowId:$codeql.workflow_id,runId:$codeql.id,runAttempt:$codeql.run_attempt,checkSuiteId:$codeql.check_suite_id,event:$codeql.event,headBranch:$codeql.head_branch,headSha:$codeql.head_sha,repository:$codeql.repository.full_name,headRepository:$codeql.head_repository.full_name,status:$codeql.status,conclusion:$codeql.conclusion},{name:"Dependency review",workflowId:$dependency.workflow_id,runId:$dependency.id,runAttempt:$dependency.run_attempt,checkSuiteId:$dependency.check_suite_id,event:$dependency.event,headBranch:$dependency.head_branch,headSha:$dependency.head_sha,repository:$dependency.repository.full_name,headRepository:$dependency.head_repository.full_name,status:$dependency.status,conclusion:$dependency.conclusion},{name:"Profile quality",workflowId:$profile.workflow_id,runId:$profile.id,runAttempt:$profile.run_attempt,checkSuiteId:$profile.check_suite_id,event:$profile.event,headBranch:$profile.head_branch,headSha:$profile.head_sha,repository:$profile.repository.full_name,headRepository:$profile.head_repository.full_name,status:$profile.status,conclusion:$profile.conclusion}] | sort_by(.name)\')"\n'
    )
    return sync[:start] + legacy + sync[end:]



def validate_spotlight_source_epoch_ref_schema(spotlight: str) -> None:
    approve = core.item9.core.job_block(spotlight, "approve", "authorize")
    start_marker = "          spotlight_source_epoch_state() {\n"
    end_marker = "          spotlight_require_current_source_epoch() {\n"
    core.require(
        approve.count(start_marker) == 1 and approve.count(end_marker) == 1,
        "Spotlight source-epoch ref-schema helper boundaries changed",
    )
    start = approve.index(start_marker)
    end = approve.index(end_marker, start)
    state = approve[start:end]
    main_fetch = 'main_response="$(spotlight_singleton_get main-current)" || return 1'
    generated_fetch = 'generated_response="$(spotlight_singleton_get generated-current)" || return 1'
    main_consume = 'current_main_sha="$(jq -er'
    generated_consume = 'current_generated_sha="$(jq -er'
    main_reproof = 'validate_git_ref_object "$main_response" "refs/heads/main" "$current_main_sha" || return 1'
    generated_reproof = 'validate_git_ref_object "$generated_response" "refs/heads/generated" "$current_generated_sha" || return 1'
    for marker in (
        main_fetch, generated_fetch, SPOTLIGHT_SOURCE_EPOCH_MAIN_SCHEMA,
        SPOTLIGHT_SOURCE_EPOCH_GENERATED_SCHEMA, main_consume, generated_consume,
        main_reproof, generated_reproof,
    ):
        core.require(
            state.count(marker) == 1,
            f"Spotlight source-epoch ref-schema anchor missing or ambiguous: {marker}",
        )
    positions = (
        state.index(main_fetch),
        state.index(generated_fetch),
        state.index(SPOTLIGHT_SOURCE_EPOCH_MAIN_SCHEMA),
        state.index(SPOTLIGHT_SOURCE_EPOCH_GENERATED_SCHEMA),
        state.index(main_consume),
        state.index(generated_consume),
        state.index(main_reproof),
        state.index(generated_reproof),
    )
    core.require(
        list(positions) == sorted(positions) and len(set(positions)) == len(positions),
        "Spotlight source-epoch Git-ref evidence must cross both complete schema boundaries before SHA consumption",
    )


def self_test_spotlight_source_epoch_ref_schema(spotlight: str) -> None:
    validate_spotlight_source_epoch_ref_schema(spotlight)
    approve_start = spotlight.index("  approve:\n")
    approve_end = spotlight.index("  authorize:\n", approve_start)
    approve = spotlight[approve_start:approve_end]
    state_start = approve.index("          spotlight_source_epoch_state() {\n")
    state_end = approve.index("          spotlight_require_current_source_epoch() {\n", state_start)
    state = approve[state_start:state_end]

    weakened_schema = SPOTLIGHT_SOURCE_EPOCH_MAIN_SCHEMA.replace(
        '(.object | type == "object" and',
        '(.object != null and',
        1,
    )
    weakened_state = state.replace(
        SPOTLIGHT_SOURCE_EPOCH_MAIN_SCHEMA,
        weakened_schema,
        1,
    )
    weakened_approve = approve[:state_start] + weakened_state + approve[state_end:]
    weakened = spotlight[:approve_start] + weakened_approve + spotlight[approve_end:]
    try:
        validate_spotlight_source_epoch_ref_schema(weakened)
    except ValueError:
        pass
    else:
        raise ValueError("Spotlight source-epoch schema self-test accepted weakened object typing")

    schema_pos = state.index(SPOTLIGHT_SOURCE_EPOCH_MAIN_SCHEMA)
    consume_pos = state.index('            current_main_sha="$(jq -er', schema_pos)
    consume_end = state.index("\n", consume_pos) + 1
    reordered_state = (
        state[:schema_pos]
        + state[schema_pos + len(SPOTLIGHT_SOURCE_EPOCH_MAIN_SCHEMA):consume_end]
        + SPOTLIGHT_SOURCE_EPOCH_MAIN_SCHEMA
        + state[consume_end:]
    )
    reordered_approve = approve[:state_start] + reordered_state + approve[state_end:]
    reordered = spotlight[:approve_start] + reordered_approve + spotlight[approve_end:]
    try:
        validate_spotlight_source_epoch_ref_schema(reordered)
    except ValueError:
        pass
    else:
        raise ValueError("Spotlight source-epoch schema self-test accepted schema-after-SHA-consumption ordering")


def validate_item10_authority_with_typed_protected_runs(sync: str) -> None:
    validate_spotlight_source_epoch_ref_schema(sync)
    self_test_spotlight_source_epoch_ref_schema(sync)
    projected = project_spotlight_source_epoch_ref_schema_to_legacy(sync)
    projected = project_spotlight_reconcile_shell_reads_to_raw(projected)
    projected = project_spotlight_propose_shell_reads_to_raw(projected)
    projected = project_spotlight_merge_shell_reads_to_raw(projected)
    projected = project_spotlight_terminal_merge_status_to_legacy(projected)
    lifecycle_overlays = (
        (
            '              CLOSED_PR_HTTP_RESPONSE="$(gh api --include --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}" --input close-pr.json)"\n'
            '              CLOSED_PR_STATUS_LINE="$(head -n 1 <<<"$CLOSED_PR_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '              [[ "$CLOSED_PR_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {\n'
            '                echo "ERROR: Spotlight stale PR close returned unexpected status: ${CLOSED_PR_STATUS_LINE}" >&2\n'
            '                exit 1\n'
            '              }\n'
            '              CLOSED_PR="$(sed \'1,/^[[:space:]]*$/d\' <<<"$CLOSED_PR_HTTP_RESPONSE")"\n',
            '              CLOSED_PR="$(gh api --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}" --input close-pr.json)"\n',
        ),
        (
            '            STALE_REF_DELETE_HTTP_RESPONSE="$(gh api --include --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BRANCH}")"\n'
            '            STALE_REF_DELETE_STATUS_LINE="$(head -n 1 <<<"$STALE_REF_DELETE_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '            [[ "$STALE_REF_DELETE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {\n'
            '              echo "ERROR: Spotlight stale candidate ref deletion returned unexpected status: ${STALE_REF_DELETE_STATUS_LINE}" >&2\n'
            '              exit 1\n'
            '            }\n',
            '            gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BRANCH}" >/dev/null\n',
        ),
        (
            '            PR_CREATE_HTTP_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/pulls" --input pr.json)"\n'
            '            PR_CREATE_STATUS_LINE="$(head -n 1 <<<"$PR_CREATE_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '            [[ "$PR_CREATE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
            '              echo "ERROR: Spotlight proposal PR creation returned unexpected status: ${PR_CREATE_STATUS_LINE}" >&2\n'
            '              exit 1\n'
            '            }\n'
            '            sed \'1,/^[[:space:]]*$/d\' <<<"$PR_CREATE_HTTP_RESPONSE" > pr-response.json\n',
            '            gh api --method POST "repos/${GITHUB_REPOSITORY}/pulls" --input pr.json > pr-response.json\n',
        ),
        (
            '            TERMINAL_REF_DELETE_HTTP_RESPONSE="$(gh api --include --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CANDIDATE_BRANCH}")"\n'
            '            TERMINAL_REF_DELETE_STATUS_LINE="$(head -n 1 <<<"$TERMINAL_REF_DELETE_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '            [[ "$TERMINAL_REF_DELETE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {\n'
            '              echo "ERROR: Spotlight terminal candidate ref deletion returned unexpected status: ${TERMINAL_REF_DELETE_STATUS_LINE}" >&2\n'
            '              exit 1\n'
            '            }\n',
            '            gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CANDIDATE_BRANCH}" >/dev/null\n',
        ),
    )
    for hardened, legacy in lifecycle_overlays:
        core.require(projected.count(hardened) == 1,
                     "Spotlight item-10 lifecycle-status projection anchor changed")
        projected = projected.replace(hardened, legacy, 1)
    ORIGINAL_VALIDATE_ITEM10_AUTHORITY(
        project_spotlight_terminal_protected_runs_to_legacy(projected)
    )



def project_spotlight_pr_response_evidence_to_legacy(sync: str) -> str:
    helper_start = "          validate_spotlight_open_pr_object() {\n"
    for next_marker in (
        "          REF_CREATED=false\n",
        "          APPROVAL_REQUESTS_JSON='[]'\n",
    ):
        core.require(
            sync.count(next_marker) == 1,
            f"Spotlight PR-response projection next anchor changed: {next_marker.strip()}",
        )
        next_pos = sync.index(next_marker)
        helper_pos = sync.rfind(helper_start, 0, next_pos)
        core.require(
            helper_pos >= 0,
            f"Spotlight PR-response projection helper missing before: {next_marker.strip()}",
        )
        sync = sync[:helper_pos] + sync[next_pos:]

    overlays = (
        (
            '          validate_spotlight_open_pr_object "$PR" "$PR_NUMBER" "$SOURCE_SHA" "$CANDIDATE_BRANCH" "$HEAD_SHA"\n',
            "",
        ),
        (
            '          validate_spotlight_open_pr_object "$PR" "$PR_NUMBER" "$BASE_SHA" "$CANDIDATE_BRANCH" "$HEAD_SHA"\n',
            "",
        ),
        (
            '          validate_spotlight_open_pr_object "$PR_AFTER_REVIEW" "$PR_NUMBER" "$BASE_SHA" "$CANDIDATE_BRANCH" "$HEAD_SHA"\n',
            "",
        ),
        (
            '          jq -e \'(type == "array") and (length == 1)\' <<<"$PRS" >/dev/null\n'
            '          APPROVAL_PR="$(jq -c \'.[0]\' <<<"$PRS")"\n'
            '          validate_spotlight_pull_list_item "$APPROVAL_PR" "$PR_NUMBER" "$BASE_SHA" "$CANDIDATE_BRANCH" "$HEAD_SHA"\n'
            '          test "$(jq -r .number <<<"$APPROVAL_PR")" = "$PR_NUMBER"\n',
            '          test "$(jq \'length\' <<<"$PRS")" = "1"\n'
            '          test "$(jq -r \'.[0].number\' <<<"$PRS")" = "$PR_NUMBER"\n',
        ),
    )
    for hardened, legacy in overlays:
        core.require(
            sync.count(hardened) == 1,
            f"Spotlight PR-response projection hardened anchor changed: {hardened.splitlines()[0]}",
        )
        sync = sync.replace(hardened, legacy, 1)
    core.require(
        "validate_spotlight_open_pr_object" not in sync
        and "validate_spotlight_pull_list_item" not in sync,
        "Spotlight PR-response projection left modern runtime schema bytes in the historical item-9 view",
    )
    return sync


def project_state_driven_spotlight_reviewer_to_legacy(sync: str) -> str:
    """Project #1276's state-driven reviewer wake back to the pre-#1276 item-9 shape."""
    init = '          REVIEW_DISPATCHED=false\n'
    terminal = '          test "$REVIEW_DISPATCHED" = "true"\n'
    state_start = (
        '              if [ "$REVIEW_DISPATCHED" = "false" ] &&\n'
        '                 [ "$CODEQL_SUCCESS" = "true" ] &&\n'
        '                 [ "$DEPENDENCY_SUCCESS" = "true" ]; then\n'
    )
    state_end = (
        '              fi\n'
        '            fi\n'
        '            if [ "$ALL_SUCCESS" = "true" ]; then break; fi\n'
    )
    core.require(
        sync.count(init) == 1 and sync.count(terminal) == 1,
        "Spotlight state-driven reviewer dispatch guard anchors changed",
    )
    core.require(
        sync.count(state_start) == 1 and sync.count(state_end) == 1,
        "Spotlight state-driven reviewer block boundary changed",
    )
    start = sync.index(state_start)
    end_anchor = sync.index(state_end, start)
    block_end = end_anchor + len('              fi\n')
    block = sync[start:block_end]
    for fragment in (
        'REVIEW_CHECKS="$(gh api "repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs?app_id=15368&filter=latest&per_page=100")"',
        'spotlight_validate_reviewer_checks_snapshot "$REVIEW_CHECKS" || {',
        'REVIEW_READY=true',
        'for CONTEXT in validate-contracts integration-pinned-upstream analyze-actions analyze-python dependency-review trusted-capability-admission; do',
        'test "$CONTEXT_COUNT" = "1"',
        'if [ "$CONTEXT_STATUS" != "completed" ]; then',
        'elif [ "$CONTEXT_CONCLUSION" != "success" ]; then',
        'if [ "$REVIEW_READY" = "true" ]; then',
        'REVIEW_DISPATCH_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/bot-pr-user-approval.yml/dispatches"',
        '[[ "$REVIEW_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {',
        'REVIEW_DISPATCHED=true',
        'Dispatched bounded singleton Spotlight reviewer evaluation from trusted main.',
        'Reviewer dispatch occurred only after six exact-head prerequisites were green.',
    ):
        core.require(
            fragment in block,
            f"Spotlight state-driven reviewer contract is missing: {fragment}",
        )
    core.require(
        block.index('REVIEW_READY=true')
        < block.index('if [ "$REVIEW_READY" = "true" ]; then')
        < block.index('actions/workflows/bot-pr-user-approval.yml/dispatches')
        < block.index('REVIEW_DISPATCHED=true'),
        "Spotlight state-driven reviewer dispatch ordering changed",
    )

    sync = sync[:start] + sync[block_end:]
    for old, new, label in (
        (
            '          APPROVAL_REQUESTED_RUN_IDS=""\n          REVIEW_DISPATCHED=false\n          for attempt in $(seq 1 60); do\n',
            '          APPROVAL_REQUESTED_RUN_IDS=""\n          for attempt in $(seq 1 60); do\n',
            "review-dispatch initialization",
        ),
        (
            '              ALL_SUCCESS=true\n              CODEQL_SUCCESS=false\n              DEPENDENCY_SUCCESS=false\n',
            '              ALL_SUCCESS=true\n',
            "review-independent success state",
        ),
        (
            '                elif [ "$STATUS" = "completed" ] && [ "$CONCLUSION" = "success" ]; then\n'
            '                  case "$NAME" in\n'
            '                    "CodeQL") CODEQL_SUCCESS=true ;;\n'
            '                    "Dependency review") DEPENDENCY_SUCCESS=true ;;\n'
            '                    "Profile quality") : ;;\n'
            '                    *) exit 1 ;;\n'
            '                  esac\n',
            '                elif [ "$STATUS" = "completed" ] && [ "$CONCLUSION" = "success" ]; then\n'
            '                  :\n',
            "review-independent workflow success classification",
        ),
        (
            '                elif [ "$STATUS" = "completed" ]; then\n'
            '                  if [ "$NAME" = "Profile quality" ]; then\n'
            '                    # The accepted-base governed-review gate is intentionally allowed to fail\n'
            '                    # once before the marker approval exists. The fixed reviewer will re-enter\n'
            '                    # only that exact failed job after the six review-independent contexts are green.\n'
            '                    ALL_SUCCESS=false\n'
            '                  else\n'
            '                    echo "Canonical Spotlight-link PR workflow failed: $NAME ($CONCLUSION)." >&2\n'
            '                    exit 1\n'
            '                  fi\n',
            '                elif [ "$STATUS" = "completed" ]; then\n'
            '                  echo "Canonical Spotlight-link PR workflow failed: $NAME ($CONCLUSION)." >&2\n'
            '                  exit 1\n',
            "pre-review Profile Quality failure classification",
        ),
        (
            '          test "$ALL_SUCCESS" = "true"\n          test "$REVIEW_DISPATCHED" = "true"\n',
            '          test "$ALL_SUCCESS" = "true"\n',
            "review-dispatch terminal proof",
        ),
    ):
        core.require(sync.count(old) == 1, f"Spotlight {label} projection anchor changed")
        sync = sync.replace(old, new, 1)

    core.require(
        "REVIEW_DISPATCHED" not in sync
        and "REVIEW_READY" not in sync
        and "REVIEW_CHECKS" not in sync,
        "Spotlight state-driven reviewer projection left #1276-only state behind",
    )
    return sync


def project_item9_sync_with_marker(sync: str) -> str:
    sync = project_spotlight_source_epoch_ref_schema_to_legacy(sync)
    sync = project_spotlight_initial_compare_schema_to_legacy(sync)
    sync = project_spotlight_reconcile_shell_reads_to_raw(sync)
    sync = project_spotlight_propose_shell_reads_to_raw(sync)
    sync = project_spotlight_merge_shell_reads_to_raw(sync)
    sync = project_spotlight_approve_shell_singleton_reads_to_raw(sync)
    sync = project_spotlight_terminal_merge_status_to_legacy(sync)
    sync = project_spotlight_terminal_protected_runs_to_legacy(sync)
    sync = project_spotlight_readme_contents_to_legacy(sync)
    sync = project_spotlight_privileged_refs_to_legacy(sync)
    sync = project_spotlight_pr_response_evidence_to_legacy(sync)

    budget_start = sync.index("  budget:\n")
    budget_end = sync.index("  quarantine:\n", budget_start)
    budget = sync[budget_start:budget_end]
    governed_permissions = (
        "    permissions:\n"
        "      actions: read\n"
        "      contents: read\n"
    )
    legacy_permissions = "    permissions:\n      actions: read\n"
    governed_read = (
        'ARTIFACTS="$(python3 source/scripts/automation_github_read.py '
        '"repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${ARTIFACT_NAME}&per_page=100")"'
    )
    legacy_read = (
        'ARTIFACTS="$(gh api '
        '"repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${ARTIFACT_NAME}&per_page=100")"'
    )
    core.require(budget.count(governed_permissions) == 1,
                 "Spotlight mutation budget governed-read permissions changed")
    core.require(
        budget.count("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1") == 1
        and budget.count("actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97") == 1,
        "Spotlight mutation budget governed runtime surface changed",
    )
    core.require("ref: main" in budget and "persist-credentials: false" in budget,
                 "Spotlight mutation budget lost static credential-free trusted-main checkout")
    core.require(
        'test "$(git -C source rev-parse HEAD)" = "$BASE_SHA"' in budget
        and 'test "$(git -C source rev-parse HEAD:scripts/automation_github_read.py)" = "1b779bcea0acd290826fef8f60fd01480113a31a"' in budget,
        "Spotlight mutation budget lost sealed-base/helper byte identity",
    )
    core.require(
        budget.count(governed_read) == 1 and legacy_read not in budget,
        "Spotlight mutation budget must use exactly one governed GET transport",
    )
    core.require("GH_TOKEN: ${{ github.token }}" in budget,
                 "Spotlight mutation budget governed GET lost run-scoped token")
    bootstrap_start = budget.index(
        "      - name: Checkout exact trusted source for governed reads\n"
    )
    admit_start = budget.index(
        "      - name: Admit exact source epoch within bounded mutation budget\n",
        bootstrap_start,
    )
    projected_budget = budget[:bootstrap_start] + budget[admit_start:]
    projected_budget = projected_budget.replace(
        governed_permissions, legacy_permissions, 1
    ).replace(
        governed_read, legacy_read, 1
    )
    sync = sync[:budget_start] + projected_budget + sync[budget_end:]
    core.require(
        sync.count(SPOTLIGHT_CAPABILITY_DISPATCH_STATUS) == 1,
        "Spotlight item-9 capability-dispatch status projection anchor changed",
    )
    core.require(
        SPOTLIGHT_CAPABILITY_DISPATCH_LEGACY not in sync,
        "Spotlight production workflow regained response-blind capability dispatch",
    )
    sync = sync.replace(
        SPOTLIGHT_CAPABILITY_DISPATCH_STATUS,
        SPOTLIGHT_CAPABILITY_DISPATCH_LEGACY,
        1,
    )
    reviewer_marker = 'Dispatched exact pre-convergence portyu9 review evaluation from trusted main.'
    capability_dispatch = 'actions/workflows/capability-admission.yml/dispatches'
    state_driven_dispatch = 'actions/workflows/bot-pr-user-approval.yml/dispatches'
    convergence_anchor = '          APPROVAL_REQUESTED_RUN_IDS=""\n          REVIEW_DISPATCHED=false\n          for attempt in $(seq 1 60); do\n'
    core.require(SPOTLIGHT_PRE_CONVERGENCE_REVIEW_WAKE not in sync and reviewer_marker not in sync,
            "Spotlight must not regain the retired main/global reviewer scan wake")
    core.require(
        sync.count(capability_dispatch) == 1
        and sync.count(state_driven_dispatch) == 1
        and sync.count(convergence_anchor) == 1,
        "Spotlight state-driven exact-candidate reviewer dispatch contract changed",
    )
    core.require(
        sync.index(capability_dispatch)
        < sync.index(convergence_anchor)
        < sync.index(state_driven_dispatch, sync.index(convergence_anchor)),
        "Spotlight reviewer wake must stay after admission dispatch and inside protected workflow convergence",
    )
    sync = project_state_driven_spotlight_reviewer_to_legacy(sync)

    sync = project_ancestry_reconcile_to_same_base(sync)
    sync = project_native_review_gate_to_legacy_order(sync)
    core.require(
        sync.count(HARDENED_RUN_BRANCH_PROOF) == 1,
        "Spotlight authority projection lost hardened protected workflow branch proof",
    )
    core.require(
        LEGACY_RUN_BRANCH_PROOF not in sync,
        "Spotlight authority projection found retired raw workflow-run branch proof in production",
    )
    sync_for_item9 = sync.replace(
        HARDENED_RUN_BRANCH_PROOF,
        LEGACY_RUN_BRANCH_PROOF,
        1,
    )
    api_surface_projection = (
        (
            '          gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/codeql.yml" \\\n'
            '            > "$RUNNER_TEMP/spotlight-codeql-workflow-definition.json"\n',
            '          CODEQL_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/codeql.yml" --jq .id)"\n',
        ),
        (
            '          gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/dependency-review.yml" \\\n'
            '            > "$RUNNER_TEMP/spotlight-dependency-workflow-definition.json"\n',
            '          DEPENDENCY_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/dependency-review.yml" --jq .id)"\n',
        ),
        (
            '          gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/profile-quality.yml" \\\n'
            '            > "$RUNNER_TEMP/spotlight-profile-workflow-definition.json"\n',
            '          PROFILE_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/profile-quality.yml" --jq .id)"\n',
        ),
        (
            '            gh api "repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100" \\\n'
            '              > "$RUNNER_TEMP/spotlight-protected-workflow-runs.json"\n',
            '            RUNS="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100")"\n',
        ),
        (
            '              CLOSED_PR_HTTP_RESPONSE="$(gh api --include --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}" --input close-pr.json)"\n'
            '              CLOSED_PR_STATUS_LINE="$(head -n 1 <<<"$CLOSED_PR_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '              [[ "$CLOSED_PR_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {\n'
            '                echo "ERROR: Spotlight stale PR close returned unexpected status: ${CLOSED_PR_STATUS_LINE}" >&2\n'
            '                exit 1\n'
            '              }\n'
            '              CLOSED_PR="$(sed \'1,/^[[:space:]]*$/d\' <<<"$CLOSED_PR_HTTP_RESPONSE")"\n',
            '              CLOSED_PR="$(gh api --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}" --input close-pr.json)"\n',
        ),
        (
            '            STALE_REF_DELETE_HTTP_RESPONSE="$(gh api --include --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BRANCH}")"\n'
            '            STALE_REF_DELETE_STATUS_LINE="$(head -n 1 <<<"$STALE_REF_DELETE_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '            [[ "$STALE_REF_DELETE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {\n'
            '              echo "ERROR: Spotlight stale candidate ref deletion returned unexpected status: ${STALE_REF_DELETE_STATUS_LINE}" >&2\n'
            '              exit 1\n'
            '            }\n',
            '            gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BRANCH}" >/dev/null\n',
        ),
        (
            '            PR_CREATE_HTTP_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/pulls" --input pr.json)"\n'
            '            PR_CREATE_STATUS_LINE="$(head -n 1 <<<"$PR_CREATE_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '            [[ "$PR_CREATE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
            '              echo "ERROR: Spotlight proposal PR creation returned unexpected status: ${PR_CREATE_STATUS_LINE}" >&2\n'
            '              exit 1\n'
            '            }\n'
            '            sed \'1,/^[[:space:]]*$/d\' <<<"$PR_CREATE_HTTP_RESPONSE" > pr-response.json\n',
            '            gh api --method POST "repos/${GITHUB_REPOSITORY}/pulls" --input pr.json > pr-response.json\n',
        ),
        (
            '            TERMINAL_REF_DELETE_HTTP_RESPONSE="$(gh api --include --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CANDIDATE_BRANCH}")"\n'
            '            TERMINAL_REF_DELETE_STATUS_LINE="$(head -n 1 <<<"$TERMINAL_REF_DELETE_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '            [[ "$TERMINAL_REF_DELETE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {\n'
            '              echo "ERROR: Spotlight terminal candidate ref deletion returned unexpected status: ${TERMINAL_REF_DELETE_STATUS_LINE}" >&2\n'
            '              exit 1\n'
            '            }\n',
            '            gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CANDIDATE_BRANCH}" >/dev/null\n',
        ),
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
        (
            SPOTLIGHT_APPROVAL_COMMENT_STATUS,
            SPOTLIGHT_APPROVAL_COMMENT_LEGACY,
        ),
        (
            '                      APPROVAL_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve")"\n'
            '                      APPROVAL_STATUS_LINE="$(head -n 1 <<<"$APPROVAL_RESPONSE" | tr -d \'\\r\')"\n'
            '                      [[ "$APPROVAL_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
            '                        echo "ERROR: Spotlight protected-run approval returned unexpected status: ${APPROVAL_STATUS_LINE}" >&2\n'
            '                        exit 1\n'
            '                      }\n',
            '                      gh api --method POST "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve" >/dev/null\n',
        ),
    )
    for hardened, legacy_api in api_surface_projection:
        core.require(
            sync_for_item9.count(hardened) == 1,
            f"Spotlight authority projection lost hardened API read surface: {hardened.splitlines()[0]}",
        )
        core.require(
            legacy_api not in sync_for_item9,
            f"Spotlight production workflow regained retired scalar API read: {legacy_api.strip()}",
        )
        sync_for_item9 = sync_for_item9.replace(hardened, legacy_api, 1)
    projected = ORIGINAL_PROJECT_ITEM9_SYNC(sync_for_item9)
    if projected.count(SPOTLIGHT_APPROVE_PERMISSIONS) != 1:
        raise ValueError("Spotlight item-9 approval-permission projection anchor changed")
    projected = projected.replace(
        SPOTLIGHT_APPROVE_PERMISSIONS, LEGACY_SPOTLIGHT_APPROVE_PERMISSIONS, 1
    )
    if projected.count(SPOTLIGHT_APPROVAL_AUDIT) != 1:
        raise ValueError("Spotlight item-9 approval-audit projection anchor changed")
    projected = projected.replace(SPOTLIGHT_APPROVAL_AUDIT, "", 1)
    if projected.count(SPOTLIGHT_PRE_CONVERGENCE_REVIEW_WAIT) == 1:
        projected = projected.replace(SPOTLIGHT_PRE_CONVERGENCE_REVIEW_WAIT, "", 1)
    else:
        singleton_error = (
            '            echo "ERROR: exact-base/head portyu9 approval is not singleton after all protected workflows converged." >&2\n'
        )
        singleton_start_marker = (
            '          REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"\n'
        )
        singleton_end_marker = (
            '          echo "Observed exact-base/head marker-bound portyu9 approval before merge authorization."\n\n'
        )
        core.require(
            projected.count(singleton_error) == 1
            and projected.count(singleton_end_marker) == 1,
            "Spotlight item-9 single-pass review observation projection anchor changed",
        )
        error_pos = projected.index(singleton_error)
        start = projected.rfind(singleton_start_marker, 0, error_pos)
        core.require(start >= 0, "Spotlight item-9 single-pass review observation start changed")
        end = projected.index(singleton_end_marker, error_pos) + len(singleton_end_marker)
        single_pass = projected[start:end]
        for fragment in (
            'REVIEW_PAGES="$(gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100")"',
            'test "$PORTYU9_APPROVAL_COUNT" = "1" || {',
            'test "$(jq -r .state <<<"$PR_AFTER_REVIEW")" = "open"',
            'test "$(jq -r .base.sha <<<"$PR_AFTER_REVIEW")" = "$BASE_SHA"',
            'test "$(jq -r .head.sha <<<"$PR_AFTER_REVIEW")" = "$HEAD_SHA"',
        ):
            core.require(
                fragment in single_pass,
                f"Spotlight item-9 single-pass review observation contract is missing: {fragment}",
            )
        core.require(
            "for REVIEW_ATTEMPT in $(seq 1 24); do" not in single_pass
            and "sleep 5" not in single_pass,
            "Spotlight single-pass review observation regained bounded polling",
        )
        projected = projected[:start] + projected[end:]
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


core.validate_item10_authority = validate_item10_authority_with_typed_protected_runs
core.item9.validate_policy_cross_contracts = validate_policy_cross_contracts_with_trusted_admission


def main() -> int:
    return core.main()


if __name__ == "__main__":
    raise SystemExit(main())
