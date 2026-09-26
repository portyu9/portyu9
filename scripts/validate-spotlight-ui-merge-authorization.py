#!/usr/bin/env python3
"""Project item-11 ADR/current-observation overlays around frozen Spotlight MAC proofs."""
from __future__ import annotations

import re

import spotlight_ui_merge_authorization_item10_core as core


COMPRESSED_DOWNLOAD_STEP = (
    "      - name: Download attested merge authorization artifact\n"
    "        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n"
    "        with:\n"
    "          name: spotlight-merge-authorization-${{ needs.propose.outputs.head_sha }}\n"
    "          path: merge-authorization-input\n"
    "          digest-mismatch: error\n"
)
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
MERGE_SUCCESS_FILTER = (
    'if type != "object" then error("Spotlight merge response must be an object") '
    'elif (.merged | type) != "boolean" or .merged != true then error("Spotlight merge response must contain literal merged=true") '
    'elif (.sha | type) != "string" or (.sha | test("^[0-9a-f]{40}$") | not) then error("Spotlight merge response sha must be lowercase SHA-40") '
    'elif (.message | type) != "string" or (.message | length) == 0 then error("Spotlight merge response message must be nonempty") '
    'else {merged:true,sha:.sha,message:.message} end'
)
MERGE_SUCCESS_BLOCK = (
    "          MERGE_SUCCESS_FILTER='" + MERGE_SUCCESS_FILTER + "'\n"
    '          VALIDATED_MERGE="$(jq -ce "$MERGE_SUCCESS_FILTER" <<<"$RESULT")"\n'
    '          MERGE_SHA="$(jq -r .sha <<<"$VALIDATED_MERGE")"\n'
)
LEGACY_MERGE_SUCCESS_BLOCK = (
    '          test "$(jq -r .merged <<<"$RESULT")" = "true"\n'
    '          MERGE_SHA="$(jq -r .sha <<<"$RESULT")"\n'
    '          test "$MERGE_SHA" != "null"\n'
)
MERGE_HTTP_STATUS_BLOCK = (
    '          MERGE_HTTP_RESPONSE="$(gh api --include --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge" --input merge.json)"\n'
    '          MERGE_STATUS_LINE="$(head -n 1 <<<"$MERGE_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
    '          [[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {\n'
    '            echo "ERROR: Spotlight terminal merge returned unexpected status: ${MERGE_STATUS_LINE}" >&2\n'
    '            exit 1\n'
    '          }\n'
    '          RESULT="$(sed \'1,/^[[:space:]]*$/d\' <<<"$MERGE_HTTP_RESPONSE")"\n'
)
LEGACY_MERGE_MUTATION = (
    '          RESULT="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge" --input merge.json)"\n'
)

APPROVAL_COMMENT_HTTP_STATUS_BLOCK = (
    '            APPROVAL_COMMENT_HTTP_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \\\n'
    '              -f body="$APPROVAL_BODY")"\n'
    '            APPROVAL_COMMENT_STATUS_LINE="$(head -n 1 <<<"$APPROVAL_COMMENT_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
    '            [[ "$APPROVAL_COMMENT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
    '              echo "ERROR: Spotlight automation-approval comment returned unexpected status: ${APPROVAL_COMMENT_STATUS_LINE}" >&2\n'
    '              exit 1\n'
    '            }\n'
    '            sed \'1,/^[[:space:]]*$/d\' <<<"$APPROVAL_COMMENT_HTTP_RESPONSE" > "$RUNNER_TEMP/spotlight-approval-comment-created.json"\n'
)
LEGACY_APPROVAL_COMMENT_MUTATION = (
    '            gh api --method POST "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \\\n'
    '              -f body="$APPROVAL_BODY" \\\n'
    '              > "$RUNNER_TEMP/spotlight-approval-comment-created.json"\n'
)

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
ORIGINAL_PROJECT_ITEM9 = core.project_item9
ORIGINAL_VALIDATE_MAC = core.validate_mac
ORIGINAL_VALIDATE_BUILDER_SCRIPT = core.validate_builder_script
LEGACY_PROTECTED_WORKFLOW_EVIDENCE = "          CODEQL_WORKFLOW_ID=\"$(gh api \"repos/${GITHUB_REPOSITORY}/actions/workflows/codeql.yml\" --jq .id)\"\n          DEPENDENCY_WORKFLOW_ID=\"$(gh api \"repos/${GITHUB_REPOSITORY}/actions/workflows/dependency-review.yml\" --jq .id)\"\n          PROFILE_WORKFLOW_ID=\"$(gh api \"repos/${GITHUB_REPOSITORY}/actions/workflows/profile-quality.yml\" --jq .id)\"\n          EXPECTED_IDENTITIES=\"$(jq -cn --argjson codeql \"$CODEQL_WORKFLOW_ID\" --argjson dependency \"$DEPENDENCY_WORKFLOW_ID\" --argjson profile \"$PROFILE_WORKFLOW_ID\" \\\n            '[{\"name\":\"CodeQL\",\"workflow_id\":$codeql},{\"name\":\"Dependency review\",\"workflow_id\":$dependency},{\"name\":\"Profile quality\",\"workflow_id\":$profile}] | sort_by(.name)')\"\n\n          APPROVAL_REQUESTED_RUN_IDS=\"\"\n          for attempt in $(seq 1 60); do\n            RUNS=\"$(gh api \"repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100\")\"\n            RUNS_TOTAL=\"$(jq -r '.total_count // empty' <<<\"$RUNS\")\"\n            RUNS_COUNT=\"$(jq '.[(\"workflow\" + \"_runs\")] | length' <<<\"$RUNS\")\"\n            [[ \"$RUNS_TOTAL\" =~ ^[0-9]+$ ]]\n            [[ \"$RUNS_COUNT\" =~ ^[0-9]+$ ]]\n            test \"$RUNS_TOTAL\" = \"$RUNS_COUNT\" || { echo \"Canonical Spotlight-link workflow-run response is incomplete.\" >&2; exit 1; }\n            test \"$RUNS_TOTAL\" -le 3 || { echo \"Canonical Spotlight-link workflow-run set is ambiguous.\" >&2; exit 1; }\n            ALL_SUCCESS=false\n            if [ \"$RUNS_TOTAL\" = \"3\" ]; then\n              OBSERVED_IDENTITIES=\"$(jq -c '[.[(\"workflow\" + \"_runs\")][] | {name,workflow_id}] | sort_by(.name)' <<<\"$RUNS\")\"\n              test \"$OBSERVED_IDENTITIES\" = \"$EXPECTED_IDENTITIES\" || { echo \"Canonical Spotlight-link workflow-run identities changed.\" >&2; exit 1; }\n              ALL_SUCCESS=true\n              for NAME in \"CodeQL\" \"Dependency review\" \"Profile quality\"; do\n                case \"$NAME\" in\n                  \"CodeQL\") EXPECTED_ID=\"$CODEQL_WORKFLOW_ID\" ;;\n                  \"Dependency review\") EXPECTED_ID=\"$DEPENDENCY_WORKFLOW_ID\" ;;\n                  \"Profile quality\") EXPECTED_ID=\"$PROFILE_WORKFLOW_ID\" ;;\n                  *) exit 1 ;;\n                esac\n                RUN_COUNT=\"$(jq --arg name \"$NAME\" --argjson workflow_id \"$EXPECTED_ID\" '[.[(\"workflow\" + \"_runs\")][] | select(.name == $name and .workflow_id == $workflow_id)] | length' <<<\"$RUNS\")\"\n                test \"$RUN_COUNT\" = \"1\"\n                RUN=\"$(jq -c --arg name \"$NAME\" --argjson workflow_id \"$EXPECTED_ID\" '[.[(\"workflow\" + \"_runs\")][] | select(.name == $name and .workflow_id == $workflow_id)][0]' <<<\"$RUNS\")\"\n                RUN_ID=\"$(jq -r .id <<<\"$RUN\")\"\n                CHECK_SUITE_ID=\"$(jq -r .check_suite_id <<<\"$RUN\")\"\n                RUN_ATTEMPT=\"$(jq -r .run_attempt <<<\"$RUN\")\"\n                STATUS=\"$(jq -r .status <<<\"$RUN\")\"\n                CONCLUSION=\"$(jq -r '.conclusion // \"\"' <<<\"$RUN\")\"\n                [[ \"$RUN_ID\" =~ ^[1-9][0-9]*$ ]]\n                [[ \"$CHECK_SUITE_ID\" =~ ^[1-9][0-9]*$ ]]\n                [[ \"$RUN_ATTEMPT\" =~ ^[1-9][0-9]*$ ]]\n                test \"$(jq -r .head_sha <<<\"$RUN\")\" = \"$HEAD_SHA\"\n                test \"$(jq -r .head_branch <<<\"$RUN\")\" = \"$CANDIDATE_BRANCH\"\n                test \"$(jq -r .event <<<\"$RUN\")\" = \"pull_request\"\n                test \"$(jq -r .workflow_id <<<\"$RUN\")\" = \"$EXPECTED_ID\"\n                test \"$(jq -r .repository.full_name <<<\"$RUN\")\" = \"$GITHUB_REPOSITORY\"\n                test \"$(jq -r .head_repository.full_name <<<\"$RUN\")\" = \"$GITHUB_REPOSITORY\"\n                case \"$NAME\" in\n                  \"CodeQL\") CODEQL_RUN_ID=\"$RUN_ID\"; CODEQL_CHECK_SUITE_ID=\"$CHECK_SUITE_ID\" ;;\n                  \"Dependency review\") DEPENDENCY_RUN_ID=\"$RUN_ID\"; DEPENDENCY_CHECK_SUITE_ID=\"$CHECK_SUITE_ID\" ;;\n                  \"Profile quality\") PROFILE_RUN_ID=\"$RUN_ID\"; PROFILE_CHECK_SUITE_ID=\"$CHECK_SUITE_ID\" ;;\n                  *) exit 1 ;;\n                esac\n                if [ \"$STATUS\" = \"action_required\" ] || [ \"$STATUS\" = \"waiting\" ] || [ \"$CONCLUSION\" = \"action_required\" ]; then\n                  case \" $APPROVAL_REQUESTED_RUN_IDS \" in\n                    *\" $RUN_ID \"*) : ;;\n                    *)\n                      gh api --method POST \"repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve\" >/dev/null\n                      APPROVAL_REQUESTED_RUN_IDS=\"${APPROVAL_REQUESTED_RUN_IDS} ${RUN_ID}\"\n                      APPROVAL_ENTRY=\"$(jq -cn --arg name \"$NAME\" --argjson workflow \"$EXPECTED_ID\" --argjson run \"$RUN_ID\" \\\n                        --argjson attempt \"$RUN_ATTEMPT\" --argjson suite \"$CHECK_SUITE_ID\" --arg head \"$HEAD_SHA\" \\\n                        '{workflowName:$name,workflowId:$workflow,runId:$run,runAttempt:$attempt,checkSuiteId:$suite,headSha:$head}')\"\n                      APPROVAL_REQUESTS_JSON=\"$(jq -c --argjson entry \"$APPROVAL_ENTRY\" '. + [$entry]' <<<\"$APPROVAL_REQUESTS_JSON\")\"\n                      echo \"approval_requests_json=$APPROVAL_REQUESTS_JSON\" >> \"$GITHUB_OUTPUT\"\n                      ;;\n                  esac\n                  ALL_SUCCESS=false\n                elif [ \"$STATUS\" = \"completed\" ] && [ \"$CONCLUSION\" = \"success\" ]; then\n                  :\n                elif [ \"$STATUS\" = \"completed\" ]; then\n                  echo \"Canonical Spotlight-link PR workflow failed: $NAME ($CONCLUSION).\" >&2\n                  exit 1\n                else\n                  ALL_SUCCESS=false\n                fi\n              done\n            fi\n            if [ \"$ALL_SUCCESS\" = \"true\" ]; then break; fi\n            test \"$attempt\" -lt 60\n            sleep 10\n          done\n          test \"$ALL_SUCCESS\" = \"true\"\n\n"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_merge_success_fixture(payload: object) -> dict[str, object]:
    """Reference model for the terminal merge response's fixed jq success boundary."""
    require(isinstance(payload, dict), "Spotlight merge response must be an object")
    require(type(payload.get("merged")) is bool and payload["merged"] is True,
            "Spotlight merge response must contain literal merged=true")
    sha = payload.get("sha")
    require(isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha) is not None,
            "Spotlight merge response sha must be lowercase SHA-40")
    message = payload.get("message")
    require(isinstance(message, str) and len(message) > 0,
            "Spotlight merge response message must be nonempty")
    return {"merged": True, "sha": sha, "message": message}


def project_spotlight_pr_response_evidence_to_legacy(sync: str) -> str:
    """Project modern PR/reviewer response schema overlays out of the frozen item-9 proof."""
    helper_start = "          validate_spotlight_open_pr_object() {\n"
    for next_marker in (
        "          REF_CREATED=false\n",
        "          APPROVAL_REQUESTS_JSON='[]'\n",
    ):
        require(
            sync.count(next_marker) == 1,
            f"Spotlight PR-response projection next anchor changed: {next_marker.strip()}",
        )
        next_pos = sync.index(next_marker)
        helper_pos = sync.rfind(helper_start, 0, next_pos)
        require(
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
        (
            '            REQUESTED_REVIEWER_HTTP_RESPONSE="$(gh api --include --method POST "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers" \\\n'
            '              -f \'reviewers[]=portyu9\')"\n'
            '            REQUESTED_REVIEWER_STATUS_LINE="$(head -n 1 <<<"$REQUESTED_REVIEWER_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
            '            [[ "$REQUESTED_REVIEWER_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
            '              echo "ERROR: Spotlight reviewer request returned unexpected status: ${REQUESTED_REVIEWER_STATUS_LINE}" >&2\n'
            '              exit 1\n'
            '            }\n'
            '            sed \'1,/^[[:space:]]*$/d\' <<<"$REQUESTED_REVIEWER_HTTP_RESPONSE" > requested-reviewer.json\n',
            '            gh api --method POST "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers" \\\n'
            '              -f \'reviewers[]=portyu9\' > requested-reviewer.json\n',
        ),
        (
            '          REQUESTED="$(jq \'[.requested_reviewers[] | select(.login == "portyu9")] | length\' <<<"$PR")"\n',
            '          REQUESTED="$(jq \'[.requested_reviewers[]? | select(.login == "portyu9")] | length\' <<<"$PR")"\n',
        ),
        (
            '            REQUESTED_REVIEWER_RESPONSE="$(cat requested-reviewer.json)"\n'
            '            validate_spotlight_reviewer_request_response "$REQUESTED_REVIEWER_RESPONSE" "$PR_NUMBER" "$SOURCE_SHA" "$CANDIDATE_BRANCH" "$HEAD_SHA"\n'
            '            test "$(jq \'[.requested_reviewers[] | select(.login == "portyu9")] | length\' <<<"$REQUESTED_REVIEWER_RESPONSE")" = "1"\n',
            '            test "$(jq \'[.requested_reviewers[]? | select(.login == "portyu9")] | length\' requested-reviewer.json)" = "1"\n',
        ),
    )
    for hardened, legacy in overlays:
        require(
            sync.count(hardened) == 1,
            f"Spotlight PR-response projection hardened anchor changed: {hardened.splitlines()[0]}",
        )
        sync = sync.replace(hardened, legacy, 1)
    require(
        "validate_spotlight_open_pr_object" not in sync
        and "validate_spotlight_reviewer_request_response" not in sync
        and "validate_spotlight_pull_list_item" not in sync,
        "Spotlight PR-response projection left modern runtime schema bytes in the frozen item-9 view",
    )
    return sync


def project_protected_workflow_evidence_to_legacy(sync: str) -> str:
    start_marker = (
        '          gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/codeql.yml" \\\n'
    )
    end_marker = (
        '          PRS="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:'
        '${CANDIDATE_BRANCH}&base=main&per_page=10")"\n'
    )
    require(sync.count(start_marker) == 1,
            "Spotlight protected workflow evidence projection start anchor changed")
    start = sync.index(start_marker)
    require(sync[start:].count(end_marker) == 1,
            "Spotlight protected workflow evidence projection end anchor changed")
    end = sync.index(end_marker, start)
    current = sync[start:end]
    require(
        'error("Spotlight protected workflow-run response must be an object")' in current
        and '> "$RUNNER_TEMP/spotlight-protected-workflow-runs-normalized.json"' in current,
        "Spotlight protected workflow evidence projection cannot identify hardened overlay",
    )
    return sync[:start] + LEGACY_PROTECTED_WORKFLOW_EVIDENCE + sync[end:]


def project_merge_http_status_to_legacy(sync: str) -> str:
    require(sync.count(MERGE_HTTP_STATUS_BLOCK) == 1,
            "Spotlight terminal merge-status projection cannot isolate exact HTTP wrapper")
    require(LEGACY_MERGE_MUTATION not in sync,
            "Spotlight terminal merge-status projection found both hardened and legacy mutations")
    return sync.replace(MERGE_HTTP_STATUS_BLOCK, LEGACY_MERGE_MUTATION, 1)


def project_approval_comment_http_status_to_legacy(sync: str) -> str:
    require(sync.count(APPROVAL_COMMENT_HTTP_STATUS_BLOCK) == 1,
            "Spotlight approval-comment status projection cannot isolate exact HTTP wrapper")
    require(LEGACY_APPROVAL_COMMENT_MUTATION not in sync,
            "Spotlight approval-comment status projection found both hardened and legacy mutations")
    return sync.replace(APPROVAL_COMMENT_HTTP_STATUS_BLOCK, LEGACY_APPROVAL_COMMENT_MUTATION, 1)


def project_merge_success_response_to_legacy(sync: str) -> str:
    require(sync.count(MERGE_SUCCESS_BLOCK) == 1,
            "Spotlight merge-success response projection cannot isolate the exact validated block")
    require(LEGACY_MERGE_SUCCESS_BLOCK not in sync,
            "Spotlight merge-success response projection found both hardened and legacy consumers")
    return sync.replace(MERGE_SUCCESS_BLOCK, LEGACY_MERGE_SUCCESS_BLOCK, 1)


def validate_mac_with_merge_http_projection(sync: str) -> None:
    """Project only the new transport wrapper before rerunning frozen item-10 MAC proof."""
    ORIGINAL_VALIDATE_MAC(project_merge_http_status_to_legacy(sync))


def validate_merge_success_response_overlay(sync: str) -> None:
    merge = core.job_block(sync, "merge", None)
    require(merge.count(MERGE_HTTP_STATUS_BLOCK) == 1,
            "Spotlight terminal merge HTTP-status block changed")
    require(merge.count(MERGE_SUCCESS_BLOCK) == 1,
            "Spotlight terminal merge-success response schema block changed")
    require(
        'RESULT="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"' not in merge,
        "Spotlight terminal merge must not consume a response-blind mutation",
    )
    require(merge.count('<<<"$RESULT"') == 1,
            "Spotlight terminal merge may consume the raw merge response only through the canonical validator")
    require('test "$(jq -r .merged <<<"$RESULT")" = "true"' not in merge and
            'MERGE_SHA="$(jq -r .sha <<<"$RESULT")"' not in merge,
            "Spotlight terminal merge retained a direct unvalidated merge-response consumer")

    mutation = merge.index('MERGE_HTTP_RESPONSE="$(gh api --include --method PUT ')
    status = merge.index('MERGE_STATUS_LINE="$(head -n 1 <<<"$MERGE_HTTP_RESPONSE" | tr -d \'\\r\')"', mutation)
    guard = merge.index('[[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {', status)
    extraction = merge.index('RESULT="$(sed \'1,/^[[:space:]]*$/d\' <<<"$MERGE_HTTP_RESPONSE")"', guard)
    validation = merge.index('VALIDATED_MERGE="$(jq -ce "$MERGE_SUCCESS_FILTER" <<<"$RESULT")"', extraction)
    normalized_sha = merge.index('MERGE_SHA="$(jq -r .sha <<<"$VALIDATED_MERGE")"')
    merged_pr = merge.index('MERGED_PR="$(gh api ')
    current_main_ref = merge.index(
        'CURRENT_MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"',
        merged_pr,
    )
    current_main_schema = merge.index(
        'validate_git_ref_object "$CURRENT_MAIN_REF_RESPONSE" "refs/heads/main" "$MERGE_SHA"',
        current_main_ref,
    )
    current_main = merge.index(
        'CURRENT_MAIN_SHA="$(jq -r .object.sha <<<"$CURRENT_MAIN_REF_RESPONSE")"',
        current_main_schema,
    )
    cleanup = merge.index('CANDIDATE_REFS="$(gh api ', current_main)
    require(
        mutation < status < guard < extraction < validation < normalized_sha < merged_pr
        < current_main_ref < current_main_schema < current_main < cleanup,
        "Spotlight merge-success validation must precede post-merge proof, typed current-main acceptance, and cleanup",
    )
    require('test "$CURRENT_MAIN_SHA" = "$MERGE_SHA"' in merge and
            'echo "merge_sha=$MERGE_SHA" >> "$GITHUB_OUTPUT"' in merge,
            "Spotlight must consume only the validated merge SHA for current-main proof and downstream evidence")


def expect_merge_success_fixture_failure(payload: object, expected: str) -> None:
    try:
        validate_merge_success_fixture(payload)
    except ValueError as exc:
        require(expected in str(exc), f"Spotlight merge-success fixture failed for wrong reason: {exc}")
    else:
        raise ValueError(f"Spotlight merge-success fixture unexpectedly passed: {expected}")


def self_test_merge_success_response_overlay(sync: str) -> None:
    validate_merge_success_response_overlay(sync)
    canonical = {
        "merged": True,
        "sha": "a" * 40,
        "message": "Pull Request successfully merged",
        "futureField": {"ignored": True},
    }
    require(
        validate_merge_success_fixture(canonical)
        == {"merged": True, "sha": "a" * 40, "message": "Pull Request successfully merged"},
        "Spotlight merge-success normalization must discard unreviewed response members",
    )
    for payload, expected in (
        ([], "must be an object"),
        ({"merged": 1, "sha": "a" * 40, "message": "ok"}, "literal merged=true"),
        ({"merged": False, "sha": "a" * 40, "message": "ok"}, "literal merged=true"),
        ({"merged": True, "sha": "A" * 40, "message": "ok"}, "lowercase SHA-40"),
        ({"merged": True, "sha": "a" * 39, "message": "ok"}, "lowercase SHA-40"),
        ({"merged": True, "sha": "a" * 40, "message": ""}, "message must be nonempty"),
        ({"merged": True, "sha": "a" * 40, "message": None}, "message must be nonempty"),
    ):
        expect_merge_success_fixture_failure(payload, expected)

    for weakened, expected in (
        (
            sync.replace(
                'gh api --include --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"',
                'gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"',
                1,
            ),
            "HTTP-status block changed",
        ),
        (
            sync.replace(
                '[[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {',
                '[[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
                1,
            ),
            "HTTP-status block changed",
        ),
        (
            sync.replace(
                MERGE_HTTP_STATUS_BLOCK,
                MERGE_HTTP_STATUS_BLOCK.replace(
                    '          [[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {\n'
                    '            echo "ERROR: Spotlight terminal merge returned unexpected status: ${MERGE_STATUS_LINE}" >&2\n'
                    '            exit 1\n'
                    '          }\n'
                    '          RESULT="$(sed \'1,/^[[:space:]]*$/d\' <<<"$MERGE_HTTP_RESPONSE")"\n',
                    '          RESULT="$(sed \'1,/^[[:space:]]*$/d\' <<<"$MERGE_HTTP_RESPONSE")"\n'
                    '          [[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {\n'
                    '            echo "ERROR: Spotlight terminal merge returned unexpected status: ${MERGE_STATUS_LINE}" >&2\n'
                    '            exit 1\n'
                    '          }\n',
                ),
                1,
            ),
            "HTTP-status block changed",
        ),
    ):
        try:
            validate_merge_success_response_overlay(weakened)
        except ValueError as exc:
            require(expected in str(exc),
                    f"Spotlight merge-status self-test failed for wrong reason: {exc}")
        else:
            raise ValueError("Spotlight merge-status self-test accepted weakened transport validation")

    weakened = sync.replace(
        'MERGE_SHA="$(jq -r .sha <<<"$VALIDATED_MERGE")"',
        'MERGE_SHA="$(jq -r .sha <<<"$RESULT")"',
        1,
    )
    try:
        validate_merge_success_response_overlay(weakened)
    except ValueError as exc:
        require("schema block changed" in str(exc) or "unvalidated" in str(exc),
                f"Spotlight raw-response self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("Spotlight merge-success self-test accepted raw RESULT consumption")


def validate_terminal_object_schema_overlay(sync: str) -> None:
    merge = core.job_block(sync, "merge", None)
    fn_start = merge.index("          validate_terminal_pr_object() {\n")
    pre_pr = merge.index('          PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"')
    fn = merge[fn_start:pre_pr]
    for fragment in (
        '(type == "object") and',
        '(.number | type == "number" and . == floor and . == $pr) and',
        '((.user | type) == "object" and (.user.login | type) == "string" and (.user.login | length) > 0) and',
        '(.state as $state | ($state | type) == "string" and ($state == "open" or $state == "closed")) and',
        '(.draft | type == "boolean") and',
        '(.merged | type == "boolean") and',
        '(.maintainer_can_modify | type == "boolean") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$"))',
        '(.body | type == "string" and length > 0) and',
        'has("merge_commit_sha")',
    ):
        require(fragment in fn, f"Spotlight terminal PR schema is missing: {fragment}")

    pre_validate = merge.index('          validate_terminal_pr_object "$PR"', pre_pr)
    pre_consume = merge.index('          test "$(jq -r \'.user.login\' <<<"$PR")"', pre_pr)
    require(pre_pr < pre_validate < pre_consume,
            "Spotlight terminal pre-merge PR fields are consumed before schema validation")
    for fragment in (
        'test "$(jq -r \'.user.login\' <<<"$PR")" = "github-actions[bot]"',
        'test "$(jq -r .draft <<<"$PR")" = "false"',
        'test "$(jq -r .merged <<<"$PR")" = "false"',
        'test "$(jq -r .base.sha <<<"$PR")" = "$BASE_SHA"',
        'test "$(jq -r .title <<<"$PR")" = "chore: sync rotating Spotlight links"',
    ):
        require(fragment in merge, f"Spotlight terminal exact pre-merge PR identity is missing: {fragment}")

    files_fetch = merge.index('          FILES="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100")"')
    files_schema = merge.index('            (type == "array") and', files_fetch)
    files_consume = merge.index('          test "$(jq \'length\' <<<"$FILES")" = "1"', files_schema)
    files_block = merge[files_fetch:files_consume]
    for fragment in (
        '(length == 1) and',
        '(.filename | type == "string" and . == "README.md")',
        '(.status | type == "string" and . == "modified")',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$"))',
        '(.additions | type == "number" and . == floor and . >= 0)',
        '(.deletions | type == "number" and . == floor and . >= 0)',
        '(.changes | type == "number" and . == floor and . >= 0)',
    ):
        require(fragment in files_block, f"Spotlight terminal changed-file schema is missing: {fragment}")
    require(files_fetch < files_schema < files_consume,
            "Spotlight terminal file evidence is consumed before schema validation")

    commit_fetch = merge.index('          CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"')
    commit_schema = merge.index('          jq -e --arg head "$HEAD_SHA" \'', commit_fetch)
    commit_consume = merge.index('          test "$(jq \'.parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"', commit_schema)
    commit_block = merge[commit_fetch:commit_consume]
    for fragment in (
        '(type == "object") and',
        '(.sha | type == "string" and . == $head) and',
        '(.parents | type == "array" and length == 1',
        '(.author | type == "object"',
        '(.committer | type == "object"',
        '(.message | type == "string" and length > 0)',
    ):
        require(fragment in commit_block, f"Spotlight terminal candidate-commit schema is missing: {fragment}")
    require(commit_fetch < commit_schema < commit_consume,
            "Spotlight terminal commit evidence is consumed before schema validation")

    merged_fetch = merge.index('          MERGED_PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"')
    merged_validate = merge.index('          validate_terminal_pr_object "$MERGED_PR"', merged_fetch)
    merged_identity = merge.index('          jq -e --argjson pr "$PR_NUMBER" --arg merge "$MERGE_SHA"', merged_validate)
    merged_consume = merge.index('          test "$(jq -r .user.login <<<"$MERGED_PR")"', merged_identity)
    merge_sha_bind = merge.index('          test "$(jq -r .merge_commit_sha <<<"$MERGED_PR")" = "$MERGE_SHA"', merged_consume)
    current_main_ref = merge.index(
        '          CURRENT_MAIN_REF_RESPONSE="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"',
        merge_sha_bind,
    )
    current_main_schema = merge.index(
        '          validate_git_ref_object "$CURRENT_MAIN_REF_RESPONSE" "refs/heads/main" "$MERGE_SHA"',
        current_main_ref,
    )
    current_main = merge.index(
        '          CURRENT_MAIN_SHA="$(jq -r .object.sha <<<"$CURRENT_MAIN_REF_RESPONSE")"',
        current_main_schema,
    )
    cleanup = merge.index('          CANDIDATE_REFS="$(gh api ', current_main)
    identity_block = merge[merged_identity:merged_consume]
    for fragment in (
        '(.number == $pr) and',
        '(.user.login == "github-actions[bot]") and',
        '(.merged == true) and',
        '(.state == "closed") and',
        '(.merge_commit_sha | type == "string" and test("^[0-9a-f]{40}$") and . == $merge) and',
        '(.base.ref == "main" and .base.sha == $base) and',
        '(.head.ref == $branch and .head.sha == $head and .head.repo.full_name == $repo)',
    ):
        require(fragment in identity_block,
                f"Spotlight post-merge canonical PR identity is missing: {fragment}")
    require(
        merged_fetch < merged_validate < merged_identity < merged_consume < merge_sha_bind
        < current_main_ref < current_main_schema < current_main < cleanup,
        "Spotlight post-merge PR schema/identity/SHA binding must precede typed current-main acceptance and cleanup",
    )
    require(merge.count('validate_terminal_pr_object "$PR"') == 1
            and merge.count('validate_terminal_pr_object "$MERGED_PR"') == 1,
            "Spotlight terminal PR schema must validate exactly the pre/post merge snapshots")


def self_test_terminal_object_schema_overlay(sync: str) -> None:
    validate_terminal_object_schema_overlay(sync)
    merge_start = sync.index("  merge:\n")
    prefix = sync[:merge_start]
    merge = sync[merge_start:]
    mutations = (
        ('              (type == "object") and\n              (.number | type == "number"',
         '              (type == "array") and\n              (.number | type == "number"'),
        ('              (.draft | type == "boolean") and', '              (.draft | type == "number") and'),
        ('              (.body | type == "string" and length > 0) and',
         '              (.body | type == "number") and'),
        ('            (type == "array") and\n            (length == 1) and',
         '            (type == "object") and\n            (length == 1) and'),
        ('              (.status | type == "string" and . == "modified")',
         '              (.status | type == "string" and . == "added")'),
        ('(.parents | type == "array" and length == 1', '(.parents | type == "array" and length == 2'),
        ('          validate_terminal_pr_object "$MERGED_PR"\n', ''),
        ('            (.merge_commit_sha | type == "string" and test("^[0-9a-f]{40}$") and . == $merge) and',
         '            (.merge_commit_sha | type == "number") and'),
        ('          test "$(jq -r .merge_commit_sha <<<"$MERGED_PR")" = "$MERGE_SHA"\n', ''),
    )
    for old, new in mutations:
        require(merge.count(old) == 1,
                f"Spotlight terminal schema self-test anchor is missing or ambiguous inside merge job: {old}")
        mutated = prefix + merge.replace(old, new, 1)
        try:
            validate_terminal_object_schema_overlay(mutated)
        except (ValueError, IndexError):
            pass
        else:
            raise ValueError(f"Spotlight terminal schema self-test accepted weakened evidence boundary: {old}")

def strip_adr_tail(workflow: str, label: str) -> str:
    marker = "  decision_receipt:\n"
    require(workflow.count(marker) == 1,
            f"{label} item-11 projection cannot isolate ADR preparer")
    start = workflow.index(marker)
    tail = workflow[start:]
    require(tail.count("  decision_receipt_attest:\n") == 1,
            f"{label} item-11 projection cannot isolate ADR signer")
    return workflow[:start]


def project_profile_item9(stats: str) -> str:
    marker = "  dispatch:\n"
    require(stats.count(marker) == 1,
            "Profile Stats item-9 dispatcher projection cannot isolate dispatch job")
    return stats[:stats.index(marker)] + LEGACY_PROFILE_DISPATCH


def project_native_review_gate_to_item10_order(sync: str) -> str:
    """Relocate item-44 proof blocks only inside the synthetic item-10/item-9 view."""
    checks_start_marker = (
        '          CHECKS="$(gh api -H \'Accept: application/vnd.github+json\' '
        '"repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs?filter=latest&per_page=100")"\n'
    )
    checks_end_marker = (
        '          echo "Spotlight terminal stage: required-checks-and-native-review-gate-verified" >&2\n\n'
    )
    require(sync.count(checks_start_marker) == 1 and sync.count(checks_end_marker) == 1,
            "Spotlight item-44 projection cannot isolate the canonical native-gate check proof")
    checks_start = sync.index(checks_start_marker)
    checks_end = sync.index(checks_end_marker, checks_start) + len(checks_end_marker)
    checks_block = sync[checks_start:checks_end]
    projected = sync[:checks_start] + sync[checks_end:]

    certificate_marker = '          CERTIFICATE="merge-authorization-input/spotlight-merge-authorization.json"\n'
    require(projected.count(certificate_marker) == 1,
            "Spotlight item-44 projection cannot restore the pre-certificate check proof")
    projected = projected.replace(certificate_marker, checks_block + certificate_marker, 1)

    roots_block = (
        '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"\n'
        '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated" --jq .object.sha)" = "$GENERATED_SHA"\n'
        '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha)" = "$HEAD_SHA"\n'
        '          echo "Spotlight terminal stage: pre-merge-roots-verified" >&2\n\n'
    )
    require(projected.count(roots_block) == 1,
            "Spotlight item-44 projection cannot isolate the relocated pre-merge root proof")
    projected = projected.replace(roots_block, "", 1)
    review_marker = '          REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"\n'
    merge_start = projected.index("  merge:\n")
    review_pos = projected.index(review_marker, merge_start)
    projected = projected[:review_pos] + roots_block + projected[review_pos:]
    return projected


def project_strict_pull_review_schema_to_legacy(sync: str) -> str:
    """Project item-31 review-schema hardening away only for the frozen item-9 proof."""
    approve_loop = "          for REVIEW_ATTEMPT in $(seq 1 24); do\n"
    require(sync.count(approve_loop) == 1,
            "Spotlight item-31 projection cannot isolate the approval review loop")
    loop_pos = sync.index(approve_loop)
    approve_start_marker = (
        '            REVIEW_PAGES="$(gh api --paginate --slurp '
        '"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100")"\n'
    )
    approve_end_marker = '            [[ "$PORTYU9_APPROVAL_COUNT" =~ ^[0-9]+$ ]]\n'
    approve_start = sync.index(approve_start_marker, loop_pos)
    approve_end = sync.index(approve_end_marker, approve_start)
    approve_block = sync[approve_start:approve_end]
    for fragment in (
        'ERROR: malformed or incomplete paginated pull-review evidence.',
        'has("commit_id") and',
        'has("body") and',
        '| unique |',
        'REVIEWS="$(jq -c \'[.[][]]\' <<<"$REVIEW_PAGES")"',
    ):
        require(fragment in approve_block,
                f"Spotlight item-31 approval projection lost strict review-schema guard: {fragment}")
    approve_legacy = (
        '            REVIEWS="$(gh api --paginate --slurp '
        '"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100")"\n'
        '            PORTYU9_APPROVAL_COUNT="$(jq --arg head "$HEAD_SHA" --arg marker "$REVIEW_MARKER" '
        '\'[.[][] | select(.user.login == "portyu9" and .state == "APPROVED" and .commit_id == $head '
        'and ((.body // "") | contains($marker)))] | length\' <<<"$REVIEWS")"\n'
    )
    projected = sync[:approve_start] + approve_legacy + sync[approve_end:]

    merge_start = projected.index("  merge:\n")
    review_marker = '          REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"\n'
    review_pos = projected.index(review_marker, merge_start) + len(review_marker)
    merge_start_marker = (
        '          REVIEW_PAGES="$(gh api --paginate --slurp '
        '"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100")"\n'
    )
    merge_end_marker = '          [[ "$PORTYU9_APPROVAL_COUNT" =~ ^[0-9]+$ ]]\n'
    schema_start = projected.index(merge_start_marker, review_pos)
    schema_end = projected.index(merge_end_marker, schema_start)
    merge_block = projected[schema_start:schema_end]
    for fragment in (
        'ERROR: malformed or incomplete paginated pull-review evidence.',
        'has("commit_id") and',
        'has("body") and',
        '| unique |',
        'LATEST_MANUAL_DECISIVE_STATE=',
    ):
        require(fragment in merge_block,
                f"Spotlight item-31 merge projection lost strict review-schema guard: {fragment}")
    merge_legacy = (
        '          REVIEWS="$(gh api --paginate --slurp '
        '"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100")"\n'
        '          PORTYU9_APPROVAL_COUNT="$(jq --arg head "$HEAD_SHA" --arg marker "$REVIEW_MARKER" '
        '\'[.[][] | select(.user.login == "portyu9" and .state == "APPROVED" and .commit_id == $head '
        'and ((.body // "") | contains($marker)))] | length\' <<<"$REVIEWS")"\n'
        '          LATEST_MANUAL_DECISIVE_STATE="$(jq -r --arg head "$HEAD_SHA" --arg marker "$REVIEW_MARKER" '
        '\'[.[][] | select(.user.login == "portyu9" and .commit_id == $head and '
        '(.state == "APPROVED" or .state == "CHANGES_REQUESTED") and '
        '(((.body // "") | contains($marker)) | not))] | sort_by(.id) | '
        'if length == 0 then "" else .[-1].state end\' <<<"$REVIEWS")"\n'
    )
    return projected[:schema_start] + merge_legacy + projected[schema_end:]



def project_ancestry_supersession_to_same_base(sync: str) -> str:
    """Project the item-912 ancestry overlay back to the accepted #910 same-base contract."""
    counter = '          ANCESTRY_PROVEN_STALE=0\n'
    require(sync.count(counter) == 1,
            "Spotlight item-9 projection cannot isolate ancestry stale counter")
    sync = sync.replace(counter, "", 1)

    classify_start = '            SAME_BASE_SUPERSEDED=false\n'
    classify_end = '            COMMITTER_DATE="$(jq -r .committer.date <<<"$CANDIDATE_COMMIT")"\n'
    require(sync.count(classify_start) == 1 and sync.count(classify_end) == 1,
            "Spotlight item-9 projection cannot isolate ancestry classification block")
    start = sync.index(classify_start)
    end = sync.index(classify_end, start)
    current = sync[start:end]
    for fragment in (
        '            ANCESTRY_PROVEN_SUPERSEDED=false\n',
        '              ANCESTRY_COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${PARENT_SHA}...${BASE_SHA}")"\n',
        '              jq -e --arg parent "$PARENT_SHA" --arg base "$BASE_SHA" \'\n',
        '                ANCESTRY_PROVEN_SUPERSEDED=true\n',
    ):
        require(fragment in current,
                f"Spotlight item-9 ancestry projection lost reviewed runtime fragment: {fragment}")
    projected = (
        '            SAME_BASE_SUPERSEDED=false\n'
        '            if [ "$PARENT_SHA" = "$BASE_SHA" ]; then\n'
        '              SAME_BASE_SUPERSEDED=true\n'
        '            fi\n\n'
    )
    sync = sync[:start] + projected + sync[end:]

    current_guard = (
        'if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ] &&\n'
        '               [ "$SAME_BASE_SUPERSEDED" != "true" ] &&\n'
        '               [ "$ANCESTRY_PROVEN_SUPERSEDED" != "true" ]; then'
    )
    same_base_guard = (
        'if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ] && '
        '[ "$SAME_BASE_SUPERSEDED" != "true" ]; then'
    )
    require(sync.count(current_guard) == 1,
            "Spotlight item-9 projection cannot isolate ancestry-aware age guard")
    require(same_base_guard not in sync,
            "Spotlight item-9 projection found both ancestry-aware and same-base age guards")
    sync = sync.replace(current_guard, same_base_guard, 1)

    ancestry_cleanup = (
        '            if [ "$ANCESTRY_PROVEN_SUPERSEDED" = "true" ]; then\n'
        '              ANCESTRY_PROVEN_STALE=$((ANCESTRY_PROVEN_STALE + 1))\n'
        '            fi\n'
    )
    require(sync.count(ancestry_cleanup) == 1,
            "Spotlight item-9 projection cannot isolate ancestry cleanup counter")
    sync = sync.replace(ancestry_cleanup, "", 1)

    ancestry_summary = (
        '            echo "- ancestry-proven old-base candidates cleaned immediately: '
        '**$ANCESTRY_PROVEN_STALE**"\n'
    )
    current_young_summary = (
        '            echo "- unproven/divergent candidates below 30-minute stale floor preserved: '
        '**$PRESERVED_YOUNG**"\n'
    )
    same_base_young_summary = (
        '            echo "- different-base candidates below 30-minute stale floor preserved: '
        '**$PRESERVED_YOUNG**"\n'
    )
    require(sync.count(ancestry_summary) == 1 and sync.count(current_young_summary) == 1,
            "Spotlight item-9 projection cannot isolate ancestry summary evidence")
    sync = sync.replace(ancestry_summary, "", 1)
    sync = sync.replace(current_young_summary, same_base_young_summary, 1)
    return sync


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
    require(
        sync.count(helper) == 4,
        "Spotlight item-9 projection cannot isolate four privileged Git-ref validators",
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
        require(
            projected.count(hardened) == expected_count,
            f"Spotlight item-9 Git-ref projection topology changed for: {legacy.strip()}",
        )
        projected = projected.replace(hardened, legacy)
    return projected



def project_spotlight_readme_contents_to_legacy(sync: str) -> str:
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
        require(
            projected.count(start_marker) == 1,
            f"Spotlight item-9 README Contents projection start anchor changed: {start_marker}",
        )
        start = projected.index(start_marker)
        end_start = projected.index(end_marker, start)
        end = end_start + len(end_marker)
        projected = projected[:start] + legacy + projected[end:]
    return projected



def project_spotlight_terminal_protected_runs_to_legacy(sync: str) -> str:
    start_marker = "          normalize_protected_certificate_run() {\n"
    end_marker = "          EXPECTED_CERTIFICATE_RUNS="
    require(
        sync.count(start_marker) == 1 and sync.count(end_marker) == 1,
        "Spotlight UI terminal protected-run projection anchors changed",
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


def project_item9(sync: str) -> str:
    sync = project_spotlight_pr_response_evidence_to_legacy(sync)
    sync = project_spotlight_terminal_protected_runs_to_legacy(sync)
    sync = project_spotlight_readme_contents_to_legacy(sync)
    sync = project_spotlight_privileged_refs_to_legacy(sync)
    sync = project_protected_workflow_evidence_to_legacy(sync)
    sync = project_ancestry_supersession_to_same_base(sync)
    current_age_guard = (
        'if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ] && '
        '[ "$SAME_BASE_SUPERSEDED" != "true" ]; then'
    )
    legacy_age_guard = 'if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ]; then'
    require(sync.count(current_age_guard) == 1,
            "Spotlight item-9 projection cannot isolate same-base supersession age guard")
    require(legacy_age_guard not in sync,
            "Spotlight item-9 projection found both same-base and legacy age guards")
    sync = sync.replace(current_age_guard, legacy_age_guard, 1)
    sync = project_approval_comment_http_status_to_legacy(sync)
    sync = project_merge_http_status_to_legacy(sync)
    sync = project_merge_success_response_to_legacy(sync)
    sync = project_strict_pull_review_schema_to_legacy(sync)
    sync = project_native_review_gate_to_item10_order(sync)
    legacy = ORIGINAL_PROJECT_ITEM9(sync)
    require(legacy.count(IMMUTABLE_ANCHOR) == 1,
            "Spotlight item-9 immutable-candidate projection anchor changed")
    legacy = legacy.replace(IMMUTABLE_ANCHOR, IMMUTABLE_PROJECTED, 1)
    require(legacy.count(CURRENT_MAIN_CAPTURE) == 1,
            "Spotlight item-9 current-main observation projection changed")
    legacy = legacy.replace(CURRENT_MAIN_CAPTURE, LEGACY_MAIN_PROOF, 1)
    require(legacy.count(CURRENT_MAIN_OUTPUT) == 1 and legacy.count(CURRENT_MAIN_ECHO) == 1,
            "Spotlight item-9 current-main output projection changed")
    legacy = legacy.replace(CURRENT_MAIN_OUTPUT, "", 1)
    legacy = legacy.replace(CURRENT_MAIN_ECHO, "", 1)
    native_expected = (
        '{name:"trusted-governed-bot-review",check_suite_id:$profile,status:"completed",'
        'conclusion:"success",head_sha:$head},'
    )
    require(legacy.count(native_expected) == 1,
            "Spotlight item-9 native review-gate expected-check projection changed")
    legacy = legacy.replace(native_expected, "", 1)
    require(legacy.count('Spotlight terminal stage: required-checks-and-native-review-gate-verified') == 1,
            "Spotlight item-9 native review-gate stage projection changed")
    legacy = legacy.replace(
        'Spotlight terminal stage: required-checks-and-native-review-gate-verified',
        'Spotlight terminal stage: required-checks-verified',
        1,
    )
    current_check_selector = 'select(.app.id == 15368 and (.name == "analyze-actions" or .name == "analyze-python" or .name == "dependency-review" or .name == "integration-pinned-upstream" or .name == "trusted-governed-bot-review" or .name == "validate-contracts"))'
    legacy_check_selector = 'select(.app.id == 15368)'
    require(legacy.count(current_check_selector) == 1,
            "Spotlight item-9 required-check selector projection changed")
    legacy = legacy.replace(current_check_selector, legacy_check_selector, 1)
    return legacy


NATIVE_REVIEW_GATE_FRAGMENTS = (
    '{name:"trusted-governed-bot-review",check_suite_id:$profile,status:"completed",conclusion:"success",head_sha:$head}',
    'select(.app.id == 15368 and (.name == "analyze-actions" or .name == "analyze-python" or .name == "dependency-review" or .name == "integration-pinned-upstream" or .name == "trusted-governed-bot-review" or .name == "validate-contracts"))',
    'Spotlight terminal stage: required-checks-and-native-review-gate-verified',
)


def validate_protected_workflow_evidence_overlay(sync: str) -> None:
    approve = core.job_block(sync, "approve", "authorize")
    workflow_paths = (
        (".github/workflows/codeql.yml", "CodeQL", "spotlight-codeql-workflow-definition.json", "CODEQL_WORKFLOW_ID"),
        (".github/workflows/dependency-review.yml", "Dependency review", "spotlight-dependency-workflow-definition.json", "DEPENDENCY_WORKFLOW_ID"),
        (".github/workflows/profile-quality.yml", "Profile quality", "spotlight-profile-workflow-definition.json", "PROFILE_WORKFLOW_ID"),
    )
    require(
        "python3 scripts/dependabot_controller.py" not in approve
        and "python3 scripts/automation_approval_comment.py" not in approve,
        "Spotlight protected workflow evidence must preserve the jq-only privileged approval firewall",
    )
    for path_value, name, filename, variable in workflow_paths:
        workflow_file = path_value.rsplit("/", 1)[1]
        endpoint = f'repos/${{GITHUB_REPOSITORY}}/actions/workflows/{workflow_file}'
        fetch = f'gh api "{endpoint}"'
        consume = f'{variable}="$(jq -er --arg path "{path_value}" --arg name "{name}" \''
        require(approve.count(fetch) == 1, f"Spotlight protected workflow definition endpoint changed: {path_value}")
        require(approve.count(consume) == 1, f"Spotlight protected workflow definition validator changed: {path_value}")
        require(
            f'> "$RUNNER_TEMP/{filename}"' in approve,
            f"Spotlight protected workflow definition raw evidence file changed: {path_value}",
        )
        fetch_pos = approve.index(fetch)
        validate_pos = approve.index(consume, fetch_pos)
        expected_pos = approve.index('EXPECTED_IDENTITIES="$(jq -cn', validate_pos)
        require(
            fetch_pos < validate_pos < expected_pos,
            "Spotlight protected workflow definition must be validated before identity consumption",
        )

    for fragment in (
        'error("Spotlight protected workflow definition must be an object")',
        'error("Spotlight protected workflow definition id is invalid")',
        'error("Spotlight protected workflow definition identity changed")',
        'error("Spotlight protected workflow definition URLs are invalid")',
        'for attempt in $(seq 1 60); do',
        'repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100',
        '> "$RUNNER_TEMP/spotlight-protected-workflow-runs.json"',
        'error("Spotlight protected workflow-run response must be an object")',
        'error("Spotlight protected workflow-run total_count is invalid")',
        'error("Spotlight protected workflow_runs shape changed")',
        'error("Spotlight protected workflow-run response is incomplete")',
        'error("Spotlight protected workflow-run set is ambiguous")',
        'error("Spotlight protected workflow-run item schema changed")',
        'error("Spotlight protected workflow run ids are not unique")',
        'error("Spotlight protected workflow ids are not unique")',
        'error("Spotlight protected workflow check-suite ids are not unique")',
        '.event != "pull_request"',
        '.head_sha != $head',
        '.head_branch != $branch',
        '.repository.full_name != $repo',
        '.head_repository.full_name != $repo',
        'totalCount:.total_count',
        'workflowId:.workflow_id',
        'checkSuiteId:.check_suite_id',
        'runAttempt:.run_attempt',
        '> "$RUNNER_TEMP/spotlight-protected-workflow-runs-normalized.json"',
        'RUNS_TOTAL="$(jq -r .totalCount "$RUNNER_TEMP/spotlight-protected-workflow-runs-normalized.json")"',
        'RUNS="$(jq -c .runs "$RUNNER_TEMP/spotlight-protected-workflow-runs-normalized.json")"',
        '.workflowId == $workflow_id',
        'CHECK_SUITE_ID="$(jq -r .checkSuiteId <<<"$RUN")"',
        'RUN_ATTEMPT="$(jq -r .runAttempt <<<"$RUN")"',
        'gh api --include --method POST "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve"',
    ):
        require(
            fragment in approve,
            f"Spotlight protected workflow evidence contract is missing: {fragment}",
        )

    for forbidden in (
        'CODEQL_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/codeql.yml" --jq .id)"',
        'DEPENDENCY_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/dependency-review.yml" --jq .id)"',
        'PROFILE_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/profile-quality.yml" --jq .id)"',
        'RUNS="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100")"',
        '\'.total_count // empty\' <<<"$RUNS"',
        'jq -r .head_sha <<<"$RUN"',
        'jq -r .head_branch <<<"$RUN"',
        'jq -r .repository.full_name <<<"$RUN"',
        'jq -r .head_repository.full_name <<<"$RUN"',
    ):
        require(
            forbidden not in approve,
            f"Spotlight protected workflow evidence regressed to raw scalar consumption: {forbidden}",
        )

    run_fetch = 'gh api "repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100"'
    run_validate = 'error("Spotlight protected workflow-run response must be an object")'
    run_normalized = '> "$RUNNER_TEMP/spotlight-protected-workflow-runs-normalized.json"'
    run_consume = 'RUNS_TOTAL="$(jq -r .totalCount "$RUNNER_TEMP/spotlight-protected-workflow-runs-normalized.json")"'
    run_mutation = 'gh api --include --method POST "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve"'
    positions = [
        approve.index(run_fetch),
        approve.index(run_validate),
        approve.index(run_normalized),
        approve.index(run_consume),
        approve.index(run_mutation),
    ]
    require(
        positions == sorted(positions),
        "Spotlight protected workflow-run evidence moved out of fetch-validate-normalize-consume-mutate order",
    )


def self_test_protected_workflow_evidence_overlay(sync: str) -> None:
    validate_protected_workflow_evidence_overlay(sync)
    mutated = sync.replace(
        'totalCount:.total_count',
        'totalCount:0',
        1,
    )
    try:
        validate_protected_workflow_evidence_overlay(mutated)
    except ValueError as exc:
        require(
            "protected workflow evidence contract is missing" in str(exc),
            f"Spotlight protected workflow evidence self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("Spotlight protected workflow evidence accepted weakened normalized total count")


def validate_approval_comment_evidence_overlay(sync: str) -> None:
    approve = core.job_block(sync, "approve", "authorize")
    get_endpoint = 'repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100'
    post_endpoint = 'repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments'
    post_mutation = 'gh api --include --method POST "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments"'
    post_status = 'APPROVAL_COMMENT_STATUS_LINE="$(head -n 1 <<<"$APPROVAL_COMMENT_HTTP_RESPONSE" | tr -d \'\\r\')"'
    post_guard = '[[ "$APPROVAL_COMMENT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {'
    post_extract = 'sed \'1,/^[[:space:]]*$/d\' <<<"$APPROVAL_COMMENT_HTTP_RESPONSE" > "$RUNNER_TEMP/spotlight-approval-comment-created.json"'
    require(
        approve.count(get_endpoint) == 1,
        "Spotlight automation-approval comment read endpoint changed",
    )
    require(
        approve.count(post_endpoint) == 2,
        "Spotlight automation-approval comment endpoint inventory changed",
    )
    require(
        "python3 scripts/automation_approval_comment.py" not in approve,
        "Spotlight privileged approval job must not acquire runner-resident Python authority",
    )
    require(approve.count(post_mutation) == 1,
            "Spotlight automation-approval comment mutation capture changed")
    require(approve.count(post_status) == 1 and approve.count(post_guard) == 1,
            "Spotlight automation-approval comment mutation must require exact HTTP 201")
    require("Spotlight automation-approval comment returned unexpected status:" in approve,
            "Spotlight automation-approval comment status failure must be explicit")
    require(approve.count(post_extract) == 1,
            "Spotlight automation-approval comment response body extraction changed")

    required = (
        'error("Spotlight automation-approval comment pages must be a bounded slurped page array")',
        'error("Spotlight automation-approval comment page shape changed")',
        'error("Spotlight automation-approval comment pagination is incomplete")',
        'error("Spotlight automation-approval comment item schema changed")',
        'error("Spotlight automation-approval comment ids are not unique")',
        '([.[][] | .id] | group_by(.) | any(length > 1))',
        'error("duplicate trusted Spotlight automation-approval comments exist")',
        '.issue_url != ("https://api.github.com/repos/" + $repo + "/issues/" + ($pr | tostring))',
        '.url != ("https://api.github.com/repos/" + $repo + "/issues/comments/" + (.id | tostring))',
        '.login == "github-actions[bot]" and (.body | contains($marker))',
        'exists:(($matches | length) == 1)',
        'commentId:(if ($matches | length) == 1 then $matches[0].id else null end)',
        'APPROVAL_COMMENT_EXISTS="$(jq -r .exists "$RUNNER_TEMP/spotlight-approval-comment-evidence.json")"',
        'test "$APPROVAL_COMMENT_EXISTS" = "true" -o "$APPROVAL_COMMENT_EXISTS" = "false"',
        'if [ "$APPROVAL_COMMENT_EXISTS" = "false" ]; then',
        'error("created Spotlight automation-approval comment must be an object")',
        'error("created Spotlight automation-approval comment id is invalid")',
        'error("created Spotlight automation-approval comment issue URL mismatch")',
        'error("created Spotlight automation-approval comment URL mismatch")',
        'error("created Spotlight automation-approval comment body mismatch")',
        'error("created Spotlight automation-approval comment actor mismatch")',
        'error("created Spotlight automation-approval comment html_url is invalid")',
        '.user.login != "github-actions[bot]"',
        '{id:.id,prNumber:$pr,repository:$repo,actor:.user.login}',
        'test "$(jq -r .actor "$RUNNER_TEMP/spotlight-approval-comment-created-normalized.json")" = "github-actions[bot]"',
        'test "$(jq -r .prNumber "$RUNNER_TEMP/spotlight-approval-comment-created-normalized.json")" = "$PR_NUMBER"',
    )
    for fragment in required:
        require(
            fragment in approve,
            f"Spotlight automation-approval comment contract is missing: {fragment}",
        )

    for forbidden in (
        'COMMENTS="$(gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100")"',
        '[.[][] | select(.body | contains($marker))] | length > 0',
        "'.body == $body' approval-comment.json",
    ):
        require(
            forbidden not in approve,
            f"Spotlight regressed to raw automation-approval comment evidence: {forbidden}",
        )

    fetch_pos = approve.index(get_endpoint)
    validate_pos = approve.index(
        'error("Spotlight automation-approval comment pages must be a bounded slurped page array")',
        fetch_pos,
    )
    normalized_pos = approve.index(
        '> "$RUNNER_TEMP/spotlight-approval-comment-evidence.json"',
        validate_pos,
    )
    consume_pos = approve.index(
        'APPROVAL_COMMENT_EXISTS="$(jq -r .exists "$RUNNER_TEMP/spotlight-approval-comment-evidence.json")"',
        normalized_pos,
    )
    create_pos = approve.index(post_mutation, consume_pos)
    create_status_pos = approve.index(post_status)
    create_guard_pos = approve.index(post_guard)
    create_extract_pos = approve.index(post_extract)
    created_validate_pos = approve.index(
        'error("created Spotlight automation-approval comment must be an object")',
        create_extract_pos,
    )
    created_normalized_pos = approve.index(
        '> "$RUNNER_TEMP/spotlight-approval-comment-created-normalized.json"',
        created_validate_pos,
    )
    created_consume_pos = approve.index(
        'test "$(jq -r .actor "$RUNNER_TEMP/spotlight-approval-comment-created-normalized.json")" = "github-actions[bot]"',
        created_normalized_pos,
    )
    require(
        fetch_pos < validate_pos < normalized_pos < consume_pos
        < create_pos < create_status_pos < create_guard_pos < create_extract_pos
        < created_validate_pos < created_normalized_pos < created_consume_pos,
        "Spotlight automation-approval comment evidence/status moved out of typed reviewed order",
    )


def self_test_approval_comment_evidence_overlay(sync: str) -> None:
    validate_approval_comment_evidence_overlay(sync)
    mutated = sync.replace(
        'exists:(($matches | length) == 1)',
        'exists:(($matches | length) >= 1)',
        1,
    )
    try:
        validate_approval_comment_evidence_overlay(mutated)
    except ValueError as exc:
        require(
            "automation-approval comment contract is missing" in str(exc),
            f"Spotlight approval-comment self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("Spotlight approval-comment contract accepted weakened trusted-match cardinality")

    for weakened, expected in (
        (
            sync.replace(
                'gh api --include --method POST "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments"',
                'gh api --method POST "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments"',
                1,
            ),
            "mutation capture changed",
        ),
        (
            sync.replace(
                '[[ "$APPROVAL_COMMENT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
                '[[ "$APPROVAL_COMMENT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {',
                1,
            ),
            "exact HTTP 201",
        ),
        (
            sync.replace(
                APPROVAL_COMMENT_HTTP_STATUS_BLOCK,
                APPROVAL_COMMENT_HTTP_STATUS_BLOCK.replace(
                    '            [[ "$APPROVAL_COMMENT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
                    '              echo "ERROR: Spotlight automation-approval comment returned unexpected status: ${APPROVAL_COMMENT_STATUS_LINE}" >&2\n'
                    '              exit 1\n'
                    '            }\n'
                    '            sed \'1,/^[[:space:]]*$/d\' <<<"$APPROVAL_COMMENT_HTTP_RESPONSE" > "$RUNNER_TEMP/spotlight-approval-comment-created.json"\n',
                    '            sed \'1,/^[[:space:]]*$/d\' <<<"$APPROVAL_COMMENT_HTTP_RESPONSE" > "$RUNNER_TEMP/spotlight-approval-comment-created.json"\n'
                    '            [[ "$APPROVAL_COMMENT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
                    '              echo "ERROR: Spotlight automation-approval comment returned unexpected status: ${APPROVAL_COMMENT_STATUS_LINE}" >&2\n'
                    '              exit 1\n'
                    '            }\n',
                ),
                1,
            ),
            "moved out of typed reviewed order",
        ),
    ):
        try:
            validate_approval_comment_evidence_overlay(weakened)
        except ValueError as exc:
            require(expected in str(exc),
                    f"Spotlight approval-comment status self-test failed for wrong reason: {exc}")
        else:
            raise ValueError(f"Spotlight approval-comment status self-test accepted weakened contract: {expected}")


def validate_native_governed_bot_review_overlay(sync: str) -> None:
    merge = core.job_block(sync, "merge", None)
    for fragment in NATIVE_REVIEW_GATE_FRAGMENTS:
        require(fragment in merge,
                f"Spotlight post-review native governed-bot gate proof is missing: {fragment}")
    check_read = 'CHECKS="$(gh api -H \'Accept: application/vnd.github+json\' "repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs?filter=latest&per_page=100")"'
    require(merge.count(check_read) == 1,
            "Spotlight terminal merge must retain exactly one canonical generic check-run read")
    review = merge.index(
        'Spotlight terminal stage: exact-base-head-portyu9-approval-and-manual-veto-verified'
    )
    gate = merge.index(check_read)
    roots = merge.index('Spotlight terminal stage: pre-merge-roots-verified')
    mutation = merge.index(
        'gh api --include --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"'
    )
    require(review < gate < roots < mutation,
            "Spotlight native governed-bot gate and root reproof must run after review/veto proof and before merge mutation")


def self_test_native_governed_bot_review_overlay(sync: str) -> None:
    validate_native_governed_bot_review_overlay(sync)
    mutated = sync.replace(
        '{name:"trusted-governed-bot-review",check_suite_id:$profile,status:"completed",conclusion:"success",head_sha:$head}',
        '{name:"spoofed-governed-bot-review",check_suite_id:$profile,status:"completed",conclusion:"success",head_sha:$head}',
        1,
    )
    try:
        validate_native_governed_bot_review_overlay(mutated)
    except ValueError as exc:
        require("native governed-bot gate proof" in str(exc),
                f"native review-gate self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("native review-gate self-test accepted a substituted required context")


def validate_preparer_script_with_trusted_admission(text: str) -> None:
    require("def gh_json(endpoint: str)" in text and '["gh", "api", endpoint]' in text,
            "Spotlight MAC preparer must retain one GET-only GitHub API helper")
    for forbidden in ("--method", "requests.", "urllib", "curl ", "wget "):
        require(forbidden not in text,
                f"Spotlight MAC preparer acquired alternate/mutating network surface: {forbidden}")
    for fragment in (
        'git/ref/heads/main',
        'git/ref/heads/generated',
        'pulls/{pr_number}/files?per_page=100',
        'compare/{base}...{head}',
        'actions/runs?head_sha={head}&event=pull_request&per_page=100',
        'total == len(runs) == 3',
        'trusted_external_pattern = re.compile(',
        'trusted_external_pattern.fullmatch(check["external_id"]) is not None',
        'trusted_identity_match = trusted_external_pattern.fullmatch(trusted_external_id)',
        'trusted_run_id = int(trusted_identity_match.group(1))',
        'trusted_run_attempt = int(trusted_identity_match.group(2))',
        'trusted_run.get("event") == "workflow_dispatch"',
        'trusted_run.get("head_branch") == "main"',
        'TRUSTED_WORKFLOW_NAME = "Capability admission"',
        'TRUSTED_CHECK_NAME = "trusted-capability-admission"',
        'check-runs?filter=all&per_page=100',
        'proof_total == len(proof_checks)',
        'trusted_matches.sort(key=lambda check: check["id"], reverse=True)',
        'candidate_run.get("event") == "workflow_dispatch"',
        'candidate_run.get("head_branch") == "main"',
        'candidate_run.get("head_sha") == base',
        'Spotlight trusted workflow-dispatch admission proof did not materialize',
        'check-runs?filter=latest&per_page=100',
        'checks_total == len(checks)',
        'for attempt in range(1, 25):',
        '"trustedAdmission"',
    ):
        require(fragment in text,
                f"Spotlight MAC preparer lost independent trusted/live-state proof: {fragment}")


def validate_builder_script_with_trusted_admission(wrapper: str, builder_core: str) -> None:
    ORIGINAL_VALIDATE_BUILDER_SCRIPT(wrapper, builder_core)
    for fragment in (
        '"trustedAdmission"',
        '"Capability admission"',
        '"trusted-capability-admission"',
        '"workflow_dispatch"',
        'f"spotlight-admission:{workflow[\'runId\']}:{workflow[\'runAttempt\']}:{pr_number}:{base}:{head}"',
        'expected_details_url = f"https://github.com/{REPOSITORY}/runs/{check[\'checkRunId\']}"',
        'server-side required-check enforcement',
        'def validate_trusted_admission(',
    ):
        require(fragment in builder_core,
                f"Spotlight MAC builder core lost trusted admission binding: {fragment}")
    schema = core.SCHEMA.read_text(encoding="utf-8")
    for fragment in (
        '"trustedAdmission"',
        '"Capability admission"',
        '"trusted-capability-admission"',
        '"event": {"const": "workflow_dispatch"}',
        '"headBranch": {"const": "main"}',
        '"externalId"',
        '"detailsUrl"',
        '"appId": {"const": 15368}',
    ):
        require(fragment in schema,
                f"Spotlight MAC schema lost trusted admission binding: {fragment}")


core.DOWNLOAD_STEP = COMPRESSED_DOWNLOAD_STEP
core.project_item9 = project_item9
core.validate_mac = validate_mac_with_merge_http_projection
core.validate_preparer_script = validate_preparer_script_with_trusted_admission
core.validate_builder_script = validate_builder_script_with_trusted_admission


def main() -> int:
    try:
        for path in (core.SYNC, core.STATS, core.POLICY, core.BUILDER, core.BUILDER_CORE,
                     core.PREPARER, core.SCHEMA):
            require(path.is_file() and not path.is_symlink(),
                    f"Spotlight merge authorization input is missing or aliased: {path.relative_to(core.ROOT)}")

        sync = strip_adr_tail(core.SYNC.read_text(encoding="utf-8"), "Spotlight")
        stats = project_profile_item9(strip_adr_tail(core.STATS.read_text(encoding="utf-8"), "Profile Stats"))
        policy = core.POLICY.read_text(encoding="utf-8")
        preparer = core.PREPARER.read_text(encoding="utf-8")
        builder = core.BUILDER.read_text(encoding="utf-8")
        builder_core = core.BUILDER_CORE.read_text(encoding="utf-8")

        legacy = project_item9(sync)
        core.item9.validate(legacy, stats, policy)
        core.item9.self_test(legacy, stats, policy)
        core.validate_preparer_script(preparer)
        core.validate_builder_script(builder, builder_core)
        core.validate_mac(sync)
        validate_protected_workflow_evidence_overlay(sync)
        self_test_protected_workflow_evidence_overlay(sync)
        validate_approval_comment_evidence_overlay(sync)
        self_test_approval_comment_evidence_overlay(sync)
        validate_native_governed_bot_review_overlay(sync)
        self_test_native_governed_bot_review_overlay(sync)
        validate_merge_success_response_overlay(sync)
        self_test_merge_success_response_overlay(sync)
        validate_terminal_object_schema_overlay(sync)
        self_test_terminal_object_schema_overlay(sync)
        core.self_test(sync, stats, policy)
        print(
            "Spotlight UI merge authorization validation passed: item-11 ADR/observation overlays are projected away before the complete frozen item-10 proof; "
            "stale reconciliation still validates the exact full PR object, the read-only MAC preparer independently re-proves live state plus the separate trusted capability-admission proof, "
            "the isolated OIDC signer attests only the deterministic certificate subject, and terminal merge binds canonical live provenance, "
            "trusted-actor exact HTTP-201-validated automation-approval comment evidence, the exact post-review trusted-governed-bot-review context, the CLI's direct verified statement, and a typed canonical GitHub merge-success "
            "response plus typed terminal PR/file/commit evidence before current-main acceptance, candidate cleanup, or decision-receipt evidence."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=core.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
