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
ORIGINAL_VALIDATE_BUILDER_SCRIPT = core.validate_builder_script


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


def project_merge_success_response_to_legacy(sync: str) -> str:
    require(sync.count(MERGE_SUCCESS_BLOCK) == 1,
            "Spotlight merge-success response projection cannot isolate the exact validated block")
    require(LEGACY_MERGE_SUCCESS_BLOCK not in sync,
            "Spotlight merge-success response projection found both hardened and legacy consumers")
    return sync.replace(MERGE_SUCCESS_BLOCK, LEGACY_MERGE_SUCCESS_BLOCK, 1)


def validate_merge_success_response_overlay(sync: str) -> None:
    merge = core.job_block(sync, "merge", None)
    require(merge.count(MERGE_SUCCESS_BLOCK) == 1,
            "Spotlight terminal merge-success response schema block changed")
    require(merge.count('<<<"$RESULT"') == 1,
            "Spotlight terminal merge may consume the raw merge response only through the canonical validator")
    require('test "$(jq -r .merged <<<"$RESULT")" = "true"' not in merge and
            'MERGE_SHA="$(jq -r .sha <<<"$RESULT")"' not in merge,
            "Spotlight terminal merge retained a direct unvalidated merge-response consumer")

    mutation = merge.index('RESULT="$(gh api --method PUT ')
    validation = merge.index('VALIDATED_MERGE="$(jq -ce "$MERGE_SUCCESS_FILTER" <<<"$RESULT")"')
    normalized_sha = merge.index('MERGE_SHA="$(jq -r .sha <<<"$VALIDATED_MERGE")"')
    merged_pr = merge.index('MERGED_PR="$(gh api ')
    current_main = merge.index('CURRENT_MAIN_SHA="$(gh api ')
    cleanup = merge.index('CANDIDATE_REFS="$(gh api ')
    require(mutation < validation < normalized_sha < merged_pr < current_main < cleanup,
            "Spotlight merge-success validation must precede post-merge proof, current-main acceptance, and cleanup")
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
        '(.state | type == "string" and (. == "open" or . == "closed")) and',
        '(.draft | type == "boolean") and',
        '(.merged | type == "boolean") and',
        '(.maintainer_can_modify | type == "boolean") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$"))',
        '(.body | type == "string" and length > 0) and',
        'has("merge_commit_sha")',
    ):
        require(fragment in fn, f"Spotlight terminal PR schema is missing: {fragment}")

    pre_validate = merge.index('          validate_terminal_pr_object "$PR"', pre_pr)
    pre_consume = merge.index('          test "$(jq -r .user.login <<<"$PR")"', pre_pr)
    require(pre_pr < pre_validate < pre_consume,
            "Spotlight terminal pre-merge PR fields are consumed before schema validation")
    for fragment in (
        'test "$(jq -r .user.login <<<"$PR")" = "github-actions[bot]"',
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
    current_main = merge.index('          CURRENT_MAIN_SHA="$(gh api ', merged_fetch)
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
    require(merged_fetch < merged_validate < merged_identity < merged_consume < merge_sha_bind < current_main < cleanup,
            "Spotlight post-merge PR schema/identity/SHA binding must precede current-main acceptance and cleanup")
    require(merge.count('validate_terminal_pr_object "$PR"') == 1
            and merge.count('validate_terminal_pr_object "$MERGED_PR"') == 1,
            "Spotlight terminal PR schema must validate exactly the pre/post merge snapshots")


def self_test_terminal_object_schema_overlay(sync: str) -> None:
    validate_terminal_object_schema_overlay(sync)
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
        require(old in sync, f"Spotlight terminal schema self-test anchor changed: {old}")
        mutated = sync.replace(old, new, 1)
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


def project_item9(sync: str) -> str:
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
        'gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"'
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
            "the exact post-review trusted-governed-bot-review context, the CLI's direct verified statement, and a typed canonical GitHub merge-success "
            "response plus typed terminal PR/file/commit evidence before current-main acceptance, candidate cleanup, or decision-receipt evidence."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=core.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
