#!/usr/bin/env python3
"""Project item-11 ADR/current-observation overlays around frozen Spotlight MAC proofs."""
from __future__ import annotations

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
        core.self_test(sync, stats, policy)
        print(
            "Spotlight UI merge authorization validation passed: item-11 ADR/observation overlays are projected away before the complete frozen item-10 proof; "
            "stale reconciliation still validates the exact full PR object, the read-only MAC preparer independently re-proves live state plus the separate trusted capability-admission proof, "
            "the isolated OIDC signer attests only the deterministic certificate subject, and terminal merge binds canonical live provenance, "
            "the exact post-review trusted-governed-bot-review context, and the CLI's direct verified statement before expected-head mutation."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=core.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
