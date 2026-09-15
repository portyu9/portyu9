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

ITEM13_CAPABILITY_FRAGMENTS = (
    'CAPABILITY_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/capability-admission.yml" --jq .id)"',
    'CAPABILITY_RUNS="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request_target&per_page=100")"',
    'test "$CAPABILITY_RUNS_TOTAL" = "$CAPABILITY_RUNS_COUNT" || {',
    'test "$CAPABILITY_RUNS_TOTAL" = "1"',
    'select(.name == "Capability admission" and .workflow_id == $workflow_id)',
    'test "$(jq -r .event <<<"$CAPABILITY_RUN")" = "pull_request_target"',
    'test "$(jq -r .head_branch <<<"$CAPABILITY_RUN")" = "$CANDIDATE_BRANCH"',
    'test "$(jq -r .head_sha <<<"$CAPABILITY_RUN")" = "$HEAD_SHA"',
    'test "$(jq -r .repository.full_name <<<"$CAPABILITY_RUN")" = "$GITHUB_REPOSITORY"',
    'test "$(jq -r .head_repository.full_name <<<"$CAPABILITY_RUN")" = "$GITHUB_REPOSITORY"',
    'test "$(jq -r .status <<<"$CAPABILITY_RUN")" = "completed"',
    'test "$(jq -r .conclusion <<<"$CAPABILITY_RUN")" = "success"',
    '{name:"trusted-capability-admission",check_suite_id:$capability,status:"completed",conclusion:"success",head_sha:$head}',
)


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


def project_item9(sync: str) -> str:
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
    return legacy


def validate_item13_trusted_admission_overlay(sync: str) -> None:
    merge = core.job_block(sync, "merge", None)
    for fragment in ITEM13_CAPABILITY_FRAGMENTS:
        require(fragment in merge,
                f"Spotlight terminal trusted-capability admission proof is missing: {fragment}")
    require(
        'test "$(printf \'%s\\n\' "$CODEQL_RUN_ID" "$DEPENDENCY_RUN_ID" "$PROFILE_RUN_ID" "$CAPABILITY_RUN_ID" | LC_ALL=C sort -u | wc -l)" = "4"' in merge,
        "Spotlight terminal run provenance must keep all four canonical run identities distinct",
    )
    require(
        'test "$(printf \'%s\\n\' "$CODEQL_CHECK_SUITE_ID" "$DEPENDENCY_CHECK_SUITE_ID" "$PROFILE_CHECK_SUITE_ID" "$CAPABILITY_CHECK_SUITE_ID" | LC_ALL=C sort -u | wc -l)" = "4"' in merge,
        "Spotlight terminal check-suite provenance must keep all four canonical suite identities distinct",
    )
    capability_run = merge.index('CAPABILITY_RUNS="$(gh api ')
    checks = merge.index('CHECKS="$(gh api -H ')
    mutation = merge.index('gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"')
    require(capability_run < checks < mutation,
            "Spotlight terminal trusted-capability proof must precede exact check binding and merge mutation")


def self_test_item13(sync: str) -> None:
    validate_item13_trusted_admission_overlay(sync)
    mutated = sync.replace(
        '{name:"trusted-capability-admission",check_suite_id:$capability,status:"completed",conclusion:"success",head_sha:$head}',
        '{name:"trusted-capability-admission",check_suite_id:$profile,status:"completed",conclusion:"success",head_sha:$head}',
        1,
    )
    try:
        validate_item13_trusted_admission_overlay(mutated)
    except ValueError as exc:
        require("trusted-capability admission proof" in str(exc),
                f"item-13 trusted admission self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("item-13 trusted admission self-test accepted an unbound trusted check suite")


def main() -> int:
    try:
        for path in (core.SYNC, core.STATS, core.POLICY, core.BUILDER, core.BUILDER_CORE,
                     core.PREPARER, core.SCHEMA):
            require(path.is_file() and not path.is_symlink(),
                    f"Spotlight merge authorization input is missing or aliased: {path.relative_to(core.ROOT)}")

        core.DOWNLOAD_STEP = COMPRESSED_DOWNLOAD_STEP
        core.project_item9 = project_item9
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
        core.self_test(sync, stats, policy)
        validate_item13_trusted_admission_overlay(sync)
        self_test_item13(sync)
        print(
            "Spotlight UI merge authorization validation passed: item-11 ADR/observation overlays are projected away before the complete frozen item-10 proof; "
            "item-13 additionally binds the exact successful default-branch-trusted capability-admission run/check-suite before terminal mutation; "
            "stale reconciliation still validates the exact full PR object, the read-only MAC preparer independently re-proves live state, "
            "the isolated OIDC signer attests only the deterministic certificate subject, and terminal merge binds canonical live provenance "
            "and the CLI's direct verified statement before expected-head mutation."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=core.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
