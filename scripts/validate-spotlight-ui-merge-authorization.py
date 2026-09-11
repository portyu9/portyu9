#!/usr/bin/env python3
"""Fail closed on overly broad Spotlight README/UI merge authority.

The pre-immutable-candidate validator is retained byte-for-byte in
spotlight_merge_authorization_core.py. This layer reuses its independent mutation-budget,
dispatch, and check-suite proofs while replacing the retired shared-branch assumptions
with the content-addressed immutable-candidate transaction and reductive reconciliation
contracts.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

import spotlight_merge_authorization_core as core

ROOT = Path(__file__).resolve().parents[1]
SYNC = ROOT / ".github/workflows/spotlight-link-sync.yml"
STATS = ROOT / ".github/workflows/profile-stats.yml"
POLICY = ROOT / ".github/SPOTLIGHT_UI_MERGE_AUTHORIZATION.md"

CANDIDATE_PREFIX = "automation/spotlight-links/"
CANDIDATE_FORMULA_PROPOSE = (
    'CANDIDATE_ID="$(printf \'%s\\n%s\\n%s\\n\' "$SOURCE_SHA" "$GENERATED_SHA" '
    '"$README_SHA256_AFTER" | sha256sum | cut -d\' \' -f1)"'
)
CANDIDATE_FORMULA_DOWNSTREAM = (
    'EXPECTED_CANDIDATE_ID="$(printf \'%s\\n%s\\n%s\\n\' "$BASE_SHA" "$GENERATED_SHA" '
    '"$README_SHA256_AFTER" | sha256sum | cut -d\' \' -f1)"'
)


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def validate_reconciliation(reconcile: str) -> None:
    require("name: reconcile-stale-candidates-write" in reconcile and "needs: plan" in reconcile,
            "Spotlight reconciler identity/dependency changed")
    require("timeout-minutes: 3" in reconcile,
            "Spotlight reconciler authority window changed")
    require("permissions:\n      contents: write\n      pull-requests: write" in reconcile,
            "Spotlight reconciler must retain only contents/PR write authority")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "actions: write", "checks: read"):
        require(forbidden not in reconcile,
                f"Spotlight reconciler acquired an unauthorized execution/permission surface: {forbidden}")

    required = (
        'test "$BASE_SHA" = "$GITHUB_SHA"',
        'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"',
        'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated" --jq .object.sha)" = "$GENERATED_SHA"',
        'EXPECTED_CANDIDATE_BRANCH=""',
        'EXPECTED_CANDIDATE_BRANCH="${BOT_BRANCH_PREFIX}${EXPECTED_CANDIDATE_ID}"',
        'STALE_AFTER_SECONDS=1800',
        'REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${BOT_BRANCH_PREFIX}")"',
        'test "$REF_COUNT" -le 20 || {',
        '(.ref | test("^refs/heads/automation/spotlight-links/[0-9a-f]{64}$") | not)',
        'if [ -n "$EXPECTED_CANDIDATE_BRANCH" ] && [ "$BRANCH" = "$EXPECTED_CANDIDATE_BRANCH" ]; then',
        'CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"',
        'test "$(jq \' .parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"',
        'test "$(jq -r .author.name <<<"$CANDIDATE_COMMIT")" = "$BOT_NAME"',
        'test "$(jq -r .committer.email <<<"$CANDIDATE_COMMIT")" = "$BOT_EMAIL"',
        'if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ]; then',
        'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${PARENT_SHA}...${HEAD_SHA}")"',
        'test "$(jq -r .total_commits <<<"$COMPARE")" = "1"',
        'test "$(jq -r \'.files[0].filename\' <<<"$COMPARE")" = "README.md"',
        'PRS="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${BRANCH}&base=main&per_page=2")"',
        'test "$PR_COUNT" = "0" || test "$PR_COUNT" = "1"',
        'test "$(jq -r .user.login <<<"$PR")" = "github-actions[bot]"',
        'test "$(jq -r .head.sha <<<"$PR")" = "$HEAD_SHA"',
        'test "$(jq -r .maintainer_can_modify <<<"$PR")" = "false"',
        'CLOSED_PR="$(gh api --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}" --input close-pr.json)"',
        'test "$(jq -r .state <<<"$CLOSED_PR")" = "closed"',
        'gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BRANCH}" >/dev/null',
        'test "$REMAINING_EXACT" = "0"',
    )
    for fragment in required:
        normalized = fragment.replace("' .parents", "'.parents")
        require(normalized in reconcile,
                f"Spotlight reconciler lost a stale-only/topology proof: {normalized}")

    require(reconcile.count('gh api --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}"') == 1,
            "Spotlight reconciler must expose exactly one PR-closing PATCH mutation")
    require(reconcile.count('gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BRANCH}"') == 1,
            "Spotlight reconciler must expose exactly one stale-ref DELETE mutation")
    for forbidden in (
        "gh api --method POST ",
        "gh api --method PUT ",
        "/approve",
        "/merge",
        'git/refs/heads/${CANDIDATE_BRANCH}',
    ):
        require(forbidden not in reconcile,
                f"Spotlight reconciler regained constructive mutation authority: {forbidden}")


def validate_candidate_publication(sync: str) -> None:
    plan = core.job_block(sync, "plan", "reconcile")
    reconcile = core.job_block(sync, "reconcile", "budget")
    propose = core.job_block(sync, "propose", "approve")
    approve = core.job_block(sync, "approve", "merge")
    merge = core.job_block(sync, "merge", None)

    validate_reconciliation(reconcile)
    require("needs: [plan, reconcile, budget]" in propose,
            "Spotlight proposer must wait for reconciliation and positive budget admission")
    require("needs: [plan, reconcile, budget, propose]" in approve,
            "Spotlight approval must remain downstream of reconciliation/proposal")
    require("needs: [plan, reconcile, budget, propose, approve]" in merge,
            "Spotlight terminal merge must remain downstream of reconciliation/approval")

    require(f'BOT_BRANCH_PREFIX: "{CANDIDATE_PREFIX}"' in sync,
            "Spotlight immutable candidate prefix changed")
    require('BOT_BRANCH: "automation/spotlight-links"' not in sync,
            "Spotlight retained the retired shared mutable branch")
    for forbidden in (
        'gh api --method PATCH "repos/${GITHUB_REPOSITORY}/git/refs/heads/',
        '-F force=true',
        'gh api --method PUT "repos/${GITHUB_REPOSITORY}/contents/README.md"',
    ):
        require(forbidden not in sync,
                f"Spotlight immutable candidate transaction regained mutable publication authority: {forbidden}")

    require('readme_sha256_after: ${{ steps.render.outputs.readme_sha256_after }}' in plan,
            "Spotlight plan must seal the proposed README digest")
    require('echo "readme_sha256_after=$README_SHA256_AFTER" >> "$GITHUB_OUTPUT"' in plan,
            "Spotlight plan must emit the sealed proposed README digest")
    require('candidate_branch: ${{ steps.propose.outputs.candidate_branch }}' in propose and
            'echo "candidate_branch=$CANDIDATE_BRANCH" >> "$GITHUB_OUTPUT"' in propose,
            "Spotlight proposer must seal one exact candidate branch identity")
    require(CANDIDATE_FORMULA_PROPOSE in propose,
            "Spotlight proposer candidate identity lost exact main/generated/README content addressing")
    require('CANDIDATE_BRANCH="${BOT_BRANCH_PREFIX}${CANDIDATE_ID}"' in propose,
            "Spotlight proposer must derive branch name only from the candidate digest")
    require('[[ "$CANDIDATE_BRANCH" =~ ^automation/spotlight-links/[0-9a-f]{64}$ ]]' in propose,
            "Spotlight proposer candidate branch grammar changed")

    for fragment in (
        'MATCHING_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"',
        'test "$EXACT_REF_COUNT" = "0" || test "$EXACT_REF_COUNT" = "1"',
        'if [ "$EXACT_REF_COUNT" = "1" ]; then',
        'HEAD_SHA="$(jq -r --arg ref "refs/heads/${CANDIDATE_BRANCH}"',
    ):
        require(fragment in propose,
                f"Spotlight retry must reuse only one exact immutable candidate ref: {fragment}")

    ordered = (
        'BLOB="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/blobs" --input blob.json)"',
        'TREE="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/trees" --input tree.json)"',
        'CANDIDATE_COMMIT="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/commits" --input commit.json)"',
        '# Validate the complete candidate object before first publication or retry reuse.',
        'CREATED_REF="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" --input ref.json)"',
    )
    cursor = -1
    for fragment in ordered:
        require(propose.count(fragment) == 1,
                f"Spotlight candidate publication must contain one reviewed transaction fragment: {fragment}")
        position = propose.index(fragment)
        require(position > cursor,
                f"Spotlight candidate publication boundary was reordered: {fragment}")
        cursor = position

    for fragment in (
        'test "$(jq \' .parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"',
        'test "$(jq -r \'.parents[0].sha\' <<<"$CANDIDATE_COMMIT")" = "$SOURCE_SHA"',
        'test "$(jq -r .author.name <<<"$CANDIDATE_COMMIT")" = "$BOT_NAME"',
        'test "$(jq -r .author.email <<<"$CANDIDATE_COMMIT")" = "$BOT_EMAIL"',
        'test "$(jq -r .committer.name <<<"$CANDIDATE_COMMIT")" = "$BOT_NAME"',
        'test "$(jq -r .committer.email <<<"$CANDIDATE_COMMIT")" = "$BOT_EMAIL"',
        'test "$(jq -r .message <<<"$CANDIDATE_COMMIT")" = "chore: sync rotating Spotlight links"',
        'test "$(jq -r .ahead_by <<<"$COMPARE")" = "1"',
        'test "$(jq -r .behind_by <<<"$COMPARE")" = "0"',
        'test "$(jq -r .total_commits <<<"$COMPARE")" = "1"',
        'test "$(jq \'.files | length\' <<<"$COMPARE")" = "1"',
        'test "$(jq -r \'.files[0].filename\' <<<"$COMPARE")" = "README.md"',
        'test "$(sha256sum candidate-readme.md | cut -d\' \' -f1)" = "$README_SHA256_AFTER"',
    ):
        normalized = fragment.replace("' .parents", "'.parents")
        require(normalized in propose,
                f"Spotlight candidate object/retry validation lost a required proof: {normalized}")

    require('test "$(jq -r .object.sha <<<"$CREATED_REF")" = "$HEAD_SHA"' in propose and
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha)" = "$HEAD_SHA"' in propose,
            "Spotlight first publication must bind the created ref to the validated candidate head")
    require('maintainer_can_modify:false' in propose and
            'test "$(jq -r .maintainer_can_modify <<<"$PR")" = "false"' in propose,
            "Spotlight candidate PR head must not be maintainer-mutable")

    for block, label in ((approve, "approval"), (merge, "terminal merge")):
        require(CANDIDATE_FORMULA_DOWNSTREAM in block,
                f"Spotlight {label} must independently rederive candidate identity")
        require('test "$CANDIDATE_BRANCH" = "${BOT_BRANCH_PREFIX}${EXPECTED_CANDIDATE_ID}"' in block,
                f"Spotlight {label} lost deterministic candidate-branch equality")
        require('test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha)" = "$HEAD_SHA"' in block,
                f"Spotlight {label} must re-prove immutable ref-to-head identity")

    require('test "$(jq -r .head_branch <<<"$RUN")" = "$CANDIDATE_BRANCH"' in approve,
            "Spotlight workflow-run authorization must bind the exact candidate branch")
    require('test "$(jq -r .head.ref <<<"$PR")" = "$CANDIDATE_BRANCH"' in merge,
            "Spotlight terminal merge must bind the exact candidate PR branch")
    require('test "$(jq -r .head.repo.full_name <<<"$PR")" = "$GITHUB_REPOSITORY"' in merge,
            "Spotlight terminal merge must bind the candidate PR head repository")
    require('test "$(jq -r .maintainer_can_modify <<<"$PR")" = "false"' in merge,
            "Spotlight terminal merge must re-prove candidate head immutability")
    require('test "$(jq -r \'.parents[0].sha\' <<<"$CANDIDATE_COMMIT")" = "$BASE_SHA"' in merge,
            "Spotlight terminal merge must re-prove the candidate single-parent source binding")
    require('CANDIDATE_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"' in merge and
            'test "$EXACT_REF_COUNT" = "0" || test "$EXACT_REF_COUNT" = "1"' in merge,
            "Spotlight terminal cleanup must classify exact candidate-ref cardinality without a failing GET")
    require('gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CANDIDATE_BRANCH}" >/dev/null' in merge,
            "Spotlight cleanup must delete only the exact consumed immutable candidate ref")
    require('test "$AFTER_EXACT" = "0"' in merge,
            "Spotlight terminal cleanup must prove the exact consumed ref is absent after deletion")
    require("CANDIDATE_REF=\"$(gh api " not in merge and "2>/dev/null" not in merge,
            "Spotlight terminal cleanup must not classify missing refs through suppressed single-ref GET failures")


def validate_run_provenance(approve: str) -> None:
    require("id: authorize" in approve,
            "Spotlight approval provenance step identity changed")
    for output in (
        "codeql_run_id", "codeql_check_suite_id", "dependency_run_id",
        "dependency_check_suite_id", "profile_run_id", "profile_check_suite_id",
    ):
        require(approve.count(f"{output}: ${{{{ steps.authorize.outputs.{output} }}}}") == 1,
                f"Spotlight approval must seal one exact provenance output: {output}")
        require(approve.count(f'echo "{output}=$') == 1,
                f"Spotlight approval must emit one exact provenance output: {output}")
    for fragment in (
        "RUNS_TOTAL=\"$(jq -r '.total_count // empty' <<<\"$RUNS\")\"",
        "RUNS_COUNT=\"$(jq '.[(\"workflow\" + \"_runs\")] | length' <<<\"$RUNS\")\"",
        core.RUN_COMPLETENESS_GATE,
        'test "$RUNS_TOTAL" -le 3 || {',
        'if [ "$RUNS_TOTAL" = "3" ]; then',
        'test "$RUN_COUNT" = "1"',
        '[[ "$RUN_ID" =~ ^[1-9][0-9]*$ ]]',
        '[[ "$CHECK_SUITE_ID" =~ ^[1-9][0-9]*$ ]]',
        '[[ "$RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]',
        'test "$(jq -r .head_sha <<<"$RUN")" = "$HEAD_SHA"',
        'test "$(jq -r .head_branch <<<"$RUN")" = "$CANDIDATE_BRANCH"',
        'test "$(jq -r .event <<<"$RUN")" = "pull_request"',
        'test "$(jq -r .workflow_id <<<"$RUN")" = "$EXPECTED_ID"',
        'test "$(jq -r .repository.full_name <<<"$RUN")" = "$GITHUB_REPOSITORY"',
        'test "$(jq -r .head_repository.full_name <<<"$RUN")" = "$GITHUB_REPOSITORY"',
    ):
        require(fragment in approve,
                f"Spotlight approval run-provenance contract is missing: {fragment}")
    require("| unique |" not in approve,
            "Spotlight approval must not hide duplicate canonical workflow-run identities")


def validate(sync: str, stats: str, policy: str) -> None:
    require("  workflow_dispatch:\n" in sync,
            "Spotlight synchronization must retain a manual recovery dispatch")
    require('  schedule:\n' in sync and '    - cron: "41 * * * *"' in sync,
            "Spotlight synchronization must retain hourly recovery reconciliation at minute 41")
    require("merge_ui_after_checks" not in sync and "merge_ui_after_checks" not in stats,
            "Spotlight standing authorization must not depend on a manual merge input")

    core.validate_mutation_budget(sync)
    approve = core.job_block(sync, "approve", "merge")
    merge = core.job_block(sync, "merge", None)
    require("name: approve-bot-pr-checks-only" in approve,
            "Spotlight approval job identity changed")
    require("permissions:\n      contents: read\n      actions: write" in approve,
            "Spotlight approval must retain only contents-read plus Actions-write authority")
    require("timeout-minutes: 12" in approve and
            "for attempt in $(seq 1 60); do" in approve and "sleep 10" in approve,
            "Spotlight Actions-only approval job must own bounded canonical workflow waiting")
    validate_run_provenance(approve)

    require("name: merge-readme-only-terminal-write" in merge,
            "Spotlight terminal merge job identity changed")
    require("timeout-minutes: 3" in merge,
            "Spotlight terminal merge authority window changed")
    require("permissions:\n      contents: write\n      pull-requests: read\n      checks: read" in merge,
            "Spotlight terminal merge authority changed")
    for forbidden in ("for attempt in ", "sleep 10", "actions/checkout@", "actions/setup-python@", "python3 "):
        require(forbidden not in merge,
                f"Spotlight terminal merge acquired polling/authored execution surface: {forbidden}")
    core.validate_check_provenance(merge)
    validate_candidate_publication(sync)
    core.validate_dispatch_job(stats)

    for forbidden in (
        "github.event_name == 'workflow_dispatch'", "inputs.merge_ui_after_checks", "pull_request_target",
        "issue_comment", "repository_dispatch",
    ):
        require(forbidden not in approve and forbidden not in merge,
                f"Spotlight merge path contains an unauthorized alternate/manual authority gate: {forbidden}")

    policy_lower = policy.lower()
    for phrase in (
        "standing authorization", "automation/spotlight-links/", "content-addressed candidate branches",
        "scheduled reconciliation", "post-publication bot dispatch", "readme-only", "mutation budget", "quarantine",
        "append-once", "no candidate-ref patch", "actions-only approval job", "terminal merge job",
        "five protected-main checks", "integration id `15368`", "no bypass actor",
        "does not authorize arbitrary readme/ui", "dependabot", "candidate refs are never moved",
        "reductive reconciliation", "30-minute stale floor",
    ):
        require(phrase.lower() in policy_lower,
                f"Spotlight standing auto-merge policy is missing: {phrase}")


def expect_failure(sync: str, stats: str, policy: str, expected: str) -> None:
    try:
        validate(sync, stats, policy)
    except ValueError as exc:
        require(expected in str(exc), f"self-test failed for wrong reason: {exc}")
    else:
        fail(f"self-test accepted forbidden Spotlight auto-merge authority drift: {expected}")


def self_test(sync: str, stats: str, policy: str) -> None:
    expect_failure(
        sync.replace("  workflow_dispatch:\n", "  workflow_dispatch:\n    inputs:\n      merge_ui_after_checks:\n        type: boolean\n", 1),
        stats, policy, "must not depend on a manual merge input",
    )
    expect_failure(
        sync.replace("          MAX_ATTEMPTS=2\n", "          MAX_ATTEMPTS=3\n", 1),
        stats, policy, "mutation-budget fail-closed contract is missing",
    )
    expect_failure(
        sync.replace(
            'STALE_AFTER_SECONDS=1800',
            'STALE_AFTER_SECONDS=0',
            1,
        ),
        stats, policy, "reconciler lost a stale-only/topology proof",
    )
    expect_failure(
        sync.replace(
            'CLOSED_PR="$(gh api --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}" --input close-pr.json)"',
            'CLOSED_PR="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge" --input close-pr.json)"',
            1,
        ),
        stats, policy, "reconciler lost a stale-only/topology proof",
    )
    expect_failure(
        sync.replace(
            'CREATED_REF="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" --input ref.json)"',
            'CREATED_REF="$(gh api --method PATCH "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CANDIDATE_BRANCH}" --input ref.json)"',
            1,
        ),
        stats, policy, "regained mutable publication authority",
    )
    expect_failure(
        sync.replace(CANDIDATE_FORMULA_PROPOSE, 'CANDIDATE_ID="$README_SHA256_AFTER"', 1),
        stats, policy, "lost exact main/generated/README content addressing",
    )
    expect_failure(
        sync.replace(
            'test "$(jq -r .head_branch <<<"$RUN")" = "$CANDIDATE_BRANCH"',
            'test "$(jq -r .head_branch <<<"$RUN")" = "automation/spotlight-links"',
            1,
        ),
        stats, policy, "run-provenance contract is missing",
    )
    expect_failure(
        sync.replace(
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha)" = "$HEAD_SHA"',
            'test -n "$CANDIDATE_BRANCH"',
            1,
        ),
        stats, policy, "first publication must bind the created ref",
    )
    expect_failure(
        sync.replace('test "$AFTER_EXACT" = "0"', 'test "$AFTER_EXACT" -le 1', 1),
        stats, policy, "terminal cleanup must prove the exact consumed ref is absent",
    )
    wrong_suite = sync.replace(
        '{name:"analyze-actions",check_suite_id:$codeql,status:"completed",conclusion:"success",head_sha:$head}',
        '{name:"analyze-actions",check_suite_id:$profile,status:"completed",conclusion:"success",head_sha:$head}',
        1,
    )
    expect_failure(wrong_suite, stats, policy, "check-provenance contract is missing")
    policy_without_append_once = re.sub(r"append-once", "mutable", policy, flags=re.IGNORECASE)
    expect_failure(sync, stats, policy_without_append_once, "append-once")


def main() -> int:
    try:
        for path in (SYNC, STATS, POLICY):
            require(path.is_file(), f"Spotlight standing auto-merge input is missing: {path.relative_to(ROOT)}")
        sync = SYNC.read_text(encoding="utf-8")
        stats = STATS.read_text(encoding="utf-8")
        policy = POLICY.read_text(encoding="utf-8")
        validate(sync, stats, policy)
        self_test(sync, stats, policy)
        print(
            "Spotlight UI merge authorization validation passed: stale interrupted candidates have topology-bound reductive reconciliation; "
            "source epochs cross the read-only two-attempt constructive mutation budget; admitted proposals publish one content-addressed candidate ref; "
            "approval binds exact workflow runs; terminal merge consumes exact check-suite provenance and uses idempotent exact-ref cleanup."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
