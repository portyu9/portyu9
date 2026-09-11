#!/usr/bin/env python3
"""Fail closed on GitHub Actions workflow authority drift.

The generic workflow/parser/profile-publication firewall is preserved byte-for-byte in
workflow_authority_contract_core.py. This layer owns the current Spotlight candidate
transaction contract, whose branch identity is content-addressed and immutable, plus the
stale-only reductive reconciliation boundary.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

import automation_policy
import spotlight_profile_links as spotlight_links
import workflow_authority_contract_core as core

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"
PROFILE_STATS = WORKFLOWS / "profile-stats.yml"
SYNC = WORKFLOWS / "spotlight-link-sync.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"
README = ROOT / "README.md"
POLICY_RELATIVE = ".github/automation-policy-v1.json"


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def validate_policy_cross_contracts(policy: dict[str, object], profile_stats: str, sync: str) -> None:
    ruleset_relative = policy["rulesetContract"]
    require(isinstance(ruleset_relative, str), "Automation Policy IR ruleset contract path is malformed")
    ruleset_path = ROOT / ruleset_relative
    require(ruleset_path.is_file() and not ruleset_path.is_symlink(),
            "Automation Policy IR ruleset contract is missing or aliased")
    try:
        rulesets = automation_policy.strict_json_loads(ruleset_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        fail(f"Automation Policy IR ruleset cross-contract JSON is invalid: {exc}")
    require(isinstance(rulesets, dict) and rulesets.get("repository") == policy["repository"],
            "Automation Policy IR repository differs from ruleset desired state")
    main = rulesets.get("rulesets", {}).get("Protect Main", {})
    required = main.get("rules", {}).get("required_status_checks", {})
    require(required.get("integration_id") == policy["githubActionsAppId"],
            "Automation Policy IR GitHub Actions app id differs from Protect Main")
    policy_contexts = [entry["context"] for entry in policy["requiredChecks"]]
    require(required.get("contexts") == policy_contexts,
            "Automation Policy IR required-check order/identity differs from Protect Main")
    generated = rulesets.get("rulesets", {}).get("Protect generated", {})
    require(generated.get("include") == [f"refs/heads/{policy['branches']['generated']}"],
            "Automation Policy IR generated branch differs from Protect generated")

    main_branch = policy["branches"]["main"]
    generated_branch = policy["branches"]["generated"]
    candidate_prefix = policy["branches"]["spotlightCandidatePrefix"]
    require(f'BOT_BRANCH_PREFIX: "{candidate_prefix}"' in sync,
            "Automation Policy IR Spotlight candidate prefix differs from workflow authority")
    require('BOT_BRANCH: "automation/spotlight-links"' not in sync,
            "Spotlight workflow retained the retired shared mutable bot branch")
    require(f"ref: {generated_branch}" in sync,
            "Automation Policy IR generated branch differs from Spotlight evidence checkout")
    require(f"refs/heads/{main_branch}" in sync,
            "Automation Policy IR main branch differs from Spotlight source authority")
    require(f"refs/heads/{main_branch}" in profile_stats,
            "Automation Policy IR main branch differs from profile publication freshness authority")
    require(f"HEAD:{generated_branch}" in profile_stats,
            "Automation Policy IR generated branch differs from terminal publication target")
    merge = core.job_block(sync, "merge", None)
    for context in policy_contexts:
        require(context in merge,
                f"Automation Policy IR required check is not consumed by Spotlight terminal merge: {context}")


def validate_immutable_candidate_contract(workflow: str, propose: str, approve: str, merge: str) -> None:
    require('BOT_BRANCH_PREFIX: "automation/spotlight-links/"' in workflow,
            "Spotlight immutable candidate prefix changed")
    require('BOT_BRANCH: "automation/spotlight-links"' not in workflow,
            "Spotlight regained the retired shared mutable bot branch")
    for forbidden in (
        'gh api --method PATCH "repos/${GITHUB_REPOSITORY}/git/refs/heads/',
        '-F force=true',
        'gh api --method PUT "repos/${GITHUB_REPOSITORY}/contents/README.md"',
    ):
        require(forbidden not in workflow,
                f"Spotlight immutable candidate publication regained mutable ref/content update authority: {forbidden}")

    require('readme_sha256_after: ${{ steps.render.outputs.readme_sha256_after }}' in workflow,
            "Spotlight plan must seal the candidate README digest")
    require('candidate_branch: ${{ steps.propose.outputs.candidate_branch }}' in propose,
            "Spotlight proposer must seal the exact immutable candidate branch")
    candidate_formula = (
        'CANDIDATE_ID="$(printf \'%s\\n%s\\n%s\\n\' "$SOURCE_SHA" "$GENERATED_SHA" '
        '"$README_SHA256_AFTER" | sha256sum | cut -d\' \' -f1)"'
    )
    require(candidate_formula in propose,
            "Spotlight proposer candidate identity lost source/generated/README content addressing")
    require('CANDIDATE_BRANCH="${BOT_BRANCH_PREFIX}${CANDIDATE_ID}"' in propose,
            "Spotlight proposer must derive branch identity only from the reviewed candidate digest")
    require('git/matching-refs/heads/${CANDIDATE_BRANCH}' in propose and
            'test "$EXACT_REF_COUNT" = "0" || test "$EXACT_REF_COUNT" = "1"' in propose,
            "Spotlight proposer must distinguish first publication from exact immutable retry reuse")

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
                f"Spotlight immutable candidate transaction must contain one reviewed fragment: {fragment}")
        position = propose.index(fragment)
        require(position > cursor,
                f"Spotlight immutable candidate transaction reordered publication boundary: {fragment}")
        cursor = position

    for fragment in (
        'test "$(jq \' .parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"',
        'test "$(jq -r \'.parents[0].sha\' <<<"$CANDIDATE_COMMIT")" = "$SOURCE_SHA"',
        'test "$(jq -r .author.name <<<"$CANDIDATE_COMMIT")" = "$BOT_NAME"',
        'test "$(jq -r .committer.email <<<"$CANDIDATE_COMMIT")" = "$BOT_EMAIL"',
    ):
        if " .parents" in fragment:
            fragment = fragment.replace("' .parents", "'.parents")
        require(fragment in propose,
                f"Spotlight immutable candidate reuse lost commit-topology/identity proof: {fragment}")
    require('test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha)" = "$HEAD_SHA"' in propose,
            "Spotlight proposer must prove the published ref equals the validated candidate head")
    require('maintainer_can_modify:false' in propose and
            'test "$(jq -r .maintainer_can_modify <<<"$PR")" = "false"' in propose,
            "Spotlight immutable candidate PR must remain non-maintainer-mutable")

    downstream_formula = (
        'EXPECTED_CANDIDATE_ID="$(printf \'%s\\n%s\\n%s\\n\' "$BASE_SHA" "$GENERATED_SHA" '
        '"$README_SHA256_AFTER" | sha256sum | cut -d\' \' -f1)"'
    )
    for block, label in ((approve, "approval"), (merge, "terminal merge")):
        require(downstream_formula in block and
                'test "$CANDIDATE_BRANCH" = "${BOT_BRANCH_PREFIX}${EXPECTED_CANDIDATE_ID}"' in block,
                f"Spotlight {label} must independently rederive the exact candidate branch")
        require('git/ref/heads/${CANDIDATE_BRANCH}' in block,
                f"Spotlight {label} must prove the immutable candidate ref still exists")
    require('test "$(jq -r .head_branch <<<"$RUN")" = "$CANDIDATE_BRANCH"' in approve,
            "Spotlight approval provenance must bind workflow runs to the immutable candidate branch")
    require('test "$(jq -r .head.ref <<<"$PR")" = "$CANDIDATE_BRANCH"' in merge,
            "Spotlight terminal merge must bind PR identity to the immutable candidate branch")
    require('gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CANDIDATE_BRANCH}" >/dev/null' in merge,
            "Spotlight cleanup must delete only the exact consumed immutable candidate ref")


def validate_sync_contract(workflow: str, readme: str) -> None:
    for forbidden in ("pull_request_target", "  workflow_run:", "repository_dispatch", "issues: write", "id-token: write", "attestations: write"):
        require(forbidden not in workflow,
                f"Spotlight direct-link sync contains forbidden authority/trigger: {forbidden.strip()}")
    require('ref: generated' in workflow and 'persist-credentials: false' in workflow,
            "Spotlight plan must read generated evidence without persisted credentials")
    require("validate-portfolio-evidence-ledger.py published/portfolio-evidence --require-live" in workflow,
            "Spotlight plan must revalidate published Ledger evidence")

    reconcile = core.job_block(workflow, "reconcile", "budget")
    budget = core.job_block(workflow, "budget", "quarantine")
    quarantine = core.job_block(workflow, "quarantine", "propose")
    propose = core.job_block(workflow, "propose", "approve")
    approve = core.job_block(workflow, "approve", "merge")
    merge = core.job_block(workflow, "merge", None)

    require("name: reconcile-stale-candidates-write" in reconcile and "needs: plan" in reconcile,
            "Spotlight stale-candidate reconciler identity/dependency changed")
    require("permissions:\n      contents: write\n      pull-requests: write" in reconcile,
            "Spotlight stale-candidate reconciler authority changed")
    require("STALE_AFTER_SECONDS=1800" in reconcile and 'test "$REF_COUNT" -le 20 || {' in reconcile,
            "Spotlight stale-candidate reconciler lost age/namespace bounds")
    require('if [ -n "$EXPECTED_CANDIDATE_BRANCH" ] && [ "$BRANCH" = "$EXPECTED_CANDIDATE_BRANCH" ]; then' in reconcile,
            "Spotlight reconciler must preserve the current deterministic candidate")
    require('test "$(jq -r .user.login <<<"$PR")" = "github-actions[bot]"' in reconcile and
            'test "$(jq -r .maintainer_can_modify <<<"$PR")" = "false"' in reconcile,
            "Spotlight reconciler lost exact bot PR identity binding")
    require(reconcile.count('gh api --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}"') == 1 and
            reconcile.count('gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BRANCH}"') == 1,
            "Spotlight reconciler mutation surface must remain one PR close plus one stale-ref delete")
    for forbidden in ("gh api --method POST ", "gh api --method PUT ", "/approve", "/merge"):
        require(forbidden not in reconcile,
                f"Spotlight reconciler regained constructive mutation authority: {forbidden}")
    core.require_exact_gh_api_surface(
        reconcile,
        label="Spotlight reconcile",
        expected_lines=(
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated" --jq .object.sha)" = "$GENERATED_SHA"',
            'REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${BOT_BRANCH_PREFIX}")"',
            'CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"',
            'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${PARENT_SHA}...${HEAD_SHA}")"',
            'PRS="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${BRANCH}&base=main&per_page=2")"',
            'CLOSED_PR="$(gh api --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}" --input close-pr.json)"',
            'gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BRANCH}" >/dev/null',
            'REMAINING_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${BRANCH}")"',
        ),
    )

    require("name: mutation-budget-read-only" in budget and "needs: plan" in budget,
            "Spotlight mutation budget identity/dependency changed")
    require("permissions:\n      actions: read" in budget,
            "Spotlight mutation budget must retain Actions-read-only authority")
    require("contents: write" not in budget and "pull-requests: write" not in budget and "actions: write" not in budget,
            "Spotlight mutation budget acquired write authority")
    require("MAX_ATTEMPTS=2" in budget,
            "Spotlight source-epoch mutation budget changed")
    require('ARTIFACT_NAME="spotlight-link-plan-${BASE_SHA}-${GENERATED_SHA}"' in budget,
            "Spotlight mutation budget lost exact main/generated epoch identity")
    require('test "$TOTAL" = "$COUNT" || {' in budget and 'test "$TOTAL" -le 100 || {' in budget,
            "Spotlight mutation budget must prove complete one-page artifact history")
    require('.workflow_run.repository_id != $repo' in budget and '.workflow_run.head_repository_id != $repo' in budget,
            "Spotlight mutation budget lost repository provenance binding")
    require('.workflow_run.head_branch != "main"' in budget and '.workflow_run.head_sha != $base' in budget,
            "Spotlight mutation budget lost exact source-main binding")
    require('test "$CURRENT" = "1" || {' in budget,
            "Spotlight mutation budget must bind exactly one current-run attempt token")
    require('echo "allowed=$ALLOWED" >> "$GITHUB_OUTPUT"' in budget,
            "Spotlight mutation budget must seal its admission decision")
    core.require_exact_gh_api_surface(
        budget,
        label="Spotlight mutation budget",
        expected_lines=(
            'ARTIFACTS="$(gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${ARTIFACT_NAME}&per_page=100")"',
        ),
    )

    require("name: mutation-budget-quarantine-read-only" in quarantine,
            "Spotlight mutation quarantine identity changed")
    require("needs: [plan, budget]" in quarantine and "needs.budget.outputs.allowed != 'true'" in quarantine,
            "Spotlight mutation quarantine must be gated on an exhausted successful budget decision")
    require("permissions:\n      contents: read" in quarantine,
            "Spotlight mutation quarantine must remain read-only")
    require("GH_TOKEN:" not in quarantine and "gh api " not in quarantine,
            "Spotlight mutation quarantine must not receive GitHub mutation/API authority")
    require("exit 1" in quarantine and "GITHUB_STEP_SUMMARY" in quarantine,
            "Spotlight mutation quarantine must fail visibly while retaining read-only diagnostics")

    require("needs: [plan, reconcile, budget]" in propose and "needs.budget.outputs.allowed == 'true'" in propose,
            "Spotlight proposal mutation must require successful reconciliation and positive budget admission")
    require("needs: [plan, reconcile, budget, propose]" in approve and "needs.budget.outputs.allowed == 'true'" in approve,
            "Spotlight approval mutation must remain downstream of reconciliation and positive budget admission")
    require("needs: [plan, reconcile, budget, propose, approve]" in merge and "needs.budget.outputs.allowed == 'true'" in merge,
            "Spotlight terminal merge must remain downstream of reconciliation and positive budget admission")
    require('APPROVAL_REQUESTED_RUN_IDS=""' in approve and 'case " $APPROVAL_REQUESTED_RUN_IDS " in' in approve,
            "Spotlight approval loop must locally de-duplicate approval mutations")
    require('APPROVAL_REQUESTED_RUN_IDS="${APPROVAL_REQUESTED_RUN_IDS} ${RUN_ID}"' in approve,
            "Spotlight approval loop must record each requested approval identity")

    require("spotlight-link-plan-${{ steps.render.outputs.base_sha }}-${{ steps.render.outputs.generated_sha }}" in workflow,
            "Spotlight changed-plan artifact must be content-addressed by source epoch")
    require("spotlight-link-plan-${{ needs.plan.outputs.base_sha }}-${{ needs.plan.outputs.generated_sha }}" in propose,
            "Spotlight proposal must download only its exact epoch plan artifact")

    validate_immutable_candidate_contract(workflow, propose, approve, merge)

    core.require_exact_gh_api_surface(
        propose,
        label="Spotlight propose",
        expected_lines=(
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$SOURCE_SHA"',
            'gh api "repos/${GITHUB_REPOSITORY}/contents/README.md?ref=main" --jq .content ' + chr(92),
            'MATCHING_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"',
            'BLOB="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/blobs" --input blob.json)"',
            'BASE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${SOURCE_SHA}")"',
            'TREE="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/trees" --input tree.json)"',
            'CANDIDATE_COMMIT="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/commits" --input commit.json)"',
            'CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"',
            'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${SOURCE_SHA}...${HEAD_SHA}")"',
            'gh api "repos/${GITHUB_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}" --jq .content ' + chr(92),
            'CREATED_REF="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" --input ref.json)"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha)" = "$HEAD_SHA"',
            'PRS="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${CANDIDATE_BRANCH}&base=main&per_page=10")"',
            'gh api --method POST "repos/${GITHUB_REPOSITORY}/pulls" --input pr.json > pr-response.json',
            'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"',
        ),
    )
    core.require_exact_gh_api_surface(
        approve,
        label="Spotlight approve",
        expected_lines=(
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated" --jq .object.sha)" = "$GENERATED_SHA"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha)" = "$HEAD_SHA"',
            'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${BASE_SHA}...${HEAD_SHA}")"',
            'CODEQL_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/codeql.yml" --jq .id)"',
            'DEPENDENCY_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/dependency-review.yml" --jq .id)"',
            'PROFILE_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/profile-quality.yml" --jq .id)"',
            'RUNS="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100")"',
            'gh api --method POST "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve" >/dev/null',
        ),
    )
    core.require_exact_gh_api_surface(
        merge,
        label="Spotlight merge",
        expected_lines=(
            'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated" --jq .object.sha)" = "$GENERATED_SHA"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha)" = "$HEAD_SHA"',
            'FILES="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100")"',
            'CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"',
            'CHECKS="$(gh api -H \'Accept: application/vnd.github+json\' "repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs?filter=latest&per_page=100")"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated" --jq .object.sha)" = "$GENERATED_SHA"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${CANDIDATE_BRANCH}" --jq .object.sha)" = "$HEAD_SHA"',
            'RESULT="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge" --input merge.json)"',
            'MERGED_PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$MERGE_SHA"',
            'CANDIDATE_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"',
            'gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CANDIDATE_BRANCH}" >/dev/null',
            'AFTER_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"',
        ),
    )

    for block, label in ((reconcile, "reconcile"), (budget, "budget"), (quarantine, "quarantine"),
                         (propose, "propose"), (approve, "approve"), (merge, "merge")):
        require("actions/checkout@" not in block and "actions/setup-python@" not in block,
                f"Spotlight {label} authority job must not checkout or execute authored Python")
    require('compare/${BASE_SHA}...${HEAD_SHA}' in approve,
            "Spotlight approval must compare exact proposed head against reviewed base")
    for check in ("analyze-actions", "analyze-python", "dependency-review", "integration-pinned-upstream", "validate-contracts"):
        require(check in merge, f"Spotlight merge is missing required check: {check}")
    for fragment in (
        'test "$(jq -r .merged <<<"$MERGED_PR")" = "true"',
        'test "$(jq -r .head.sha <<<"$MERGED_PR")" = "$HEAD_SHA"',
        'test "$EXACT_REF_COUNT" = "0" || test "$EXACT_REF_COUNT" = "1"',
        'test "$(jq -r --arg ref "refs/heads/${CANDIDATE_BRANCH}" \'[.[] | select(.ref == $ref)][0].object.sha\' <<<"$CANDIDATE_REFS")" = "$HEAD_SHA"',
        'gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CANDIDATE_BRANCH}" >/dev/null',
        'test "$AFTER_EXACT" = "0"',
    ):
        require(fragment in merge,
                f"Spotlight merge lost exact-head immutable-candidate cleanup closure: {fragment}")

    require(readme.count(spotlight_links.START) == 1 and readme.count(spotlight_links.END) == 1,
            "README must contain exactly one guarded Spotlight direct-link block")
    start = readme.index(spotlight_links.START)
    end = readme.index(spotlight_links.END, start) + len(spotlight_links.END)
    block = readme[start:end]
    card_targets = core.re.findall(r'<a href="(https://github\.com/portyu9/[A-Za-z0-9_.-]+)"><picture>', block)
    workflow_targets = core.re.findall(r'<a href="(https://github\.com/portyu9/[A-Za-z0-9_.-]+/actions/workflows/(?:ci|security)\.yml)">', block)
    require(len(card_targets) == 3 and len(set(card_targets)) == 3,
            "Spotlight block must contain three distinct repository targets")
    require(len(workflow_targets) == 6 and len(set(workflow_targets)) == 6,
            "Spotlight block must contain six distinct direct workflow targets")


def expect_sync_failure(workflow: str, readme: str, expected_fragment: str) -> None:
    try:
        validate_sync_contract(workflow, readme)
    except ValueError as exc:
        require(expected_fragment in str(exc), f"Spotlight immutable-candidate self-test failed for wrong reason: {exc}")
    else:
        fail(f"Spotlight immutable-candidate self-test accepted forbidden drift: {expected_fragment}")


def self_test_current_sync(workflow: str, readme: str) -> None:
    validate_sync_contract(workflow, readme)
    expect_sync_failure(
        workflow.replace(
            'CREATED_REF="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" --input ref.json)"',
            'CREATED_REF="$(gh api --method PATCH "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CANDIDATE_BRANCH}" --input ref.json)"',
            1,
        ),
        readme,
        "regained mutable ref/content update authority",
    )
    expect_sync_failure(
        workflow.replace(
            'test "$(jq -r .head_branch <<<"$RUN")" = "$CANDIDATE_BRANCH"',
            'test "$(jq -r .head_branch <<<"$RUN")" = "automation/spotlight-links"',
            1,
        ),
        readme,
        "approval provenance must bind workflow runs",
    )
    expect_sync_failure(
        workflow.replace(
            'test "$CANDIDATE_BRANCH" = "${BOT_BRANCH_PREFIX}${EXPECTED_CANDIDATE_ID}"',
            'test -n "$CANDIDATE_BRANCH"',
            1,
        ),
        readme,
        "approval must independently rederive",
    )
    expect_sync_failure(
        workflow.replace(
            'needs: [plan, reconcile, budget]',
            'needs: [plan, budget]',
            1,
        ),
        readme,
        "must require successful reconciliation",
    )


def main() -> int:
    try:
        for path in (automation_policy.POLICY_PATH, QUALITY, PROFILE_STATS, GOVERNANCE, README, SYNC):
            require(path.is_file(), f"Workflow authority input is missing: {path.relative_to(ROOT)}")
        policy = automation_policy.load_policy()
        core.self_test(policy)
        core.validate_inventory(policy)
        profile_stats = PROFILE_STATS.read_text(encoding="utf-8")
        sync = SYNC.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        validate_policy_cross_contracts(policy, profile_stats, sync)
        core.validate_quality_contract(QUALITY.read_text(encoding="utf-8"))
        core.validate_profile_stats_contract(profile_stats)
        self_test_current_sync(sync, readme)
        core.validate_governance(GOVERNANCE.read_text(encoding="utf-8"))
        print(
            f"Workflow authority validation passed: {policy['policyId']} is the executable semantic authority graph for "
            f"{len(policy['workflows'])} workflows and {sum(len(workflow['jobs']) for workflow in policy['workflows'].values())} jobs; "
            "generic workflow/profile-publication guards remain byte-preserved; Spotlight has stale-only reductive reconciliation, "
            "content-addressed create-once candidates, exact-ref approval/merge revalidation, and exact API-surface negative tests."
        )
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())