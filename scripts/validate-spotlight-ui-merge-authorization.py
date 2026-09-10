#!/usr/bin/env python3
"""Fail closed on overly broad Spotlight README/UI merge authority."""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SYNC = ROOT / ".github/workflows/spotlight-link-sync.yml"
STATS = ROOT / ".github/workflows/profile-stats.yml"
POLICY = ROOT / ".github/SPOTLIGHT_UI_MERGE_AUTHORIZATION.md"

BUDGET_IF_EXPR = "needs.plan.outputs.changed == 'true'"
QUARANTINE_IF_EXPR = (
    "always() && needs.plan.outputs.changed == 'true' && needs.budget.result == 'success' "
    "&& needs.budget.outputs.allowed != 'true'"
)
PROPOSE_IF_EXPR = "needs.plan.outputs.changed == 'true' && needs.budget.outputs.allowed == 'true'"
APPROVE_IF_EXPR = (
    "needs.plan.outputs.changed == 'true' && needs.budget.outputs.allowed == 'true' "
    "&& needs.propose.result == 'success'"
)
MERGE_IF_EXPR = (
    "needs.plan.outputs.changed == 'true' && needs.budget.outputs.allowed == 'true' "
    "&& needs.propose.result == 'success' && needs.approve.result == 'success'"
)
JOB_IF_LINE = re.compile(r"(?m)^    if:\s*(?P<expr>.+?)\s*$")
DISPATCH_HEADER = (
    "  dispatch:\n"
    "    name: dispatch-spotlight-link-sync\n"
    "    needs: publish\n"
    "    runs-on: ubuntu-24.04\n"
    "    timeout-minutes: 2\n"
    "    permissions:\n"
    "      actions: write\n"
)
DISPATCH_STEP = (
    "      - name: Dispatch exact Spotlight reconciliation workflow\n"
    "        env:\n"
    "          GH_TOKEN: ${{ github.token }}\n"
    "        run: |\n"
    "          set -euo pipefail\n"
    "          gh api --method POST \\\n"
    "            \"repos/${GITHUB_REPOSITORY}/actions/workflows/spotlight-link-sync.yml/dispatches\" \\\n"
    "            -f ref=main"
)
CLEANUP_404_GATE = (
    "          else\n"
    "            test \"$(jq -r '.status // empty' <<<\"$BRANCH_REF\")\" = \"404\"\n"
    "          fi"
)
RUN_COMPLETENESS_GATE = 'test "$RUNS_TOTAL" = "$RUNS_COUNT" || {'
CHECK_COMPLETENESS_GATE = 'test "$CHECKS_TOTAL" = "$CHECKS_COUNT" || {'
CHECK_BINDING_GATE = 'test "$OBSERVED_CHECKS" = "$EXPECTED_CHECKS"'
BUDGET_COMPLETENESS_GATE = 'test "$TOTAL" = "$COUNT" || {'
BUDGET_CURRENT_GATE = 'test "$CURRENT" = "1" || {'


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def job_block(workflow: str, key: str, next_key: str | None) -> str:
    start = re.search(rf"(?m)^  {re.escape(key)}:\s*$", workflow)
    require(start is not None, f"workflow job is missing: {key}")
    if next_key is None:
        return workflow[start.start():]
    end = re.search(rf"(?m)^  {re.escape(next_key)}:\s*$", workflow[start.end():])
    require(end is not None, f"workflow job boundary is missing after {key}: {next_key}")
    return workflow[start.start(): start.end() + end.start()]


def exact_job_if(block: str, label: str) -> str:
    """Return one canonical job-level if expression, never a comment or nested step predicate."""
    expressions = [match.group("expr").strip() for match in JOB_IF_LINE.finditer(block)]
    require(len(expressions) == 1, f"{label} must contain exactly one canonical job-level if predicate")
    return expressions[0]


def validate_dispatch_job(stats: str) -> None:
    """Bind post-publication authority to one exact fixed-workflow, ref-only dispatch step."""
    dispatch = job_block(stats, "dispatch", None)
    require(dispatch.startswith(DISPATCH_HEADER),
            "Profile-stats dispatcher job metadata/authority changed")
    require(dispatch.count("      - name: ") == 1,
            "Profile-stats dispatcher must contain exactly one reviewed step")
    require(dispatch.count(DISPATCH_STEP) == 1,
            "Profile-stats dispatcher must remain one exact ref-only fixed-workflow reconciliation dispatch")
    for forbidden in (
        "repository_dispatch", "workflow_id=", "-f inputs", "-F inputs", "pull_request_target",
    ):
        require(forbidden not in dispatch,
                f"Profile-stats dispatcher contains unauthorized alternate dispatch authority: {forbidden}")


def validate_mutation_budget(sync: str) -> None:
    """Require an exact read-only per-source-epoch circuit breaker before every mutation job."""
    plan = job_block(sync, "plan", "budget")
    budget = job_block(sync, "budget", "quarantine")
    quarantine = job_block(sync, "quarantine", "propose")
    propose = job_block(sync, "propose", "approve")
    approve = job_block(sync, "approve", "merge")
    merge = job_block(sync, "merge", None)

    require(exact_job_if(budget, "Spotlight mutation budget job") == BUDGET_IF_EXPR,
            "Spotlight mutation budget must execute only for a changed reviewed plan")
    require("name: mutation-budget-read-only" in budget and "needs: plan" in budget,
            "Spotlight mutation budget identity/dependency changed")
    require("permissions:\n      actions: read" in budget,
            "Spotlight mutation budget must retain only Actions-read authority")
    for forbidden in (
        "contents: write", "pull-requests: write", "actions: write", "checks: write",
        "id-token: write", "attestations: write", "actions/checkout@", "actions/setup-python@", "python3 ",
    ):
        require(forbidden not in budget,
                f"Spotlight mutation budget acquired forbidden authority/code surface: {forbidden}")
    require(budget.count("gh api ") == 1,
            "Spotlight mutation budget must contain exactly one reviewed GitHub API read")
    require('ARTIFACTS="$(gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${ARTIFACT_NAME}&per_page=100")"' in budget,
            "Spotlight mutation budget artifact-history API identity changed")
    for fragment in (
        'ARTIFACT_NAME="spotlight-link-plan-${BASE_SHA}-${GENERATED_SHA}"',
        "MAX_ATTEMPTS=2",
        BUDGET_COMPLETENESS_GATE,
        'test "$TOTAL" -le 100 || {',
        '.workflow_run.repository_id != $repo',
        '.workflow_run.head_repository_id != $repo',
        '.workflow_run.head_branch != "main"',
        '.workflow_run.head_sha != $base',
        BUDGET_CURRENT_GATE,
        'echo "allowed=$ALLOWED" >> "$GITHUB_OUTPUT"',
        'echo "attempt_count=$TOTAL" >> "$GITHUB_OUTPUT"',
    ):
        require(fragment in budget,
                f"Spotlight mutation-budget fail-closed contract is missing: {fragment}")
    require("spotlight-link-plan-${{ steps.render.outputs.base_sha }}-${{ steps.render.outputs.generated_sha }}" in plan,
            "Spotlight changed-plan attempt token must be content-addressed by main/generated source epoch")

    require(exact_job_if(quarantine, "Spotlight mutation quarantine job") == QUARANTINE_IF_EXPR,
            "Spotlight mutation quarantine predicate changed")
    require("name: mutation-budget-quarantine-read-only" in quarantine and "needs: [plan, budget]" in quarantine,
            "Spotlight mutation quarantine identity/dependency changed")
    require("permissions:\n      contents: read" in quarantine,
            "Spotlight mutation quarantine must remain read-only")
    for forbidden in ("GH_TOKEN:", "gh api ", "contents: write", "pull-requests:", "actions:", "checks:"):
        require(forbidden not in quarantine,
                f"Spotlight mutation quarantine acquired forbidden API/authority surface: {forbidden}")
    require("GITHUB_STEP_SUMMARY" in quarantine and "exit 1" in quarantine,
            "Spotlight mutation quarantine must retain diagnostics and fail visibly")

    require(exact_job_if(propose, "Spotlight propose job") == PROPOSE_IF_EXPR,
            "Spotlight proposal must require exact positive mutation-budget admission")
    require("needs: [plan, budget]" in propose,
            "Spotlight proposal dependency must include mutation-budget admission")
    require("spotlight-link-plan-${{ needs.plan.outputs.base_sha }}-${{ needs.plan.outputs.generated_sha }}" in propose,
            "Spotlight proposal must consume only the exact source-epoch plan artifact")

    require(exact_job_if(approve, "Spotlight approve job") == APPROVE_IF_EXPR,
            "Spotlight approval must require exact positive mutation-budget admission")
    require("needs: [plan, budget, propose]" in approve,
            "Spotlight approval dependency must include mutation-budget admission")
    for fragment in (
        'APPROVAL_REQUESTED_RUN_IDS=""',
        'case " $APPROVAL_REQUESTED_RUN_IDS " in',
        '*" $RUN_ID "*) : ;;',
        'APPROVAL_REQUESTED_RUN_IDS="${APPROVAL_REQUESTED_RUN_IDS} ${RUN_ID}"',
    ):
        require(fragment in approve,
                f"Spotlight approval mutation de-duplication contract is missing: {fragment}")

    require(exact_job_if(merge, "Spotlight merge job") == MERGE_IF_EXPR,
            "Spotlight merge job must require the exact mutation-budget/plan/propose/approve prerequisites")
    require("needs: [plan, budget, propose, approve]" in merge,
            "Spotlight terminal merge dependency must include mutation-budget admission")


def validate_run_provenance(approve: str) -> None:
    """Require a complete canonical workflow-run set and seal exact run/suite identities."""
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
        RUN_COMPLETENESS_GATE,
        'test "$RUNS_TOTAL" -le 3 || {',
        'if [ "$RUNS_TOTAL" = "3" ]; then',
        'test "$RUN_COUNT" = "1"',
        '[[ "$RUN_ID" =~ ^[1-9][0-9]*$ ]]',
        '[[ "$CHECK_SUITE_ID" =~ ^[1-9][0-9]*$ ]]',
        '[[ "$RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]',
        'test "$(jq -r .head_sha <<<"$RUN")" = "$HEAD_SHA"',
        'test "$(jq -r .head_branch <<<"$RUN")" = "$BOT_BRANCH"',
        'test "$(jq -r .event <<<"$RUN")" = "pull_request"',
        'test "$(jq -r .workflow_id <<<"$RUN")" = "$EXPECTED_ID"',
        'test "$(jq -r .repository.full_name <<<"$RUN")" = "$GITHUB_REPOSITORY"',
        'test "$(jq -r .head_repository.full_name <<<"$RUN")" = "$GITHUB_REPOSITORY"',
    ):
        require(fragment in approve,
                f"Spotlight approval run-provenance contract is missing: {fragment}")
    require("| unique |" not in approve,
            "Spotlight approval must not hide duplicate canonical workflow-run identities")


def validate_check_provenance(merge: str) -> None:
    """Bind every accepted required check to the sealed canonical workflow check suite."""
    for name in ("CODEQL", "DEPENDENCY", "PROFILE"):
        require(f"{name}_RUN_ID: ${{{{ needs.approve.outputs.{name.lower()}_run_id }}}}" in merge,
                f"Spotlight terminal merge lost sealed {name.lower()} run identity")
        require(f"{name}_CHECK_SUITE_ID: ${{{{ needs.approve.outputs.{name.lower()}_check_suite_id }}}}" in merge,
                f"Spotlight terminal merge lost sealed {name.lower()} check-suite identity")
    for fragment in (
        "CHECKS_TOTAL=\"$(jq -r '.total_count // empty' <<<\"$CHECKS\")\"",
        "CHECKS_COUNT=\"$(jq '.check_runs | length' <<<\"$CHECKS\")\"",
        CHECK_COMPLETENESS_GATE,
        "--argjson codeql \"$CODEQL_CHECK_SUITE_ID\"",
        "--argjson dependency \"$DEPENDENCY_CHECK_SUITE_ID\"",
        "--argjson profile \"$PROFILE_CHECK_SUITE_ID\"",
        '{name:"analyze-actions",check_suite_id:$codeql,status:"completed",conclusion:"success",head_sha:$head}',
        '{name:"analyze-python",check_suite_id:$codeql,status:"completed",conclusion:"success",head_sha:$head}',
        '{name:"dependency-review",check_suite_id:$dependency,status:"completed",conclusion:"success",head_sha:$head}',
        '{name:"integration-pinned-upstream",check_suite_id:$profile,status:"completed",conclusion:"success",head_sha:$head}',
        '{name:"validate-contracts",check_suite_id:$profile,status:"completed",conclusion:"success",head_sha:$head}',
        "select(.app.id == 15368)",
        "check_suite_id:.check_suite.id",
        CHECK_BINDING_GATE,
    ):
        require(fragment in merge,
                f"Spotlight terminal check-provenance contract is missing: {fragment}")
    require("actions: read" not in merge and "actions: write" not in merge,
            "Spotlight terminal merge must consume sealed run provenance without Actions authority")


def validate(sync: str, stats: str, policy: str) -> None:
    require("  workflow_dispatch:\n" in sync,
            "Spotlight synchronization must retain a manual recovery dispatch")
    require('  schedule:\n' in sync and '    - cron: "41 * * * *"' in sync,
            "Spotlight synchronization must retain hourly recovery reconciliation at minute 41")
    require("merge_ui_after_checks" not in sync,
            "Spotlight standing authorization must not depend on a manual merge input")
    require("merge_ui_after_checks" not in stats,
            "Profile-stats post-publication dispatch must not introduce a separate merge input")

    validate_mutation_budget(sync)
    approve = job_block(sync, "approve", "merge")
    merge = job_block(sync, "merge", None)
    require("name: approve-bot-pr-checks-only" in approve,
            "Spotlight approval job identity changed")
    require("permissions:\n      contents: read\n      actions: write" in approve,
            "Spotlight approval must retain only contents-read plus Actions-write authority")
    require("timeout-minutes: 12" in approve,
            "Spotlight approval/check-wait boundary changed")
    require("for attempt in $(seq 1 60); do" in approve and "sleep 10" in approve,
            "Spotlight Actions-only approval job must own canonical workflow waiting")
    validate_run_provenance(approve)

    require("name: merge-readme-only-terminal-write" in merge,
            "Spotlight terminal merge job identity changed")
    require("timeout-minutes: 3" in merge,
            "Spotlight terminal merge authority window changed")
    require("permissions:\n      contents: write\n      pull-requests: read\n      checks: read" in merge,
            "Spotlight terminal merge authority changed")
    require(CLEANUP_404_GATE in merge,
            "Spotlight terminal branch cleanup must fail closed on every lookup failure except explicit 404")
    for forbidden in ("for attempt in ", "sleep 10", "actions/checkout@", "actions/setup-python@", "python3 "):
        require(forbidden not in merge,
                f"Spotlight terminal merge acquired polling/authored execution surface: {forbidden}")
    for check in ("analyze-actions", "analyze-python", "dependency-review", "integration-pinned-upstream", "validate-contracts"):
        require(check in merge, f"Spotlight terminal merge lost required-check revalidation: {check}")
    validate_check_provenance(merge)

    for forbidden in (
        "github.event_name == 'workflow_dispatch'", "inputs.merge_ui_after_checks", "pull_request_target",
        "issue_comment", "repository_dispatch",
    ):
        require(forbidden not in approve and forbidden not in merge,
                f"Spotlight merge path contains an unauthorized alternate/manual authority gate: {forbidden}")

    validate_dispatch_job(stats)

    policy_lower = policy.lower()
    for phrase in (
        "standing authorization", "automation/spotlight-links", "scheduled reconciliation",
        "post-publication bot dispatch", "readme-only", "mutation budget", "quarantine",
        "actions-only approval job", "terminal merge job", "five protected-main checks",
        "integration id `15368`", "no bypass actor", "does not authorize arbitrary readme/ui", "dependabot",
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
        sync.replace(MERGE_IF_EXPR, MERGE_IF_EXPR.replace("needs.budget.outputs.allowed == 'true' && ", ""), 1),
        stats, policy, "exact mutation-budget/plan/propose/approve prerequisites",
    )
    guarded_line = f"    if: {MERGE_IF_EXPR}"
    comment_shadow = sync.replace(
        guarded_line, f"    # if: {MERGE_IF_EXPR}\n    if: always()", 1,
    )
    expect_failure(
        comment_shadow, stats, policy, "exact mutation-budget/plan/propose/approve prerequisites",
    )
    duplicate_job_if = sync.replace(
        guarded_line, guarded_line + "\n    if: always()", 1,
    )
    expect_failure(
        duplicate_job_if, stats, policy, "exactly one canonical job-level if predicate",
    )
    budget_widened = sync.replace("          MAX_ATTEMPTS=2\n", "          MAX_ATTEMPTS=3\n", 1)
    expect_failure(
        budget_widened, stats, policy, "mutation-budget fail-closed contract is missing",
    )
    budget_incomplete = sync.replace(BUDGET_COMPLETENESS_GATE, 'test "$TOTAL" -ge "$COUNT" || {', 1)
    expect_failure(
        budget_incomplete, stats, policy, "mutation-budget fail-closed contract is missing",
    )
    budget_unbound_current = sync.replace(BUDGET_CURRENT_GATE, 'test "$CURRENT" -ge "0" || {', 1)
    expect_failure(
        budget_unbound_current, stats, policy, "mutation-budget fail-closed contract is missing",
    )
    quarantine_fail_open = sync.replace(
        "          exit 1\n\n  propose:", "          :\n\n  propose:", 1,
    )
    expect_failure(
        quarantine_fail_open, stats, policy, "quarantine must retain diagnostics and fail visibly",
    )
    propose_bypass = sync.replace(PROPOSE_IF_EXPR, "needs.plan.outputs.changed == 'true'", 1)
    expect_failure(
        propose_bypass, stats, policy, "proposal must require exact positive mutation-budget admission",
    )
    approval_rededupe = sync.replace('          APPROVAL_REQUESTED_RUN_IDS=""\n', "", 1)
    expect_failure(
        approval_rededupe, stats, policy, "approval mutation de-duplication contract is missing",
    )
    missing_wait = sync.replace("          for attempt in $(seq 1 60); do\n", "          for attempt in $(seq 1 1); do\n", 1)
    expect_failure(
        missing_wait, stats, policy, "Actions-only approval job must own canonical workflow waiting",
    )
    terminal_polling = sync.replace(
        "          # Revalidate the exact PR, mutable roots, README-only closure, and required checks\n",
        "          for attempt in $(seq 1 60); do\n            sleep 10\n          done\n"
        "          # Revalidate the exact PR, mutable roots, README-only closure, and required checks\n",
        1,
    )
    expect_failure(
        terminal_polling, stats, policy, "polling/authored execution surface",
    )
    terminal_pr_write = sync.replace(
        "      pull-requests: read\n      checks: read\n",
        "      pull-requests: write\n      checks: read\n",
        1,
    )
    expect_failure(
        terminal_pr_write, stats, policy, "terminal merge authority changed",
    )
    cleanup_fail_open = sync.replace(
        CLEANUP_404_GATE,
        "          else\n            :\n          fi",
        1,
    )
    expect_failure(
        cleanup_fail_open, stats, policy, "fail closed on every lookup failure except explicit 404",
    )
    incomplete_run_page = sync.replace(
        RUN_COMPLETENESS_GATE, 'test "$RUNS_TOTAL" -ge "$RUNS_COUNT" || {', 1,
    )
    expect_failure(
        incomplete_run_page, stats, policy, "run-provenance contract is missing",
    )
    incomplete_check_page = sync.replace(
        CHECK_COMPLETENESS_GATE, 'test "$CHECKS_TOTAL" -ge "$CHECKS_COUNT" || {', 1,
    )
    expect_failure(
        incomplete_check_page, stats, policy, "check-provenance contract is missing",
    )
    wrong_suite = sync.replace(
        '{name:"analyze-actions",check_suite_id:$codeql,status:"completed",conclusion:"success",head_sha:$head}',
        '{name:"analyze-actions",check_suite_id:$profile,status:"completed",conclusion:"success",head_sha:$head}',
        1,
    )
    expect_failure(
        wrong_suite, stats, policy, "check-provenance contract is missing",
    )

    dispatch_comment_shadow = stats.replace(
        '          gh api --method POST \\\n            "repos/${GITHUB_REPOSITORY}/actions/workflows/spotlight-link-sync.yml/dispatches" \\\n            -f ref=main',
        '          # gh api --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/spotlight-link-sync.yml/dispatches" -f ref=main\n'
        '          gh api --method POST "repos/${GITHUB_REPOSITORY}/dispatches"',
        1,
    )
    expect_failure(
        sync, dispatch_comment_shadow, policy, "one exact ref-only fixed-workflow reconciliation dispatch",
    )
    duplicate_dispatch_step = stats.replace(
        "      - name: Dispatch exact Spotlight reconciliation workflow\n",
        "      - name: Unreviewed dispatch step\n        run: echo unreviewed\n\n"
        "      - name: Dispatch exact Spotlight reconciliation workflow\n",
        1,
    )
    expect_failure(
        sync, duplicate_dispatch_step, policy, "exactly one reviewed step",
    )
    expect_failure(
        sync, stats + "\nmerge_ui_after_checks: true\n", policy,
        "must not introduce a separate merge input",
    )
    policy_without_standing_authorization = re.sub(
        r"standing authorization", "standing permission", policy, flags=re.IGNORECASE,
    )
    expect_failure(
        sync, stats, policy_without_standing_authorization, "standing authorization",
    )
    policy_without_budget = re.sub(r"mutation budget", "attempt allowance", policy, flags=re.IGNORECASE)
    expect_failure(sync, stats, policy_without_budget, "mutation budget")


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
            "Spotlight UI merge authorization validation passed: changed source epochs cross an Actions-read-only two-attempt mutation budget before any write; exhausted epochs enter read-only quarantine; "
            "canonical workflow waiting remains under de-duplicated Actions-only approval authority, exact run/check-suite provenance remains complete, and terminal merge authority stays exact-head/fail-closed."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())