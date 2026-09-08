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

MERGE_IF_EXPR = (
    "needs.plan.outputs.changed == 'true' && needs.propose.result == 'success' "
    "&& needs.approve.result == 'success'"
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
        "repository_dispatch",
        "workflow_id=",
        "-f inputs",
        "-F inputs",
        "pull_request_target",
    ):
        require(forbidden not in dispatch,
                f"Profile-stats dispatcher contains unauthorized alternate dispatch authority: {forbidden}")


def validate(sync: str, stats: str, policy: str) -> None:
    require("  workflow_dispatch:\n" in sync,
            "Spotlight synchronization must retain a manual recovery dispatch")
    require('  schedule:\n' in sync and '    - cron: "41 * * * *"' in sync,
            "Spotlight synchronization must retain hourly recovery reconciliation at minute 41")
    require("merge_ui_after_checks" not in sync,
            "Spotlight standing authorization must not depend on a manual merge input")
    require("merge_ui_after_checks" not in stats,
            "Profile-stats post-publication dispatch must not introduce a separate merge input")

    merge = job_block(sync, "merge", None)
    require(
        exact_job_if(merge, "Spotlight merge job") == MERGE_IF_EXPR,
        "Spotlight merge job must require the exact guarded plan/propose/approve prerequisites",
    )
    for forbidden in (
        "github.event_name == 'workflow_dispatch'",
        "inputs.merge_ui_after_checks",
        "pull_request_target",
        "issue_comment",
        "repository_dispatch",
    ):
        require(forbidden not in merge,
                f"Spotlight merge job contains an unauthorized alternate/manual authority gate: {forbidden}")

    validate_dispatch_job(stats)

    policy_lower = policy.lower()
    for phrase in (
        "standing authorization",
        "automation/spotlight-links",
        "scheduled reconciliation",
        "post-publication bot dispatch",
        "readme-only",
        "five protected-main checks",
        "integration id `15368`",
        "no bypass actor",
        "does not authorize arbitrary readme/ui",
        "dependabot",
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
        stats,
        policy,
        "must not depend on a manual merge input",
    )
    expect_failure(
        sync.replace(" && needs.approve.result == 'success'", "", 1),
        stats,
        policy,
        "exact guarded plan/propose/approve prerequisites",
    )
    guarded_line = f"    if: {MERGE_IF_EXPR}"
    comment_shadow = sync.replace(
        guarded_line,
        f"    # if: {MERGE_IF_EXPR}\n    if: always()",
        1,
    )
    expect_failure(
        comment_shadow,
        stats,
        policy,
        "exact guarded plan/propose/approve prerequisites",
    )
    duplicate_job_if = sync.replace(
        guarded_line,
        guarded_line + "\n    if: always()",
        1,
    )
    expect_failure(
        duplicate_job_if,
        stats,
        policy,
        "exactly one canonical job-level if predicate",
    )

    dispatch_comment_shadow = stats.replace(
        '          gh api --method POST \\\n            "repos/${GITHUB_REPOSITORY}/actions/workflows/spotlight-link-sync.yml/dispatches" \\\n            -f ref=main',
        '          # gh api --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/spotlight-link-sync.yml/dispatches" -f ref=main\n'
        '          gh api --method POST "repos/${GITHUB_REPOSITORY}/dispatches"',
        1,
    )
    expect_failure(
        sync,
        dispatch_comment_shadow,
        policy,
        "one exact ref-only fixed-workflow reconciliation dispatch",
    )
    duplicate_dispatch_step = stats.replace(
        "      - name: Dispatch exact Spotlight reconciliation workflow\n",
        "      - name: Unreviewed dispatch step\n        run: echo unreviewed\n\n"
        "      - name: Dispatch exact Spotlight reconciliation workflow\n",
        1,
    )
    expect_failure(
        sync,
        duplicate_dispatch_step,
        policy,
        "exactly one reviewed step",
    )

    expect_failure(
        sync,
        stats + "\nmerge_ui_after_checks: true\n",
        policy,
        "must not introduce a separate merge input",
    )
    policy_without_standing_authorization = re.sub(
        r"standing authorization",
        "standing permission",
        policy,
        flags=re.IGNORECASE,
    )
    expect_failure(
        sync,
        stats,
        policy_without_standing_authorization,
        "standing authorization",
    )


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
            "Spotlight UI merge authorization validation passed: the fixed deterministic README-only synchronization class "
            "has standing auto-merge authority after one exact parsed plan/propose/approval job guard and the five protected-main checks; "
            "post-publication reconciliation remains one exact fixed-workflow, ref-only dispatch."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
