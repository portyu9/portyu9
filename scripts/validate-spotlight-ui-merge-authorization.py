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

MERGE_IF = (
    "if: needs.plan.outputs.changed == 'true' && needs.propose.result == 'success' "
    "&& needs.approve.result == 'success'"
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
    require(MERGE_IF in merge,
            "Spotlight merge job must require the exact guarded plan/propose/approve prerequisites")
    require(merge.count(MERGE_IF) == 1,
            "Spotlight standing merge predicate must appear exactly once")
    for forbidden in (
        "github.event_name == 'workflow_dispatch'",
        "inputs.merge_ui_after_checks",
        "pull_request_target",
        "issue_comment",
        "repository_dispatch",
    ):
        require(forbidden not in merge,
                f"Spotlight merge job contains an unauthorized alternate/manual authority gate: {forbidden}")

    require(
        '"repos/${GITHUB_REPOSITORY}/actions/workflows/spotlight-link-sync.yml/dispatches"' in stats
        and "-f ref=main" in stats,
        "Profile-stats dispatcher must remain a ref-only fixed-workflow reconciliation dispatch",
    )

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
            "has standing auto-merge authority after plan/propose/approval guards and the five protected-main checks; "
            "scheduled/post-publication runs may converge automatically without authorizing arbitrary UI or dependency PRs."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
