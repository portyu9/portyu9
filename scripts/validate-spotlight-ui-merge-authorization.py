#!/usr/bin/env python3
"""Fail closed on implicit Spotlight README/UI merge authority."""
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
    "&& needs.approve.result == 'success' && github.event_name == 'workflow_dispatch' "
    "&& inputs.merge_ui_after_checks == true"
)
INPUT_BLOCK = """  workflow_dispatch:
    inputs:
      merge_ui_after_checks:
        description: Explicitly authorize merging the generated README/UI PR after required checks
        required: false
        type: boolean
        default: false
"""


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
    require(INPUT_BLOCK in sync,
            "Spotlight workflow_dispatch merge authorization must be one optional boolean defaulting false")
    require(sync.count("      merge_ui_after_checks:\n") == 1,
            "Spotlight UI merge authorization input must be declared exactly once")
    require(sync.count("inputs.merge_ui_after_checks") == 1,
            "Spotlight UI merge authorization input must gate exactly one execution surface")

    merge = job_block(sync, "merge", None)
    require(MERGE_IF in merge,
            "Spotlight merge job must require explicit workflow_dispatch UI merge authorization")
    require(merge.count("inputs.merge_ui_after_checks == true") == 1,
            "Spotlight merge job exact explicit-authorization predicate changed")
    require("github.event_name == 'workflow_dispatch'" in merge,
            "Scheduled or bot-dispatched Spotlight runs must never reach UI merge authority")

    require("merge_ui_after_checks" not in stats,
            "Profile-stats post-publication dispatch must not authorize Spotlight UI merging")
    require(
        '"repos/${GITHUB_REPOSITORY}/actions/workflows/spotlight-link-sync.yml/dispatches"' in stats
        and "-f ref=main" in stats,
        "Profile-stats dispatcher must remain a ref-only reconciliation dispatch",
    )

    policy_lower = policy.lower()
    for phrase in (
        "merge_ui_after_checks",
        "defaults to `false`",
        "scheduled reconciliation",
        "post-publication bot dispatch",
        "explicit manual authorization",
        "five protected-main checks",
        "no bypass",
    ):
        require(phrase.lower() in policy_lower,
                f"Spotlight UI merge authorization policy is missing: {phrase}")


def expect_failure(sync: str, stats: str, policy: str, expected: str) -> None:
    try:
        validate(sync, stats, policy)
    except ValueError as exc:
        require(expected in str(exc), f"self-test failed for wrong reason: {exc}")
    else:
        fail(f"self-test accepted forbidden UI merge authorization drift: {expected}")


def self_test(sync: str, stats: str, policy: str) -> None:
    expect_failure(
        sync.replace("        default: false\n", "        default: true\n", 1),
        stats,
        policy,
        "optional boolean defaulting false",
    )
    expect_failure(
        sync.replace(" && github.event_name == 'workflow_dispatch'", "", 1),
        stats,
        policy,
        "explicit workflow_dispatch UI merge authorization",
    )
    expect_failure(
        sync.replace(" && inputs.merge_ui_after_checks == true", "", 1),
        stats,
        policy,
        "must gate exactly one execution surface",
    )
    expect_failure(
        sync,
        stats + "\nmerge_ui_after_checks: true\n",
        policy,
        "must not authorize Spotlight UI merging",
    )


def main() -> int:
    try:
        for path in (SYNC, STATS, POLICY):
            require(path.is_file(), f"Spotlight UI merge authorization input is missing: {path.relative_to(ROOT)}")
        sync = SYNC.read_text(encoding="utf-8")
        stats = STATS.read_text(encoding="utf-8")
        policy = POLICY.read_text(encoding="utf-8")
        validate(sync, stats, policy)
        self_test(sync, stats, policy)
        print(
            "Spotlight UI merge authorization validation passed: reconciliation may plan, propose, and approve checks, "
            "but merge authority is reachable only from an explicit workflow_dispatch boolean opt-in; scheduled and "
            "post-publication bot dispatches remain merge-ineligible."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
