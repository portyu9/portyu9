#!/usr/bin/env python3
"""Fail closed on Profile Quality's bounded pinned-upstream retry boundary."""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/profile-quality.yml"
UPSTREAM_SHA = "49b5f7091182a45f3ef93923505b660c6da5f835"
UPSTREAM_USES = f"shinpr/github-profile-stats@{UPSTREAM_SHA} # v0.2.0"
PRIMARY_IF = "steps.stats_primary.outcome == 'failure'"


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def job_block(text: str, key: str, next_key: str | None) -> str:
    start = re.search(rf"(?m)^  {re.escape(key)}:\s*$", text)
    require(start is not None, f"workflow job is missing: {key}")
    if next_key is None:
        return text[start.start():]
    relative = text[start.end():]
    end = re.search(rf"(?m)^  {re.escape(next_key)}:\s*$", relative)
    require(end is not None, f"workflow job boundary is missing after {key}: {next_key}")
    return text[start.start(): start.end() + end.start()]


def step_block(job: str, name: str, next_name: str | None) -> str:
    marker = f"      - name: {name}\n"
    require(job.count(marker) == 1, f"integration step identity changed or is ambiguous: {name}")
    start = job.index(marker)
    if next_name is None:
        return job[start:]
    next_marker = f"      - name: {next_name}\n"
    require(job.count(next_marker) == 1, f"integration step boundary is missing: {next_name}")
    end = job.index(next_marker, start + len(marker))
    return job[start:end]


def require_action(block: str, *, primary: bool) -> None:
    label = "primary" if primary else "retry"
    expected_id = "stats_primary" if primary else "stats_retry"
    require(f"        id: {expected_id}\n" in block,
            f"Pinned upstream {label} step id changed")
    require(f"        uses: {UPSTREAM_USES}\n" in block,
            f"Pinned upstream {label} Action identity changed")
    require(block.count("username: portyu9") == 1 and
            block.count('token: ${{ github.token }}') == 1 and
            block.count("profile: signal-field") == 1,
            f"Pinned upstream {label} input surface changed")
    if primary:
        require("        continue-on-error: true\n" in block,
                "Primary pinned upstream attempt must expose failure to the one reviewed retry path")
        require("        if:" not in block,
                "Primary pinned upstream attempt must execute unconditionally after runtime setup")
    else:
        require(f"        if: {PRIMARY_IF}\n" in block,
                "Retry pinned upstream Action must run only after primary failure")
        require("continue-on-error:" not in block,
                "Retry pinned upstream Action must fail the integration job if it fails")


def validate(text: str) -> None:
    integration = job_block(text, "integration", None)
    require("name: integration-pinned-upstream" in integration,
            "Pinned upstream integration job identity changed")
    require("permissions:\n      contents: read" in integration,
            "Pinned upstream integration job must remain contents: read")
    require(integration.count(f"uses: {UPSTREAM_USES}") == 2,
            "Integration must execute exactly two possible attempts of one immutable upstream Action identity")

    names = (
        "Generate actual pinned upstream Signal Field",
        "Back off before one exact pinned upstream retry",
        "Retry exact pinned upstream Signal Field once",
        "Select successful exact pinned upstream output",
        "Exercise canonical profile evidence generation pipeline",
    )
    primary = step_block(integration, names[0], names[1])
    backoff = step_block(integration, names[1], names[2])
    retry = step_block(integration, names[2], names[3])
    selector = step_block(integration, names[3], names[4])

    require_action(primary, primary=True)
    require(f"        if: {PRIMARY_IF}\n" in backoff,
            "Pinned upstream retry backoff must run only after primary failure")
    require(backoff.count("        run: sleep 60\n") == 1,
            "Pinned upstream retry must use exactly one 60-second backoff")
    require("gh api" not in backoff and "curl " not in backoff and "wget " not in backoff,
            "Pinned upstream retry backoff must not poll or scrape GitHub APIs")
    require_action(retry, primary=False)

    require("        id: stats\n" in selector,
            "Pinned upstream selector must retain the canonical downstream step id")
    for fragment in (
        'PRIMARY_OUTCOME: ${{ steps.stats_primary.outcome }}',
        'PRIMARY_READY_DIR: ${{ steps.stats_primary.outputs.ready-dir }}',
        'RETRY_OUTCOME: ${{ steps.stats_retry.outcome }}',
        'RETRY_READY_DIR: ${{ steps.stats_retry.outputs.ready-dir }}',
        'if [ "$PRIMARY_OUTCOME" = "success" ]; then',
        'test "$PRIMARY_OUTCOME" = "failure"',
        'test "$RETRY_OUTCOME" = "success"',
        'echo "ready-dir=$READY_DIR" >> "$GITHUB_OUTPUT"',
    ):
        require(fragment in selector, f"Pinned upstream successful-output selector changed: {fragment}")
    require(selector.count("ready-dir=$READY_DIR") == 1,
            "Pinned upstream selector must emit exactly one canonical ready-dir output")

    prefix = integration[:integration.index(f"      - name: {names[0]}\n")]
    require("gh api" not in prefix and "search/issues" not in integration,
            "Pinned upstream retry must not add Search polling ahead of the Action")
    tail = integration[integration.index(f"      - name: {names[4]}\n"):]
    require("steps.stats_primary" not in tail and "steps.stats_retry" not in tail,
            "Downstream integration must consume only the successful-output selector, never a raw attempt")
    require("steps.stats.outputs.ready-dir" in tail,
            "Downstream integration lost the canonical selected ready-dir boundary")


def expect_failure(text: str, expected: str) -> None:
    try:
        validate(text)
    except ValueError as exc:
        require(expected in str(exc), f"self-test failed for wrong reason: {exc}")
    else:
        fail(f"self-test accepted forbidden pinned-upstream retry drift: {expected}")


def self_test(text: str) -> None:
    expect_failure(
        text.replace(UPSTREAM_SHA, "0" * 40, 1),
        "exactly two possible attempts",
    )
    expect_failure(
        text.replace("        run: sleep 60\n", "        run: sleep 1\n", 1),
        "60-second backoff",
    )
    expect_failure(
        text.replace(f"        if: {PRIMARY_IF}\n", "        if: always()\n", 1),
        "only after primary",
    )
    expect_failure(
        text.replace("        id: stats_retry\n", "        id: stats_retry\n        continue-on-error: true\n", 1),
        "must fail the integration job",
    )
    expect_failure(
        text.replace('READY_DIR: ${{ steps.stats.outputs.ready-dir }}',
                     'READY_DIR: ${{ steps.stats_primary.outputs.ready-dir }}', 1),
        "never a raw attempt",
    )
    injected_poll = text.replace(
        "      - name: Generate actual pinned upstream Signal Field\n",
        "      - name: Poll Search first\n        run: gh api search/issues\n\n"
        "      - name: Generate actual pinned upstream Signal Field\n",
        1,
    )
    expect_failure(injected_poll, "must not add Search polling")


def main() -> int:
    try:
        require(WORKFLOW.is_file(), "Profile Quality workflow is missing")
        text = WORKFLOW.read_text(encoding="utf-8")
        validate(text)
        self_test(text)
        print(
            "Pinned upstream retry validation passed: the immutable upstream Action has one primary attempt, "
            "one 60-second bounded backoff, and one terminal retry; no Search polling is introduced and "
            "downstream evidence can consume only the explicitly selected successful exact-pinned output."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())