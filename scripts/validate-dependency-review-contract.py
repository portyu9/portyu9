#!/usr/bin/env python3
"""Validate the repository's fail-closed Dependency Review merge gate."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/dependency-review.yml"
QUALITY = ROOT / ".github/workflows/profile-quality.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
DEPENDENCY_REVIEW_SHA = "a1d282b36b6f3519aa1f3fc636f609c47dddb294"
DEPENDENCY_REVIEW_RELEASE = "v5.0.0"

EXPECTED_WORKFLOW = f"""name: Dependency review

on:
  pull_request:
  workflow_dispatch:
    inputs:
      base_sha:
        description: Exact current main SHA for trusted controller dispatch
        required: true
        type: string
      head_sha:
        description: Exact candidate head SHA for trusted controller dispatch
        required: true
        type: string

permissions:
  contents: read

concurrency:
  group: dependency-review-${{{{ github.ref }}}}
  cancel-in-progress: true

jobs:
  dependency-review:
    name: dependency-review
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions:
      contents: read

    steps:
      - name: Checkout
        uses: actions/checkout@{CHECKOUT_SHA} # v7.0.1
        with:
          persist-credentials: false

      - name: Bind exact dispatched candidate
        if: github.event_name == 'workflow_dispatch'
        env:
          GH_TOKEN: ${{{{ github.token }}}}
          TARGET_REPOSITORY: ${{{{ github.repository }}}}
          BASE_SHA: ${{{{ inputs.base_sha }}}}
          HEAD_SHA: ${{{{ inputs.head_sha }}}}
        run: |
          set -euo pipefail
          test "$TARGET_REPOSITORY" = "portyu9/portyu9"
          [[ "$BASE_SHA" =~ ^[0-9a-f]{{40}}$ ]]
          [[ "$HEAD_SHA" =~ ^[0-9a-f]{{40}}$ ]]
          test "$GITHUB_SHA" = "$HEAD_SHA"
          test "$(git rev-parse HEAD)" = "$HEAD_SHA"
          test "$(gh api "repos/${{TARGET_REPOSITORY}}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"

      - name: Review dependency changes
        uses: actions/dependency-review-action@{DEPENDENCY_REVIEW_SHA} # {DEPENDENCY_REVIEW_RELEASE}
        with:
          base-ref: ${{{{ inputs.base_sha || github.event.pull_request.base.sha }}}}
          head-ref: ${{{{ inputs.head_sha || github.event.pull_request.head.sha }}}}
          fail-on-severity: moderate
          fail-on-scopes: runtime, development, unknown
          license-check: false
          vulnerability-check: true
          comment-summary-in-pr: never
          warn-only: false
"""


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def validate_workflow(text: str) -> None:
    require(text.startswith("name: Dependency review\n"), "Dependency Review workflow name changed")

    require(text.count("  pull_request:\n") == 1, "Dependency Review must run on every pull request")
    require(text.count("  workflow_dispatch:\n") == 1,
            "Dependency Review must expose exactly one reviewed exact-head dispatch entry")
    for forbidden_event in ("pull_request_target:", "  push:", "  schedule:", "  repository_dispatch:", "  workflow_run:"):
        require(forbidden_event not in text, f"Dependency Review contains forbidden trigger: {forbidden_event.strip()}")
    require("paths:" not in text and "paths-ignore:" not in text,
            "Dependency Review must not use path filters that create an unreviewed dependency-change path")
    for fragment in (
        "      base_sha:\n",
        "      head_sha:\n",
        "        required: true\n",
        "        type: string\n",
        "if: github.event_name == 'workflow_dispatch'",
        'test "$GITHUB_SHA" = "$HEAD_SHA"',
        'test "$(git rev-parse HEAD)" = "$HEAD_SHA"',
        'git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"',
        "base-ref: ${{ inputs.base_sha || github.event.pull_request.base.sha }}",
        "head-ref: ${{ inputs.head_sha || github.event.pull_request.head.sha }}",
    ):
        require(fragment in text, f"Dependency Review exact-head dispatch binding is missing: {fragment}")

    jobs_index = text.find("\njobs:\n")
    require(jobs_index > 0, "Dependency Review jobs block is missing")
    require("permissions:\n  contents: read\n" in text[:jobs_index],
            "Dependency Review workflow default permissions must remain contents: read")
    for forbidden_permission in (
        "contents: write",
        "pull-requests: write",
        "actions: write",
        "checks: write",
        "security-events: write",
        "id-token: write",
        "attestations: write",
        "packages: write",
    ):
        require(forbidden_permission not in text,
                f"Dependency Review received forbidden authority: {forbidden_permission}")

    require(text.count("  dependency-review:\n") == 1,
            "Dependency Review must contain exactly one dependency-review job")
    require("    name: dependency-review\n" in text, "Dependency Review required job name changed")
    require("    runs-on: ubuntu-24.04\n" in text, "Dependency Review runner must remain ubuntu-24.04")
    require("    timeout-minutes: 5\n" in text, "Dependency Review timeout contract changed")
    require("    permissions:\n      contents: read\n" in text,
            "Dependency Review job permissions must remain contents: read")
    require("group: dependency-review-${{ github.ref }}" in text,
            "Dependency Review concurrency identity changed")
    require("cancel-in-progress: true" in text, "Dependency Review must cancel stale scans")
    require("continue-on-error:" not in text, "Dependency Review must not be made non-blocking")

    require(text.count(f"actions/checkout@{CHECKOUT_SHA}") == 1,
            "Dependency Review must use the reviewed checkout SHA exactly once")
    require("persist-credentials: false" in text,
            "Dependency Review checkout must not persist credentials")
    require(text.count(f"actions/dependency-review-action@{DEPENDENCY_REVIEW_SHA}") == 1,
            f"Dependency Review must use reviewed {DEPENDENCY_REVIEW_RELEASE} commit SHA exactly once")

    require("fail-on-severity: moderate" in text,
            "Dependency Review must block moderate-or-higher vulnerabilities")
    require("fail-on-scopes: runtime, development, unknown" in text,
            "Dependency Review must cover runtime, development, and unknown scopes")
    require("license-check: false" in text,
            "Dependency Review vulnerability gate must not silently become a license-policy gate")
    require("vulnerability-check: true" in text,
            "Dependency Review vulnerability checking must remain enabled")
    require("comment-summary-in-pr: never" in text,
            "Dependency Review must not require pull-request write permission for comments")
    require("warn-only: false" in text,
            "Dependency Review must fail rather than warn on policy violations")

    require(text == EXPECTED_WORKFLOW,
            "Dependency Review workflow drifted from the reviewed canonical merge-gate policy")


def validate_quality(text: str) -> None:
    require("python3 scripts/validate-dependency-review-contract.py" in text,
            "Profile Quality must execute the Dependency Review governance validator")
    require('- ".github/workflows/**"' in text,
            "Profile Quality must continue to cover every workflow change")


def validate_governance(text: str) -> None:
    for phrase in (
        "## Dependency review gate",
        ".github/workflows/dependency-review.yml",
        "Dependency review / dependency-review",
        "moderate-or-higher",
        "runtime, development, and unknown",
        "license policy",
        "contents: read",
        "no path filters",
        "exact-head controller dispatch",
    ):
        require(phrase in text, f"Dependency Review governance documentation is missing: {phrase}")


def self_test() -> None:
    validate_workflow(EXPECTED_WORKFLOW)
    mutations = (
        (EXPECTED_WORKFLOW.replace("fail-on-severity: moderate", "fail-on-severity: high"),
         "moderate-or-higher"),
        (EXPECTED_WORKFLOW.replace("warn-only: false", "warn-only: true"),
         "fail rather than warn"),
        (EXPECTED_WORKFLOW.replace("      contents: read", "      contents: write"),
         "forbidden authority"),
        (EXPECTED_WORKFLOW.replace("  pull_request:\n", "  pull_request:\n    paths:\n      - '.github/**'\n"),
         "path filters"),
        (EXPECTED_WORKFLOW.replace('test "$GITHUB_SHA" = "$HEAD_SHA"', "true"),
         "dispatch binding"),
        (EXPECTED_WORKFLOW.replace("comment-summary-in-pr: never", "comment-summary-in-pr: always"),
         "must not require pull-request write permission"),
        (EXPECTED_WORKFLOW.replace(DEPENDENCY_REVIEW_SHA, "v5"),
         f"reviewed {DEPENDENCY_REVIEW_RELEASE} commit SHA"),
    )
    for mutated, expected in mutations:
        try:
            validate_workflow(mutated)
        except ValueError as exc:
            require(expected in str(exc), f"Dependency Review self-test failed for the wrong reason: {exc}")
        else:
            fail(f"Dependency Review self-test accepted forbidden mutation: {expected}")


def main() -> int:
    try:
        for path in (WORKFLOW, QUALITY, GOVERNANCE):
            require(path.is_file(), f"Dependency Review governance input is missing: {path.relative_to(ROOT)}")
        self_test()
        validate_workflow(WORKFLOW.read_text(encoding="utf-8"))
        validate_quality(QUALITY.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))
        print(
            "Dependency Review governance validation passed: every PR plus the exact-head trusted controller dispatch is checked "
            "read-only; moderate-or-higher vulnerabilities across every dependency scope fail closed and license policy stays isolated."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
