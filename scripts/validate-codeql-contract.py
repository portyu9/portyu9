#!/usr/bin/env python3
"""Validate the repository's governed CodeQL security-analysis contract."""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CODEQL = ROOT / ".github/workflows/codeql.yml"
QUALITY = ROOT / ".github/workflows/profile-quality.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
CODEQL_SHA = "e4fba868fa4b1b91e1fdab776edc8cfbe6e9fb81"
CODEQL_RELEASE = "v4.37.3"


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def job_block(workflow: str, key: str) -> str:
    match = re.search(rf"(?m)^  {re.escape(key)}:\s*$", workflow)
    if not match:
        fail(f"CodeQL workflow job is missing: {key}")
    return workflow[match.start():]


def validate_codeql(text: str) -> None:
    require(text.startswith("name: CodeQL\n"), "CodeQL workflow name changed")

    # Event coverage: analyze every PR, every main update, on demand, and weekly even
    # when the repository is quiet. Path filters are intentionally forbidden because
    # workflow/config/script edits can change security posture indirectly.
    require(text.count("  pull_request:\n") == 1, "CodeQL must run on every pull request")
    require(text.count("  push:\n") == 1, "CodeQL must run on push")
    require("    branches:\n      - main\n" in text, "CodeQL push analysis must target main")
    require(text.count('    - cron: "17 5 * * 3"') == 1, "CodeQL weekly schedule changed")
    require(text.count("  workflow_dispatch:\n") == 1, "CodeQL manual dispatch must remain available")
    require("paths:" not in text and "paths-ignore:" not in text,
            "CodeQL must not use path filters that can create scan gaps")

    # Default token is read-only. Only the analysis job gets SARIF upload authority.
    jobs_index = text.find("\njobs:\n")
    require(jobs_index > 0, "CodeQL jobs block is missing")
    pre_jobs = text[:jobs_index]
    require("permissions:\n  contents: read\n" in pre_jobs,
            "CodeQL default workflow permissions must remain contents: read")
    require("contents: write" not in text, "CodeQL must never receive repository-content write authority")
    require("id-token: write" not in text, "CodeQL must not receive OIDC signing authority")
    require("attestations: write" not in text, "CodeQL must not receive attestation authority")
    require("pull-requests: write" not in text, "CodeQL must not mutate pull requests")
    require("actions: write" not in text, "CodeQL must not mutate Actions state")
    require("packages: write" not in text, "CodeQL must not receive package write authority")

    require("group: codeql-${{ github.workflow }}-${{ github.ref }}" in text,
            "CodeQL concurrency identity changed")
    require("cancel-in-progress: true" in text, "CodeQL must cancel stale scans")

    analyze = job_block(text, "analyze")
    require("name: analyze-python" in analyze, "CodeQL required job name changed")
    require("runs-on: ubuntu-24.04" in analyze, "CodeQL runner must remain ubuntu-24.04")
    require("timeout-minutes: 15" in analyze, "CodeQL timeout contract changed")
    require("permissions:\n      contents: read\n      security-events: write\n" in analyze,
            "CodeQL analysis job must have only contents: read plus security-events: write")
    require("continue-on-error:" not in analyze, "CodeQL findings/errors must not be made non-blocking")

    checkout_ref = f"actions/checkout@{CHECKOUT_SHA}"
    require(analyze.count(checkout_ref) == 1, "CodeQL must use the reviewed checkout SHA exactly once")
    require("persist-credentials: false" in analyze, "CodeQL checkout must not persist credentials")

    init_ref = f"github/codeql-action/init@{CODEQL_SHA}"
    analyze_ref = f"github/codeql-action/analyze@{CODEQL_SHA}"
    require(analyze.count(init_ref) == 1,
            f"CodeQL init must use reviewed {CODEQL_RELEASE} commit SHA")
    require(analyze.count(analyze_ref) == 1,
            f"CodeQL analyze must use reviewed {CODEQL_RELEASE} commit SHA")
    require(analyze.count("github/codeql-action/") == 2,
            "CodeQL workflow must contain only the reviewed init and analyze action steps")
    require("github/codeql-action/autobuild" not in analyze,
            "Python CodeQL analysis must not add an unnecessary autobuild authority surface")

    require("languages: python" in analyze, "CodeQL language scope must remain Python")
    require("build-mode: none" in analyze, "Python CodeQL build mode must remain none")
    require("queries: security-extended" in analyze,
            "CodeQL must retain the reviewed security-extended query suite")
    require("matrix:" not in analyze, "CodeQL must remain a single Python analysis job")


def validate_quality(text: str) -> None:
    require("python3 scripts/validate-codeql-contract.py" in text,
            "Profile Quality must execute the CodeQL governance validator")
    require('- ".github/workflows/**"' in text,
            "Profile Quality must continue to cover every workflow change")


def validate_governance(text: str) -> None:
    for phrase in (
        "## CodeQL security analysis",
        ".github/workflows/codeql.yml",
        "analyze-python",
        "security-events: write",
        "security-extended",
        "exact commit SHA",
        "weekly",
        "no path filters",
        "CodeQL is not an attestation",
    ):
        require(phrase in text, f"CodeQL governance documentation is missing: {phrase}")


def self_test(good: str) -> None:
    validate_codeql(good)
    mutations = (
        (good.replace(CODEQL_SHA, "v4"), "reviewed v4.37.3 commit SHA"),
        (good.replace("languages: python", "languages: javascript-typescript"), "language scope"),
        (good.replace("security-events: write", "security-events: read"), "security-events: write"),
        (good.replace("  pull_request:\n", "  pull_request:\n    paths:\n      - 'scripts/**'\n"), "path filters"),
        (good.replace("      contents: read\n      security-events: write", "      contents: write\n      security-events: write"),
         "repository-content write authority"),
    )
    for mutated, expected in mutations:
        try:
            validate_codeql(mutated)
        except ValueError as exc:
            require(expected in str(exc), f"CodeQL self-test failed for the wrong reason: {exc}")
        else:
            fail(f"CodeQL self-test accepted forbidden mutation expected to trigger: {expected}")


def main() -> int:
    try:
        for path in (CODEQL, QUALITY, GOVERNANCE):
            require(path.is_file(), f"CodeQL governance input is missing: {path.relative_to(ROOT)}")

        codeql = CODEQL.read_text(encoding="utf-8")
        self_test(codeql)
        validate_quality(QUALITY.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))

        print(
            "CodeQL governance validation passed: Python analysis covers PR/main/weekly/manual events with no path gaps, "
            "uses security-extended queries, keeps SARIF upload authority isolated, and executes only reviewed SHA-pinned actions."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
