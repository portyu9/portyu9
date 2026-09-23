#!/usr/bin/env python3
"""Validate the repository's governed CodeQL security-analysis contract."""
from __future__ import annotations

from pathlib import Path
import re
import sys

from codeql_autofix_admission import self_test as autofix_admission_self_test
from codeql_autofix_controller_contract import self_test as autofix_controller_self_test
from codeql_autofix_discovery import self_test as autofix_discovery_self_test
from codeql_autofix_queue import self_test as autofix_queue_self_test

ROOT = Path(__file__).resolve().parents[1]
CODEQL = ROOT / ".github/workflows/codeql.yml"
AUTOFIX = ROOT / ".github/workflows/codeql-autofix.yml"
QUALITY = ROOT / ".github/workflows/profile-quality.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
CODEQL_SHA = "b96794f015dfd88f77b49b1c93e0fa7110f94c63"
CODEQL_RELEASE = "v4.38.0"
STEP_START = re.compile(r"^      - name: (?P<name>.+?)\s*$")
EXPECTED_STEP_NAMES = ("Checkout", "Initialize CodeQL", "Analyze")

EXPECTED_CHECKOUT_STEP = (
    "      - name: Checkout\n"
    f"        uses: actions/checkout@{CHECKOUT_SHA} # v7.0.1\n"
    "        with:\n"
    "          persist-credentials: false"
)
EXPECTED_INIT_STEP = (
    "      - name: Initialize CodeQL\n"
    f"        uses: github/codeql-action/init@{CODEQL_SHA} # {CODEQL_RELEASE}\n"
    "        with:\n"
    "          languages: ${{ matrix.language }}\n"
    "          queries: security-extended"
)
EXPECTED_ANALYZE_STEP = (
    "      - name: Analyze\n"
    f"        uses: github/codeql-action/analyze@{CODEQL_SHA} # {CODEQL_RELEASE}\n"
    "        with:\n"
    "          category: \"/language:${{ matrix.language }}\""
)
EXPECTED_STEPS = {
    "Checkout": EXPECTED_CHECKOUT_STEP,
    "Initialize CodeQL": EXPECTED_INIT_STEP,
    "Analyze": EXPECTED_ANALYZE_STEP,
}


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def job_block(workflow: str, key: str) -> str:
    match = re.search(rf"(?m)^  {re.escape(key)}:\s*$", workflow)
    if not match:
        fail(f"CodeQL workflow job is missing: {key}")
    return workflow[match.start():]


def codeql_step_blocks(analyze: str) -> dict[str, str]:
    """Return the exact ordered named steps from the CodeQL analysis job."""
    lines = analyze.splitlines()
    starts = [index for index, line in enumerate(lines) if line == "    steps:"]
    require(len(starts) == 1, "CodeQL analyze job must contain exactly one steps block")

    ordered: list[tuple[str, str]] = []
    current_name: str | None = None
    current_lines: list[str] = []
    for line in lines[starts[0] + 1 :]:
        if line.startswith("      - "):
            match = STEP_START.fullmatch(line)
            require(match is not None, f"CodeQL contains an unnamed or noncanonical step: {line.strip()}")
            if current_name is not None:
                ordered.append((current_name, "\n".join(current_lines).rstrip()))
            current_name = match.group("name")
            current_lines = [line]
            continue
        if current_name is None:
            if not line.strip():
                continue
            require(indentation(line) > 4, f"CodeQL steps block ended before a reviewed step: {line.strip()}")
            fail(f"CodeQL contains content before the first reviewed step: {line.strip()}")
        if line.strip() and indentation(line) <= 4:
            break
        current_lines.append(line)

    if current_name is not None:
        ordered.append((current_name, "\n".join(current_lines).rstrip()))
    require(tuple(name for name, _ in ordered) == EXPECTED_STEP_NAMES,
            f"CodeQL step inventory/order changed: {[name for name, _ in ordered]!r}")
    require(len({name for name, _ in ordered}) == len(ordered), "CodeQL step names must be distinct")
    return dict(ordered)


def validate_codeql(text: str) -> None:
    require(text.startswith("name: CodeQL\n"), "CodeQL workflow name changed")

    require(text.count("  pull_request:\n") == 1, "CodeQL must run on every pull request")
    require(text.count("  push:\n") == 1, "CodeQL must run on push")
    require("    branches:\n      - main\n" in text, "CodeQL push analysis must target main")
    require(text.count('    - cron: "17 5 * * 3"') == 1, "CodeQL weekly schedule changed")
    require(text.count("  workflow_dispatch:\n") == 1, "CodeQL manual dispatch must remain available")
    require("paths:" not in text and "paths-ignore:" not in text,
            "CodeQL must not use path filters that can create scan gaps")

    jobs_index = text.find("\njobs:\n")
    require(jobs_index > 0, "CodeQL jobs block is missing")
    pre_jobs = text[:jobs_index]
    require("permissions:\n  contents: read\n" in pre_jobs,
            "CodeQL default workflow permissions must remain contents: read")
    for forbidden, message in (
        ("contents: write", "CodeQL must never receive repository-content write authority"),
        ("id-token: write", "CodeQL must not receive OIDC signing authority"),
        ("attestations: write", "CodeQL must not receive attestation authority"),
        ("pull-requests: write", "CodeQL must not mutate pull requests"),
        ("actions: write", "CodeQL must not mutate Actions state"),
        ("packages: write", "CodeQL must not receive package write authority"),
    ):
        require(forbidden not in text, message)

    require("group: codeql-${{ github.workflow }}-${{ github.ref }}" in text,
            "CodeQL concurrency identity changed")
    require("cancel-in-progress: true" in text, "CodeQL must cancel stale scans")

    analyze = job_block(text, "analyze")
    require("name: analyze-${{ matrix.language }}" in analyze,
            "CodeQL job naming must expose one stable status per language")
    require("runs-on: ubuntu-24.04" in analyze, "CodeQL runner must remain ubuntu-24.04")
    require("timeout-minutes: 15" in analyze, "CodeQL timeout contract changed")
    require("permissions:\n      contents: read\n      security-events: write\n" in analyze,
            "CodeQL analysis jobs must have only contents: read plus security-events: write")
    require("continue-on-error:" not in analyze, "CodeQL findings/errors must not be made non-blocking")

    require("strategy:\n      fail-fast: false\n      matrix:\n" in analyze,
            "CodeQL must isolate languages in a non-fail-fast matrix")
    expected_matrix = "      matrix:\n        language:\n          - python\n          - actions\n"
    require(expected_matrix in analyze,
            "CodeQL language matrix must contain exactly Python and GitHub Actions")
    matrix_start = analyze.index("      matrix:\n")
    steps_start = analyze.index("\n    steps:\n", matrix_start)
    matrix_block = analyze[matrix_start:steps_start]
    require(matrix_block.count("          - ") == 2,
            "CodeQL language matrix must not silently add or remove analysis languages")

    steps = codeql_step_blocks(analyze)
    for name in EXPECTED_STEP_NAMES:
        require(steps[name] == EXPECTED_STEPS[name], f"CodeQL {name} step changed")

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
            "Python/Actions CodeQL analysis must not add an unnecessary autobuild step")
    require("build-mode:" not in analyze,
            "Python and GitHub Actions should use their native no-build CodeQL defaults")

    require("languages: ${{ matrix.language }}" in analyze,
            "CodeQL init must analyze the isolated matrix language")
    require("queries: security-extended" in analyze,
            "CodeQL must retain the reviewed security-extended query suite")
    require('category: "/language:${{ matrix.language }}"' in analyze,
            "CodeQL results must retain a stable per-language SARIF category")


def validate_autofix_continuation(text: str) -> None:
    require(
        text.count('repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml/runs?branch=main&event=workflow_dispatch&per_page=100') == 1,
        "CodeQL Autofix post-merge run discovery endpoint changed",
    )
    require(
        text.count('python3 scripts/codeql_autofix_controller.py followup-select') == 2,
        "CodeQL Autofix must bind the post-merge CodeQL dispatch before and after creation",
    )
    require(
        text.count('python3 scripts/codeql_autofix_controller.py followup-run') == 1,
        "CodeQL Autofix must verify exactly one bound post-merge CodeQL run",
    )
    require(
        text.count('repos/${TARGET_REPOSITORY}/actions/runs/${POST_MERGE_CODEQL_RUN_ID}') == 1,
        "CodeQL Autofix exact post-merge run endpoint changed",
    )
    require(
        'for attempt in $(seq 1 60); do' in text and 'for attempt in $(seq 1 120); do' in text,
        "CodeQL Autofix post-merge discovery/completion polling bounds changed",
    )
    require(
        text.count('test "$POST_MERGE_CODEQL_CONCLUSION" = "success"') == 1,
        "CodeQL Autofix must require successful completion of the exact post-merge CodeQL run",
    )
    require(
        text.count('python3 scripts/codeql_autofix_controller.py merge-success-response') == 1,
        "CodeQL Autofix must validate exactly one terminal merge success response",
    )
    for fragment in (
        '--response-file merge.json',
        '--out merge-success-normalized.json',
        'MERGE_SHA="$(jq -r .sha merge-success-normalized.json)"',
    ):
        require(fragment in text, f"CodeQL Autofix merge-success response contract is missing: {fragment}")
    require(
        'MERGE_SHA="$(jq -r .sha merge.json)"' not in text
        and 'test "$(jq -r .merged merge.json)" = "true"' not in text,
        "CodeQL Autofix must not consume the terminal merge response before typed success validation",
    )

    merge_pos = text.index('repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/merge')
    merge_validate_pos = text.index(
        'python3 scripts/codeql_autofix_controller.py merge-success-response',
        merge_pos,
    )
    normalized_sha_pos = text.index(
        'MERGE_SHA="$(jq -r .sha merge-success-normalized.json)"',
        merge_validate_pos,
    )
    main_reproof_pos = text.index('\n          assert_main_is_merge_sha\n', normalized_sha_pos)
    snapshot_pos = text.index(
        'repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml/runs?branch=main&event=workflow_dispatch&per_page=100',
        merge_pos,
    )
    scan_dispatch_pos = text.index(
        'repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml/dispatches',
        snapshot_pos,
    )
    exact_run_pos = text.index(
        'repos/${TARGET_REPOSITORY}/actions/runs/${POST_MERGE_CODEQL_RUN_ID}',
        scan_dispatch_pos,
    )
    success_pos = text.index(
        'test "$POST_MERGE_CODEQL_CONCLUSION" = "success"',
        exact_run_pos,
    )
    continuation_pos = text.index(
        '-f event_type=codeql-autofix >/dev/null',
        success_pos,
    )
    require(
        merge_pos < merge_validate_pos < normalized_sha_pos < main_reproof_pos
        < snapshot_pos < scan_dispatch_pos < exact_run_pos < success_pos < continuation_pos,
        "CodeQL Autofix typed merge-success validation / post-merge causal continuation ordering changed",
    )
    require(
        text.count('assert_main_is_merge_sha() {') == 1
        and text.count('assert_main_is_merge_sha') >= 4,
        "CodeQL Autofix must repeatedly fail closed if main moves during post-merge continuation",
    )


def validate_unsupported_evidence(text: str) -> None:
    get_endpoint = 'repos/${TARGET_REPOSITORY}/commits/${BASE_SHA}/comments?per_page=100'
    post_endpoint = 'repos/${TARGET_REPOSITORY}/commits/${BASE_SHA}/comments'
    require(text.count(get_endpoint) == 1,
            "CodeQL Autofix unsupported evidence comment-read endpoint changed")
    require(text.count(post_endpoint) == 2,
            "CodeQL Autofix unsupported evidence comment endpoint inventory changed")
    require(
        text.count('python3 scripts/codeql_autofix_controller.py unsupported-evidence') == 2,
        "CodeQL Autofix unsupported evidence validators changed",
    )
    require(
        text.count('test "$EVIDENCE_EXISTS" = "true" -o "$EVIDENCE_EXISTS" = "false"') == 1,
        "CodeQL Autofix unsupported evidence deduplication proof changed",
    )
    unsupported_pos = text.index('test "$ERROR_TEXT" = "gh: Alert is not supported by autofix. (HTTP 422)"')
    main_before_pos = text.index(
        'test "$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"',
        unsupported_pos,
    )
    read_pos = text.index(get_endpoint, main_before_pos)
    decide_pos = text.index(
        'python3 scripts/codeql_autofix_controller.py unsupported-evidence',
        read_pos,
    )
    create_pos = text.index(post_endpoint, decide_pos)
    created_verify_pos = text.index(
        'python3 scripts/codeql_autofix_controller.py unsupported-evidence-created',
        create_pos,
    )
    main_after_pos = text.index(
        'test "$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"',
        created_verify_pos,
    )
    continuation_pos = text.index(
        'gh api --method POST "repos/${TARGET_REPOSITORY}/dispatches" --input unsupported-dispatch.json',
        main_after_pos,
    )
    require(
        unsupported_pos < main_before_pos < read_pos < decide_pos < create_pos < created_verify_pos
        < main_after_pos < continuation_pos,
        "CodeQL Autofix unsupported evidence ordering changed",
    )
    require(
        'if [ "$EVIDENCE_EXISTS" = "false" ]; then' in text,
        "CodeQL Autofix unsupported evidence must be deduplicated before mutation",
    )
    require(
        "code-scanning/alerts/${ALERT_NUMBER}/dismiss" not in text,
        "CodeQL Autofix must never dismiss unsupported alerts",
    )


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
        "analyze-actions",
        "GitHub Actions workflows",
        "security-events: write",
        "security-extended",
        "exact commit SHA",
        "weekly",
        "no path filters",
        "CodeQL is not an attestation",
    ):
        require(phrase in text, f"CodeQL governance documentation is missing: {phrase}")


def self_test(good: str) -> None:
    autofix_admission_self_test()
    autofix_controller_self_test()
    autofix_discovery_self_test()
    autofix_queue_self_test()
    validate_codeql(good)
    mutations = (
        (good.replace(CODEQL_SHA, "v4"), "Initialize CodeQL step changed"),
        (good.replace("          - actions\n", ""), "Python and GitHub Actions"),
        (good.replace("security-events: write", "security-events: read"), "security-events: write"),
        (good.replace("  pull_request:\n", "  pull_request:\n    paths:\n      - 'scripts/**'\n"), "path filters"),
        (good.replace("      contents: read\n      security-events: write", "      contents: write\n      security-events: write"),
         "repository-content write authority"),
        (good.replace("queries: security-extended", "queries: security-and-quality"), "Initialize CodeQL step changed"),
        (
            good.replace(
                "      - name: Initialize CodeQL\n",
                "      - name: Preprocess checkout\n        run: rm -rf scripts .github/workflows\n\n"
                "      - name: Initialize CodeQL\n",
            ),
            "step inventory/order changed",
        ),
        (
            good.replace(
                "          queries: security-extended\n",
                "          queries: security-and-quality\n          # queries: security-extended\n",
            ),
            "Initialize CodeQL step changed",
        ),
        (
            good.replace(
                '          category: "/language:${{ matrix.language }}"\n',
                '          category: "/language:${{ matrix.language }}"\n        if: false\n',
            ),
            "Analyze step changed",
        ),
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
        for path in (CODEQL, AUTOFIX, QUALITY, GOVERNANCE):
            require(path.is_file(), f"CodeQL governance input is missing: {path.relative_to(ROOT)}")

        codeql = CODEQL.read_text(encoding="utf-8")
        self_test(codeql)
        autofix = AUTOFIX.read_text(encoding="utf-8")
        validate_autofix_continuation(autofix)
        validate_unsupported_evidence(autofix)
        validate_quality(QUALITY.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))

        print(
            "CodeQL governance validation passed: Python and GitHub Actions analysis cover PR/main/weekly/manual events "
            "with no path gaps, use security-extended queries, keep SARIF upload authority isolated, execute exactly three "
            "reviewed steps, use only reviewed SHA-pinned actions, and exercise fail-closed Autofix admission, discovery, "
            "controller trust/provenance, unsupported-alert queue fixtures, durable deduplicated unsupported evidence, "
            "and exact post-merge CodeQL continuation."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
