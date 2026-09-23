#!/usr/bin/env python3
"""Validate the repository's governed CodeQL security-analysis contract."""
from __future__ import annotations

from pathlib import Path
import re
import sys

from codeql_autofix_admission import self_test as autofix_admission_self_test
from codeql_autofix_controller_contract import self_test as autofix_controller_self_test
from codeql_autofix_controller import self_test as autofix_runtime_controller_self_test
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


def validate_autofix_constructive_response_schemas(text: str) -> None:
    created_ref_validator = "python3 scripts/codeql_autofix_controller.py created-ref-response"
    reviewer_validator = "python3 scripts/codeql_autofix_controller.py reviewer-request-response"
    require(text.count(created_ref_validator) == 1,
            "CodeQL Autofix must validate exactly one created-ref mutation response")
    require(text.count(reviewer_validator) == 1,
            "CodeQL Autofix must validate exactly one reviewer-request mutation response")

    for fragment in (
        "--response-file created-ref.json",
        '--branch "$BRANCH"',
        '--expected-sha "$BASE_SHA"',
        "--out created-ref-normalized.json",
        'test "$(jq -r .ref created-ref-normalized.json)" = "$TARGET_REF"',
        'test "$(jq -r .sha created-ref-normalized.json)" = "$BASE_SHA"',
        "--response-file requested-reviewer.json",
        '--pr-number "$PR_NUMBER"',
        '--repository "$TARGET_REPOSITORY"',
        '--base-sha "$BASE_SHA"',
        '--head-sha "$HEAD_SHA"',
        "--out requested-reviewer-normalized.json",
        'test "$(jq -r .prNumber requested-reviewer-normalized.json)" = "$PR_NUMBER"',
        'test "$(jq -r .reviewer requested-reviewer-normalized.json)" = "portyu9"',
        'test "$(jq -r .headSha requested-reviewer-normalized.json)" = "$HEAD_SHA"',
    ):
        require(fragment in text,
                f"CodeQL Autofix constructive mutation-response contract is missing: {fragment}")

    for forbidden in (
        'jq -r .ref created-ref.json',
        'jq -r .object.sha created-ref.json',
        '.requested_reviewers[]? | select(.login == "portyu9")',
    ):
        require(forbidden not in text,
                f"CodeQL Autofix must not consume an untyped constructive mutation response: {forbidden}")

    ref_post = text.index('gh api -X POST "repos/${TARGET_REPOSITORY}/git/refs"')
    ref_validate = text.index(created_ref_validator, ref_post)
    ref_consume = text.index('test "$(jq -r .ref created-ref-normalized.json)" = "$TARGET_REF"', ref_validate)
    autofix_commit = text.index(
        '"repos/${TARGET_REPOSITORY}/code-scanning/alerts/${ALERT_NUMBER}/autofix/commits"',
        ref_consume,
    )
    pr_create = text.index('gh api -X POST "repos/${TARGET_REPOSITORY}/pulls"', autofix_commit)
    receipt = text.index("python3 scripts/codeql_autofix_controller.py receipt", pr_create)
    reviewer_post = text.index(
        'repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers',
        receipt,
    )
    reviewer_validate = text.index(reviewer_validator, reviewer_post)
    reviewer_consume = text.index(
        'test "$(jq -r .headSha requested-reviewer-normalized.json)" = "$HEAD_SHA"',
        reviewer_validate,
    )
    receipt_upload = text.index("- name: Upload immutable controller provenance receipt", reviewer_consume)
    require(
        ref_post < ref_validate < ref_consume < autofix_commit < pr_create < receipt
        < reviewer_post < reviewer_validate < reviewer_consume < receipt_upload,
        "CodeQL Autofix constructive mutation responses must be typed before downstream consumption",
    )


def self_test_autofix_constructive_response_schemas(good: str) -> None:
    validate_autofix_constructive_response_schemas(good)
    mutations = (
        (
            good.replace(
                "python3 scripts/codeql_autofix_controller.py created-ref-response",
                "python3 scripts/codeql_autofix_controller.py commit",
                1,
            ),
            "exactly one created-ref mutation response",
        ),
        (
            good.replace(
                "python3 scripts/codeql_autofix_controller.py reviewer-request-response",
                "python3 scripts/codeql_autofix_controller.py commit",
                1,
            ),
            "exactly one reviewer-request mutation response",
        ),
        (
            good.replace(
                "          python3 scripts/codeql_autofix_controller.py created-ref-response",
                '          test "$(jq -r .ref created-ref.json)" = "$TARGET_REF"\n'
                "          python3 scripts/codeql_autofix_controller.py created-ref-response",
                1,
            ),
            "must not consume an untyped constructive mutation response",
        ),
        (
            good.replace(
                "          python3 scripts/codeql_autofix_controller.py reviewer-request-response",
                '          test "$(jq \'[.requested_reviewers[]? | select(.login == "portyu9")] | length\' '
                'requested-reviewer.json)" = "1"\n'
                "          python3 scripts/codeql_autofix_controller.py reviewer-request-response",
                1,
            ),
            "must not consume an untyped constructive mutation response",
        ),
    )
    for mutated, expected in mutations:
        try:
            validate_autofix_constructive_response_schemas(mutated)
        except ValueError as exc:
            require(expected in str(exc),
                    f"Autofix constructive-response self-test failed for the wrong reason: {exc}")
        else:
            fail(f"Autofix constructive-response self-test accepted forbidden mutation: {expected}")


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
    discovery_endpoint_pos = text.index(
        'repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml/runs?branch=main&event=workflow_dispatch&per_page=100',
        merge_pos,
    )
    snapshot_pos = text.index(
        'fetch_codeql_dispatch_runs > codeql-dispatch-runs-before.json',
        main_reproof_pos,
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
        merge_pos < merge_validate_pos < normalized_sha_pos < discovery_endpoint_pos
        < main_reproof_pos < snapshot_pos < scan_dispatch_pos < exact_run_pos < success_pos < continuation_pos,
        "CodeQL Autofix typed merge-success validation / post-merge causal continuation ordering changed",
    )
    require(
        text.count('assert_main_is_merge_sha() {') == 1
        and text.count('assert_main_is_merge_sha') >= 4,
        "CodeQL Autofix must repeatedly fail closed if main moves during post-merge continuation",
    )


def validate_autofix_readiness_evidence(text: str) -> None:
    start_marker = "          TRUSTED_READY=false\n"
    end_marker = "      - name: Verify an existing Autofix PR and perform protected merge\n"
    require(text.count(start_marker) == 1 and text.count(end_marker) == 1,
            "CodeQL Autofix readiness block anchors changed")
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    readiness = text[start:end]

    trusted_fetch = (
        'repos/${TARGET_REPOSITORY}/commits/${HEAD_SHA}/check-runs?'
        'app_id=15368&check_name=trusted-capability-admission&filter=latest&per_page=100'
    )
    ghas_fetch = (
        'repos/${TARGET_REPOSITORY}/commits/${HEAD_SHA}/check-runs?'
        'app_id=57789&check_name=CodeQL&filter=latest&per_page=100'
    )
    require(readiness.count(trusted_fetch) == 1 and readiness.count(ghas_fetch) == 1,
            "CodeQL Autofix readiness check-run endpoints changed")
    require(
        readiness.count("python3 scripts/codeql_autofix_controller.py readiness-check") == 2,
        "CodeQL Autofix must validate both readiness check-run responses before consumption",
    )
    for fragment in (
        "--response-file trusted-readiness-response.json",
        '--head-sha "$HEAD_SHA"',
        "--name trusted-capability-admission",
        "--app-id 15368",
        "--out trusted-readiness.json",
        'TRUSTED_STATE="$(jq -r .state trusted-readiness.json)"',
        "--response-file ghas-readiness-response.json",
        "--name CodeQL",
        "--app-id 57789",
        "--out ghas-readiness.json",
        'GHAS_STATE="$(jq -r .state ghas-readiness.json)"',
        'case "$TRUSTED_STATE" in',
        'case "$GHAS_STATE" in',
        'test "$TRUSTED_READY" = "true"',
        'test "$GHAS_READY" = "true"',
    ):
        require(fragment in readiness, f"CodeQL Autofix readiness evidence contract is missing: {fragment}")

    for forbidden in (
        'TRUSTED_COUNT="$(jq -r .total_count <<<"$TRUSTED")"',
        '.check_runs[0] | .name == "trusted-capability-admission"',
        '"$(jq -r .total_count <<<"$GHAS")" = "1"',
        ".check_runs[0] | .head_sha == $head",
    ):
        require(forbidden not in readiness,
                f"CodeQL Autofix regressed to raw readiness response consumption: {forbidden}")

    trusted_fetch_pos = readiness.index(trusted_fetch)
    trusted_validate_pos = readiness.index(
        "python3 scripts/codeql_autofix_controller.py readiness-check", trusted_fetch_pos
    )
    trusted_consume_pos = readiness.index(
        'TRUSTED_STATE="$(jq -r .state trusted-readiness.json)"', trusted_validate_pos
    )
    ghas_fetch_pos = readiness.index(ghas_fetch, trusted_consume_pos)
    ghas_validate_pos = readiness.index(
        "python3 scripts/codeql_autofix_controller.py readiness-check", ghas_fetch_pos
    )
    ghas_consume_pos = readiness.index(
        'GHAS_STATE="$(jq -r .state ghas-readiness.json)"', ghas_validate_pos
    )
    require(
        trusted_fetch_pos < trusted_validate_pos < trusted_consume_pos
        < ghas_fetch_pos < ghas_validate_pos < ghas_consume_pos,
        "CodeQL Autofix readiness responses must be validated before state consumption",
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
    autofix_runtime_controller_self_test()
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
        self_test_autofix_constructive_response_schemas(autofix)
        validate_autofix_continuation(autofix)
        validate_autofix_readiness_evidence(autofix)
        validate_unsupported_evidence(autofix)
        validate_quality(QUALITY.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))

        print(
            "CodeQL governance validation passed: Python and GitHub Actions analysis cover PR/main/weekly/manual events "
            "with no path gaps, use security-extended queries, keep SARIF upload authority isolated, execute exactly three "
            "reviewed steps, use only reviewed SHA-pinned actions, and exercise fail-closed Autofix admission, discovery, "
            "controller trust/provenance, typed constructive mutation responses, typed exact-head Autofix readiness check evidence, unsupported-alert queue fixtures, "
            "durable deduplicated unsupported evidence, and exact post-merge CodeQL continuation."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
