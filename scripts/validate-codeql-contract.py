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
CODEQL_SHA = "1c5b675653bb5c22dbe9b12b556ec555138e09fd"
CODEQL_RELEASE = "v4.38.1"
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



def validate_autofix_reviewer_request_status(text: str) -> None:
    response = (
        'REQUESTED_REVIEWER_HTTP_RESPONSE="$(gh api --include --method POST '
        '"repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers" \\'
    )
    status = (
        'REQUESTED_REVIEWER_STATUS_LINE="$(head -n 1 <<<"$REQUESTED_REVIEWER_HTTP_RESPONSE" '
        '| tr -d \'\\r\')"'
    )
    guard = (
        '[[ "$REQUESTED_REVIEWER_STATUS_LINE" =~ '
        '^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {'
    )
    body = (
        'sed \'1,/^[[:space:]]*$/d\' <<<"$REQUESTED_REVIEWER_HTTP_RESPONSE" '
        '> requested-reviewer.json'
    )
    schema = "python3 scripts/codeql_autofix_controller.py reviewer-request-response"
    consume = 'test "$(jq -r .headSha requested-reviewer-normalized.json)" = "$HEAD_SHA"'

    require(text.count(response) == 1,
            "CodeQL Autofix reviewer request must capture exactly one --include response")
    require(text.count(status) == 1,
            "CodeQL Autofix reviewer-request status extraction changed")
    require(text.count(guard) == 1,
            "CodeQL Autofix reviewer request must require exact HTTP 201")
    require(
        "CodeQL Autofix reviewer request returned unexpected status:" in text,
        "CodeQL Autofix reviewer-request status failure must be explicit and fail closed",
    )
    require(text.count(body) == 1,
            "CodeQL Autofix reviewer-request body extraction changed")
    require(
        'gh api --method POST "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers"'
        not in text,
        "CodeQL Autofix must not use a response-blind reviewer-request mutation",
    )

    response_pos = text.index(response)
    status_pos = text.index(status, response_pos)
    guard_pos = text.index(guard, response_pos)
    body_pos = text.index(body, response_pos)
    schema_pos = text.index(schema, body_pos)
    consume_pos = text.index(consume, schema_pos)
    require(
        response_pos < status_pos < guard_pos < body_pos < schema_pos < consume_pos,
        "CodeQL Autofix reviewer request must prove HTTP 201 before body/schema consumption",
    )


def self_test_autofix_reviewer_request_status(text: str) -> None:
    validate_autofix_reviewer_request_status(text)

    missing_include = text.replace(
        'gh api --include --method POST "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers"',
        'gh api --method POST "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers"',
        1,
    )
    try:
        validate_autofix_reviewer_request_status(missing_include)
    except ValueError as exc:
        require(
            "--include response" in str(exc),
            f"Autofix reviewer-request response self-test failed for wrong reason: {exc}",
        )
    else:
        fail("Autofix reviewer-request self-test accepted response-blind mutation")

    wrong_status = text.replace(
        '[[ "$REQUESTED_REVIEWER_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        '[[ "$REQUESTED_REVIEWER_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {',
        1,
    )
    try:
        validate_autofix_reviewer_request_status(wrong_status)
    except ValueError as exc:
        require(
            "exact HTTP 201" in str(exc),
            f"Autofix reviewer-request status self-test failed for wrong reason: {exc}",
        )
    else:
        fail("Autofix reviewer-request self-test accepted non-201 success class")

    status_line = '          REQUESTED_REVIEWER_STATUS_LINE="$(head -n 1 <<<"$REQUESTED_REVIEWER_HTTP_RESPONSE" | tr -d \'\\r\')"\n'
    guard_block = (
        '          [[ "$REQUESTED_REVIEWER_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
        '            echo "ERROR: CodeQL Autofix reviewer request returned unexpected status: ${REQUESTED_REVIEWER_STATUS_LINE}" >&2\n'
        '            exit 1\n'
        '          }\n'
    )
    body_line = (
        '          sed \'1,/^[[:space:]]*$/d\' <<<"$REQUESTED_REVIEWER_HTTP_RESPONSE" '
        '> requested-reviewer.json\n'
    )
    ordered = status_line + guard_block + body_line
    require(ordered in text, "Autofix reviewer-request ordering fixture anchor changed")
    reordered = text.replace(ordered, body_line + status_line + guard_block, 1)
    try:
        validate_autofix_reviewer_request_status(reordered)
    except ValueError as exc:
        require(
            "prove HTTP 201 before body/schema consumption" in str(exc),
            f"Autofix reviewer-request ordering self-test failed for wrong reason: {exc}",
        )
    else:
        fail("Autofix reviewer-request self-test accepted body extraction before status proof")


def validate_autofix_read_singleton_evidence(text: str) -> None:
    read_validator = "python3 scripts/codeql_autofix_controller.py read-ref-response"
    workflow_validator = "python3 scripts/codeql_autofix_controller.py workflow-definition-response"
    pr_validator = "python3 scripts/codeql_autofix_controller.py pull-request-response"
    run_validator = "python3 scripts/codeql_autofix_controller.py protected-workflow-runs-response"
    require(
        text.count(read_validator) == 4,
        "CodeQL Autofix read-ref response validator topology changed",
    )
    require(
        text.count(workflow_validator) == 3,
        "CodeQL Autofix must type exactly three workflow-definition responses",
    )
    require(
        text.count(pr_validator) == 4,
        "CodeQL Autofix must type exactly four pull-request singleton responses",
    )
    require(
        text.count(run_validator) == 1,
        "CodeQL Autofix must type exactly one protected workflow-run collection response",
    )
    require(
        text.count("assert_main_sha() {") == 3
        and text.count("assert_head_sha() {") == 1,
        "CodeQL Autofix static ref helper topology changed",
    )
    require(
        text.count('assert_main_sha "$BASE_SHA"') == 4
        and text.count('assert_head_sha "$HEAD_SHA"') == 1
        and text.count('assert_main_sha "$ADMITTED_BASE_SHA"') == 1
        and text.count('assert_main_sha "$MERGE_SHA"') == 4,
        "CodeQL Autofix expected-SHA ref reproof topology changed",
    )

    for forbidden in (
        'git/ref/heads/main" --jq .object.sha',
        'git/ref/heads/${BRANCH}" --jq .object.sha',
        'actions/workflows/codeql.yml" --jq .id',
        'actions/workflows/dependency-review.yml" --jq .id',
        'actions/workflows/profile-quality.yml" --jq .id',
        'pulls/${PR_NUMBER}" --jq',
        'jq -r .head.sha pr.json',
        'jq -r .state final-pr.json',
        'RUNS="$(gh api "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}',
        'jq -r .total_count <<<"$RUNS"',
        "final-main-ref.json",
    ):
        require(
            forbidden not in text,
            f"CodeQL Autofix regressed to untyped singleton evidence consumption: {forbidden}",
        )

    main_fetch = (
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main" '
        '> "$RUNNER_TEMP/codeql-autofix-main-ref.json"'
    )
    main_response = '--response-file "$RUNNER_TEMP/codeql-autofix-main-ref.json"'
    main_expected = '--expected-ref "refs/heads/main"'
    main_out = '--out "$RUNNER_TEMP/codeql-autofix-main-ref-normalized.json"'
    main_consume = (
        'test "$(jq -r .sha "$RUNNER_TEMP/codeql-autofix-main-ref-normalized.json")" '
        '= "$expected_sha"'
    )
    require(text.count(main_fetch) == 3, "CodeQL Autofix static main-ref GET topology changed")
    require(text.count(main_response) == 3 and text.count(main_expected) == 3
            and text.count(main_out) == 3 and text.count(main_consume) == 3,
            "CodeQL Autofix main-ref typed helper contract changed")

    cursor = -1
    for _ in range(3):
        fetch_pos = text.find(main_fetch, cursor + 1)
        require(fetch_pos > cursor, "CodeQL Autofix main-ref helper fetch disappeared")
        validate_pos = text.find(read_validator, fetch_pos)
        consume_pos = text.find(main_consume, validate_pos)
        require(fetch_pos < validate_pos < consume_pos,
                "CodeQL Autofix main-ref response must be typed before SHA consumption")
        cursor = consume_pos

    head_fetch = (
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${BRANCH}" '
        '> "$RUNNER_TEMP/codeql-autofix-head-ref.json"'
    )
    head_consume = (
        'test "$(jq -r .sha "$RUNNER_TEMP/codeql-autofix-head-ref-normalized.json")" '
        '= "$expected_sha"'
    )
    for fragment in (
        head_fetch,
        '--response-file "$RUNNER_TEMP/codeql-autofix-head-ref.json"',
        '--expected-ref "refs/heads/${BRANCH}"',
        '--out "$RUNNER_TEMP/codeql-autofix-head-ref-normalized.json"',
        head_consume,
    ):
        require(fragment in text, f"CodeQL Autofix exact-head ref contract is missing: {fragment}")
    head_fetch_pos = text.index(head_fetch)
    head_validate_pos = text.index(read_validator, head_fetch_pos)
    head_consume_pos = text.index(head_consume, head_validate_pos)
    require(
        head_fetch_pos < head_validate_pos < head_consume_pos,
        "CodeQL Autofix candidate ref response must be typed before SHA consumption",
    )

    workflow_contracts = (
        (
            'gh api "repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml" '
            '> "$RUNNER_TEMP/codeql-workflow-definition.json"',
            '--response-file "$RUNNER_TEMP/codeql-workflow-definition.json"',
            '--expected-path ".github/workflows/codeql.yml"',
            '--out "$RUNNER_TEMP/codeql-workflow-definition-normalized.json"',
            'CODEQL_WORKFLOW_ID="$(jq -r .id "$RUNNER_TEMP/codeql-workflow-definition-normalized.json")"',
        ),
        (
            'gh api "repos/${TARGET_REPOSITORY}/actions/workflows/dependency-review.yml" '
            '> "$RUNNER_TEMP/dependency-workflow-definition.json"',
            '--response-file "$RUNNER_TEMP/dependency-workflow-definition.json"',
            '--expected-path ".github/workflows/dependency-review.yml"',
            '--out "$RUNNER_TEMP/dependency-workflow-definition-normalized.json"',
            'DEPENDENCY_WORKFLOW_ID="$(jq -r .id "$RUNNER_TEMP/dependency-workflow-definition-normalized.json")"',
        ),
        (
            'gh api "repos/${TARGET_REPOSITORY}/actions/workflows/profile-quality.yml" '
            '> "$RUNNER_TEMP/profile-workflow-definition.json"',
            '--response-file "$RUNNER_TEMP/profile-workflow-definition.json"',
            '--expected-path ".github/workflows/profile-quality.yml"',
            '--out "$RUNNER_TEMP/profile-workflow-definition-normalized.json"',
            'PROFILE_WORKFLOW_ID="$(jq -r .id "$RUNNER_TEMP/profile-workflow-definition-normalized.json")"',
        ),
    )
    cursor = -1
    for fetch, response, expected_path, output, consume in workflow_contracts:
        for fragment in (fetch, response, expected_path, output, consume):
            require(fragment in text, f"CodeQL Autofix workflow-definition contract is missing: {fragment}")
        fetch_pos = text.index(fetch, cursor + 1)
        validate_pos = text.index(workflow_validator, fetch_pos)
        consume_pos = text.index(consume, validate_pos)
        require(
            fetch_pos < validate_pos < consume_pos,
            "CodeQL Autofix workflow definition must be typed before ID consumption",
        )
        cursor = consume_pos

    pr_contracts = (
        (
            'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > "$RUNNER_TEMP/codeql-autofix-candidate-pr.json"',
            '--response-file "$RUNNER_TEMP/codeql-autofix-candidate-pr.json"',
            '--base-sha "$BASE_SHA"',
            '--head-sha "$HEAD_SHA"',
            '--out "$RUNNER_TEMP/codeql-autofix-candidate-pr-normalized.json"',
            'test "$(jq -r .headSha "$RUNNER_TEMP/codeql-autofix-candidate-pr-normalized.json")" = "$HEAD_SHA"',
        ),
        (
            'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > "$RUNNER_TEMP/codeql-autofix-continuation-pr.json"',
            '--response-file "$RUNNER_TEMP/codeql-autofix-continuation-pr.json"',
            '--base-sha "$BASE_SHA"',
            '--head-sha "$HEAD_SHA"',
            '--out "$RUNNER_TEMP/codeql-autofix-continuation-pr-normalized.json"',
            'test "$(jq -r .headSha "$RUNNER_TEMP/codeql-autofix-continuation-pr-normalized.json")" = "$HEAD_SHA"',
        ),
        (
            'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > pr.json',
            '--response-file pr.json',
            '--base-sha "$BASE_SHA"',
            '--head-sha "$EXPECTED_HEAD_SHA"',
            '--out pr-normalized.json',
            'test "$(jq -r .headSha pr-normalized.json)" = "$EXPECTED_HEAD_SHA"',
        ),
        (
            'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > final-pr.json',
            '--response-file final-pr.json',
            '--base-sha "$ADMITTED_BASE_SHA"',
            '--head-sha "$ADMITTED_HEAD_SHA"',
            '--out final-pr-normalized.json',
            'test "$(jq -r .headSha final-pr-normalized.json)" = "$ADMITTED_HEAD_SHA"',
        ),
    )
    cursor = -1
    for fetch, response, base_arg, head_arg, output, consume in pr_contracts:
        fetch_pos = text.index(fetch, cursor + 1)
        validate_pos = text.index(pr_validator, fetch_pos)
        consume_pos = text.index(consume, validate_pos)
        block = text[validate_pos:consume_pos]
        for fragment in (
            response,
            '--pr-number "$PR_NUMBER"',
            '--repository "$TARGET_REPOSITORY"',
            base_arg,
            '--branch "$BRANCH"',
            head_arg,
            output,
        ):
            require(
                fragment in block,
                f"CodeQL Autofix pull-request singleton contract is missing: {fragment}",
            )
        require(
            fetch_pos < validate_pos < consume_pos,
            "CodeQL Autofix pull-request singleton must be typed before scalar consumption",
        )
        cursor = consume_pos

    require(
        'test "$(printf \'%s\\n\' "$CODEQL_WORKFLOW_ID" "$DEPENDENCY_WORKFLOW_ID" "$PROFILE_WORKFLOW_ID" '
        '| LC_ALL=C sort -u | wc -l)" = "3"' in text,
        "CodeQL Autofix workflow IDs must remain exactly three distinct identities",
    )

    run_fetch = (
        'gh api "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100" \\'
        '\n              > "$RUNNER_TEMP/codeql-autofix-protected-runs.json"'
    )
    run_consume = (
        'RUN_COUNT="$(jq -r .totalCount "$RUNNER_TEMP/codeql-autofix-protected-runs-normalized.json")"'
    )
    for fragment in (
        run_fetch,
        '--response-file "$RUNNER_TEMP/codeql-autofix-protected-runs.json"',
        '--head-sha "$HEAD_SHA"',
        '--branch "$BRANCH"',
        '--codeql-workflow-id "$CODEQL_WORKFLOW_ID"',
        '--dependency-workflow-id "$DEPENDENCY_WORKFLOW_ID"',
        '--profile-workflow-id "$PROFILE_WORKFLOW_ID"',
        '--out "$RUNNER_TEMP/codeql-autofix-protected-runs-normalized.json"',
        run_consume,
        'MATCHES="$(jq -c .runs "$RUNNER_TEMP/codeql-autofix-protected-runs-normalized.json")"',
        'test "$(jq \'[.[].workflowId] | unique | length\' <<<"$MATCHES")" = "3"',
    ):
        require(
            fragment in text,
            f"CodeQL Autofix protected workflow-run collection contract is missing: {fragment}",
        )
    run_fetch_pos = text.index(run_fetch)
    run_validate_pos = text.index(run_validator, run_fetch_pos)
    run_consume_pos = text.index(run_consume, run_validate_pos)
    require(
        run_fetch_pos < run_validate_pos < run_consume_pos,
        "CodeQL Autofix protected workflow-run collection must be typed before scalar consumption",
    )


def self_test_autofix_read_singleton_evidence(good: str) -> None:
    validate_autofix_read_singleton_evidence(good)
    mutations = (
        (
            good.replace(
                "python3 scripts/codeql_autofix_controller.py read-ref-response",
                "python3 scripts/codeql_autofix_controller.py commit",
                1,
            ),
            "read-ref response validator topology changed",
        ),
        (
            good.replace(
                "python3 scripts/codeql_autofix_controller.py workflow-definition-response",
                "python3 scripts/codeql_autofix_controller.py commit",
                1,
            ),
            "exactly three workflow-definition responses",
        ),
        (
            good.replace(
                "python3 scripts/codeql_autofix_controller.py pull-request-response",
                "python3 scripts/codeql_autofix_controller.py commit",
                1,
            ),
            "exactly four pull-request singleton responses",
        ),
        (
            good.replace(
                "python3 scripts/codeql_autofix_controller.py protected-workflow-runs-response",
                "python3 scripts/codeql_autofix_controller.py commit",
                1,
            ),
            "exactly one protected workflow-run collection response",
        ),
        (
            good.replace(
                '          assert_main_sha "$BASE_SHA"',
                '          test "$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"\n'
                '          assert_main_sha "$BASE_SHA"',
                1,
            ),
            "untyped singleton evidence consumption",
        ),
        (
            good.replace(
                'CODEQL_WORKFLOW_ID="$(jq -r .id "$RUNNER_TEMP/codeql-workflow-definition-normalized.json")"',
                'CODEQL_WORKFLOW_ID="$(gh api "repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml" --jq .id)"',
                1,
            ),
            "untyped singleton evidence consumption",
        ),
        (
            good.replace(
                "          python3 scripts/codeql_autofix_controller.py pull-request-response",
                '          test "$(gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" --jq .head.sha)" = "$HEAD_SHA"\\n'
                "          python3 scripts/codeql_autofix_controller.py pull-request-response",
                1,
            ),
            "untyped singleton evidence consumption",
        ),
    )
    for mutated, expected in mutations:
        try:
            validate_autofix_read_singleton_evidence(mutated)
        except ValueError as exc:
            require(
                expected in str(exc),
                f"Autofix singleton-evidence self-test failed for the wrong reason: {exc}",
            )
        else:
            fail(f"Autofix singleton-evidence self-test accepted forbidden mutation: {expected}")



def validate_autofix_workflow_run_approval_status(text: str) -> None:
    endpoint = 'repos/${TARGET_REPOSITORY}/actions/runs/${CHECK_RUN_ID}/approve'
    response = (
        'APPROVAL_RESPONSE="$(gh api --include --method POST '
        '"repos/${TARGET_REPOSITORY}/actions/runs/${CHECK_RUN_ID}/approve")"'
    )
    status = 'APPROVAL_STATUS_LINE="$(head -n 1 <<<"$APPROVAL_RESPONSE" | tr -d \'\\r\')"'
    guard = '[[ "$APPROVAL_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {'
    downstream = 'APPROVAL_REQUESTED_RUN_IDS="${APPROVAL_REQUESTED_RUN_IDS} ${CHECK_RUN_ID}"'

    require(text.count(endpoint) == 1,
            "CodeQL Autofix protected-run approval endpoint inventory changed")
    require(text.count(response) == 1,
            "CodeQL Autofix protected-run approval must capture exactly one --include response")
    require(text.count(status) == 1,
            "CodeQL Autofix protected-run approval status extraction changed")
    require(text.count(guard) == 1,
            "CodeQL Autofix protected-run approval must require exact HTTP 201")
    require(
        "CodeQL Autofix protected-run approval returned unexpected status:" in text,
        "CodeQL Autofix protected-run approval failure must be explicit and fail closed",
    )
    require(
        'gh api --method POST "repos/${TARGET_REPOSITORY}/actions/runs/${CHECK_RUN_ID}/approve" >/dev/null'
        not in text,
        "CodeQL Autofix must not discard the protected-run approval response",
    )
    response_pos = text.index(response)
    status_pos = text.index(status, response_pos)
    guard_pos = text.index(guard, status_pos)
    downstream_pos = text.index(downstream, guard_pos)
    require(
        response_pos < status_pos < guard_pos < downstream_pos,
        "CodeQL Autofix must prove HTTP 201 before recording protected-run approval state",
    )


def self_test_autofix_workflow_run_approval_status(text: str) -> None:
    validate_autofix_workflow_run_approval_status(text)

    response_blind = text.replace(
        'gh api --include --method POST "repos/${TARGET_REPOSITORY}/actions/runs/${CHECK_RUN_ID}/approve"',
        'gh api --method POST "repos/${TARGET_REPOSITORY}/actions/runs/${CHECK_RUN_ID}/approve"',
        1,
    )
    try:
        validate_autofix_workflow_run_approval_status(response_blind)
    except ValueError as exc:
        require(
            "--include response" in str(exc),
            f"Autofix protected-run approval response self-test failed for wrong reason: {exc}",
        )
    else:
        fail("Autofix protected-run approval self-test accepted a response-blind mutation")

    wrong_status = text.replace(
        '[[ "$APPROVAL_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
        '[[ "$APPROVAL_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {',
        1,
    )
    try:
        validate_autofix_workflow_run_approval_status(wrong_status)
    except ValueError as exc:
        require(
            "exact HTTP 201" in str(exc),
            f"Autofix protected-run approval status self-test failed for wrong reason: {exc}",
        )
    else:
        fail("Autofix protected-run approval self-test accepted a non-201 success class")


def validate_autofix_continuation(text: str) -> None:
    require(
        text.count('repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml/runs?branch=main&event=workflow_dispatch&per_page=100') == 1,
        "CodeQL Autofix post-merge run discovery endpoint changed",
    )
    dispatch_fetch = (
        'POST_MERGE_CODEQL_DISPATCH_RESPONSE="$(gh api --include --method POST \\\n'
        '            "repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml/dispatches" \\\n'
        '            -f ref=main)"'
    )
    dispatch_status = 'POST_MERGE_CODEQL_DISPATCH_STATUS_LINE="$(head -n 1 <<<"$POST_MERGE_CODEQL_DISPATCH_RESPONSE" | tr -d \'\\r\')"'
    dispatch_guard = '[[ "$POST_MERGE_CODEQL_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {'
    require(
        text.count(dispatch_fetch) == 1,
        "CodeQL Autofix post-merge CodeQL dispatch must capture exactly one --include response",
    )
    require(
        text.count(dispatch_status) == 1 and text.count(dispatch_guard) == 1,
        "CodeQL Autofix post-merge CodeQL dispatch must require exact HTTP 204 before continuation",
    )
    require(
        'CodeQL Autofix post-merge CodeQL dispatch returned unexpected status:' in text,
        "CodeQL Autofix post-merge dispatch failure must be explicit and fail closed",
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
    merge_fetch = 'MERGE_HTTP_RESPONSE="$(gh api --include --method PUT "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/merge"'
    merge_status = 'MERGE_STATUS_LINE="$(head -n 1 <<<"$MERGE_HTTP_RESPONSE" | tr -d \'\\r\')"'
    merge_guard = '[[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {'
    merge_extract = 'sed \'1,/^[[:space:]]*$/d\' <<<"$MERGE_HTTP_RESPONSE" > merge.json'
    for fragment in (
        merge_fetch,
        merge_status,
        merge_guard,
        'CodeQL Autofix terminal merge returned unexpected status:',
        merge_extract,
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

    for fragment, label in (
        (merge_fetch, "mutation"),
        (merge_status, "status extraction"),
        (merge_guard, "HTTP 200 guard"),
        (merge_extract, "body extraction"),
    ):
        require(
            text.count(fragment) == 1,
            f"CodeQL Autofix terminal merge {label} anchor is not singleton",
        )
    merge_pos = text.index(merge_fetch)
    merge_status_pos = text.index(merge_status)
    merge_guard_pos = text.index(merge_guard)
    merge_extract_pos = text.index(merge_extract)
    merge_validate_pos = text.index(
        'python3 scripts/codeql_autofix_controller.py merge-success-response',
        merge_extract_pos,
    )
    normalized_sha_pos = text.index(
        'MERGE_SHA="$(jq -r .sha merge-success-normalized.json)"',
        merge_validate_pos,
    )
    main_reproof_pos = text.index('\n          assert_main_sha "$MERGE_SHA"\n', normalized_sha_pos)
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
    dispatch_guard_pos = text.index(dispatch_guard, scan_dispatch_pos)
    exact_run_pos = text.index(
        'repos/${TARGET_REPOSITORY}/actions/runs/${POST_MERGE_CODEQL_RUN_ID}',
        dispatch_guard_pos,
    )
    success_pos = text.index(
        'test "$POST_MERGE_CODEQL_CONCLUSION" = "success"',
        exact_run_pos,
    )
    continuation_pos = text.index(
        'POST_MERGE_CONTROLLER_DISPATCH_RESPONSE="$(gh api --include --method POST "repos/${TARGET_REPOSITORY}/dispatches"',
        success_pos,
    )
    require(
        merge_pos < merge_status_pos < merge_guard_pos < merge_extract_pos
        < merge_validate_pos < normalized_sha_pos < discovery_endpoint_pos
        < main_reproof_pos < snapshot_pos < scan_dispatch_pos < dispatch_guard_pos
        < exact_run_pos < success_pos < continuation_pos,
        "CodeQL Autofix typed merge-success validation / post-merge causal continuation ordering changed",
    )
    require(
        text.count('assert_main_sha "$MERGE_SHA"') == 4,
        "CodeQL Autofix must repeatedly fail closed with typed main evidence during post-merge continuation",
    )


def self_test_autofix_continuation(text: str) -> None:
    validate_autofix_continuation(text)
    mutations = (
        (
            text.replace(
                'gh api --include --method PUT "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/merge"',
                'gh api --method PUT "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/merge"',
                1,
            ),
            "merge-success response contract",
        ),
        (
            text.replace(
                '[[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {',
                '[[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {',
                1,
            ),
            "merge-success response contract",
        ),
        (
            text.replace(
                '          [[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {\n'
                '            echo "ERROR: CodeQL Autofix terminal merge returned unexpected status: ${MERGE_STATUS_LINE}" >&2\n'
                '            exit 1\n'
                '          }\n'
                '          sed \'1,/^[[:space:]]*$/d\' <<<"$MERGE_HTTP_RESPONSE" > merge.json\n',
                '          sed \'1,/^[[:space:]]*$/d\' <<<"$MERGE_HTTP_RESPONSE" > merge.json\n'
                '          [[ "$MERGE_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {\n'
                '            echo "ERROR: CodeQL Autofix terminal merge returned unexpected status: ${MERGE_STATUS_LINE}" >&2\n'
                '            exit 1\n'
                '          }\n',
                1,
            ),
            "moved out of reviewed order",
        ),
        (
            text.replace(
                'gh api --include --method POST \\\n            "repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml/dispatches"',
                'gh api --method POST \\\n            "repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml/dispatches"',
                1,
            ),
            "--include response",
        ),
        (
            text.replace(
                '[[ "$POST_MERGE_CODEQL_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {',
                '[[ "$POST_MERGE_CODEQL_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {',
                1,
            ),
            "exact HTTP 204",
        ),
    )
    for mutated, expected in mutations:
        try:
            validate_autofix_continuation(mutated)
        except ValueError as exc:
            require(
                expected in str(exc),
                f"Autofix continuation dispatch-status self-test failed for the wrong reason: {exc}",
            )
        else:
            fail(f"Autofix continuation dispatch-status self-test accepted weakened contract: {expected}")


def validate_autofix_repository_dispatch_status(text: str) -> None:
    require(
        text.count('repos/${TARGET_REPOSITORY}/dispatches') == 4,
        "CodeQL Autofix repository-dispatch endpoint inventory changed",
    )
    specs = (
        (
            'UNSUPPORTED_DISPATCH_RESPONSE="$(gh api --include --method POST "repos/${TARGET_REPOSITORY}/dispatches" --input unsupported-dispatch.json)"',
            'UNSUPPORTED_DISPATCH_STATUS_LINE="$(head -n 1 <<<"$UNSUPPORTED_DISPATCH_RESPONSE" | tr -d \'\\r\')"',
            '[[ "$UNSUPPORTED_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {',
            "CodeQL Autofix unsupported-alert repository dispatch returned unexpected status:",
            'printf \'ready=false\\n\' >> "$GITHUB_OUTPUT"',
        ),
        (
            'ADMISSION_DISPATCH_RESPONSE="$(gh api --include --method POST "repos/${TARGET_REPOSITORY}/dispatches" --input admission-dispatch.json)"',
            'ADMISSION_DISPATCH_STATUS_LINE="$(head -n 1 <<<"$ADMISSION_DISPATCH_RESPONSE" | tr -d \'\\r\')"',
            '[[ "$ADMISSION_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {',
            "CodeQL Autofix admission repository dispatch returned unexpected status:",
            "TRUSTED_READY=false",
        ),
        (
            'CONTINUATION_DISPATCH_RESPONSE="$(gh api --include --method POST "repos/${TARGET_REPOSITORY}/dispatches" \\\n            -f event_type=codeql-autofix)"',
            'CONTINUATION_DISPATCH_STATUS_LINE="$(head -n 1 <<<"$CONTINUATION_DISPATCH_RESPONSE" | tr -d \'\\r\')"',
            '[[ "$CONTINUATION_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {',
            "CodeQL Autofix existing-PR repository dispatch returned unexpected status:",
            "      - name: Verify an existing Autofix PR and perform protected merge",
        ),
        (
            'POST_MERGE_CONTROLLER_DISPATCH_RESPONSE="$(gh api --include --method POST "repos/${TARGET_REPOSITORY}/dispatches" \\\n            -f event_type=codeql-autofix)"',
            'POST_MERGE_CONTROLLER_DISPATCH_STATUS_LINE="$(head -n 1 <<<"$POST_MERGE_CONTROLLER_DISPATCH_RESPONSE" | tr -d \'\\r\')"',
            '[[ "$POST_MERGE_CONTROLLER_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {',
            "CodeQL Autofix post-merge repository dispatch returned unexpected status:",
            None,
        ),
    )
    for response, status, guard, error, downstream in specs:
        require(text.count(response) == 1, f"CodeQL Autofix repository dispatch response capture changed: {response}")
        require(text.count(status) == 1, f"CodeQL Autofix repository dispatch status extraction changed: {status}")
        require(text.count(guard) == 1, f"CodeQL Autofix repository dispatch HTTP 204 guard changed: {guard}")
        require(error in text, f"CodeQL Autofix repository dispatch fail-closed diagnostic changed: {error}")
        response_pos = text.index(response)
        status_pos = text.index(status, response_pos)
        guard_pos = text.index(guard, status_pos)
        require(response_pos < status_pos < guard_pos,
                "CodeQL Autofix repository dispatch must validate status after the mutation response")
        if downstream is not None:
            downstream_pos = text.index(downstream, guard_pos)
            require(guard_pos < downstream_pos,
                    "CodeQL Autofix repository dispatch status validation moved after downstream continuation")

    for forbidden in (
        'gh api --method POST "repos/${TARGET_REPOSITORY}/dispatches" --input unsupported-dispatch.json >/dev/null',
        'gh api --method POST "repos/${TARGET_REPOSITORY}/dispatches" --input admission-dispatch.json >/dev/null',
        '-f event_type=codeql-autofix >/dev/null',
    ):
        require(forbidden not in text,
                f"CodeQL Autofix must not discard repository-dispatch responses: {forbidden}")


def self_test_autofix_repository_dispatch_status(text: str) -> None:
    validate_autofix_repository_dispatch_status(text)
    response_blind = text.replace(
        'gh api --include --method POST "repos/${TARGET_REPOSITORY}/dispatches" --input unsupported-dispatch.json',
        'gh api --method POST "repos/${TARGET_REPOSITORY}/dispatches" --input unsupported-dispatch.json',
        1,
    )
    try:
        validate_autofix_repository_dispatch_status(response_blind)
    except ValueError as exc:
        require("response capture changed" in str(exc),
                f"Autofix repository-dispatch response self-test failed for wrong reason: {exc}")
    else:
        fail("Autofix repository-dispatch self-test accepted response-blind mutation")

    wrong_status = text.replace(
        '[[ "$ADMISSION_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+204([[:space:]]|$) ]] || {',
        '[[ "$ADMISSION_DISPATCH_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {',
        1,
    )
    try:
        validate_autofix_repository_dispatch_status(wrong_status)
    except ValueError as exc:
        require("HTTP 204 guard changed" in str(exc),
                f"Autofix repository-dispatch status self-test failed for wrong reason: {exc}")
    else:
        fail("Autofix repository-dispatch self-test accepted non-204 success class")


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
        'assert_main_sha "$BASE_SHA"',
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
        'assert_main_sha "$BASE_SHA"',
        created_verify_pos,
    )
    continuation_pos = text.index(
        'UNSUPPORTED_DISPATCH_RESPONSE="$(gh api --include --method POST "repos/${TARGET_REPOSITORY}/dispatches" --input unsupported-dispatch.json)"',
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


def validate_approval_comment_evidence(text: str) -> None:
    get_endpoint = 'repos/${TARGET_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100'
    post_endpoint = 'gh api --method POST "repos/${TARGET_REPOSITORY}/issues/${PR_NUMBER}/comments"'
    evidence_validator = "python3 scripts/codeql_autofix_controller.py approval-comment-evidence"
    created_validator = "python3 scripts/codeql_autofix_controller.py approval-comment-created"

    require(text.count(get_endpoint) == 1,
            "CodeQL Autofix approval-comment read endpoint changed")
    require(text.count(post_endpoint) == 1,
            "CodeQL Autofix approval-comment mutation endpoint changed")
    require(text.count(evidence_validator) == 1,
            "CodeQL Autofix must type exactly one approval-comment page collection")
    require(text.count(created_validator) == 1,
            "CodeQL Autofix must type exactly one created approval-comment response")

    for forbidden in (
        'COMMENTS="$(gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100")"',
        '[.[][] | select(.body | contains($marker))] | length > 0',
        'jq -r .body approval-comment.json',
    ):
        require(
            forbidden not in text,
            f"CodeQL Autofix regained raw approval-comment evidence consumption: {forbidden}",
        )

    marker_pos = text.index(
        'APPROVAL_MARKER="<!-- portyu9-automation-approval:v1 head=${ADMITTED_HEAD_SHA} -->"'
    )
    get_pos = text.index(get_endpoint, marker_pos)
    validate_pos = text.index(evidence_validator, get_pos)
    consume_pos = text.index(
        'APPROVAL_COMMENT_EXISTS="$(jq -r .exists approval-comment-evidence.json)"',
        validate_pos,
    )
    branch_pos = text.index(
        'if [ "$APPROVAL_COMMENT_EXISTS" = "false" ]; then',
        consume_pos,
    )
    post_pos = text.index(post_endpoint, branch_pos)
    created_pos = text.index(created_validator, post_pos)
    actor_pos = text.index(
        'test "$(jq -r .actor approval-comment-normalized.json)" = "github-actions[bot]"',
        created_pos,
    )
    merge_pos = text.index(
        'gh api --include --method PUT "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/merge"',
        actor_pos,
    )
    require(
        marker_pos < get_pos < validate_pos < consume_pos < branch_pos < post_pos
        < created_pos < actor_pos < merge_pos,
        "CodeQL Autofix approval-comment fetch/validate/create ordering changed",
    )
    for fragment in (
        '--comments-file approval-comment-pages.json',
        '--pr-number "$PR_NUMBER"',
        '--marker "$APPROVAL_MARKER"',
        '--out approval-comment-evidence.json',
        'test "$APPROVAL_COMMENT_EXISTS" = "true" -o "$APPROVAL_COMMENT_EXISTS" = "false"',
        '--comment-file approval-comment.json',
        '--expected-body "$APPROVAL_BODY"',
        '--out approval-comment-normalized.json',
        'test "$(jq -r .prNumber approval-comment-normalized.json)" = "$PR_NUMBER"',
    ):
        require(
            fragment in text,
            f"CodeQL Autofix approval-comment contract is missing: {fragment}",
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
        self_test_autofix_reviewer_request_status(autofix)
        self_test_autofix_read_singleton_evidence(autofix)
        self_test_autofix_workflow_run_approval_status(autofix)
        self_test_autofix_continuation(autofix)
        self_test_autofix_repository_dispatch_status(autofix)
        validate_autofix_readiness_evidence(autofix)
        validate_unsupported_evidence(autofix)
        validate_approval_comment_evidence(autofix)
        validate_quality(QUALITY.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))

        print(
            "CodeQL governance validation passed: Python and GitHub Actions analysis cover PR/main/weekly/manual events "
            "with no path gaps, use security-extended queries, keep SARIF upload authority isolated, execute exactly three "
            "reviewed steps, use only reviewed SHA-pinned actions, and exercise fail-closed Autofix admission, discovery, "
            "controller trust/provenance, typed constructive mutation responses with exact HTTP-201-validated reviewer requests, typed read-only ref/workflow-definition evidence, typed exact-head Autofix readiness check evidence, exact HTTP-201-validated protected-run approvals, unsupported-alert queue fixtures, "
            "durable deduplicated unsupported evidence, trusted-actor-bound approval-comment evidence, exact HTTP-204-validated repository dispatches and post-merge CodeQL workflow dispatch, and exact post-merge CodeQL continuation."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
