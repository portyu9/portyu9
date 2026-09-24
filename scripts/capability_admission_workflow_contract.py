#!/usr/bin/env python3
"""Exact byte and trust-boundary contract for trusted capability admission."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/capability-admission.yml"
EXPECTED_GIT_BLOB = "91586841790d09c244ae33f79ada137ffbcaaa74"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
SETUP_PYTHON = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0"

ORDINARY_EVALUATOR = """            python3 scripts/workflow_capability_admission.py \\
              candidate-capability-source \\
              --candidate-tree-sha "$TREE_SHA" \\
              > capability-admission.json
"""
DEPENDABOT_EVALUATOR = """            python3 scripts/dependabot_capability_admission.py \\
              candidate-capability-source \\
              --candidate-tree-sha "$TREE_SHA" \\
              --pr "$RUNNER_TEMP/dependabot-pr.json" \\
              --expected-head-sha "$HEAD_SHA" \\
              --resolved-release dependabot-release-identity.json \\
              --changed-paths dependabot-changed-paths.txt \\
              > capability-admission.json
"""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()  # noqa: S324 - Git object identity is SHA-1 by protocol.


def validate_text(text: str) -> None:
    require(text.startswith("name: Capability admission\n\non:\n  pull_request_target:\n"),
            "trusted capability admission trigger identity changed")
    for event_type in ("opened", "reopened", "synchronize", "ready_for_review"):
        require(text.count(f"      - {event_type}\n") == 1,
                f"trusted capability admission event type changed: {event_type}")
    require(
        "  repository_dispatch:\n    types:\n      - codeql-autofix-admission\n      - dependabot-admission\n" in text,
        "trusted capability admission repository_dispatch trigger changed",
    )
    require('  schedule:\n    - cron: "*/5 * * * *"\n' in text,
            "trusted capability admission scheduled Spotlight recovery trigger changed")
    require("workflow_run:" not in text,
            "trusted capability admission retained forbidden workflow_run authority")

    workflow_permissions = (
        "permissions:\n"
        "  actions: read\n"
        "  checks: write\n"
        "  contents: read\n"
        "  pull-requests: read\n"
    )
    job_permissions = (
        "    permissions:\n"
        "      actions: read\n"
        "      checks: write\n"
        "      contents: read\n"
        "      pull-requests: read\n"
    )
    require(text.count(workflow_permissions) == 1,
            "trusted capability admission workflow permission set changed")
    require(text.count(job_permissions) == 1,
            "trusted capability admission job permission set changed")
    for forbidden in (
        "contents: write", "actions: write", "pull-requests: write", "security-events: write",
        "id-token: write", "attestations: write", "--method PUT", "--method PATCH", "--method DELETE",
        "curl ", "wget ",
    ):
        require(forbidden not in text, f"trusted capability admission acquired forbidden authority: {forbidden}")
    require(text.count("--method POST") == 1,
            "trusted capability admission write-call count changed")

    require(text.count(f"uses: {CHECKOUT}") == 1,
            "trusted capability admission checkout pin changed")
    require(text.count(f"uses: {SETUP_PYTHON}") == 1,
            "trusted capability admission Python setup pin changed")
    require("ref: main" in text,
            "trusted capability admission no longer checks out static trusted main")
    require('run: test "$(git rev-parse HEAD)" = "$BASE_SHA"' in text,
            "trusted capability admission no longer re-proves the exact checked-out base SHA")
    require("persist-credentials: false" in text and "fetch-depth: 1" in text,
            "trusted capability admission checkout boundary changed")
    checkout_pos = text.index("- name: Checkout static trusted main")
    setup_pos = text.index("- name: Set up Python")
    runtime_pos = text.index("- name: Verify resolved Python runtime")
    bind_pos = text.index("- name: Bind exact candidate context")
    spotlight_parser_pos = text.find(
        "python3 scripts/workflow_capability_api_collection.py pull-requests",
        bind_pos,
    )
    exact_base_pos = text.index("- name: Verify exact trusted base checkout", bind_pos)
    if spotlight_parser_pos >= 0:
        require(
            checkout_pos < setup_pos < runtime_pos < bind_pos < spotlight_parser_pos < exact_base_pos,
            "trusted capability admission bootstrap ordering regressed",
        )
    require("ref: ${{ github.event.pull_request.head.sha }}" not in text and
            "ref: ${{ steps.candidate.outputs.head_sha }}" not in text,
            "trusted capability admission must never checkout candidate code")
    for forbidden_execution in (
        "python3 candidate-capability-source", "source candidate-capability-source", "bash candidate-capability-source",
    ):
        require(forbidden_execution not in text,
                "trusted capability admission must never execute candidate-controlled code")

    for binding in (
        "GH_TOKEN: ${{ github.token }}",
        "EVENT_NAME: ${{ github.event_name }}",
        "TARGET_REPOSITORY: ${{ github.repository }}",
        'PR="$(jq -c \'.pull_request\' "$GITHUB_EVENT_PATH")"',
        'ACTION="$(jq -r \'.action // ""\' "$GITHUB_EVENT_PATH")"',
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main"',
        'gh api "repos/${TARGET_REPOSITORY}/git/commits/${HEAD_SHA}"',
        'gh api "repos/${HEAD_REPOSITORY}/git/trees/${TREE_SHA}?recursive=1"',
        'python3 scripts/workflow_capability_tcb.py select',
        'TREE_SHA="$(cat candidate-capability-source/.candidate-tree-sha)"',
    ):
        require(binding in text, f"trusted capability admission identity binding changed: {binding}")

    for pr_schema_fragment in (
        'validate_api_pr_object() {',
        '--argjson number "$number"',
        '(.number | type == "number" and . == floor and . > 0 and . == $number) and',
        '(.user | (type == "object") and (.login | (type == "string") and length > 0)) and',
        '(.state == "open") and',
        '(.draft | type == "boolean") and',
        '(.maintainer_can_modify | type == "boolean") and',
        '(.base | type == "object" and',
        '(.head | type == "object" and',
        '(.repo | type == "object" and',
        '(.title | type == "string" and length > 0) and',
        'has("body") and',
        '(.body == null or (.body | type == "string"))',
        'ERROR: malformed CodeQL Autofix capability-admission PR evidence for #${PR_NUMBER}.',
        'ERROR: malformed delegated Dependabot capability-admission PR evidence for #${PR_NUMBER}.',
        'ERROR: malformed Spotlight capability-admission PR evidence for #${PR_NUMBER}.',
    ):
        require(
            pr_schema_fragment in text,
            f"trusted capability admission PR-object schema contract is missing: {pr_schema_fragment}",
        )
    schema_call = 'validate_api_pr_object "$PR" "$PR_NUMBER"'
    require(
        text.count(schema_call) == 3,
        "trusted capability admission must schema-validate exactly all three API-hydrated PR objects",
    )

    codeql_lane = text.index("codeql-autofix-admission)")
    codeql_fetch = text.index('PR="$(gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}")"', codeql_lane)
    codeql_schema = text.index(schema_call, codeql_fetch)
    codeql_consumer = text.index('test "$(jq -r .state <<<"$PR")" = "open"', codeql_schema)
    require(
        codeql_fetch < codeql_schema < codeql_consumer,
        "trusted capability admission must validate CodeQL Autofix PR evidence before field consumption",
    )

    dependabot_lane = text.index("dependabot-admission)")
    dependabot_fetch = text.index(
        'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > "$RUNNER_TEMP/dependabot-pr.json"',
        dependabot_lane,
    )
    dependabot_assign = text.index('PR="$(cat "$RUNNER_TEMP/dependabot-pr.json")"', dependabot_fetch)
    dependabot_schema = text.index(schema_call, dependabot_assign)
    dependabot_consumer = text.index('test "$(jq -r .state <<<"$PR")" = "open"', dependabot_schema)
    require(
        dependabot_fetch < dependabot_assign < dependabot_schema < dependabot_consumer,
        "trusted capability admission must validate delegated Dependabot PR evidence before field consumption",
    )

    spotlight_lane = text.index("workflow_dispatch|schedule)")
    spotlight_fetch = text.index('PR="$(gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}")"', spotlight_lane)
    spotlight_schema = text.index(schema_call, spotlight_fetch)
    spotlight_consumer = text.index('test "$(jq -r .number <<<"$PR")" = "$PR_NUMBER"', spotlight_schema)
    require(
        spotlight_fetch < spotlight_schema < spotlight_consumer,
        "trusted capability admission must validate Spotlight PR evidence before field consumption",
    )

    ref_schema_start = text.index("          validate_git_ref_object() {")
    ref_schema_end = text.index("          validate_readme_contents_object() {", ref_schema_start)
    ref_schema = text[ref_schema_start:ref_schema_end]
    for schema_fragment in (
        'local ref_json="$1" expected_ref="$2" expected_sha="${3:-}"',
        '(type == "object") and',
        '(.ref | type == "string" and . == $ref) and',
        '(.object | type == "object" and',
        '(.type | type == "string" and . == "commit") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$"))) and',
        '($sha == "" or .object.sha == $sha)',
    ):
        require(
            schema_fragment in ref_schema,
            f"trusted capability admission Git-ref response schema changed: {schema_fragment}",
        )

    contents_schema_start = ref_schema_end
    contents_schema_end = text.index('          case "$EVENT_NAME" in', contents_schema_start)
    contents_schema = text[contents_schema_start:contents_schema_end]
    for schema_fragment in (
        'local contents_json="$1" expected_blob_sha="$2"',
        '(type == "object") and',
        '(.type | type == "string" and . == "file") and',
        '(.name | type == "string" and . == "README.md") and',
        '(.path | type == "string" and . == "README.md") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $blob) and',
        '(.size | type == "number" and . == floor and . >= 0) and',
        '(.encoding | type == "string" and . == "base64") and',
        '(.content | type == "string" and length > 0)',
    ):
        require(
            schema_fragment in contents_schema,
            f"trusted capability admission README Contents response schema changed: {schema_fragment}",
        )

    discovery_lane = text.index("workflow_dispatch|schedule)")
    discovery_ref_call = text.index(
        'MAIN_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main")"',
        discovery_lane,
    )
    discovery_ref_schema = text.index(
        'validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" || {',
        discovery_ref_call,
    )
    discovery_ref_consume = text.index(
        'MAIN_SHA="$(jq -r .object.sha <<<"$MAIN_REF_RESPONSE")"',
        discovery_ref_call,
    )
    common_ref_call = text.index(
        'MAIN_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main")"',
        discovery_ref_call + 1,
    )
    common_ref_schema = text.index(
        'validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$BASE_SHA" || {',
        common_ref_call,
    )
    common_ref_consume = text.index(
        'test "$(jq -r .object.sha <<<"$MAIN_REF_RESPONSE")" = "$BASE_SHA"',
        common_ref_call,
    )
    head_ref_call = text.index(
        'HEAD_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}")"',
        common_ref_consume,
    )
    head_ref_schema = text.index(
        'validate_git_ref_object "$HEAD_REF_RESPONSE" "refs/heads/${HEAD_REF}" "$HEAD_SHA" || {',
        head_ref_call,
    )
    head_ref_consume = text.index(
        'test "$(jq -r .object.sha <<<"$HEAD_REF_RESPONSE")" = "$HEAD_SHA"',
        head_ref_call,
    )
    generated_ref_call = text.index(
        'GENERATED_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/generated")"',
        head_ref_consume,
    )
    generated_ref_schema = text.index(
        'validate_git_ref_object "$GENERATED_REF_RESPONSE" "refs/heads/generated" || {',
        generated_ref_call,
    )
    generated_ref_consume = text.index(
        'GENERATED_SHA="$(jq -r .object.sha <<<"$GENERATED_REF_RESPONSE")"',
        generated_ref_call,
    )
    require(
        discovery_ref_call < discovery_ref_schema < discovery_ref_consume
        < common_ref_call < common_ref_schema < common_ref_consume
        < head_ref_call < head_ref_schema < head_ref_consume
        < generated_ref_call < generated_ref_schema < generated_ref_consume,
        "trusted capability admission Git-ref schemas must precede scalar consumption",
    )

    readme_call = text.index(
        'README_CONTENTS_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}")"',
        generated_ref_consume,
    )
    readme_schema = text.index(
        'validate_readme_contents_object "$README_CONTENTS_RESPONSE" "$README_BLOB_SHA" || {',
        readme_call,
    )
    readme_path_consume = text.index(
        'test "$(jq -r .path <<<"$README_CONTENTS_RESPONSE")" = "README.md"',
        readme_call,
    )
    readme_sha_consume = text.index(
        'test "$(jq -r .sha <<<"$README_CONTENTS_RESPONSE")" = "$README_BLOB_SHA"',
        readme_call,
    )
    readme_content_consume = text.index(
        'jq -r .content <<<"$README_CONTENTS_RESPONSE" \\',
        readme_call,
    )
    require(
        readme_call < readme_schema < readme_path_consume < readme_sha_consume < readme_content_consume,
        "trusted capability admission README Contents schema must precede scalar consumption",
    )
    require(
        "README_BLOB_SHA=\"$(jq -r '.files[0].sha' <<<\"$COMPARE\")\"" in text,
        "trusted capability admission README blob identity is no longer bound to typed compare evidence",
    )
    require(
        "malformed Capability Admission main-ref discovery evidence." in text
        and "malformed or stale Capability Admission main-ref evidence." in text
        and "malformed or mismatched Capability Admission Spotlight candidate-ref evidence." in text
        and "malformed Capability Admission generated-ref evidence." in text,
        "trusted capability admission Git-ref schema failures must remain visible",
    )
    require(
        "malformed or mismatched Capability Admission Spotlight README evidence." in text,
        "trusted capability admission README Contents schema failure must remain visible",
    )

    require(text.count(ORDINARY_EVALUATOR) == 1,
            "ordinary evaluator lost exact candidate tree binding")
    require(text.count(DEPENDABOT_EVALUATOR) == 1,
            "delegated evaluator lost exact candidate tree binding")

    for autofix_binding in (
        "codeql-autofix-admission)",
        '"codeql-autofix/alert-${ALERT_NUMBER}/run-${ORIGIN_RUN_ID}"',
        "python3 scripts/codeql_autofix_controller.py artifact",
        'test "$(jq -r .status origin-run.json)" = "in_progress"',
        'EXTERNAL_ID="codeql-autofix-admission:${ORIGIN_RUN_ID}:${PR_NUMBER}:${HEAD_SHA}"',
    ):
        require(autofix_binding in text,
                f"trusted capability admission Autofix proof changed: {autofix_binding}")

    for dependabot_binding in (
        "dependabot-admission)",
        'test "$(jq -r \'.sender.login // ""\' "$GITHUB_EVENT_PATH")" = "github-actions[bot]"',
        'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > "$RUNNER_TEMP/dependabot-pr.json"',
        'PR="$(cat "$RUNNER_TEMP/dependabot-pr.json")"',
        'test "$(jq -r .maintainer_can_modify <<<"$PR")" = "false"',
        '[[ "$HEAD_REF" =~ ^dependabot/github_actions/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]]',
        'gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100" > dependabot-file-pages.json',
        "python3 scripts/workflow_capability_api_collection.py files",
        "--input dependabot-file-pages.json",
        "--out dependabot-changed-paths.txt",
        'for PATH_VALUE in .github/action-lock.json .github/workflow-capability-bom-v1.json scripts/validate-codeql-contract.py; do',
        "python3 scripts/dependabot_controller.py probe",
        'test "$DEPENDENCY_REPOSITORY" = "github/codeql-action"',
        'git ls-remote --tags "https://github.com/${DEPENDENCY_REPOSITORY}.git"',
        "python3 scripts/dependabot_release.py",
        'gh api "repos/${DEPENDENCY_REPOSITORY}" > dependabot-release-repository.json',
        'gh api "repos/${DEPENDENCY_REPOSITORY}/releases/tags/${CANDIDATE_TAG}" > dependabot-release.json',
        '--repository-json dependabot-release-repository.json',
        '--release-json dependabot-release.json',
        'test "$(jq -r .sha dependabot-release-identity.json)" = "$CANDIDATE_SHA"',
        '--resolved-release dependabot-release-identity.json',
        'test "$(jq -r .decision.authorizationId capability-admission.json)" = "delegated-dependabot-codeql-v1"',
        '[[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ ]]',
        '[[ "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]',
        'for HISTORY_ATTEMPT in $(seq 1 20); do',
        'gh api "repos/${TARGET_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/attempts/${HISTORY_ATTEMPT}"',
        "python3 scripts/dependabot_admission_proof.py build",
        '--summary-out dependabot-admission-proof-summary.json',
        '--meta-out dependabot-admission-proof-meta.json',
        'SUMMARY_SHA256="$(jq -r .summarySha256 dependabot-admission-proof-meta.json)"',
        'EXTERNAL_ID="dependabot-delegated-admission:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}:${SUMMARY_SHA256}:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
    ):
        require(dependabot_binding in text,
                f"trusted capability admission delegated Dependabot proof changed: {dependabot_binding}")

    for spotlight_binding in (
        '    - cron: "*/5 * * * *"',
        "  workflow_dispatch:",
        'test "$ACTOR" = "github-actions[bot]"',
        'workflow_dispatch|schedule)',
        'SPOTLIGHT_MODE="delegated"',
        "python3 scripts/workflow_capability_api_collection.py pull-requests",
        "--input spotlight-open-pr-pages.json",
        "--out spotlight-open-prs.json",
        '.user.login == "github-actions[bot]"',
        'test("^automation/spotlight-links/[0-9a-f]{64}$")',
        'test "$MATCH_COUNT" -le 1',
        'DISCOVERED_PR="$(jq -c \'.[0]\' <<<"$MATCHES")"',
        'PR="$(gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}")"',
        'test "$(jq -r .maintainer_can_modify <<<"$PR")" = "false"',
        'test "$(jq -r .message <<<"$CANDIDATE_COMMIT")" = "chore: sync rotating Spotlight links"',
        'test "$(jq -r .total_commits <<<"$COMPARE")" = "1"',
        'test "$(jq -r \'.files[0].filename\' <<<"$COMPARE")" = "README.md"',
        'test "$HEAD_REF" = "automation/spotlight-links/${CANDIDATE_ID}"',
        '[[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ ]]',
        '[[ "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]',
        'EXTERNAL_ID="spotlight-admission:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
    ):
        require(spotlight_binding in text,
                f"trusted capability admission Spotlight proof changed: {spotlight_binding}")

    candidate_call = 'CANDIDATE_COMMIT="$(gh api "repos/${TARGET_REPOSITORY}/git/commits/${HEAD_SHA}")"'
    candidate_schema_marker = 'jq -e --arg head "$HEAD_SHA" --arg base "$BASE_SHA" \\'
    candidate_schema_end_marker = "' <<<\"$CANDIDATE_COMMIT\" >/dev/null || {"
    candidate_consume_marker = 'test "$(jq \'.parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"'
    compare_call = 'COMPARE="$(gh api "repos/${TARGET_REPOSITORY}/compare/${BASE_SHA}...${HEAD_SHA}")"'
    compare_schema_marker = 'jq -e --arg base "$BASE_SHA" --arg head "$HEAD_SHA" \''
    compare_schema_end_marker = "' <<<\"$COMPARE\" >/dev/null || {"
    compare_consume_marker = 'test "$(jq -r .status <<<"$COMPARE")" = "ahead"'
    for marker, label in (
        (candidate_call, "candidate commit call"),
        (candidate_schema_marker, "candidate commit schema"),
        (candidate_schema_end_marker, "candidate commit schema end"),
        (candidate_consume_marker, "candidate commit scalar consumption"),
        (compare_call, "compare call"),
        (compare_schema_marker, "compare schema"),
        (compare_schema_end_marker, "compare schema end"),
        (compare_consume_marker, "compare scalar consumption"),
    ):
        require(text.count(marker) == 1,
                f"trusted capability admission Spotlight topology anchor changed: {label}")

    candidate_call_pos = text.index(candidate_call)
    candidate_schema_pos = text.index(candidate_schema_marker, candidate_call_pos)
    candidate_schema_end_pos = text.index(candidate_schema_end_marker, candidate_schema_pos) + len(candidate_schema_end_marker)
    candidate_consume_pos = text.index(candidate_consume_marker, candidate_call_pos)
    compare_call_pos = text.index(compare_call, candidate_call_pos)
    compare_schema_pos = text.index(compare_schema_marker, compare_call_pos)
    compare_schema_end_pos = text.index(compare_schema_end_marker, compare_schema_pos) + len(compare_schema_end_marker)
    compare_consume_pos = text.index(compare_consume_marker, compare_call_pos)
    require(
        candidate_call_pos < candidate_schema_pos < candidate_schema_end_pos < candidate_consume_pos
        < compare_call_pos < compare_schema_pos < compare_schema_end_pos < compare_consume_pos,
        "trusted capability admission Spotlight topology schemas must precede scalar consumption",
    )

    candidate_schema = text[candidate_schema_pos:candidate_schema_end_pos]
    for schema_fragment in (
        '(type == "object") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $head) and',
        '(.tree | type == "object" and',
        '(.parents | type == "array" and length == 1 and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $base))) and',
        '(.author | type == "object" and\n'
        '                (.name | type == "string" and . == $name) and\n'
        '                (.email | type == "string" and . == $email)) and',
        '(.committer | type == "object" and\n'
        '                (.name | type == "string" and . == $name) and\n'
        '                (.email | type == "string" and . == $email) and\n'
        '                (.date | type == "string" and length > 0)) and',
        '(.message | type == "string" and . == "chore: sync rotating Spotlight links")',
    ):
        require(
            schema_fragment in candidate_schema,
            f"trusted capability admission Spotlight candidate commit response schema changed: {schema_fragment}",
        )
    require(
        "malformed or mismatched Capability Admission Spotlight candidate commit evidence." in text,
        "trusted capability admission Spotlight candidate commit response schema must fail visibly",
    )

    compare_schema = text[compare_schema_pos:compare_schema_end_pos]
    for schema_fragment in (
        '(type == "object") and',
        '(.status | type == "string" and . == "ahead") and',
        '(.base_commit | type == "object" and\n'
        '                (.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $base)) and',
        '(.merge_base_commit | type == "object" and\n'
        '                (.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $base)) and',
        '(.ahead_by | type == "number" and . == floor and . == 1) and',
        '(.behind_by | type == "number" and . == floor and . == 0) and',
        '(.total_commits | type == "number" and . == floor and . == 1) and',
        '(.commits | type == "array" and length == 1 and\n'
        '                (.[0] | type == "object" and\n'
        '                  (.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $head))) and',
        '(.files | type == "array" and length == 1 and',
        '(.filename | type == "string" and . == "README.md") and',
        '(.status | type == "string" and . == "modified") and',
        '(.sha | type == "string" and test("^[0-9a-f]{40}$")) and',
        '(.additions | type == "number" and . == floor and . >= 0) and',
        '(.deletions | type == "number" and . == floor and . >= 0) and',
        '(.changes | type == "number" and . == floor and . >= 0)))',
    ):
        require(
            schema_fragment in compare_schema,
            f"trusted capability admission Spotlight compare response schema changed: {schema_fragment}",
        )
    require(
        "malformed or mismatched Capability Admission Spotlight compare evidence." in text,
        "trusted capability admission Spotlight compare response schema must fail visibly",
    )

    publisher = 'gh api --method POST "repos/${TARGET_REPOSITORY}/check-runs"'
    schema_marker = "jq -e --arg name \"$CHECK_NAME\" --arg head \"$HEAD_SHA\" --arg external \"$EXTERNAL_ID\" --arg summary \"$SUMMARY\" '"
    schema_end_marker = "' <<<\"$CHECK\" >/dev/null || {"
    consume_marker = '[[ "$(jq -r .id <<<"$CHECK")" =~ ^[1-9][0-9]*$ ]]'
    require(text.count(publisher) == 1,
            "trusted capability admission exact candidate-check publisher surface changed")
    require(text.count(schema_marker) == 1 and text.count(schema_end_marker) == 1,
            "trusted capability admission check-run response schema anchor changed")
    require(text.count(consume_marker) == 1,
            "trusted capability admission check-run response scalar-consumption anchor changed")
    publisher_pos = text.index(publisher)
    schema_pos = text.index(schema_marker, publisher_pos)
    schema_end_pos = text.index(schema_end_marker, schema_pos) + len(schema_end_marker)
    consume_pos = text.index(consume_marker, publisher_pos)
    require(
        publisher_pos < schema_pos < schema_end_pos < consume_pos,
        "trusted capability admission check-run response schema must precede scalar consumption",
    )
    schema = text[schema_pos:schema_end_pos]
    for schema_fragment in (
        '(type == "object") and',
        '(.id | type == "number" and . == floor and . > 0) and',
        '(.name | type == "string" and . == $name) and',
        '(.head_sha | type == "string" and test("^[0-9a-f]{40}$") and . == $head) and',
        '(.status | type == "string" and . == "completed") and',
        '(.conclusion | type == "string" and . == "success") and',
        '(.external_id | type == "string" and length > 0 and . == $external) and',
        '(.details_url | type == "string" and test("^https://github\\\\.com/portyu9/portyu9/runs/[1-9][0-9]*$")) and',
        '(.output | type == "object" and',
        '(.title | type == "string" and . == "Trusted capability admission passed") and',
        '(.summary | type == "string" and . == $summary)) and',
        '(.app | type == "object" and',
        '(.id | type == "number" and . == floor and . == 15368) and',
        '(.slug | type == "string" and . == "github-actions"))',
    ):
        require(
            schema_fragment in schema,
            f"trusted capability admission check-run response schema changed: {schema_fragment}",
        )
    require(
        "malformed or mismatched trusted capability-admission check-run creation response." in text,
        "trusted capability admission check-run response schema must fail visibly",
    )
    for publisher_binding in (
        '-f name="$CHECK_NAME"',
        '-f head_sha="$HEAD_SHA"',
        "-f status=completed",
        "-f conclusion=success",
        '-f external_id="$EXTERNAL_ID"',
        'test "$(jq -r .name <<<"$CHECK")" = "$CHECK_NAME"',
        'CHECK_NAME="trusted-capability-admission-proof"',
        'CHECK_NAME="trusted-capability-admission"',
        'test "$(jq -r .app.id <<<"$CHECK")" = "15368"',
    ):
        require(publisher_binding in text,
                f"trusted capability admission candidate-check binding changed: {publisher_binding}")
    require(
        "if: steps.candidate.outputs.dispatch == 'true' || steps.candidate.outputs.dependabot == 'true' || steps.candidate.outputs.spotlight == 'true'"
        in text,
        "trusted capability admission check write is no longer bound to reviewed bot paths",
    )


def validate() -> None:
    require(WORKFLOW.is_file() and not WORKFLOW.is_symlink(),
            "trusted capability admission workflow is missing or aliased")
    data = WORKFLOW.read_bytes()
    observed = git_blob_sha(data)
    require(observed == EXPECTED_GIT_BLOB,
            f"trusted capability admission workflow bytes changed: expected={EXPECTED_GIT_BLOB} observed={observed}")
    validate_text(data.decode("utf-8"))


def expect_failure(text: str, old: str, new: str, expected: str, *, count: int = 1) -> None:
    require(text.count(old) == count,
            f"capability admission self-test fixture anchor count changed: expected={count} observed={text.count(old)}")
    mutated = text.replace(old, new, 1)
    try:
        validate_text(mutated)
    except ValueError as exc:
        require(expected in str(exc),
                f"trusted capability admission self-test failed for wrong reason: expected={expected!r} observed={exc}")
    else:
        raise ValueError(f"trusted capability admission contract accepted forbidden mutation: {expected}")


def expect_check_schema_failure(text: str, old: str, new: str) -> None:
    schema_marker = "jq -e --arg name \"$CHECK_NAME\" --arg head \"$HEAD_SHA\" --arg external \"$EXTERNAL_ID\" --arg summary \"$SUMMARY\" '"
    consume_marker = '[[ "$(jq -r .id <<<"$CHECK")" =~ ^[1-9][0-9]*$ ]]'
    schema_start = text.index(schema_marker)
    schema_end = text.index(consume_marker, schema_start)
    schema = text[schema_start:schema_end]
    require(schema.count(old) == 1,
            f"capability admission check-schema self-test anchor count changed: {old!r}")
    mutated_schema = schema.replace(old, new, 1)
    mutated = text[:schema_start] + mutated_schema + text[schema_end:]
    try:
        validate_text(mutated)
    except ValueError as exc:
        require("check-run response schema" in str(exc),
                f"trusted capability admission check-schema self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("trusted capability admission contract accepted malformed check-run response schema")


def expect_check_schema_reorder_failure(text: str) -> None:
    schema_marker = "jq -e --arg name \"$CHECK_NAME\" --arg head \"$HEAD_SHA\" --arg external \"$EXTERNAL_ID\" --arg summary \"$SUMMARY\" '"
    consume_marker = '[[ "$(jq -r .id <<<"$CHECK")" =~ ^[1-9][0-9]*$ ]]'
    schema_start = text.index(schema_marker)
    consume_start = text.index(consume_marker, schema_start)
    schema_block = text[schema_start:consume_start]
    without_schema = text[:schema_start] + text[consume_start:]
    relocated_consume = without_schema.index(consume_marker)
    consume_end = without_schema.index("\n", relocated_consume) + 1
    mutated = without_schema[:consume_end] + schema_block + without_schema[consume_end:]
    try:
        validate_text(mutated)
    except ValueError as exc:
        require("must precede scalar consumption" in str(exc),
                f"trusted capability admission schema-reordering self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("trusted capability admission contract accepted schema-after-consumption reordering")


def expect_spotlight_topology_schema_failure(
    text: str,
    *,
    schema_marker: str,
    consume_marker: str,
    old: str,
    new: str,
    expected: str,
) -> None:
    schema_start = text.index(schema_marker)
    schema_end = text.index(consume_marker, schema_start)
    schema = text[schema_start:schema_end]
    require(schema.count(old) == 1,
            f"Capability Admission Spotlight topology self-test anchor count changed: {old!r}")
    mutated_schema = schema.replace(old, new, 1)
    mutated = text[:schema_start] + mutated_schema + text[schema_end:]
    try:
        validate_text(mutated)
    except ValueError as exc:
        require(expected in str(exc),
                f"Capability Admission Spotlight topology self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"Capability Admission accepted malformed Spotlight topology response schema: {expected}")


def expect_spotlight_topology_schema_reorder_failure(
    text: str,
    *,
    schema_marker: str,
    consume_marker: str,
) -> None:
    schema_start = text.index(schema_marker)
    consume_start = text.index(consume_marker, schema_start)
    schema_block = text[schema_start:consume_start]
    without_schema = text[:schema_start] + text[consume_start:]
    relocated_consume = without_schema.index(consume_marker)
    consume_end = without_schema.index("\n", relocated_consume) + 1
    mutated = without_schema[:consume_end] + schema_block + without_schema[consume_end:]
    try:
        validate_text(mutated)
    except ValueError as exc:
        require("schemas must precede scalar consumption" in str(exc),
                f"Capability Admission Spotlight topology reorder self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("Capability Admission accepted Spotlight topology schema-after-consumption reordering")


def expect_scoped_schema_failure(
    text: str,
    *,
    start_marker: str,
    end_marker: str,
    old: str,
    new: str,
    expected: str,
) -> None:
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    scope = text[start:end]
    require(scope.count(old) == 1,
            f"Capability Admission scoped schema self-test anchor count changed: {old!r}")
    mutated_scope = scope.replace(old, new, 1)
    mutated = text[:start] + mutated_scope + text[end:]
    try:
        validate_text(mutated)
    except ValueError as exc:
        require(expected in str(exc),
                f"Capability Admission scoped schema self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"Capability Admission accepted malformed scoped response schema: {expected}")


def expect_runtime_schema_reorder_failure(
    text: str,
    *,
    call_marker: str,
    schema_marker: str,
    consume_marker: str,
    expected: str,
) -> None:
    call_start = text.index(call_marker)
    schema_start = text.index(schema_marker, call_start)
    consume_start = text.index(consume_marker, schema_start)
    schema_block = text[schema_start:consume_start]
    without_schema = text[:schema_start] + text[consume_start:]
    relocated_consume = without_schema.index(consume_marker, call_start)
    consume_end = without_schema.index("\n", relocated_consume) + 1
    mutated = without_schema[:consume_end] + schema_block + without_schema[consume_end:]
    try:
        validate_text(mutated)
    except ValueError as exc:
        require(expected in str(exc),
                f"Capability Admission runtime schema reorder self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("Capability Admission accepted runtime schema-after-consumption reordering")


def self_test() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    validate_text(text)
    expect_failure(text, "checks: write", "contents: write", "permission set changed", count=2)
    expect_failure(
        text,
        "python3 scripts/workflow_capability_api_collection.py pull-requests",
        "python3 scripts/broken_api_collection.py pull-requests",
        "Spotlight proof changed",
    )
    expect_failure(
        text,
        "python3 scripts/workflow_capability_api_collection.py files",
        "python3 scripts/broken_api_collection.py files",
        "delegated Dependabot proof changed",
    )
    expect_failure(
        text,
        'gh api --method POST "repos/${TARGET_REPOSITORY}/check-runs"',
        'gh api --method POST "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/merge"',
        "candidate-check publisher",
    )
    expect_scoped_schema_failure(
        text,
        start_marker="          validate_git_ref_object() {",
        end_marker="          validate_readme_contents_object() {",
        old='(.ref | type == "string" and . == $ref) and',
        new='(.ref == $ref) and',
        expected="Git-ref response schema",
    )
    expect_scoped_schema_failure(
        text,
        start_marker="          validate_git_ref_object() {",
        end_marker="          validate_readme_contents_object() {",
        old='(.type | type == "string" and . == "commit") and',
        new='(.type == "commit") and',
        expected="Git-ref response schema",
    )
    expect_scoped_schema_failure(
        text,
        start_marker="          validate_git_ref_object() {",
        end_marker="          validate_readme_contents_object() {",
        old='($sha == "" or .object.sha == $sha)',
        new='true',
        expected="Git-ref response schema",
    )
    expect_scoped_schema_failure(
        text,
        start_marker="          validate_readme_contents_object() {",
        end_marker='          case "$EVENT_NAME" in',
        old='(.path | type == "string" and . == "README.md") and',
        new='(.path == "README.md") and',
        expected="README Contents response schema",
    )
    expect_scoped_schema_failure(
        text,
        start_marker="          validate_readme_contents_object() {",
        end_marker='          case "$EVENT_NAME" in',
        old='(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $blob) and',
        new='(.sha | type == "string" and test("^[0-9a-f]{40}$")) and',
        expected="README Contents response schema",
    )
    expect_scoped_schema_failure(
        text,
        start_marker="          validate_readme_contents_object() {",
        end_marker='          case "$EVENT_NAME" in',
        old='(.encoding | type == "string" and . == "base64") and',
        new='(.encoding == "base64") and',
        expected="README Contents response schema",
    )
    expect_scoped_schema_failure(
        text,
        start_marker="          validate_readme_contents_object() {",
        end_marker='          case "$EVENT_NAME" in',
        old='(.content | type == "string" and length > 0)',
        new='(.content != null)',
        expected="README Contents response schema",
    )
    expect_runtime_schema_reorder_failure(
        text,
        call_marker='HEAD_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}")"',
        schema_marker='validate_git_ref_object "$HEAD_REF_RESPONSE" "refs/heads/${HEAD_REF}" "$HEAD_SHA" || {',
        consume_marker='test "$(jq -r .object.sha <<<"$HEAD_REF_RESPONSE")" = "$HEAD_SHA"',
        expected="Git-ref schemas must precede scalar consumption",
    )
    expect_runtime_schema_reorder_failure(
        text,
        call_marker='README_CONTENTS_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}")"',
        schema_marker='validate_readme_contents_object "$README_CONTENTS_RESPONSE" "$README_BLOB_SHA" || {',
        consume_marker='test "$(jq -r .path <<<"$README_CONTENTS_RESPONSE")" = "README.md"',
        expected="README Contents schema must precede scalar consumption",
    )
    candidate_schema_marker = 'jq -e --arg head "$HEAD_SHA" --arg base "$BASE_SHA" \\'
    candidate_consume_marker = 'test "$(jq \'.parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"'
    compare_schema_marker = 'jq -e --arg base "$BASE_SHA" --arg head "$HEAD_SHA" \''
    compare_consume_marker = 'test "$(jq -r .status <<<"$COMPARE")" = "ahead"'
    expect_spotlight_topology_schema_failure(
        text,
        schema_marker=candidate_schema_marker,
        consume_marker=candidate_consume_marker,
        old='(type == "object") and\n              (.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $head) and',
        new='(type != "null") and\n              (.sha | type == "string" and . == $head) and',
        expected="Spotlight candidate commit response schema",
    )
    expect_spotlight_topology_schema_failure(
        text,
        schema_marker=candidate_schema_marker,
        consume_marker=candidate_consume_marker,
        old='(.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $base))) and',
        new='(.sha == $base))) and',
        expected="Spotlight candidate commit response schema",
    )
    expect_spotlight_topology_schema_failure(
        text,
        schema_marker=candidate_schema_marker,
        consume_marker=candidate_consume_marker,
        old='(.author | type == "object" and\n                (.name | type == "string" and . == $name) and',
        new='(.author | type == "object" and\n                (.name == $name) and',
        expected="Spotlight candidate commit response schema",
    )
    expect_spotlight_topology_schema_failure(
        text,
        schema_marker=candidate_schema_marker,
        consume_marker=candidate_consume_marker,
        old='(.committer | type == "object" and\n                (.name | type == "string" and . == $name) and',
        new='(.committer | type == "object" and\n                (.name == $name) and',
        expected="Spotlight candidate commit response schema",
    )
    expect_spotlight_topology_schema_failure(
        text,
        schema_marker=compare_schema_marker,
        consume_marker=compare_consume_marker,
        old='(type == "object") and\n              (.status | type == "string" and . == "ahead") and',
        new='(type != "null") and\n              (.status == "ahead") and',
        expected="Spotlight compare response schema",
    )
    expect_spotlight_topology_schema_failure(
        text,
        schema_marker=compare_schema_marker,
        consume_marker=compare_consume_marker,
        old='(.ahead_by | type == "number" and . == floor and . == 1) and',
        new='(.ahead_by == 1) and',
        expected="Spotlight compare response schema",
    )
    expect_spotlight_topology_schema_failure(
        text,
        schema_marker=compare_schema_marker,
        consume_marker=compare_consume_marker,
        old='(.base_commit | type == "object" and\n                (.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $base)) and',
        new='(.base_commit | type == "object" and\n                (.sha == $base)) and',
        expected="Spotlight compare response schema",
    )
    expect_spotlight_topology_schema_failure(
        text,
        schema_marker=compare_schema_marker,
        consume_marker=compare_consume_marker,
        old='(.commits | type == "array" and length == 1 and\n                (.[0] | type == "object" and\n                  (.sha | type == "string" and test("^[0-9a-f]{40}$") and . == $head))) and',
        new='(.commits | type == "array" and length == 1 and\n                (.[0] | type == "object" and\n                  (.sha == $head))) and',
        expected="Spotlight compare response schema",
    )
    expect_spotlight_topology_schema_failure(
        text,
        schema_marker=compare_schema_marker,
        consume_marker=compare_consume_marker,
        old='(.filename | type == "string" and . == "README.md") and',
        new='(.filename == "README.md") and',
        expected="Spotlight compare response schema",
    )
    expect_spotlight_topology_schema_failure(
        text,
        schema_marker=compare_schema_marker,
        consume_marker=compare_consume_marker,
        old='(.additions | type == "number" and . == floor and . >= 0) and',
        new='(.additions >= 0) and',
        expected="Spotlight compare response schema",
    )
    expect_spotlight_topology_schema_reorder_failure(
        text,
        schema_marker=candidate_schema_marker,
        consume_marker=candidate_consume_marker,
    )
    expect_spotlight_topology_schema_reorder_failure(
        text,
        schema_marker=compare_schema_marker,
        consume_marker=compare_consume_marker,
    )
    expect_check_schema_failure(text, '(type == "object") and', '(type != "null") and')
    expect_check_schema_failure(
        text,
        '(.id | type == "number" and . == floor and . > 0) and',
        '(.id | . > 0) and',
    )
    expect_check_schema_failure(
        text,
        '(.name | type == "string" and . == $name) and',
        '(.name == $name) and',
    )
    expect_check_schema_failure(
        text,
        '(.head_sha | type == "string" and test("^[0-9a-f]{40}$") and . == $head) and',
        '(.head_sha == $head) and',
    )
    expect_check_schema_failure(
        text,
        '(.status | type == "string" and . == "completed") and',
        '(.status == "completed") and',
    )
    expect_check_schema_failure(
        text,
        '(.conclusion | type == "string" and . == "success") and',
        '(.conclusion == "success") and',
    )
    expect_check_schema_failure(
        text,
        '(.external_id | type == "string" and length > 0 and . == $external) and',
        '(.external_id == $external) and',
    )
    expect_check_schema_failure(
        text,
        '(.app | type == "object" and',
        '(.app != null and',
    )
    expect_check_schema_failure(
        text,
        '(.id | type == "number" and . == floor and . == 15368) and',
        '(.id == 15368) and',
    )
    expect_check_schema_reorder_failure(text)
    expect_failure(
        text,
        "ref: main",
        "ref: ${{ steps.candidate.outputs.head_sha }}",
        "static trusted main",
    )
    expect_failure(
        text,
        'run: test "$(git rev-parse HEAD)" = "$BASE_SHA"',
        'run: test -n "$BASE_SHA"',
        "exact checked-out base SHA",
    )
    ordinary_bad = ORDINARY_EVALUATOR.replace('--candidate-tree-sha "$TREE_SHA"', '--candidate-tree-sha "$HEAD_SHA"')
    expect_failure(text, ORDINARY_EVALUATOR, ordinary_bad, "ordinary evaluator lost exact candidate tree binding")
    delegated_bad = DEPENDABOT_EVALUATOR.replace('--candidate-tree-sha "$TREE_SHA"', '--candidate-tree-sha "$HEAD_SHA"')
    expect_failure(text, DEPENDABOT_EVALUATOR, delegated_bad, "delegated evaluator lost exact candidate tree binding")
    expect_failure(
        text,
        'EXTERNAL_ID="codeql-autofix-admission:${ORIGIN_RUN_ID}:${PR_NUMBER}:${HEAD_SHA}"',
        'EXTERNAL_ID="codeql-autofix-unbound:${PR_NUMBER}"',
        "Autofix proof",
    )
    expect_failure(
        text,
        '    - cron: "*/5 * * * *"',
        '    - cron: "17 * * * *"',
        "scheduled Spotlight recovery trigger changed",
    )
    expect_failure(
        text,
        'test "$(jq -r \'.sender.login // ""\' "$GITHUB_EVENT_PATH")" = "github-actions[bot]"',
        'test "$(jq -r \'.sender.login // ""\' "$GITHUB_EVENT_PATH")" = "dependabot[bot]"',
        "delegated Dependabot proof",
    )
    expect_failure(text, 'test "$DEPENDENCY_REPOSITORY" = "github/codeql-action"',
                   'test -n "$DEPENDENCY_REPOSITORY"', "delegated Dependabot proof")
    expect_failure(
        text,
        'test "$(jq -r .decision.authorizationId capability-admission.json)" = "delegated-dependabot-codeql-v1"',
        'test "$(jq -r .decision.allowed capability-admission.json)" = "true"',
        "delegated Dependabot proof",
    )
    expect_failure(
        text,
        'EXTERNAL_ID="dependabot-delegated-admission:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}:${SUMMARY_SHA256}:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
        'EXTERNAL_ID="dependabot-unbound:${PR_NUMBER}"',
        "delegated Dependabot proof",
    )


if __name__ == "__main__":
    self_test()
    validate()
    print(
        "Trusted capability admission workflow contract passed: exact bytes; base-only execution; distinct exact ordinary and "
        "delegated evaluator tree bindings; immutable Autofix provenance; deterministic Spotlight recovery with typed pre-consumption candidate topology evidence; exact native "
        "Dependabot release/delegation reproof; data-only candidate TCB evaluation; and one bounded exact-head check publisher with a typed pre-consumption creation-response boundary."
    )
