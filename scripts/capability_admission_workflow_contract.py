#!/usr/bin/env python3
"""Exact byte and trust-boundary contract for trusted capability admission."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/capability-admission.yml"
EXPECTED_GIT_BLOB = "7f5af3620794863064708cccaf550c4d8c9281cf"
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
              --pr dependabot-pr.json \\
              --expected-head-sha "$HEAD_SHA" \\
              --resolved-release-sha "$RESOLVED_RELEASE_SHA" \\
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
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main" --jq .object.sha',
        'gh api "repos/${TARGET_REPOSITORY}/git/commits/${HEAD_SHA}"',
        'gh api "repos/${HEAD_REPOSITORY}/git/trees/${TREE_SHA}?recursive=1"',
        'python3 scripts/workflow_capability_tcb.py select',
        'TREE_SHA="$(cat candidate-capability-source/.candidate-tree-sha)"',
    ):
        require(binding in text, f"trusted capability admission identity binding changed: {binding}")

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
        'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > dependabot-pr.json',
        'test "$(jq -r .maintainer_can_modify <<<"$PR")" = "false"',
        '[[ "$HEAD_REF" =~ ^dependabot/github_actions/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]]',
        'gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100" > dependabot-file-pages.json',
        'for PATH_VALUE in .github/action-lock.json .github/workflow-capability-bom-v1.json scripts/validate-codeql-contract.py; do',
        "python3 scripts/dependabot_controller.py probe",
        'test "$DEPENDENCY_REPOSITORY" = "github/codeql-action"',
        'git ls-remote --tags "https://github.com/${DEPENDENCY_REPOSITORY}.git"',
        "python3 scripts/dependabot_release.py",
        'test "$(cat dependabot-resolved-release-sha.txt)" = "$CANDIDATE_SHA"',
        'test "$(jq -r .decision.authorizationId capability-admission.json)" = "delegated-dependabot-codeql-v1"',
        'EXTERNAL_ID="dependabot-delegated-admission:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
    ):
        require(dependabot_binding in text,
                f"trusted capability admission delegated Dependabot proof changed: {dependabot_binding}")

    for spotlight_binding in (
        '    - cron: "*/5 * * * *"',
        '.user.login == "github-actions[bot]"',
        'test("^automation/spotlight-links/[0-9a-f]{64}$")',
        'test "$MATCH_COUNT" -le 1',
        'test "$(jq -r .message <<<"$CANDIDATE_COMMIT")" = "chore: sync rotating Spotlight links"',
        'test "$(jq -r .total_commits <<<"$COMPARE")" = "1"',
        'test "$(jq -r \'.files[0].filename\' <<<"$COMPARE")" = "README.md"',
        'test "$HEAD_REF" = "automation/spotlight-links/${CANDIDATE_ID}"',
        'EXTERNAL_ID="spotlight-scheduled-admission:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
    ):
        require(spotlight_binding in text,
                f"trusted capability admission scheduled Spotlight proof changed: {spotlight_binding}")

    publisher = 'gh api --method POST "repos/${TARGET_REPOSITORY}/check-runs"'
    require(text.count(publisher) == 1,
            "trusted capability admission exact candidate-check publisher surface changed")
    for publisher_binding in (
        "-f name=trusted-capability-admission",
        '-f head_sha="$HEAD_SHA"',
        "-f status=completed",
        "-f conclusion=success",
        '-f external_id="$EXTERNAL_ID"',
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


def self_test() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    validate_text(text)
    expect_failure(text, "checks: write", "contents: write", "permission set changed", count=2)
    expect_failure(
        text,
        'gh api --method POST "repos/${TARGET_REPOSITORY}/check-runs"',
        'gh api --method POST "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/merge"',
        "candidate-check publisher",
    )
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
        'EXTERNAL_ID="dependabot-delegated-admission:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
        'EXTERNAL_ID="dependabot-unbound:${PR_NUMBER}"',
        "delegated Dependabot proof",
    )


if __name__ == "__main__":
    self_test()
    validate()
    print(
        "Trusted capability admission workflow contract passed: exact bytes; base-only execution; distinct exact ordinary and "
        "delegated evaluator tree bindings; immutable Autofix provenance; deterministic Spotlight recovery; exact native "
        "Dependabot release/delegation reproof; data-only candidate TCB evaluation; and one bounded exact-head check publisher."
    )
