#!/usr/bin/env python3
"""Validate Dependabot policy and immutable external-action references.

The repository intentionally keeps this validator dependency-free. The Dependabot
configuration is small enough to lock canonically, while workflow action references
are discovered across every current/future workflow and must use immutable Git SHAs.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

from dependabot_admission import self_test as admission_self_test
from dependabot_capability_admission import self_test as capability_admission_self_test
from dependabot_controller import self_test as controller_self_test
from dependabot_admission_proof import self_test as admission_proof_self_test
from dependabot_pin_diff import self_test as pin_diff_self_test
from dependabot_pr_identity import self_test as pr_identity_self_test
from dependabot_reconciliation import self_test as reconciliation_self_test
from dependabot_release import self_test as release_self_test
from automation_approval_comment import self_test as approval_comment_self_test
from workflow_capability_api_collection import self_test as api_collection_self_test

ROOT = Path(__file__).resolve().parents[1]
DEPENDABOT = ROOT / ".github/dependabot.yml"
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"
CONTROLLER = WORKFLOWS / "dependabot-controller.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"
APPROVAL_COMMENT_HELPER = ROOT / "scripts/automation_approval_comment.py"

EXPECTED_DEPENDABOT = """version: 2

updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "daily"
      time: "09:00"
      timezone: "America/New_York"
    cooldown:
      default-days: 7
    groups:
      codeql-action-release:
        applies-to: version-updates
        patterns:
          - "github/codeql-action/*"
    open-pull-requests-limit: 10
    commit-message:
      prefix: "chore(deps)"
"""

REQUIRED_EXTERNAL_ACTIONS = {
    "actions/checkout",
    "actions/setup-python",
    "actions/upload-artifact",
    "actions/download-artifact",
    "actions/attest",
    "actions/dependency-review-action",
    "shinpr/github-profile-stats",
}
ACTION_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.\-/]+)?")
SHA40 = re.compile(r"[0-9a-fA-F]{40}")
USES_LINE = re.compile(r"^\s*(?:-\s*)?(?:['\"]?uses['\"]?)\s*:\s*(.+?)\s*$")


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def validate_dependabot(text: str) -> None:
    require(
        text == EXPECTED_DEPENDABOT,
        "Dependabot configuration drifted from the reviewed canonical GitHub-Actions-only policy",
    )


def validate_uses_text(text: str, label: str) -> set[str]:
    """Return external action names after rejecting mutable/unsupported references."""
    external: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = USES_LINE.match(line)
        if not match:
            continue
        value = match.group(1).split("#", 1)[0].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1].strip()

        if value.startswith("./"):
            continue

        require(
            not value.startswith("docker://"),
            f"{label}:{line_number} uses an external Docker action that Dependabot cannot govern: {value}",
        )
        require(
            "@" in value,
            f"{label}:{line_number} external action must use repository@commit syntax: {value}",
        )
        action, ref = value.rsplit("@", 1)
        require(
            ACTION_NAME.fullmatch(action) is not None,
            f"{label}:{line_number} external action reference is not GitHub repository syntax: {value}",
        )
        require(
            SHA40.fullmatch(ref) is not None,
            f"{label}:{line_number} external action must be pinned to an exact 40-character commit SHA: {value}",
        )
        external.add(action)
    return external


def validate_all_workflow_pins() -> None:
    require(WORKFLOWS.is_dir(), ".github/workflows is missing")
    workflow_files = sorted({*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")})
    require(workflow_files, "No GitHub Actions workflows found")

    observed: set[str] = set()
    for path in workflow_files:
        observed |= validate_uses_text(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT)))

    missing = sorted(REQUIRED_EXTERNAL_ACTIONS - observed)
    require(
        not missing,
        "Reviewed trust-boundary action dependency disappeared without governance review: " + ", ".join(missing),
    )


def validate_controller_wake_contract(text: str) -> None:
    required = """  workflow_run:
    workflows:
      - Profile quality
      - CodeQL
    types:
      - completed
    branches:
      - main
      - "dependabot/github_actions/**"
"""
    require(
        required in text,
        "Dependabot controller workflow_run wake branches must be exactly main plus native GitHub-Actions Dependabot branches",
    )
    require(
        text.count('dependabot/github_actions/**') == 1,
        "Dependabot controller native branch trigger grammar changed",
    )
    require(
        "branches-ignore:" not in text,
        "Dependabot controller must use an explicit allowlist rather than branch exclusions",
    )
    require(
        "if: github.event_name == 'schedule' || (github.event_name == 'workflow_run' && (github.event.workflow_run.head_branch != 'main' || github.event.workflow_run.event != 'pull_request')) || (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main')" in text,
        "Dependabot controller must skip main-headed pull_request workflow_run ancestry-sync wakes before privileged job execution",
    )
    reverse_sync_noop = """              if [ "$WAKE_HEAD_BRANCH" = "main" ]; then
                if [ "$WAKE_EVENT" = "pull_request" ]; then
                  printf 'has_target=false\\n' >> "$GITHUB_OUTPUT"
                  echo "Ignoring main-headed pull_request workflow_run wake; reverse ancestry-sync PRs are not Dependabot candidates."
                  exit 0
                fi
                test "$WAKE_EVENT" = "push" || test "$WAKE_EVENT" = "workflow_dispatch"
              else
"""
    require(
        reverse_sync_noop in text,
        "Dependabot controller runtime must reduce main-headed pull_request wakes to an explicit no-op",
    )
    require(
        text.count("Ignoring main-headed pull_request workflow_run wake; reverse ancestry-sync PRs are not Dependabot candidates.") == 1,
        "Dependabot controller reverse-sync wake no-op must remain singular and explicit",
    )
    require(
        text.count("python3 scripts/dependabot_controller.py wake-run-response") == 1,
        "Dependabot controller must validate exactly one workflow_run wake singleton response",
    )
    wake_fetch = 'gh api "repos/${TARGET_REPOSITORY}/actions/runs/${WAKE_RUN_ID}" > "$RUNNER_TEMP/dependabot-wake-run.json"'
    wake_schema = "python3 scripts/dependabot_controller.py wake-run-response"
    wake_consume = 'test "$(jq -r .id <<<"$WAKE")" = "$WAKE_RUN_ID"'
    for fragment in (
        wake_fetch,
        wake_schema,
        '--expected-run-id "$WAKE_RUN_ID"',
        '--expected-repository "$TARGET_REPOSITORY"',
        '--out "$RUNNER_TEMP/dependabot-wake-run-normalized.json"',
        'WAKE="$(cat "$RUNNER_TEMP/dependabot-wake-run.json")"',
    ):
        require(fragment in text, f"Dependabot wake singleton response contract is missing: {fragment}")
    require(
        text.index(wake_fetch) < text.index(wake_schema) < text.index(wake_consume),
        "Dependabot controller must validate the wake singleton before any wake field consumption",
    )
    require(
        'WAKE="$(gh api "repos/${TARGET_REPOSITORY}/actions/runs/${WAKE_RUN_ID}")"' not in text,
        "Dependabot controller regressed to direct wake singleton consumption",
    )


def validate_controller_read_ref_response_contract(text: str) -> None:
    require(
        text.count("python3 scripts/dependabot_controller.py git-ref-read-response") == 13,
        "Dependabot controller read-ref schema boundary count changed",
    )
    require(
        text.count("assert_main_sha() {") == 5
        and text.count("assert_head_sha() {") == 5,
        "Dependabot controller must retain five reviewed static main/head ref assertion pairs",
    )
    require(
        text.count('assert_main_sha "$BASE_SHA"') == 6
        and text.count('assert_head_sha "$HEAD_SHA"') == 5
        and text.count('assert_main_sha "$MERGE_SHA"') == 1,
        "Dependabot controller exact expected-SHA read-ref proof topology changed",
    )
    for forbidden in (
        'git/ref/heads/main" --jq .object.sha',
        'git/ref/heads/${HEAD_REF}" --jq .object.sha',
    ):
        require(
            forbidden not in text,
            f"Dependabot controller regressed to direct Git-ref scalar consumption: {forbidden}",
        )

    required = (
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main" > "$RUNNER_TEMP/dependabot-initial-main-ref.json"',
        '--response "$RUNNER_TEMP/dependabot-initial-main-ref.json"',
        '--expected-ref "refs/heads/main"',
        '--out "$RUNNER_TEMP/dependabot-initial-main-ref-normalized.json"',
        'MAIN_SHA="$(jq -r .sha "$RUNNER_TEMP/dependabot-initial-main-ref-normalized.json")"',
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main" > "$RUNNER_TEMP/dependabot-validation-main-ref.json"',
        '--response "$RUNNER_TEMP/dependabot-validation-main-ref.json"',
        '--out "$RUNNER_TEMP/dependabot-validation-main-ref-normalized.json"',
        'BASE_SHA="$(jq -r .sha "$RUNNER_TEMP/dependabot-validation-main-ref-normalized.json")"',
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}" > "$RUNNER_TEMP/dependabot-validation-head-ref.json"',
        '--response "$RUNNER_TEMP/dependabot-validation-head-ref.json"',
        '--expected-ref "refs/heads/${HEAD_REF}"',
        '--expected-sha "$HEAD_SHA"',
        '--out "$RUNNER_TEMP/dependabot-validation-head-ref-normalized.json"',
        'test "$(jq -r .sha "$RUNNER_TEMP/dependabot-validation-head-ref-normalized.json")" = "$HEAD_SHA"',
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main" > "$RUNNER_TEMP/dependabot-main-ref.json"',
        '--response "$RUNNER_TEMP/dependabot-main-ref.json"',
        '--out "$RUNNER_TEMP/dependabot-main-ref-normalized.json"',
        'test "$(jq -r .sha "$RUNNER_TEMP/dependabot-main-ref-normalized.json")" = "$expected_sha"',
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}" > "$RUNNER_TEMP/dependabot-head-ref.json"',
        '--response "$RUNNER_TEMP/dependabot-head-ref.json"',
        '--out "$RUNNER_TEMP/dependabot-head-ref-normalized.json"',
        'test "$(jq -r .sha "$RUNNER_TEMP/dependabot-head-ref-normalized.json")" = "$expected_sha"',
    )
    for fragment in required:
        require(fragment in text, f"Dependabot read-ref response contract is missing: {fragment}")

    initial_fetch = required[0]
    initial_schema = 'python3 scripts/dependabot_controller.py git-ref-read-response'
    initial_consume = 'MAIN_SHA="$(jq -r .sha "$RUNNER_TEMP/dependabot-initial-main-ref-normalized.json")"'
    require(
        text.index(initial_fetch)
        < text.index(initial_schema, text.index(initial_fetch))
        < text.index(initial_consume),
        "Dependabot initial main ref must be typed before SHA discovery",
    )

    validation_fetch = required[5]
    validation_consume = 'BASE_SHA="$(jq -r .sha "$RUNNER_TEMP/dependabot-validation-main-ref-normalized.json")"'
    validation_schema = text.index(
        "python3 scripts/dependabot_controller.py git-ref-read-response",
        text.index(validation_fetch),
    )
    require(
        text.index(validation_fetch) < validation_schema < text.index(validation_consume),
        "Dependabot validation main ref must be typed before SHA discovery",
    )


def validate_controller_pr_response_contract(text: str) -> None:
    list_validator = "python3 scripts/dependabot_controller.py pull-request-list-response"
    require(
        text.count(list_validator) == 1,
        "Dependabot validation pull-list response boundary count changed",
    )
    validator = "python3 scripts/dependabot_controller.py pull-request-response"
    require(
        text.count(validator) == 6,
        "Dependabot controller pull-request response boundary count changed",
    )
    require(
        text.count("python3 scripts/dependabot_controller.py update-branch-response") == 1,
        "Dependabot controller update-branch response boundary count changed",
    )
    for forbidden in (
        'HEAD_SHA="$(jq -r .head.sha dependabot-pr.json)"',
        'HEAD_REF="$(jq -r .head.ref dependabot-pr.json)"',
        'BASE_SHA="$(jq -r .base.sha dependabot-pr.json)"',
        'test "$(jq -r .message update-branch.json)" = "Updating pull request branch."',
        'PR="$(gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}")"',
        'PRS="$(gh api "repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&head=portyu9:${HEAD_REF}&per_page=10")"',
        "PR_NUMBER=\"$(jq -r '.[0].number' <<<\"$PRS\")\"",
    ):
        require(
            forbidden not in text,
            f"Dependabot controller regained raw singleton PR/update response consumption: {forbidden}",
        )

    initial_fetch = 'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > dependabot-pr.json'
    initial_schema = validator
    initial_consume = 'HEAD_SHA="$(jq -r .headSha dependabot-pr-normalized.json)"'
    require(
        text.index(initial_fetch)
        < text.index(initial_schema, text.index(initial_fetch))
        < text.index(initial_consume),
        "Dependabot initial selected PR must be typed before identity consumption",
    )

    reviewer_fetch = (
        'gh api --method POST "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers"'
    )
    reviewer_schema = text.index(validator, text.index(reviewer_fetch))
    reviewer_consume = text.index(
        'test "$(jq -r .portyu9Requested requested-reviewer-normalized.json)" = "true"',
        reviewer_schema,
    )
    require(
        text.index(reviewer_fetch) < reviewer_schema < reviewer_consume,
        "Dependabot reviewer mutation response must be typed before reviewer-state consumption",
    )

    update_fetch = 'gh api --method PUT "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/update-branch"'
    update_schema = text.index(
        "python3 scripts/dependabot_controller.py update-branch-response",
        text.index(update_fetch),
    )
    update_consume = text.index(
        'test "$(jq -r .message update-branch-normalized.json)" = "Updating pull request branch."',
        update_schema,
    )
    require(
        text.index(update_fetch) < update_schema < update_consume,
        "Dependabot update-branch response must be typed before acknowledgement consumption",
    )

    require(
        "Requested exact-head Dependabot branch update; next scheduled pass will re-prove the new head." not in text,
        "Dependabot stale-base recovery regressed to schedule-dependent forward progress",
    )
    update_rebind_fragments = (
        'PRE_UPDATE_HEAD_SHA="$HEAD_SHA"',
        'for UPDATE_ATTEMPT in $(seq 1 24); do',
        'sleep 5',
        '> "$RUNNER_TEMP/dependabot-post-update-pr.json"',
        '--response "$RUNNER_TEMP/dependabot-post-update-pr.json"',
        '--expected-number "$PR_NUMBER"',
        '--expected-repository "$TARGET_REPOSITORY"',
        '--out "$RUNNER_TEMP/dependabot-post-update-pr-normalized.json"',
        'UPDATED_HEAD_SHA="$(jq -r .headSha "$RUNNER_TEMP/dependabot-post-update-pr-normalized.json")"',
        'UPDATED_HEAD_REF="$(jq -r .headRef "$RUNNER_TEMP/dependabot-post-update-pr-normalized.json")"',
        'UPDATED_BASE_SHA="$(jq -r .baseSha "$RUNNER_TEMP/dependabot-post-update-pr-normalized.json")"',
        'test "$UPDATED_HEAD_REF" = "$HEAD_REF"',
        'if [ "$UPDATED_BASE_SHA" = "$MAIN_SHA" ]; then',
        'if [ "$UPDATED_HEAD_SHA" = "$PRE_UPDATE_HEAD_SHA" ]; then',
        'HEAD_SHA="$UPDATED_HEAD_SHA"',
        'BASE_SHA="$UPDATED_BASE_SHA"',
        'UPDATE_CONVERGED=true',
        'Dependabot exact-head update converged to current main on bounded attempt',
        'exact-head Dependabot branch update did not converge to the trusted current main inside the bounded window.',
    )
    for fragment in update_rebind_fragments:
        require(
            fragment in text,
            f"Dependabot same-transaction update convergence contract is missing: {fragment}",
        )
    post_update_fetch = text.index(
        '> "$RUNNER_TEMP/dependabot-post-update-pr.json"',
        update_consume,
    )
    post_update_schema = text.index(validator, post_update_fetch)
    post_update_consume = text.index(
        'UPDATED_HEAD_SHA="$(jq -r .headSha "$RUNNER_TEMP/dependabot-post-update-pr-normalized.json")"',
        post_update_schema,
    )
    rebound_head = text.index('HEAD_SHA="$UPDATED_HEAD_SHA"', post_update_consume)
    output_target = text.index("printf 'has_target=true\\n' >> \"$GITHUB_OUTPUT\"", rebound_head)
    require(
        update_consume < post_update_fetch < post_update_schema < post_update_consume < rebound_head < output_target,
        "Dependabot branch-update convergence must type the refreshed PR before exact-head rebinding and target publication",
    )

    require(
        text.count('> "$RUNNER_TEMP/dependabot-pr-snapshot.json"') == 2
        and text.count('PR="$(cat "$RUNNER_TEMP/dependabot-pr-snapshot-normalized.json")"') == 2,
        "Dependabot protected merge/dispatch PR snapshot topology changed",
    )

    validation_step_start = '      - name: Bind exact controller-issued validation target\n'
    validation_step_end = '      - name: Reconstruct exact reconciled candidate as data\n'
    require(
        text.count(validation_step_start) == 1 and text.count(validation_step_end) == 1,
        "Dependabot validation-bind step anchors changed",
    )
    validation_block = text[
        text.index(validation_step_start):text.index(validation_step_end)
    ]
    list_fetch = (
        'gh api "repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&head=portyu9:'
        '${HEAD_REF}&per_page=10"'
    )
    list_output = '> "$RUNNER_TEMP/dependabot-validation-pr-list.json"'
    list_consume = (
        'PR_NUMBER="$(jq -r .number "$RUNNER_TEMP/dependabot-validation-pr-list-normalized.json")"'
    )
    validation_fetch = validation_block.rindex(initial_fetch)
    validation_schema = validation_block.index(validator, validation_fetch)
    validation_consume = validation_block.index(
        'test "$(jq -r .number dependabot-pr-normalized.json)" = "$PR_NUMBER"',
        validation_schema,
    )
    list_block = validation_block[
        validation_block.index(list_fetch):validation_fetch
    ]
    for fragment in (
        list_fetch,
        list_output,
        list_validator,
        '--response "$RUNNER_TEMP/dependabot-validation-pr-list.json"',
        '--expected-repository "$TARGET_REPOSITORY"',
        '--expected-base-sha "$BASE_SHA"',
        '--expected-head-ref "$HEAD_REF"',
        '--expected-head-sha "$HEAD_SHA"',
        '--out "$RUNNER_TEMP/dependabot-validation-pr-list-normalized.json"',
        list_consume,
    ):
        require(
            list_block.count(fragment) == 1,
            f"Dependabot validation pull-list boundary anchor changed: {fragment}",
        )
    require(
        validation_block.index(list_fetch)
        < validation_block.index(list_output, validation_block.index(list_fetch))
        < validation_block.index(list_validator, validation_block.index(list_fetch))
        < validation_block.index(list_consume)
        < validation_fetch
        < validation_schema
        < validation_consume,
        "Dependabot validation pull-list must be typed before PR-number selection and full hydration",
    )


def validate_controller_collection_contract(text: str) -> None:
    require(
        text.count('python3 scripts/workflow_capability_api_collection.py pull-requests') == 1,
        "Dependabot controller must validate its paginated open-PR collection exactly once",
    )
    require(
        text.count('python3 scripts/workflow_capability_api_collection.py files') == 2,
        "Dependabot controller must validate both paginated changed-file collections",
    )
    require(
        text.count('repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&per_page=100') == 1,
        "Dependabot controller open-PR discovery endpoint count changed",
    )
    require(
        text.count('repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100') == 2,
        "Dependabot controller changed-file endpoint count changed",
    )
    require(
        "jq -r '.[][] | .filename' pr-file-pages.json" not in text,
        "Dependabot controller must not flatten changed-file pages before schema validation",
    )
    require(
        'MATCHES="$(jq -c \'[.[] | select(' in text,
        "Dependabot controller must select candidates only from the validated flat PR collection",
    )


def validate_controller_protected_workflow_evidence_contract(text: str) -> None:
    start_marker = "          approve_exact_pr_workflows() {\n"
    end_marker = "\n\n          assert_transaction\n          approve_exact_pr_workflows\n"
    require(
        text.count(start_marker) == 1 and text.count(end_marker) == 1,
        "Dependabot protected workflow approval block anchors changed",
    )
    block = text[text.index(start_marker):text.index(end_marker, text.index(start_marker))]

    workflow_validator = "python3 scripts/dependabot_controller.py workflow-definition-response"
    run_validator = "python3 scripts/dependabot_controller.py protected-workflow-runs-response"
    require(
        block.count(workflow_validator) == 3,
        "Dependabot must type exactly three protected workflow-definition responses",
    )
    require(
        block.count(run_validator) == 1,
        "Dependabot must type exactly one protected pull-request workflow-run collection",
    )
    for forbidden in (
        'actions/workflows/codeql.yml" --jq .id',
        'actions/workflows/dependency-review.yml" --jq .id',
        'actions/workflows/profile-quality.yml" --jq .id',
        'runs="$(gh api "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100")"',
        "'.total_count // empty' <<<\"$runs\"",
        'jq -r .head_sha <<<"$run"',
        'jq -r .head_branch <<<"$run"',
        'jq -r .event <<<"$run"',
        'jq -r .repository.full_name <<<"$run"',
        'jq -r .head_repository.full_name <<<"$run"',
    ):
        require(
            forbidden not in block,
            f"Dependabot protected workflow approval regained raw evidence consumption: {forbidden}",
        )

    workflow_contracts = (
        (
            'gh api "repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml"',
            '--response "$RUNNER_TEMP/dependabot-codeql-workflow-definition.json"',
            '--expected-path ".github/workflows/codeql.yml"',
            'codeql_workflow_id="$(jq -r .id "$RUNNER_TEMP/dependabot-codeql-workflow-definition-normalized.json")"',
        ),
        (
            'gh api "repos/${TARGET_REPOSITORY}/actions/workflows/dependency-review.yml"',
            '--response "$RUNNER_TEMP/dependabot-dependency-workflow-definition.json"',
            '--expected-path ".github/workflows/dependency-review.yml"',
            'dependency_workflow_id="$(jq -r .id "$RUNNER_TEMP/dependabot-dependency-workflow-definition-normalized.json")"',
        ),
        (
            'gh api "repos/${TARGET_REPOSITORY}/actions/workflows/profile-quality.yml"',
            '--response "$RUNNER_TEMP/dependabot-profile-workflow-definition.json"',
            '--expected-path ".github/workflows/profile-quality.yml"',
            'profile_workflow_id="$(jq -r .id "$RUNNER_TEMP/dependabot-profile-workflow-definition-normalized.json")"',
        ),
    )
    cursor = -1
    for fetch, response, expected_path, consume in workflow_contracts:
        fetch_pos = block.index(fetch, cursor + 1)
        validate_pos = block.index(workflow_validator, fetch_pos)
        consume_pos = block.index(consume, validate_pos)
        validator_block = block[validate_pos:consume_pos]
        for fragment in (response, expected_path):
            require(
                fragment in validator_block,
                f"Dependabot workflow-definition contract is missing: {fragment}",
            )
        require(
            fetch_pos < validate_pos < consume_pos,
            "Dependabot workflow-definition evidence must be typed before ID consumption",
        )
        cursor = consume_pos

    run_fetch = (
        'gh api "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}'
        '&event=pull_request&per_page=100"'
    )
    run_consume = (
        'total="$(jq -r .totalCount "$RUNNER_TEMP/dependabot-protected-workflow-runs-normalized.json")"'
    )
    for fragment in (
        '> "$RUNNER_TEMP/dependabot-protected-workflow-runs.json"',
        '--response "$RUNNER_TEMP/dependabot-protected-workflow-runs.json"',
        '--head-sha "$HEAD_SHA"',
        '--branch "$HEAD_REF"',
        '--codeql-workflow-id "$codeql_workflow_id"',
        '--dependency-workflow-id "$dependency_workflow_id"',
        '--profile-workflow-id "$profile_workflow_id"',
        '--out "$RUNNER_TEMP/dependabot-protected-workflow-runs-normalized.json"',
        run_consume,
        'runs="$(jq -c .runs "$RUNNER_TEMP/dependabot-protected-workflow-runs-normalized.json")"',
        '.workflowId == $workflow_id',
        '.checkSuiteId',
        '.runAttempt',
    ):
        require(
            fragment in block,
            f"Dependabot protected workflow-run contract is missing: {fragment}",
        )
    fetch_pos = block.index(run_fetch)
    validate_pos = block.index(run_validator, fetch_pos)
    consume_pos = block.index(run_consume, validate_pos)
    require(
        fetch_pos < validate_pos < consume_pos,
        "Dependabot protected workflow-run collection must be typed before scalar consumption",
    )
    require(
        "for attempt in $(seq 1 12); do" in block
        and 'gh api --method POST "repos/${TARGET_REPOSITORY}/actions/runs/${run_id}/approve"' in block,
        "Dependabot protected workflow approval retry/mutation authority changed",
    )


def validate_controller_git_read_response_contract(text: str) -> None:
    validators = {
        "git-commit-read-response": 2,
        "git-tree-read-response": 2,
        "git-blob-read-response": 2,
    }
    for command, expected_count in validators.items():
        require(
            text.count(f"python3 scripts/dependabot_controller.py {command}") == expected_count,
            f"Dependabot controller must validate {command} exactly {expected_count} time(s)",
        )

    for forbidden in (
        'COMMIT="$(gh api "repos/${TARGET_REPOSITORY}/git/commits/${HEAD_SHA}")"',
        'TREE="$(gh api "repos/${TARGET_REPOSITORY}/git/trees/${TREE_SHA}?recursive=1")"',
        'BLOB="$(gh api "repos/${TARGET_REPOSITORY}/git/blobs/${BLOB_SHA}")"',
    ):
        require(
            forbidden not in text,
            f"Dependabot controller regained raw candidate Git read consumption: {forbidden}",
        )

    blocks = (
        (
            '      - name: Assemble exact candidate tree as data\n',
            '      - name: Prove bot identity, atomic pin closure, and public release provenance\n',
            "controller candidate assembly",
        ),
        (
            '      - name: Reconstruct exact reconciled candidate as data\n',
            '      - name: Independently re-prove deterministic reconciliation\n',
            "validation candidate reconstruction",
        ),
    )
    for start_marker, end_marker, label in blocks:
        require(
            text.count(start_marker) == 1 and text.count(end_marker) == 1,
            f"Dependabot {label} step anchors changed",
        )
        start = text.index(start_marker)
        end = text.index(end_marker, start)
        block = text[start:end]
        required = (
            'gh api "repos/${TARGET_REPOSITORY}/git/commits/${HEAD_SHA}"',
            '> "$RUNNER_TEMP/dependabot-candidate-commit-read.json"',
            'python3 scripts/dependabot_controller.py git-commit-read-response',
            '--response "$RUNNER_TEMP/dependabot-candidate-commit-read.json"',
            '--expected-sha "$HEAD_SHA"',
            '--out "$RUNNER_TEMP/dependabot-candidate-commit-read-normalized.json"',
            'COMMIT="$(cat "$RUNNER_TEMP/dependabot-candidate-commit-read-normalized.json")"',
            'TREE_SHA="$(jq -r .tree.sha <<<"$COMMIT")"',
            'gh api "repos/${TARGET_REPOSITORY}/git/trees/${TREE_SHA}?recursive=1"',
            '> "$RUNNER_TEMP/dependabot-candidate-tree-read.json"',
            'python3 scripts/dependabot_controller.py git-tree-read-response',
            '--response "$RUNNER_TEMP/dependabot-candidate-tree-read.json"',
            '--expected-sha "$TREE_SHA"',
            '--out "$RUNNER_TEMP/dependabot-candidate-tree-read-normalized.json"',
            'TREE="$(cat "$RUNNER_TEMP/dependabot-candidate-tree-read-normalized.json")"',
            'ENTRY="$(jq -c --arg path "$PATH_VALUE"',
            'gh api "repos/${TARGET_REPOSITORY}/git/blobs/${BLOB_SHA}"',
            '> "$RUNNER_TEMP/dependabot-candidate-blob-read.json"',
            'python3 scripts/dependabot_controller.py git-blob-read-response',
            '--response "$RUNNER_TEMP/dependabot-candidate-blob-read.json"',
            '--expected-sha "$BLOB_SHA"',
            '--out "$RUNNER_TEMP/dependabot-candidate-blob-read-normalized.json"',
            'BLOB="$(cat "$RUNNER_TEMP/dependabot-candidate-blob-read-normalized.json")"',
            'jq -r .content <<<"$BLOB" | base64 --decode',
        )
        for fragment in required:
            require(
                block.count(fragment) == 1,
                f"Dependabot {label} Git read boundary anchor changed: {fragment}",
            )
        ordered = (
            required[0],
            required[1],
            required[2],
            required[6],
            required[7],
            required[8],
            required[9],
            required[10],
            required[14],
            required[15],
            required[16],
            required[17],
            required[18],
            required[22],
            required[23],
        )
        cursor = -1
        for fragment in ordered:
            position = block.find(fragment, cursor + 1)
            require(
                position > cursor,
                f"Dependabot {label} Git read response validation moved out of reviewed order: {fragment}",
            )
            cursor = position


def validate_controller_git_mutation_response_contract(text: str) -> None:
    commands = {
        "git-blob-response": 1,
        "git-tree-response": 1,
        "git-commit-response": 1,
        "git-ref-response": 1,
    }
    for command, expected_count in commands.items():
        require(
            text.count(f"python3 scripts/dependabot_controller.py {command}") == expected_count,
            f"Dependabot controller must validate {command} exactly {expected_count} time(s)",
        )

    required_fragments = (
        '> git-blob-response.json',
        '--response git-blob-response.json',
        '--out git-blob-response-normalized.json',
        'BLOB_SHA="$(jq -r .sha git-blob-response-normalized.json)"',
        '> git-tree-response.json',
        '--response git-tree-response.json',
        '--out git-tree-response-normalized.json',
        'NEW_TREE_SHA="$(jq -r .sha git-tree-response-normalized.json)"',
        '> git-commit-response.json',
        '--response git-commit-response.json',
        '--expected-tree "$NEW_TREE_SHA"',
        '--expected-parent "$HEAD_SHA"',
        '--out git-commit-response-normalized.json',
        'NEW_HEAD_SHA="$(jq -r .sha git-commit-response-normalized.json)"',
        '> updated-ref.json',
        '--response updated-ref.json',
        '--expected-ref "refs/heads/${HEAD_REF}"',
        '--expected-sha "$NEW_HEAD_SHA"',
        '--out updated-ref-normalized.json',
        'test "$(jq -r .sha updated-ref-normalized.json)" = "$NEW_HEAD_SHA"',
    )
    for fragment in required_fragments:
        require(fragment in text, f"Dependabot Git mutation response contract is missing: {fragment}")

    forbidden_fragments = (
        'BLOB="$(gh api --method POST "repos/${TARGET_REPOSITORY}/git/blobs"',
        'NEW_TREE="$(gh api --method POST "repos/${TARGET_REPOSITORY}/git/trees"',
        'NEW_COMMIT="$(gh api --method POST "repos/${TARGET_REPOSITORY}/git/commits"',
        'test "$(jq -r .object.sha updated-ref.json)" = "$NEW_HEAD_SHA"',
    )
    for fragment in forbidden_fragments:
        require(fragment not in text,
                f"Dependabot controller regained direct consumption of unvalidated Git mutation evidence: {fragment}")

    ordered = (
        '> git-blob-response.json',
        'python3 scripts/dependabot_controller.py git-blob-response',
        'BLOB_SHA="$(jq -r .sha git-blob-response-normalized.json)"',
        '> git-tree-response.json',
        'python3 scripts/dependabot_controller.py git-tree-response',
        'NEW_TREE_SHA="$(jq -r .sha git-tree-response-normalized.json)"',
        '> git-commit-response.json',
        'python3 scripts/dependabot_controller.py git-commit-response',
        'NEW_HEAD_SHA="$(jq -r .sha git-commit-response-normalized.json)"',
        '> updated-ref.json',
        'python3 scripts/dependabot_controller.py git-ref-response',
        'test "$(jq -r .sha updated-ref-normalized.json)" = "$NEW_HEAD_SHA"',
        'repos/${TARGET_REPOSITORY}/dispatches',
    )
    cursor = -1
    for fragment in ordered:
        position = text.find(fragment, cursor + 1)
        require(position > cursor,
                f"Dependabot Git mutation response validation moved out of reviewed order: {fragment}")
        cursor = position


def validate_controller_merge_success_response_contract(text: str) -> None:
    require(
        text.count("python3 scripts/dependabot_controller.py merge-success-response") == 1,
        "Dependabot controller must validate exactly one terminal merge success response",
    )
    for fragment in (
        "if [ \"$(jq -r '.merged // false' <<<\"$MERGE\")\" != \"true\" ]; then",
        'Dependabot merge API rejected exact-head merge:',
        'python3 scripts/dependabot_controller.py merge-success-response',
        '--response "$MERGE_BODY"',
        '--out "$RUNNER_TEMP/dependabot-merge-success-normalized.json"',
        'MERGE_SHA="$(jq -r .sha "$RUNNER_TEMP/dependabot-merge-success-normalized.json")"',
        'assert_main_sha "$MERGE_SHA"',
        'repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml/dispatches',
    ):
        require(fragment in text, f"Dependabot terminal merge response contract is missing: {fragment}")

    require(
        'MERGE_SHA="$(jq -r .sha <<<"$MERGE")"' not in text,
        "Dependabot controller must not consume terminal merge SHA before typed success validation",
    )

    ordered = (
        "if [ \"$(jq -r '.merged // false' <<<\"$MERGE\")\" != \"true\" ]; then",
        'python3 scripts/dependabot_controller.py merge-success-response',
        'MERGE_SHA="$(jq -r .sha "$RUNNER_TEMP/dependabot-merge-success-normalized.json")"',
        'assert_main_sha "$MERGE_SHA"',
        'repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml/dispatches',
    )
    cursor = -1
    for fragment in ordered:
        position = text.find(fragment, cursor + 1)
        require(position > cursor,
                f"Dependabot terminal merge success validation moved out of reviewed order: {fragment}")
        cursor = position


def validate_controller_approval_comment_contract(text: str) -> None:
    get_endpoint = 'repos/${TARGET_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100'
    post_endpoint = 'repos/${TARGET_REPOSITORY}/issues/${PR_NUMBER}/comments'
    require(
        text.count(get_endpoint) == 1,
        "Dependabot automation-approval comment read endpoint changed",
    )
    require(
        text.count(post_endpoint) == 2,
        "Dependabot automation-approval comment endpoint inventory changed",
    )
    require(
        text.count("python3 scripts/automation_approval_comment.py evidence") == 1,
        "Dependabot must validate exactly one automation-approval comment collection",
    )
    require(
        text.count("python3 scripts/automation_approval_comment.py created") == 1,
        "Dependabot must validate exactly one created automation-approval comment response",
    )
    for fragment in (
        "APPROVAL_COMMENT_EXISTS=false",
        "if python3 scripts/automation_approval_comment.py evidence",
        '--comments-file "$RUNNER_TEMP/dependabot-approval-comment-pages.json"',
        '--repository "$TARGET_REPOSITORY"',
        '--pr-number "$PR_NUMBER"',
        '--marker "$APPROVAL_MARKER"; then',
        "APPROVAL_COMMENT_EXISTS=true",
        'APPROVAL_EVIDENCE_STATUS="$?"',
        'if [ "$APPROVAL_EVIDENCE_STATUS" != "3" ]; then',
        'echo "ERROR: malformed Dependabot automation-approval comment evidence." >&2',
        'exit "$APPROVAL_EVIDENCE_STATUS"',
        'test "$APPROVAL_COMMENT_EXISTS" = "true" -o "$APPROVAL_COMMENT_EXISTS" = "false"',
        'if [ "$APPROVAL_COMMENT_EXISTS" = "false" ]; then',
        '--comment-file "$RUNNER_TEMP/dependabot-approval-comment-created.json"',
        '--expected-body "$APPROVAL_BODY"',
    ):
        require(
            fragment in text,
            f"Dependabot automation-approval comment contract is missing: {fragment}",
        )

    for forbidden in (
        'COMMENTS="$(gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100")"',
        '[.[][] | select(.body | contains($marker))] | length > 0',
        'test "$(jq -r .body approval-comment.json | grep -Fxc "$APPROVAL_BODY")" = "1"',
        'dependabot-approval-comment-evidence.json',
        'dependabot-approval-comment-created-normalized.json',
        'jq -r .actor',
        'jq -r .prNumber',
    ):
        require(
            forbidden not in text,
            f"Dependabot regressed to output-bearing/raw automation-approval comment evidence: {forbidden}",
        )

    fetch_pos = text.index(get_endpoint)
    validate_pos = text.index("if python3 scripts/automation_approval_comment.py evidence", fetch_pos)
    present_pos = text.index("APPROVAL_COMMENT_EXISTS=true", validate_pos)
    status_pos = text.index('APPROVAL_EVIDENCE_STATUS="$?"', present_pos)
    absent_guard_pos = text.index(
        'if [ "$APPROVAL_EVIDENCE_STATUS" != "3" ]; then',
        status_pos,
    )
    decision_pos = text.index(
        'test "$APPROVAL_COMMENT_EXISTS" = "true" -o "$APPROVAL_COMMENT_EXISTS" = "false"',
        absent_guard_pos,
    )
    create_pos = text.index(post_endpoint, decision_pos)
    created_validate_pos = text.index(
        "python3 scripts/automation_approval_comment.py created",
        create_pos,
    )
    merge_pos = text.index(
        'repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/merge',
        created_validate_pos,
    )
    require(
        fetch_pos < validate_pos < present_pos < status_pos < absent_guard_pos
        < decision_pos < create_pos < created_validate_pos < merge_pos,
        "Dependabot automation-approval comment evidence moved out of fail-closed reviewed order",
    )


def validate_release_resolution_parity_contract(text: str) -> None:
    delegated_step_binding = (
        "      - name: Independently re-prove deterministic reconciliation\n"
        "        env:\n"
        "          GH_TOKEN: ${{ github.token }}\n"
        "          PR_NUMBER: ${{ steps.bind.outputs.pr_number }}\n"
        "          HEAD_SHA: ${{ steps.bind.outputs.head_sha }}\n"
        "          CANDIDATE_ROOT: ${{ steps.candidate_data.outputs.candidate_root }}\n"
    )
    require(
        text.count(delegated_step_binding) == 1,
        "delegated Dependabot release reproof must bind exact GitHub token once",
    )
    resolver = "python3 scripts/dependabot_release.py"
    ls_remote = 'git ls-remote --tags "https://github.com/${DEPENDENCY_REPOSITORY}.git"'
    repository_get = 'gh api "repos/${DEPENDENCY_REPOSITORY}" > release-repository.json'
    release_get = (
        'gh api "repos/${DEPENDENCY_REPOSITORY}/releases/tags/${CANDIDATE_TAG}" > release.json'
    )
    repository_arg = "--repository-json release-repository.json"
    release_arg = "--release-json release.json"
    output_arg = "--out resolved-release.json"
    consume_sha = 'RESOLVED_SHA="$(jq -r .sha resolved-release.json)"'
    verify_sha = 'test "$RESOLVED_SHA" = "$CANDIDATE_SHA"'
    admit = "python3 scripts/dependabot_controller.py admit"
    resolved_arg = "--resolved-release resolved-release.json"

    for fragment, expected_count in (
        (ls_remote, 2),
        (repository_get, 2),
        (release_get, 2),
        (resolver, 2),
        (repository_arg, 2),
        (release_arg, 2),
        (output_arg, 2),
        (consume_sha, 2),
        (verify_sha, 2),
        (resolved_arg, 2),
    ):
        require(
            text.count(fragment) == expected_count,
            f"Dependabot canonical/delegated release reproof parity changed: {fragment}",
        )

    for forbidden in (
        "--resolved-release-sha",
        "resolved-release-sha.txt",
    ):
        require(
            forbidden not in text,
            f"Dependabot release reproof retained obsolete interface: {forbidden}",
        )

    cursor = -1
    for label in ("canonical controller", "delegated admission"):
        ls_pos = text.index(ls_remote, cursor + 1)
        repository_pos = text.index(repository_get, ls_pos)
        release_pos = text.index(release_get, repository_pos)
        resolver_pos = text.index(resolver, release_pos)
        repository_arg_pos = text.index(repository_arg, resolver_pos)
        release_arg_pos = text.index(release_arg, repository_arg_pos)
        output_pos = text.index(output_arg, release_arg_pos)
        consume_pos = text.index(consume_sha, output_pos)
        verify_pos = text.index(verify_sha, consume_pos)
        admit_pos = text.index(admit, verify_pos)
        resolved_arg_pos = text.index(resolved_arg, admit_pos)
        require(
            ls_pos < repository_pos < release_pos < resolver_pos
            < repository_arg_pos < release_arg_pos < output_pos
            < consume_pos < verify_pos < admit_pos < resolved_arg_pos,
            f"Dependabot {label} release reproof ordering changed",
        )
        cursor = resolved_arg_pos


def validate_approval_comment_helper_contract(text: str) -> None:
    for forbidden in (
        "def dump(",
        "def emit(",
        "Path(path).write_text(",
        "json.dumps(",
        'p.add_argument("--out"',
    ):
        require(
            forbidden not in text,
            f"automation-approval helper must not retain a clear-text output sink: {forbidden}",
        )
    for required in (
        "def load(path: str) -> Any:",
        'return json.loads(Path(path).read_text(encoding="utf-8"))',
        'decision = evidence(',
        'return 0 if decision["exists"] else 3',
        'validate_created(',
        'print("Governed automation-approval comment evidence self-test passed.")',
    ):
        require(
            required in text,
            f"automation-approval helper exit-only boundary changed: {required}",
        )


def validate_quality_contract(text: str) -> None:
    require(
        '- ".github/dependabot.yml"' in text,
        "Profile Quality push paths must include Dependabot governance changes",
    )
    require(
        '- ".github/workflows/**"' in text,
        "Profile Quality push paths must cover every current and future workflow",
    )
    require(
        "python3 scripts/validate-dependabot-contract.py" in text,
        "Profile Quality must execute the Dependabot governance validator",
    )

    start = text.index("\n  dependabot_admission:")
    end = text.index("\n  governed_bot_review:", start)
    block = text[start:end]

    required_fragments = (
        "- name: Prove exact PR-native Dependabot context",
        '(.maintainer_can_modify | type == "boolean" and . == false)',
        'validate_dependabot_pr_object "$PR"',
        'validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$BASE_SHA"',
        'validate_git_ref_object "$HEAD_REF_RESPONSE" "refs/heads/${HEAD_REF}" "$HEAD_SHA"',
        'BASE_GATE="$(gh api "repos/${TARGET_REPOSITORY}/contents/.github/workflows/profile-quality.yml?ref=${BASE_SHA}")"',
        'HEAD_GATE="$(gh api "repos/${TARGET_REPOSITORY}/contents/.github/workflows/profile-quality.yml?ref=${HEAD_SHA}")"',
        'validate_contents_file_object "$BASE_GATE" ".github/workflows/profile-quality.yml"',
        'validate_contents_file_object "$HEAD_GATE" ".github/workflows/profile-quality.yml"',
        'test "$BASE_GATE_BLOB" = "$HEAD_GATE_BLOB" || {',
        "- name: Checkout exact accepted-base trusted admission source",
        "ref: ${{ github.event.pull_request.base.sha }}",
        "path: trusted-base",
        "- name: Checkout exact Dependabot candidate as inert data",
        "ref: ${{ github.event.pull_request.head.sha }}",
        "path: candidate-source",
        "- name: Set up Python",
        "- name: Verify resolved Python runtime",
        "run: python3 trusted-base/scripts/verify-python-runtime.py",
        "- name: Verify exact accepted-base admission source identity",
        'test "$(git -C trusted-base rev-parse HEAD)" = "$BASE_SHA"',
        'test "$(git -C candidate-source rev-parse HEAD)" = "$HEAD_SHA"',
        'test "$(git -C trusted-base rev-parse HEAD:scripts/dependabot_capability_admission.py)" = "96107595641a0f9ff0203d9df2b684b1822b0346"',
        "- name: Fetch exact candidate release evidence",
        'PYTHONPATH="$GITHUB_WORKSPACE/trusted-base/scripts"',
        'gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100"',
        "python3 trusted-base/scripts/dependabot_controller.py probe",
        'git ls-remote --tags "https://github.com/${DEPENDENCY_REPOSITORY}.git" "refs/tags/${CANDIDATE_TAG}" "refs/tags/${CANDIDATE_TAG}^{}"',
        'gh api "repos/${DEPENDENCY_REPOSITORY}"',
        'gh api "repos/${DEPENDENCY_REPOSITORY}/releases/tags/${CANDIDATE_TAG}"',
        "python3 trusted-base/scripts/dependabot_release.py",
        "- name: Evaluate exact accepted-base semantic admission",
        "python3 trusted-base/scripts/dependabot_capability_admission.py",
        "candidate-source",
        '.decision.authorizationId == "delegated-dependabot-codeql-v1"',
        'echo "Exact accepted-base PR-native Dependabot semantic admission passed without cross-run proof polling."',
    )
    for fragment in required_fragments:
        require(
            fragment in block,
            f"Profile Quality PR-native Dependabot admission contract is missing: {fragment}",
        )

    require(
        "permissions:\n      contents: read\n      pull-requests: read" in block,
        "Profile Quality PR-native Dependabot admission permissions changed",
    )
    for forbidden in (
        "checks: read",
        "actions: read",
        "checks: write",
        "actions: write",
        "contents: write",
        "pull-requests: write",
        "id-token: write",
        "trusted-capability-admission-proof",
        'for ATTEMPT in $(seq 1 36)',
        "trusted-main Dependabot admission proof has not materialized yet",
        "dependabot-delegated-admission:",
    ):
        require(
            forbidden not in block,
            f"Profile Quality PR-native Dependabot admission retained forbidden relay/authority surface: {forbidden}",
        )

    ordered = (
        'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > "$RUNNER_TEMP/dependabot-pr.json"',
        'validate_dependabot_pr_object "$PR"',
        'MAIN_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main")"',
        'validate_git_ref_object "$MAIN_REF_RESPONSE" "refs/heads/main" "$BASE_SHA"',
        'HEAD_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}")"',
        'validate_git_ref_object "$HEAD_REF_RESPONSE" "refs/heads/${HEAD_REF}" "$HEAD_SHA"',
        'BASE_GATE="$(gh api "repos/${TARGET_REPOSITORY}/contents/.github/workflows/profile-quality.yml?ref=${BASE_SHA}")"',
        'HEAD_GATE="$(gh api "repos/${TARGET_REPOSITORY}/contents/.github/workflows/profile-quality.yml?ref=${HEAD_SHA}")"',
        'validate_contents_file_object "$BASE_GATE" ".github/workflows/profile-quality.yml"',
        'validate_contents_file_object "$HEAD_GATE" ".github/workflows/profile-quality.yml"',
        'test "$BASE_GATE_BLOB" = "$HEAD_GATE_BLOB" || {',
        "- name: Checkout exact accepted-base trusted admission source",
        "- name: Checkout exact Dependabot candidate as inert data",
        "- name: Set up Python",
        "- name: Verify resolved Python runtime",
        "- name: Verify exact accepted-base admission source identity",
        "- name: Fetch exact candidate release evidence",
        "python3 trusted-base/scripts/dependabot_controller.py probe",
        'git ls-remote --tags "https://github.com/${DEPENDENCY_REPOSITORY}.git" "refs/tags/${CANDIDATE_TAG}" "refs/tags/${CANDIDATE_TAG}^{}"',
        "python3 trusted-base/scripts/dependabot_release.py",
        "- name: Evaluate exact accepted-base semantic admission",
        "python3 trusted-base/scripts/dependabot_capability_admission.py",
        'echo "Exact accepted-base PR-native Dependabot semantic admission passed without cross-run proof polling."',
    )
    cursor = -1
    for fragment in ordered:
        position = block.index(fragment, cursor + 1)
        require(position > cursor, f"Profile Quality PR-native admission ordering changed: {fragment}")
        cursor = position


def validate_governance(text: str) -> None:
    for phrase in (
        "## Dependency update automation",
        ".github/dependabot.yml",
        "exact commit SHA",
        "separate pull request",
        "actions/attest",
        "actions/checkout",
        "shinpr/github-profile-stats",
        "Dependency review / dependency-review",
        "delegated Dependabot CodeQL",
        "workflow_run liveness",
        "newly advanced base",
        "stale native Dependabot PR",
        "eventual-consistency recovery trigger",
        "dependabot-dispatch-codeql",
        "candidate bytes as data",
        "static trusted `main`",
        "Dependabot alerts",
        "SHA-pinned GitHub Actions",
        "Profile quality / validate-contracts",
        "Profile quality / integration-pinned-upstream",
    ):
        require(phrase in text, f"Dependabot governance documentation is missing: {phrase}")


def self_test() -> None:
    api_collection_self_test()
    pin_diff_self_test()
    pr_identity_self_test()
    admission_self_test()
    reconciliation_self_test()
    release_self_test()
    approval_comment_self_test()
    controller_self_test()
    admission_proof_self_test()
    capability_admission_self_test()
    good_sha = "a" * 40
    observed = validate_uses_text(
        f"steps:\n  - uses: actions/checkout@{good_sha} # v7\n  - uses : ./.github/actions/local\n  - 'uses' : actions/setup-python@{good_sha} # v6\n",
        "self-test-good.yml",
    )
    require(
        observed == {"actions/checkout", "actions/setup-python"},
        "Action-pin self-test failed to identify immutable external actions",
    )

    for bad, expected in (
        ("steps:\n  - uses: actions/checkout@v7\n", "exact 40-character commit SHA"),
        ("steps:\n  - uses : docker://alpine:3.22\n", "external Docker action"),
        ("steps:\n  - \"uses\" : owner/repo\n", "repository@commit syntax"),
    ):
        try:
            validate_uses_text(bad, "self-test-bad.yml")
        except ValueError as exc:
            require(expected in str(exc), f"Action-pin self-test rejected input for the wrong reason: {exc}")
        else:
            fail(f"Action-pin self-test accepted forbidden reference: {bad.strip()}")


def main() -> int:
    try:
        for path in (DEPENDABOT, QUALITY, CONTROLLER, GOVERNANCE, APPROVAL_COMMENT_HELPER):
            require(path.is_file(), f"Dependabot governance input is missing: {path.relative_to(ROOT)}")

        self_test()
        validate_dependabot(DEPENDABOT.read_text(encoding="utf-8"))
        validate_all_workflow_pins()
        controller_text = CONTROLLER.read_text(encoding="utf-8")
        validate_controller_wake_contract(controller_text)
        validate_controller_read_ref_response_contract(controller_text)
        validate_controller_protected_workflow_evidence_contract(controller_text)
        validate_controller_pr_response_contract(controller_text)
        validate_controller_collection_contract(controller_text)
        validate_controller_git_read_response_contract(controller_text)
        validate_controller_git_mutation_response_contract(controller_text)
        validate_release_resolution_parity_contract(controller_text)
        validate_controller_merge_success_response_contract(controller_text)
        validate_controller_approval_comment_contract(controller_text)
        validate_approval_comment_helper_contract(APPROVAL_COMMENT_HELPER.read_text(encoding="utf-8"))
        validate_quality_contract(QUALITY.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))

        print(
            "Dependabot governance validation passed: canonical discovery/grouping remains locked; exact native bot identity, "
            "atomic single-repository pin closure, forward SemVer, public release tag-to-SHA provenance, deterministic governance "
            "reconciliation, fail-closed wake/ref, pull-list, singleton PR/update, and candidate Git read response evidence, fail-closed paginated PR/file collection evidence, fail-closed Git mutation response topology, mirrored canonical/delegated public release reproof, typed terminal merge success evidence, trusted-actor automation-approval comment evidence, delegated CodeQL-only capability admission, exact protected checks, and exact-head merge are all "
            "self-tested while every external action remains pinned to one immutable commit SHA."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
