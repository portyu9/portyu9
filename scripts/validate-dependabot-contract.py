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
        "Dependabot must type exactly one automation-approval comment collection",
    )
    require(
        text.count("python3 scripts/automation_approval_comment.py created") == 1,
        "Dependabot must type exactly one created automation-approval comment response",
    )
    for fragment in (
        '--comments-file "$RUNNER_TEMP/dependabot-approval-comment-pages.json"',
        '--repository "$TARGET_REPOSITORY"',
        '--pr-number "$PR_NUMBER"',
        '--marker "$APPROVAL_MARKER"',
        '> "$RUNNER_TEMP/dependabot-approval-comment-evidence.json"',
        'APPROVAL_COMMENT_EXISTS="$(jq -r .exists "$RUNNER_TEMP/dependabot-approval-comment-evidence.json")"',
        'test "$APPROVAL_COMMENT_EXISTS" = "true" -o "$APPROVAL_COMMENT_EXISTS" = "false"',
        'if [ "$APPROVAL_COMMENT_EXISTS" = "false" ]; then',
        '--comment-file "$RUNNER_TEMP/dependabot-approval-comment-created.json"',
        '--expected-body "$APPROVAL_BODY"',
        '> "$RUNNER_TEMP/dependabot-approval-comment-created-normalized.json"',
        'test "$(jq -r .actor "$RUNNER_TEMP/dependabot-approval-comment-created-normalized.json")" = "github-actions[bot]"',
        'test "$(jq -r .prNumber "$RUNNER_TEMP/dependabot-approval-comment-created-normalized.json")" = "$PR_NUMBER"',
    ):
        require(
            fragment in text,
            f"Dependabot automation-approval comment contract is missing: {fragment}",
        )

    for forbidden in (
        'COMMENTS="$(gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100")"',
        '[.[][] | select(.body | contains($marker))] | length > 0',
        'test "$(jq -r .body approval-comment.json | grep -Fxc "$APPROVAL_BODY")" = "1"',
    ):
        require(
            forbidden not in text,
            f"Dependabot regressed to raw automation-approval comment evidence: {forbidden}",
        )

    fetch_pos = text.index(get_endpoint)
    validate_pos = text.index("python3 scripts/automation_approval_comment.py evidence", fetch_pos)
    consume_pos = text.index(
        'APPROVAL_COMMENT_EXISTS="$(jq -r .exists "$RUNNER_TEMP/dependabot-approval-comment-evidence.json")"',
        validate_pos,
    )
    create_pos = text.index(post_endpoint, consume_pos)
    created_validate_pos = text.index(
        "python3 scripts/automation_approval_comment.py created",
        create_pos,
    )
    created_consume_pos = text.index(
        'test "$(jq -r .actor "$RUNNER_TEMP/dependabot-approval-comment-created-normalized.json")" = "github-actions[bot]"',
        created_validate_pos,
    )
    require(
        fetch_pos < validate_pos < consume_pos < create_pos < created_validate_pos < created_consume_pos,
        "Dependabot automation-approval comment evidence moved out of typed reviewed order",
    )


def validate_approval_comment_helper_contract(text: str) -> None:
    for forbidden in (
        "def dump(",
        "Path(path).write_text(",
        'p.add_argument("--out"',
    ):
        require(
            forbidden not in text,
            f"automation-approval helper must not retain a generic clear-text file sink: {forbidden}",
        )
    for required in (
        "def emit(value: Any) -> None:",
        'print(json.dumps(value, sort_keys=True, separators=(",", ":")))',
        "def load(path: str) -> Any:",
        'return json.loads(Path(path).read_text(encoding="utf-8"))',
    ):
        require(
            required in text,
            f"automation-approval helper stdout-only boundary changed: {required}",
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
        validate_controller_collection_contract(controller_text)
        validate_controller_git_mutation_response_contract(controller_text)
        validate_controller_merge_success_response_contract(controller_text)
        validate_controller_approval_comment_contract(controller_text)
        validate_approval_comment_helper_contract(APPROVAL_COMMENT_HELPER.read_text(encoding="utf-8"))
        validate_quality_contract(QUALITY.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))

        print(
            "Dependabot governance validation passed: canonical discovery/grouping remains locked; exact native bot identity, "
            "atomic single-repository pin closure, forward SemVer, public release tag-to-SHA provenance, deterministic governance "
            "reconciliation, fail-closed wake/ref singleton evidence, fail-closed paginated PR/file collection evidence, fail-closed Git mutation response topology, typed terminal merge success evidence, trusted-actor automation-approval comment evidence, delegated CodeQL-only capability admission, exact protected checks, and exact-head merge are all "
            "self-tested while every external action remains pinned to one immutable commit SHA."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
