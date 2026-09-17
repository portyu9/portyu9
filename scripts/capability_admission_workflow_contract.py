#!/usr/bin/env python3
"""Exact byte and trust-boundary contract for the trusted capability admission workflow."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/capability-admission.yml"
EXPECTED_GIT_BLOB = "045dc687738b760dfc9629cfec2442f5f9ff1400"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
SETUP_PYTHON = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0"


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
            "trusted capability admission retained default-SHA workflow_run authority")

    permission_block = (
        "permissions:\n"
        "  actions: read\n"
        "  checks: write\n"
        "  contents: read\n"
        "  pull-requests: read\n"
    )
    job_permission_block = (
        "    permissions:\n"
        "      actions: read\n"
        "      checks: write\n"
        "      contents: read\n"
        "      pull-requests: read\n"
    )
    require(text.count(permission_block) == 1,
            "trusted capability admission workflow permission set changed")
    require(text.count(job_permission_block) == 1,
            "trusted capability admission job permission set changed")
    for forbidden in (
        "contents: write", "actions: write", "pull-requests: write",
        "id-token: write", "attestations: write", "security-events: write",
        "--method PUT", "--method PATCH", "--method DELETE",
        "curl ", "wget ", "pull_request.head.sha }}\n          persist-credentials",
    ):
        require(forbidden not in text, f"trusted capability admission acquired forbidden authority: {forbidden}")
    require(text.count("--method POST") == 1,
            "trusted capability admission write-call count changed")

    require(text.count(f"uses: {CHECKOUT}") == 1, "trusted admission checkout pin changed")
    require(text.count(f"uses: {SETUP_PYTHON}") == 1, "trusted admission Python setup pin changed")
    require("- name: Bind exact candidate context" in text,
            "trusted admission lost exact event-context binding")
    require("GH_TOKEN: ${{ github.token }}" in text,
            "trusted admission lost authenticated exact-object binding")
    require("EVENT_NAME: ${{ github.event_name }}" in text,
            "trusted admission event identity binding changed")
    require("TARGET_REPOSITORY: ${{ github.repository }}" in text,
            "trusted admission repository identity binding changed")
    require('PR="$(jq -c \'.pull_request\' "$GITHUB_EVENT_PATH")"' in text,
            "trusted admission pull_request_target binding changed")
    require('ACTION="$(jq -r \'.action // ""\' "$GITHUB_EVENT_PATH")"' in text,
            "trusted admission dispatch action binding changed")
    for dispatch_type in ("codeql-autofix-admission)", "dependabot-admission)"):
        require(text.count(dispatch_type) == 1,
                f"trusted admission dispatch type binding changed: {dispatch_type}")
    for payload_binding in (
        ".client_payload.prNumber",
        ".client_payload.originRunId",
        ".client_payload.alertNumber",
        ".client_payload.baseSha",
        ".client_payload.headSha",
    ):
        require(payload_binding in text,
                f"trusted admission dispatch payload binding changed: {payload_binding}")
    for pr_binding in (
        '.state <<<"$PR"', '.draft <<<"$PR"', '.base.ref <<<"$PR"', '.base.sha <<<"$PR"',
        '.head.sha <<<"$PR"', '.head.repo.full_name <<<"$PR"', '.head.ref <<<"$PR"',
    ):
        require(pr_binding in text,
                f"trusted admission exact PR identity proof changed: {pr_binding}")
    require('gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}"' in text,
            "trusted admission exact PR read surface changed")
    require('gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main" --jq .object.sha' in text,
            "trusted admission exact main ref binding changed")
    require('"codeql-autofix/alert-${ALERT_NUMBER}/run-${ORIGIN_RUN_ID}"' in text,
            "trusted admission Autofix branch/run/alert identity binding changed")
    require('[[ "$HEAD_REF" =~ ^codeql-autofix/alert-[1-9][0-9]*/run-[1-9][0-9]*$ ]]' in text,
            "trusted admission Autofix branch shape binding changed")

    for dependabot_fragment in (
        'test "$(jq -r \'.sender.login // ""\' "$GITHUB_EVENT_PATH")" = "github-actions[bot]"',
        'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > dependabot-pr.json',
        'test "$(jq -r .maintainer_can_modify <<<"$PR")" = "false"',
        '[[ "$(jq -r .head.ref <<<"$PR")" =~ ^dependabot/github_actions/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]]',
        '[[ "$HEAD_REF" =~ ^dependabot/github_actions/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]]',
        'DEPENDABOT=true',
        'printf \'dependabot=%s\\n\' "$DEPENDABOT"',
        'gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100" > dependabot-file-pages.json',
        'jq -r \'.[][] | .filename\' dependabot-file-pages.json | LC_ALL=C sort > dependabot-changed-paths.txt',
        'for PATH_VALUE in .github/action-lock.json .github/workflow-capability-bom-v1.json scripts/validate-codeql-contract.py; do',
        'python3 scripts/dependabot_controller.py probe',
        'test "$DEPENDENCY_REPOSITORY" = "github/codeql-action"',
        'git ls-remote --tags "https://github.com/${DEPENDENCY_REPOSITORY}.git"',
        'python3 scripts/dependabot_release.py',
        '--expected-sha "$CANDIDATE_SHA"',
        'python3 scripts/dependabot_capability_admission.py',
        '--resolved-release-sha "$RESOLVED_RELEASE_SHA"',
        '--changed-paths dependabot-changed-paths.txt',
        'test "$(jq -r .decision.authorizationId capability-admission.json)" = "delegated-dependabot-codeql-v1"',
    ):
        require(dependabot_fragment in text,
                f"trusted admission delegated Dependabot proof changed: {dependabot_fragment}")

    for spotlight_fragment in (
        'gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&per_page=100"',
        '.user.login == "github-actions[bot]"',
        '.head.repo.full_name == "portyu9/portyu9"',
        'test("^automation/spotlight-links/[0-9a-f]{64}$")',
        '.title == "chore: sync rotating Spotlight links"',
        '.maintainer_can_modify == false',
        'test "$MATCH_COUNT" -le 1',
        'printf \'has_candidate=false\\n\'',
        'test "$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}" --jq .object.sha)" = "$HEAD_SHA"',
        'test "$(jq \'.parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"',
        'test "$(jq -r \'.parents[0].sha\' <<<"$CANDIDATE_COMMIT")" = "$BASE_SHA"',
        'test "$(jq -r .author.name <<<"$CANDIDATE_COMMIT")" = "github-actions[bot]"',
        'test "$(jq -r .author.email <<<"$CANDIDATE_COMMIT")" = "41898282+github-actions[bot]@users.noreply.github.com"',
        'test "$(jq -r .committer.name <<<"$CANDIDATE_COMMIT")" = "github-actions[bot]"',
        'test "$(jq -r .committer.email <<<"$CANDIDATE_COMMIT")" = "41898282+github-actions[bot]@users.noreply.github.com"',
        'test "$(jq -r .message <<<"$CANDIDATE_COMMIT")" = "chore: sync rotating Spotlight links"',
        'COMPARE="$(gh api "repos/${TARGET_REPOSITORY}/compare/${BASE_SHA}...${HEAD_SHA}")"',
        'test "$(jq -r .ahead_by <<<"$COMPARE")" = "1"',
        'test "$(jq -r .behind_by <<<"$COMPARE")" = "0"',
        'test "$(jq -r .total_commits <<<"$COMPARE")" = "1"',
        'test "$(jq \'.files | length\' <<<"$COMPARE")" = "1"',
        'test "$(jq -r \'.files[0].filename\' <<<"$COMPARE")" = "README.md"',
        'GENERATED_SHA="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/generated" --jq .object.sha)"',
        'gh api "repos/${TARGET_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}" --jq .content',
        'CANDIDATE_ID="$(printf \'%s\\n%s\\n%s\\n\' "$BASE_SHA" "$GENERATED_SHA" "$README_SHA256" | sha256sum | cut -d\' \' -f1)"',
        'test "$HEAD_REF" = "automation/spotlight-links/${CANDIDATE_ID}"',
    ):
        require(spotlight_fragment in text,
                f"trusted admission scheduled Spotlight identity proof changed: {spotlight_fragment}")
    require('SPOTLIGHT=true' in text and 'printf \'spotlight=%s\\n\'' in text,
            "trusted admission lost scheduled Spotlight publication binding")

    for output_name in (
        "dispatch", "dependabot", "base_ref", "base_sha", "head_ref", "head_repository", "head_sha",
    ):
        require(f"printf '{output_name}=%s\\n'" in text,
                f"trusted admission lost verified context output: {output_name}")

    require("ref: ${{ steps.candidate.outputs.base_sha }}" in text,
            "trusted admission no longer checks out the exact verified trusted base SHA")
    require("if: steps.candidate.outputs.has_candidate == 'true'" in text,
            "trusted admission no longer skips execution on an empty scheduled recovery scan")
    require("persist-credentials: false" in text and "fetch-depth: 1" in text,
            "trusted admission checkout credential/depth boundary changed")
    require("BASE_REF: ${{ steps.candidate.outputs.base_ref }}" in text,
            "trusted admission base ref identity binding changed")
    require("BASE_SHA: ${{ steps.candidate.outputs.base_sha }}" in text,
            "trusted admission base SHA identity binding changed")
    require("HEAD_SHA: ${{ steps.candidate.outputs.head_sha }}" in text,
            "trusted admission candidate head identity binding changed")
    require("HEAD_REPOSITORY: ${{ steps.candidate.outputs.head_repository }}" in text,
            "trusted admission candidate repository identity binding changed")

    for provenance_endpoint in (
        'gh api "repos/${TARGET_REPOSITORY}/actions/runs/${ORIGIN_RUN_ID}/artifacts?per_page=100"',
        'gh api "repos/${TARGET_REPOSITORY}/actions/artifacts/${ARTIFACT_ID}/zip"',
        'gh api "repos/${TARGET_REPOSITORY}/actions/runs/${ORIGIN_RUN_ID}/attempts/${RECEIPT_ATTEMPT}"',
    ):
        require(text.count(provenance_endpoint) == 1,
                f"trusted admission immutable provenance read surface changed: {provenance_endpoint}")
    require("python3 scripts/codeql_autofix_controller.py artifact" in text,
            "trusted admission lost exact controller receipt-artifact selection")
    for receipt_field in (
        ".controllerId", ".flowId", ".repository", ".workflowPath", ".runId", ".runAttempt",
        ".baseSha", ".alertNumber", ".targetBranch", ".autofixCommitSha", ".prNumber",
    ):
        require(receipt_field in text,
                f"trusted admission controller receipt binding changed: {receipt_field}")
    for origin_binding in (
        '.id origin-run.json', '.run_attempt origin-run.json', '.name origin-run.json',
        '.path origin-run.json', '.event origin-run.json', '.head_branch origin-run.json',
        '.head_sha origin-run.json', '.status origin-run.json', '.conclusion // "null"',
    ):
        require(origin_binding in text,
                f"trusted admission origin-controller binding changed: {origin_binding}")
    require('test "$(jq -r .status origin-run.json)" = "in_progress"' in text,
            "trusted admission no longer proves the origin controller is the live dispatcher")

    commit_endpoint = 'gh api "repos/${HEAD_REPOSITORY}/git/commits/${HEAD_SHA}"'
    tree_endpoint = 'gh api "repos/${HEAD_REPOSITORY}/git/trees/${TREE_SHA}?recursive=1"'
    blob_endpoint = 'gh api "repos/${HEAD_REPOSITORY}/git/blobs/${BLOB_SHA}"'
    require(text.count(commit_endpoint) == 1, "trusted admission candidate commit fetch surface changed")
    require(text.count(tree_endpoint) == 1, "trusted admission candidate tree fetch surface changed")
    require(text.count(blob_endpoint) == 2,
            "trusted admission candidate blob fetch surface must remain one TCB loop plus one Dependabot-derived-file loop")
    require('test "$(jq -r .truncated <<<"$TREE")" = "false"' in text,
            "trusted admission lost complete candidate-tree proof")
    require(text.count('test "$(jq -r \'.[0].mode\' <<<"$ENTRY")" = "100644"') == 2,
            "trusted admission lost candidate regular-file mode proofs")
    require("candidate-capability-source/.github/workflows" in text and
            "candidate-capability-source/scripts" in text,
            "trusted admission candidate data roots changed")

    require("python3 scripts/workflow_capability_tcb.py select" in text,
            "trusted admission no longer selects candidate TCB bytes with trusted code")
    require("printf '%s\\n' \"$TREE_SHA\" > candidate-capability-source/.candidate-tree-sha" in text,
            "trusted admission no longer persists the exact candidate tree SHA")
    require('TREE_SHA="$(cat candidate-capability-source/.candidate-tree-sha)"' in text,
            "trusted admission lost cross-step candidate tree SHA binding")
    require("python3 scripts/workflow_capability_admission.py" in text and
            "--candidate-tree-sha \"$TREE_SHA\"" in text,
            "trusted admission ordinary evaluator lost exact candidate tree binding")
    require("python3 scripts/dependabot_capability_admission.py" in text and
            "--candidate-tree-sha \"$TREE_SHA\"" in text,
            "trusted admission delegated evaluator lost exact candidate tree binding")

    publisher = 'gh api --method POST "repos/${TARGET_REPOSITORY}/check-runs"'
    require(text.count(publisher) == 1,
            "trusted admission exact candidate-check publisher surface changed")
    for publisher_binding in (
        "-f name=trusted-capability-admission",
        '-f head_sha="$HEAD_SHA"',
        "-f status=completed",
        "-f conclusion=success",
        '-f external_id="$EXTERNAL_ID"',
        'test "$(jq -r .name <<<"$CHECK")" = "trusted-capability-admission"',
        'test "$(jq -r .head_sha <<<"$CHECK")" = "$HEAD_SHA"',
        'test "$(jq -r .status <<<"$CHECK")" = "completed"',
        'test "$(jq -r .conclusion <<<"$CHECK")" = "success"',
        'test "$(jq -r .app.id <<<"$CHECK")" = "15368"',
        'EXTERNAL_ID="codeql-autofix-admission:${ORIGIN_RUN_ID}:${PR_NUMBER}:${HEAD_SHA}"',
        'EXTERNAL_ID="dependabot-delegated-admission:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
        'EXTERNAL_ID="spotlight-scheduled-admission:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
    ):
        require(publisher_binding in text,
                f"trusted admission candidate-check binding changed: {publisher_binding}")
    require(
        "if: steps.candidate.outputs.dispatch == 'true' || steps.candidate.outputs.dependabot == 'true' || steps.candidate.outputs.spotlight == 'true'"
        in text,
        "trusted admission candidate-check write is no longer bound to reviewed bot recovery paths",
    )

    require(text.count("actions/checkout@") == 1,
            "trusted admission gained an additional checkout execution surface")
    require("ref: ${{ github.event.pull_request.head.sha }}" not in text and
            "ref: ${{ steps.candidate.outputs.head_sha }}" not in text,
            "trusted admission must never checkout candidate code")
    require("python3 candidate-capability-source" not in text and
            "source candidate-capability-source" not in text and
            "bash candidate-capability-source" not in text,
            "trusted admission must never execute candidate-controlled code")


def validate() -> None:
    require(WORKFLOW.is_file() and not WORKFLOW.is_symlink(),
            "trusted capability admission workflow is missing or aliased")
    data = WORKFLOW.read_bytes()
    observed = git_blob_sha(data)
    require(observed == EXPECTED_GIT_BLOB,
            f"trusted capability admission workflow bytes changed: expected={EXPECTED_GIT_BLOB} observed={observed}")
    validate_text(data.decode("utf-8"))


def expect_failure(text: str, old: str, new: str, expected: str) -> None:
    require(old in text, f"capability admission self-test fixture missing mutation anchor: {old}")
    try:
        validate_text(text.replace(old, new, 1))
    except ValueError as exc:
        require(expected in str(exc),
                f"trusted admission self-test failed for wrong reason: expected={expected!r} observed={exc}")
    else:
        raise ValueError(f"trusted admission contract accepted forbidden mutation: {expected}")


def self_test() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    validate_text(text)
    expect_failure(text, "checks: write", "contents: write", "permission set changed")
    expect_failure(
        text,
        'gh api --method POST "repos/${TARGET_REPOSITORY}/check-runs"',
        'gh api --method POST "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/merge"',
        "candidate-check publisher",
    )
    expect_failure(
        text,
        "ref: ${{ steps.candidate.outputs.base_sha }}",
        "ref: ${{ steps.candidate.outputs.head_sha }}",
        "trusted base SHA",
    )
    expect_failure(text, "--candidate-tree-sha \"$TREE_SHA\"", "--candidate-tree-sha \"$HEAD_SHA\"",
                   "candidate tree binding")
    expect_failure(text, ".autofixCommitSha", ".unboundCommitSha", "receipt binding")
    expect_failure(text, '    - cron: "*/5 * * * *"', '    - cron: "17 * * * *"',
                   "scheduled Spotlight recovery trigger")
    expect_failure(text,
                   'test "$HEAD_REF" = "automation/spotlight-links/${CANDIDATE_ID}"',
                   'test "$HEAD_REF" = "automation/spotlight-links/unbound"',
                   "scheduled Spotlight identity proof")
    expect_failure(text,
                   'test "$(jq -r \'.sender.login // ""\' "$GITHUB_EVENT_PATH")" = "github-actions[bot]"',
                   'test "$(jq -r \'.sender.login // ""\' "$GITHUB_EVENT_PATH")" = "dependabot[bot]"',
                   "delegated Dependabot proof")
    expect_failure(text,
                   'test "$DEPENDENCY_REPOSITORY" = "github/codeql-action"',
                   'test -n "$DEPENDENCY_REPOSITORY"',
                   "delegated Dependabot proof")
    expect_failure(text,
                   'test "$(jq -r .decision.authorizationId capability-admission.json)" = "delegated-dependabot-codeql-v1"',
                   'test "$(jq -r .decision.allowed capability-admission.json)" = "true"',
                   "delegated Dependabot proof")
    expect_failure(text,
                   'EXTERNAL_ID="dependabot-delegated-admission:${PR_NUMBER}:${BASE_SHA}:${HEAD_SHA}"',
                   'EXTERNAL_ID="dependabot-unbound:${PR_NUMBER}"',
                   "candidate-check binding")


if __name__ == "__main__":
    self_test()
    validate()
    print(
        "Trusted capability admission workflow contract passed: exact bytes, base-only execution, immutable Autofix provenance, "
        "scheduled deterministic Spotlight recovery, exact native Dependabot/release/delegation reproof, data-only candidate TCB "
        "evaluation, and one bounded exact-head GitHub Actions check publisher."
    )
