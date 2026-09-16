#!/usr/bin/env python3
"""Exact byte and trust-boundary contract for the trusted capability admission workflow."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/capability-admission.yml"
EXPECTED_GIT_BLOB = "a23bb60711913db8200614e8316deae496ca9dfc"
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
        "  repository_dispatch:\n    types:\n      - codeql-autofix-admission\n" in text,
        "trusted capability admission repository_dispatch trigger changed",
    )
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
    require('test "$(jq -r \'.action // ""\' "$GITHUB_EVENT_PATH")" = "codeql-autofix-admission"' in text,
            "trusted admission dispatch type binding changed")
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
    for output_name in (
        "dispatch", "base_ref", "base_sha", "head_ref", "head_repository", "head_sha",
    ):
        require(f"printf '{output_name}=%s\\n'" in text,
                f"trusted admission lost verified context output: {output_name}")

    require("ref: ${{ steps.candidate.outputs.base_sha }}" in text,
            "trusted admission no longer checks out the exact verified trusted base SHA")
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

    for endpoint in (
        'gh api "repos/${HEAD_REPOSITORY}/git/commits/${HEAD_SHA}"',
        'gh api "repos/${HEAD_REPOSITORY}/git/trees/${TREE_SHA}?recursive=1"',
        'gh api "repos/${HEAD_REPOSITORY}/git/blobs/${BLOB_SHA}"',
    ):
        require(text.count(endpoint) == 1,
                f"trusted admission candidate object fetch surface changed: {endpoint}")
    require('test "$(jq -r .truncated <<<"$TREE")" = "false"' in text,
            "trusted admission lost complete candidate-tree proof")
    require('test "$(jq -r \'.[0].mode\' <<<"$ENTRY")" = "100644"' in text,
            "trusted admission lost candidate regular-file mode proof")
    require("candidate-capability-source/.github/workflows" in text and
            "candidate-capability-source/scripts" in text,
            "trusted admission candidate data roots changed")

    require("python3 scripts/workflow_capability_tcb.py select" in text,
            "trusted admission no longer selects candidate TCB bytes with trusted code")
    require("printf '%s\\n' \"$TREE_SHA\" > candidate-capability-source/.candidate-tree-sha" in text,
            "trusted admission no longer persists the exact candidate tree SHA")
    require('TREE_SHA="$(cat candidate-capability-source/.candidate-tree-sha)"' in text,
            "trusted admission lost cross-step candidate tree SHA binding")
    require("python3 scripts/workflow_capability_admission.py \\\n            candidate-capability-source \\\n            --candidate-tree-sha \"$TREE_SHA\"" in text,
            "trusted admission evaluator lost exact candidate tree binding")

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
    ):
        require(publisher_binding in text,
                f"trusted admission candidate-check binding changed: {publisher_binding}")
    require("if: steps.candidate.outputs.dispatch == 'true'" in text,
            "trusted admission candidate-check write is no longer dispatch-only")

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


def self_test() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    validate_text(text)
    try:
        validate_text(text.replace("checks: write", "contents: write", 1))
    except ValueError as exc:
        require("permission set changed" in str(exc) or "forbidden authority" in str(exc),
                f"trusted admission permission self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("trusted admission contract accepted altered write authority")
    try:
        validate_text(text.replace(
            'gh api --method POST "repos/${TARGET_REPOSITORY}/check-runs"',
            'gh api --method POST "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/merge"',
            1,
        ))
    except ValueError as exc:
        require("candidate-check publisher" in str(exc),
                f"trusted admission publisher self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("trusted admission contract accepted a different mutation surface")
    try:
        validate_text(text.replace(
            "ref: ${{ steps.candidate.outputs.base_sha }}",
            "ref: ${{ steps.candidate.outputs.head_sha }}",
            1,
        ))
    except ValueError as exc:
        require(
            "trusted base SHA" in str(exc)
            or "checkout candidate" in str(exc)
            or "forbidden authority" in str(exc),
            f"trusted admission checkout self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("trusted admission contract accepted candidate checkout")
    try:
        validate_text(text.replace("--candidate-tree-sha \"$TREE_SHA\"", "", 1))
    except ValueError as exc:
        require("candidate tree binding" in str(exc),
                f"trusted admission tree-binding self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("trusted admission contract accepted an unbound candidate TCB")
    try:
        validate_text(text.replace(".autofixCommitSha", ".unboundCommitSha", 1))
    except ValueError as exc:
        require("receipt binding" in str(exc),
                f"trusted admission receipt-binding self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("trusted admission contract accepted an unbound controller receipt")


if __name__ == "__main__":
    self_test()
    validate()
    print("Trusted capability admission workflow contract passed: exact bytes, base-only execution, immutable Autofix provenance, data-only candidate TCB evaluation, and one bounded exact-head GitHub Actions check publisher.")
