#!/usr/bin/env python3
"""Exact byte and trust-boundary contract for the trusted capability admission workflow."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/capability-admission.yml"
EXPECTED_GIT_BLOB = "ec26fe497e7b008f2d1d47d265bfe29221890437"
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
        '  workflow_run:\n    workflows:\n      - Profile quality\n    types:\n      - requested\n'
        '    branches:\n      - "codeql-autofix/**"\n' in text,
        "trusted capability admission workflow_run trigger changed",
    )
    require(text.count("permissions:\n  contents: read") == 1,
            "trusted capability admission workflow permission changed")
    require(text.count("    permissions:\n      contents: read") == 1,
            "trusted capability admission job permission changed")
    for forbidden in (
        "contents: write", "actions: write", "checks: write", "pull-requests: write",
        "id-token: write", "attestations: write", "security-events: write",
        "--method POST", "--method PUT", "--method PATCH", "--method DELETE",
        "curl ", "wget ", "pull_request.head.sha }}\n          persist-credentials",
    ):
        require(forbidden not in text, f"trusted capability admission acquired forbidden authority: {forbidden}")

    require(text.count(f"uses: {CHECKOUT}") == 1, "trusted admission checkout pin changed")
    require(text.count(f"uses: {SETUP_PYTHON}") == 1, "trusted admission Python setup pin changed")
    require("- name: Bind exact candidate context" in text,
            "trusted admission lost exact event-context binding")
    require("EVENT_NAME: ${{ github.event_name }}" in text,
            "trusted admission event identity binding changed")
    require("TARGET_REPOSITORY: ${{ github.repository }}" in text,
            "trusted admission repository identity binding changed")
    require('PR="$(jq -c \'.pull_request\' "$GITHUB_EVENT_PATH")"' in text,
            "trusted admission pull_request_target binding changed")
    require('PULLS="$(jq -c \'.workflow_run.pull_requests\' "$GITHUB_EVENT_PATH")"' in text,
            "trusted admission workflow_run PR-set binding changed")
    require('test "$(jq \'length\' <<<"$PULLS")" = "1"' in text,
            "trusted admission workflow_run single-PR proof changed")
    for workflow_run_binding in (
        '.workflow_run.event // ""',
        '.workflow_run.name // ""',
        '.workflow_run.path // ""',
        '.workflow_run.run_attempt // 0',
        '.workflow_run.actor.login // ""',
        'github-actions[bot]',
        '.workflow_run.head_branch',
        '.workflow_run.head_sha',
        '.repository.id',
        '.base.repo.id',
        '.head.repo.id',
    ):
        require(workflow_run_binding in text,
                f"trusted admission workflow_run identity proof changed: {workflow_run_binding}")
    require('[[ "$HEAD_REF" =~ ^codeql-autofix/alert-[1-9][0-9]*/run-[1-9][0-9]*$ ]]' in text,
            "trusted admission Autofix branch identity binding changed")
    for output_name in ("base_ref", "base_sha", "head_repository", "head_sha"):
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
        validate_text(text.replace("contents: read", "contents: write", 1))
    except ValueError as exc:
        require("permission changed" in str(exc) or "forbidden authority" in str(exc),
                f"trusted admission contract self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("trusted admission contract accepted write authority")
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
        validate_text(text.replace("github-actions[bot]", "portyu9", 1))
    except ValueError as exc:
        require("workflow_run identity proof" in str(exc),
                f"trusted admission bot-binding self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("trusted admission contract accepted a non-bot workflow_run actor")


if __name__ == "__main__":
    self_test()
    validate()
    print("Trusted capability admission workflow contract passed: exact bytes, read-only authority, base-only execution, candidate TCB bound to exact event-derived tree.")
