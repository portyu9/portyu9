#!/usr/bin/env python3
"""Exact byte and trust-boundary contract for the trusted capability admission workflow."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/capability-admission.yml"
EXPECTED_GIT_BLOB = "55be56ddc6c55fe55e4c6740c8f92c15476d3e0f"
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
    require("ref: ${{ github.event.pull_request.base.sha }}" in text,
            "trusted admission no longer checks out the exact trusted base SHA")
    require("persist-credentials: false" in text and "fetch-depth: 1" in text,
            "trusted admission checkout credential/depth boundary changed")
    require("HEAD_SHA: ${{ github.event.pull_request.head.sha }}" in text,
            "trusted admission candidate head identity binding changed")
    require("HEAD_REPOSITORY: ${{ github.event.pull_request.head.repo.full_name }}" in text,
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
    require("candidate-capability-source/.github/workflows" in text,
            "trusted admission candidate data root changed")
    require("python3 scripts/workflow_capability_admission.py candidate-capability-source" in text,
            "trusted admission evaluator command changed")

    require(text.count("actions/checkout@") == 1,
            "trusted admission gained an additional checkout execution surface")
    require("ref: ${{ github.event.pull_request.head.sha }}" not in text,
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
            "ref: ${{ github.event.pull_request.base.sha }}",
            "ref: ${{ github.event.pull_request.head.sha }}",
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


if __name__ == "__main__":
    self_test()
    validate()
    print("Trusted capability admission workflow contract passed: exact bytes, read-only authority, base-only execution.")
