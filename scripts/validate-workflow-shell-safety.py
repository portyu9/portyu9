#!/usr/bin/env python3
"""Extend the frozen workflow shell-safety scanner with item-11 ADR signers."""
from __future__ import annotations

import sys

import workflow_capability_shell_source as shell_source
import workflow_shell_safety_item10_core as core


ITEM11_PRIVILEGED_JOBS = {
    "profile-stats.yml": ("publish", "dispatch", "decision_receipt_attest"),
    "spotlight-link-sync.yml": (
        "reconcile", "propose", "approve", "authorize_attest", "merge", "decision_receipt_attest"
    ),
}
EXACT_COMPRESSED_ATTESTATION_VERIFY = (
    'gh attestation verify "$SUBJECT" --repo "$GITHUB_REPOSITORY" '
    '--predicate-type https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/'
    'spotlight-merge-authorization-v1.schema.json '
    '--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/spotlight-link-sync.yml" '
    '--signer-digest "$BASE_SHA" --source-digest "$BASE_SHA" --source-ref refs/heads/main '
    '--deny-self-hosted-runners --format json > verified-merge-authorization.json'
)
FROZEN_SELF_TEST_VERIFY_HEAD = 'gh attestation verify "$SUBJECT" \\'
ORIGINAL_SELF_TEST = core.self_test




def validate_serialized_separator_inventory() -> tuple[int, int]:
    paths = sorted({*core.WORKFLOWS.glob("*.yml"), *core.WORKFLOWS.glob("*.yaml")})
    core.require(paths, "No workflow files found")
    run_count = 0
    for path in paths:
        label = path.name
        text = path.read_text(encoding="utf-8")
        run_count += shell_source.validate_workflow_text(text, label)
    return len(paths), run_count


def self_test_serialized_separator() -> None:
    shell_source.self_test()

def self_test_with_frozen_fixture() -> None:
    production_verify = core.GH_ATTESTATION_VERIFY_HEAD
    core.GH_ATTESTATION_VERIFY_HEAD = FROZEN_SELF_TEST_VERIFY_HEAD
    try:
        ORIGINAL_SELF_TEST()
    finally:
        core.GH_ATTESTATION_VERIFY_HEAD = production_verify


def main() -> int:
    original_jobs = core.PRIVILEGED_JOBS
    original_verify = core.GH_ATTESTATION_VERIFY_HEAD
    original_self_test = core.self_test
    core.PRIVILEGED_JOBS = ITEM11_PRIVILEGED_JOBS
    core.GH_ATTESTATION_VERIFY_HEAD = EXACT_COMPRESSED_ATTESTATION_VERIFY
    core.self_test = self_test_with_frozen_fixture
    try:
        self_test_serialized_separator()
        result = core.main()
        if result != 0:
            return result
        workflow_count, run_count = validate_serialized_separator_inventory()
        print(
            f"Workflow serialized-separator validation passed: scanned {run_count} run blocks across "
            f"{workflow_count} workflows; quoted/quoted-heredoc \\n data remains valid while every unquoted "
            "literal backslash-n in shell source is rejected."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        core.PRIVILEGED_JOBS = original_jobs
        core.GH_ATTESTATION_VERIFY_HEAD = original_verify
        core.self_test = original_self_test


if __name__ == "__main__":
    raise SystemExit(main())