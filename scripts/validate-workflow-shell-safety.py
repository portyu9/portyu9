#!/usr/bin/env python3
"""Extend the frozen workflow shell-safety scanner with item-11 ADR signers."""
from __future__ import annotations

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
        return core.main()
    finally:
        core.PRIVILEGED_JOBS = original_jobs
        core.GH_ATTESTATION_VERIFY_HEAD = original_verify
        core.self_test = original_self_test


if __name__ == "__main__":
    raise SystemExit(main())