#!/usr/bin/env python3
"""Extend the frozen repository-governance contract with item-11 ADR jobs."""
from __future__ import annotations

import governance_contract_item10_core as core


CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"
UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
UPSTREAM_SHA = "49b5f7091182a45f3ef93923505b660c6da5f835"
ATTEST_SHA = "1e69f48acb82d1966a394da916b4c1698aa569d6"

ORIGINAL_VALIDATE_STATS = core.validate_stats
ORIGINAL_VALIDATE_QUALITY = core.validate_quality


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_action_identity_projection() -> None:
    for name, value in (
        ("CHECKOUT_SHA", CHECKOUT_SHA),
        ("SETUP_PYTHON_SHA", SETUP_PYTHON_SHA),
        ("UPLOAD_SHA", UPLOAD_SHA),
        ("DOWNLOAD_SHA", DOWNLOAD_SHA),
        ("UPSTREAM_SHA", UPSTREAM_SHA),
        ("ATTEST_SHA", ATTEST_SHA),
    ):
        require(value == getattr(core, name),
                f"Governance adapter {name} differs from frozen contract")



def validate_quality_native_gate(text: str) -> None:
    marker = "  governed_bot_review:\n"
    require(text.count(marker) == 1,
            "Profile Quality native governed-bot review gate must exist exactly once")
    gate = text[text.index(marker):]
    for fragment in (
        "name: trusted-governed-bot-review",
        "runs-on: ubuntu-24.04",
        "permissions:\n      contents: read\n      pull-requests: read",
        "scripts/governed_bot_review_gate.py?ref=${EVENT_BASE_SHA}",
        "EXPECTED_GATE_BLOB: 844026bd8a752433dd8b01477e7e1b56b587d0b1",
        'python3 "$TRUSTED_GATE" --self-test',
        'python3 "$TRUSTED_GATE"',
    ):
        require(fragment in gate, f"Profile Quality native review gate contract is missing: {fragment}")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "contents: write", "pull-requests: write"):
        require(forbidden not in gate,
                f"Profile Quality native review gate acquired forbidden authority/execution surface: {forbidden}")

    legacy_quality = text[:text.index(marker)]
    validate = core.job_block(legacy_quality, "validate", "integration")
    integration = core.job_block(legacy_quality, "integration", "dependabot_admission")
    witness_permissions = (
        "permissions:\n"
        "      actions: read\n"
        "      attestations: read\n"
        "      contents: read"
    )
    require(validate.count(witness_permissions) == 1,
            "Profile Quality Action-provenance consumer must retain exact read-only authority")
    require(integration.count(witness_permissions) == 1,
            "Profile Quality generator-compatibility consumer must retain exact read-only authority")
    for forbidden in (
        "actions: write",
        "attestations: write",
        "checks: write",
        "contents: write",
        "id-token: write",
        "pull-requests: write",
    ):
        require(forbidden not in validate and forbidden not in integration,
                f"Profile Quality witness consumers acquired forbidden write authority: {forbidden}")

    projected_quality = legacy_quality.replace(
        witness_permissions,
        "permissions:\n      contents: read",
        1,
    )
    projected_quality = projected_quality.replace(
        witness_permissions,
        "permissions:\n      contents: read",
        1,
    )
    ORIGINAL_VALIDATE_QUALITY(projected_quality)


def validate_stats_item11(text: str) -> None:
    require(text.count("runs-on: ubuntu-24.04") == 11,
            "All eleven Profile Stats jobs must pin ubuntu-24.04")
    preparer = core.job_block(text, "decision_receipt", "decision_receipt_attest")
    signer = core.job_block(text, "decision_receipt_attest", None)
    require("name: prepare-automation-decision-receipt-read-only" in preparer,
            "Profile Stats ADR preparer identity changed")
    require("permissions:\n      contents: read\n      actions: read" in preparer,
            "Profile Stats ADR preparer must remain contents/actions read-only")
    require("needs: [dispatch, lease]" in preparer,
            "Profile Stats ADR preparer dependency closure changed")
    require("name: attest-automation-decision-receipt-write-only" in signer,
            "Profile Stats ADR signer identity changed")
    require("permissions:\n      contents: read\n      id-token: write\n      attestations: write" in signer,
            "Profile Stats ADR signer authority changed")
    require("needs: [decision_receipt, lease, attest]" in signer,
            "Profile Stats ADR signer dependency closure changed")
    for forbidden in ("contents: write", "actions: write", "pull-requests: write", "checks: write"):
        require(forbidden not in preparer and forbidden not in signer,
                f"Profile Stats ADR jobs acquired unrelated write authority: {forbidden}")

    marker = "  decision_receipt:\n"
    require(text.count(marker) == 1,
            "Profile Stats ADR projection cannot isolate decision receipt tail")
    tail = text[text.index(marker):]
    require(tail.count("  decision_receipt_attest:\n") == 1,
            "Profile Stats ADR projection cannot isolate signer")
    ORIGINAL_VALIDATE_STATS(text[:text.index(marker)])


def main() -> int:
    original_stats = core.validate_stats
    original_quality = core.validate_quality
    core.validate_stats = validate_stats_item11
    core.validate_quality = validate_quality_native_gate
    try:
        validate_action_identity_projection()
        return core.main()
    finally:
        core.validate_stats = original_stats
        core.validate_quality = original_quality


if __name__ == "__main__":
    raise SystemExit(main())
