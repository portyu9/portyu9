#!/usr/bin/env python3
"""Extend the frozen repository-governance contract with item-11 ADR jobs."""
from __future__ import annotations

import governance_contract_item10_core as core


ORIGINAL_VALIDATE_STATS = core.validate_stats


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


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
    original = core.validate_stats
    core.validate_stats = validate_stats_item11
    try:
        return core.main()
    finally:
        core.validate_stats = original


if __name__ == "__main__":
    raise SystemExit(main())
