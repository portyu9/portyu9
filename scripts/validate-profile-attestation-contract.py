#!/usr/bin/env python3
"""Apply the item-11 ADR boundary around the frozen profile attestation proof."""
from __future__ import annotations

import profile_attestation_contract_item10_core as core


LEGACY_JOB_BLOCK = core.job_block


def item11_job_block(workflow: str, key: str, next_key: str | None) -> str:
    """Keep the evidence-attestation domain ending at the ADR preparer."""
    if key == "dispatch" and next_key is None:
        next_key = "decision_receipt"
    return LEGACY_JOB_BLOCK(workflow, key, next_key)


def main() -> int:
    core.job_block = item11_job_block
    return core.main()


if __name__ == "__main__":
    raise SystemExit(main())
