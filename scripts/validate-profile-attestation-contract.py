#!/usr/bin/env python3
"""Apply post-item-10 Profile Stats extensions around the frozen attestation proof."""
from __future__ import annotations

import profile_attestation_contract_item10_core as core


LEGACY_JOB_BLOCK = core.job_block
CURRENT_DISPATCH_NEEDS = "    needs: [dispatch_plan, receipt_attest, lease, attest]\n"
LEGACY_DISPATCH_NEEDS = "    needs: [receipt_attest, lease, attest]\n"


def item11_job_block(workflow: str, key: str, next_key: str | None) -> str:
    """Project only reviewed post-item-10 boundaries into the frozen proof."""
    if key == "receipt_attest" and next_key == "dispatch":
        return LEGACY_JOB_BLOCK(workflow, key, "dispatch_plan")

    if key == "dispatch" and next_key is None:
        block = LEGACY_JOB_BLOCK(workflow, key, "decision_receipt")
        if block.count(CURRENT_DISPATCH_NEEDS) != 1:
            raise ValueError(
                "Profile Stats frozen attestation projection lost exact dispatch-plan dependency"
            )
        return block.replace(CURRENT_DISPATCH_NEEDS, LEGACY_DISPATCH_NEEDS, 1)

    return LEGACY_JOB_BLOCK(workflow, key, next_key)


def main() -> int:
    core.job_block = item11_job_block
    return core.main()


if __name__ == "__main__":
    raise SystemExit(main())
